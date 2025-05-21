const queryLog = `PREFIX logs: <http://www.semanticweb.org/logs-ontology-v2#>
PREFIX rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX xsd:  <http://www.w3.org/2001/XMLSchema#>

SELECT
  ?log
  ?type
  ?timestamp
  ?action
  ?state
  ?decision
  ?context
  ?command
  ?package_name
  ?package_version
  ?package_architecture
FROM <http://localhost:8890/linpack>
WHERE {
  ## Apenas estes quatro tipos de evento
  ?log rdf:type ?type .
  FILTER(?type IN (
    logs:StateEvent,
    logs:ActionEvent,
    logs:ConffileEvent,
    logs:StartupEvent
  ))
  
  ## Timestamp comum a todos
  ?log logs:timestamp ?timestamp .
  
  ## Propriedades específicas de cada tipo
  OPTIONAL { ?log logs:action   ?action }      # ActionEvent
  OPTIONAL { ?log logs:state    ?state  }      # StateEvent
  OPTIONAL { ?log logs:decision ?decision }    # ConfFileEvent
  OPTIONAL { ?log logs:context  ?context }     # StartUpEvent
  OPTIONAL { ?log logs:command  ?command }     # StartUpEvent

  ## Pacote (só para ActionEvent e StateEvent)
  OPTIONAL {
    ?log  logs:has_package ?package .
    ?package
      logs:package_name         ?package_name ;
      logs:current_version      ?package_version ;
      logs:package_architecture ?package_architecture .
  }
}
ORDER BY ?timestamp`

const queryCVE=`PREFIX cve: <http://purl.org/cyber/cve#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

SELECT ?cve ?description ?base_score ?base_severity ?cvss_version ?cvss_code
       ?product ?product_name
       ?vendor ?vendor_name
       ?ref ?ref_url ?ref_source ?ref_name
       ?first_version ?last_version
       ?first_version_major ?first_version_minor ?first_version_patch
       ?last_version_major ?last_version_minor ?last_version_patch
FROM <http://localhost:8890/linpack>
WHERE {
  # CVE entity
  ?cve a cve:CVE ;
       cve:description ?description ;
       cve:base_score ?base_score ;
       cve:base_severity ?base_severity ;
       cve:cvss_version ?cvss_version ;
       cve:cvss_code ?cvss_code ;
       cve:has_references ?ref ;
       cve:has_affected_product ?product .

  # Reference info
  ?ref a cve:References ;
       cve:url ?ref_url ;
       cve:ref_source ?ref_source ;
       cve:ref_name ?ref_name .

  # Product info
  ?product a cve:Product ;
           cve:product_name ?product_name ;
           cve:has_vendor ?vendor ;
           cve:has_first_version ?first_version ;
           cve:has_last_version ?last_version ;
           cve:has_cve ?cve .  # <=== Restriction: product has this CVE

  # Vendor info
  ?vendor a cve:Vendor ;
          cve:vendor_name ?vendor_name .

  # First version details
  ?first_version a cve:Version ;
                 cve:version_major ?first_version_major ;
                 cve:version_minor ?first_version_minor ;
                 cve:version_patch ?first_version_patch ;
                 cve:has_cve_affecting_product ?cve .  # <=== Restriction: version tied to this CVE

  # Last version details
  ?last_version a cve:Version ;
                cve:version_major ?last_version_major ;
                cve:version_minor ?last_version_minor ;
                cve:version_patch ?last_version_patch ;
                cve:has_cve_affecting_product ?cve .  # <=== Restriction: version tied to this CVE
}`

const highestSeverityCVEsQuery = `
PREFIX cve: <http://purl.org/cyber/cve#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

SELECT ?cve ?description ?base_score ?base_severity ?cvss_version ?cvss_code
FROM <http://localhost:8890/linpack>
WHERE {
  ?cve a cve:CVE ;
       cve:description ?description ;
       cve:base_score ?base_score ;
       cve:base_severity ?base_severity ;
       cve:cvss_version ?cvss_version ;
       cve:cvss_code ?cvss_code .
}
ORDER BY DESC(?base_score)
LIMIT 5
`
const countCVEsPerProductQuery = `
PREFIX : <http://purl.org/cyber/cve#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

SELECT ?product ?productName (COUNT(?cve) AS ?numCVEs)
WHERE {
  ?product rdf:type :Product .
  ?product :product_name ?productName .
  ?product :has_cve ?cve .
}
GROUP BY ?product ?productName
ORDER BY DESC(?numCVEs)
`


/**
  * Fetch data from SPARQL endpoint
  * @param {string} query - The SPARQL query to execute
  * @returns {Promise<Array>} - A promise that resolves to the results of the query
 */

async function fetchDataFromSPARQLEndPoint(query) {
  const endpoint = 'http://localhost:3001/sparql?query=' + encodeURIComponent(query);
  const response = await fetch(endpoint, {
    method: 'GET',
    headers: {
      'Accept': 'application/sparql-results+json'
    }
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`HTTP error ${response.status}:\n${text}`);
  }

  const data = await response.json();
  return data.results.bindings;
}



/**
 * Extract local name from a URI
 * @param {string} uri - The URI to extract the local name from
 * @returns {string|null} - The local name or null if not found
 * */

function extractLocalName(uri) {
  if (!uri) return null;
  const match = uri.match(/[#\/]([^#\/]+)$/);
  return match ? match[1] : uri;
}

/**
  * Process log data to create a graph structure
  * @param {Array} bindings - The log data from SPARQL endpoint
  * @return {Object} - An object containing nodes and links
  * */

function processLogDataToGraph(bindings) {
  const nodesMap = new Map(); // We use a Map to assure the unicity of the nodes
  const links = [];

  bindings.forEach(entry => {
    const logURI = entry.log?.value;
    const logId = extractLocalName(logURI);
    const eventTypeURI = entry.type?.value;
    const eventType = extractLocalName(eventTypeURI);

    // If the node wasn't already added to the Map...
    if (!nodesMap.has(logId)) {
      const node = {
        id: logId,
        uri: logURI,
        type: eventType,
      };

      // Common properties
      if (entry.timestamp) {
        node["timestamp"] = entry.timestamp.value;
      }

      // Type properties
      if (eventType === "ActionEvent" && entry.action) {
        node["action"] = entry.action.value;
      }

      if (eventType === "StateEvent" && entry.state) {
        node["state"] = entry.state.value;
      }

      if (eventType === "ConffileEvent" && entry.decision) {
        node["decision"] = entry.decision.value;
      }

      if (eventType === "StartupEvent") {
        if (entry.context) node["context"] = entry.context.value;
        if (entry.command) node["command"] = entry.command.value;
      }

      // Adds the node to the map
      nodesMap.set(logId, node);
    }

    // If it has a package...
    const pkgName = entry.package_name?.value;
    const pkgVersion = entry.package_version?.value;
    const pkgArch = entry.package_architecture?.value;

    if (pkgName) {
      const pkgId = `${pkgName}-${pkgVersion}-${pkgArch}`;

      // If the package hasn't been already added to the map...
      if (!nodesMap.has(pkgId)) {
        const pkgNode = {
          id: pkgId,
          type: "Package",
          "package_name": pkgName,
          "current_version": pkgVersion,
          "package_architecture": pkgArch
        };

        // Adds the package to the map
        nodesMap.set(pkgId, pkgNode);
      }

      // Creates the link: log -> package
      links.push({
        source: logId,
        target: pkgId,
        type: "has_package"
      });
    }
  });

  // Converts the map back to an array of nodes
  const nodes = Array.from(nodesMap.values());

  return {
    nodes,
    links
  };
}

function processCVEDataToGraph(bindings) {
  const nodesMap = new Map();
  const links = [];

  bindings.forEach(entry => {
    const cveUri = entry.cve.value;
    const cveId = extractLocalName(cveUri);

    // Nodo CVE
    if (!nodesMap.has(cveId)) {
      nodesMap.set(cveId, {
        id: cveId,
        type: "CVE",
        uri: cveUri,
        description: entry.description?.value,
        base_score: entry.base_score?.value,
        base_severity: entry.base_severity?.value,
        cvss_version: entry.cvss_version?.value,
        cvss_code: entry.cvss_code?.value,
      });
    }

    // Produto afetado
    const productName = entry.product_name?.value;
    const vendorName = entry.vendor_name?.value;
    const productId = `prod_${productName}`;

    if (productName && !nodesMap.has(productId)) {
      nodesMap.set(productId, {
        id: productId,
        type: "Product",
        name: productName,
        vendor: vendorName
      });
    }

    // Link CVE -> Produto
    if (productName) {
      links.push({
        source: cveId,
        target: productId,
        type: "affects_product"
      });
    }

    // Versões
    const firstVersionId = entry.first_version?.value;
    const lastVersionId = entry.last_version?.value;

    if (firstVersionId) {
      const versionId = extractLocalName(firstVersionId);
      if (!nodesMap.has(versionId)) {
        nodesMap.set(versionId, {
          id: versionId,
          type: "Version",
          major: entry.first_version_major?.value,
          minor: entry.first_version_minor?.value,
          patch: entry.first_version_patch?.value
        });
      }
      links.push({
        source: productId,
        target: versionId,
        type: "has_first_version"
      });

      // Link versão para CVE (has_cve_affecting_product)
      links.push({
        source: versionId,
        target: cveId,
        type: "has_cve_affecting_product"
      });
    }

    if (lastVersionId) {
      const versionId = extractLocalName(lastVersionId);
      if (!nodesMap.has(versionId)) {
        nodesMap.set(versionId, {
          id: versionId,
          type: "Version",
          major: entry.last_version_major?.value,
          minor: entry.last_version_minor?.value,
          patch: entry.last_version_patch?.value
        });
      }
      links.push({
        source: productId,
        target: versionId,
        type: "has_last_version"
      });

      // Link versão para CVE (has_cve_affecting_product)
      links.push({
        source: versionId,
        target: cveId,
        type: "has_cve_affecting_product"
      });
    }

    // Referências
    const refUri = entry.ref?.value;
    if (refUri) {
      const refId = extractLocalName(refUri);
      if (!nodesMap.has(refId)) {
        nodesMap.set(refId, {
          id: refId,
          type: "References",
          name: entry.ref_name?.value,
          source: entry.ref_source?.value,
          url: entry.ref_url?.value
        });
      }
      links.push({
        source: cveId,
        target: refId,
        type: "has_references"
      });
    }
  });

  return {
    nodes: Array.from(nodesMap.values()),
    links
  };
}

// Extract needed data for bubbles: productName and count
function processCountData(bindings) {
  return bindings.map(d => ({
    productName: d.productName.value,
    numCVEs: +d.numCVEs.value
  }));
}


function mergeGraphs(graph1, graph2) {
  const nodesMap = new Map();

  // Adiciona nós do grafo 1
  graph1.nodes.forEach(node => nodesMap.set(node.id, node));
  // Adiciona nós do grafo 2 (sem sobrescrever)
  graph2.nodes.forEach(node => {
    if (!nodesMap.has(node.id)) {
      nodesMap.set(node.id, node);
    }
  });

  const combinedNodes = Array.from(nodesMap.values());
  const combinedLinks = [...graph1.links, ...graph2.links];

  return {
    nodes: combinedNodes,
    links: combinedLinks
  };
}




// Main function
function main() {
  fetchDataFromSPARQLEndPoint(queryCVE)
    .then(data => {
      //console.log("Fetched data:", data);
      const graph = processCVEDataToGraph(data)
      graph.nodes.forEach(node => {
        if (node.type === "Version") {
          console.log("Version Node:", node);
        }
      });
      // const graph = processLogDataToGraph(data);
      // graph.nodes.forEach(node => {
      //   console.log("Node:", node);
      // });
      // graph.links.forEach(link => {
      //   console.log("Link:", link);
      // });
      // console.log(encodeURIComponent(queryLog));
    })
    .catch(error => {
      console.error("Error fetching SPARQL data:", error);
    });
}

main();