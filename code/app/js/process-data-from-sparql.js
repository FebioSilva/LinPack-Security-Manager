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
       cve:has_affected_product ?product .

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

  // Map para relacionar produto -> versões (para evitar duplicação)
  const productVersionsMap = new Map();

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
        cvss_code: entry.cvss_code?.value
      });
    }

    const cveNode = nodesMap.get(cveId);

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
      productVersionsMap.set(productId, new Map()); // Inicializa mapa de versões para o produto
    }

    // Versões (normalmente first e last versões, que indicam intervalo)
    const versionData = [
      {
        versionUri: entry.first_version?.value,
        major: entry.first_version_major?.value,
        minor: entry.first_version_minor?.value,
        patch: entry.first_version_patch?.value,
      },
      {
        versionUri: entry.last_version?.value,
        major: entry.last_version_major?.value,
        minor: entry.last_version_minor?.value,
        patch: entry.last_version_patch?.value,
      }
    ];

    if (productName) {
      // Para cada versão do CVE, criamos nó de versão (se não existir)
      versionData.forEach(({ versionUri, major, minor, patch }) => {
        if (versionUri) {
          const versionId = extractLocalName(versionUri);

          // Verifica se versão já foi adicionada para esse produto
          if (!productVersionsMap.get(productId).has(versionId)) {
            nodesMap.set(versionId, {
              id: versionId,
              type: "Version",
              major,
              minor,
              patch
            });

            // Marca que essa versão pertence ao produto
            productVersionsMap.get(productId).set(versionId, true);

            // Link produto -> versão
            links.push({ source: productId, target: versionId, type: "has_version" });
          }

          // Link versão -> CVE
          links.push({ source: versionId, target: cveId, type: "has_cve_affecting_product" });
        }
      });

      // Opcional: link direto produto -> CVE (pode ajudar, mas pode causar clutter)
      // links.push({ source: productId, target: cveId, type: "affects_product" });
    }
  });

  return {
    nodes: Array.from(nodesMap.values()),
    links: links
  };
}


// Extract needed data for bubbles: productName and count
function processCountData(bindings) {
  return bindings.map(d => ({
    productName: d.productName.value,
    numCVEs: +d.numCVEs.value
  }));
}

function processTopCVEsData(bindings) {
  const cveList = []
  bindings.forEach(cve => {
    cveList.push({ 
      id: cve.cve.value.split("#")[1],
      score: Number(cve['base_score']['value']),
      severity: cve['base_severity']['value'],
      version: cve['cvss_version']['value']
    })
  })
  return {
    cves: cveList
  }
}

function mergeGraphs(graph1, graph2) {
  const nodeMap = new Map();
  const linkSet = new Set();

  // Adiciona todos os nós do primeiro grafo
  for (const node of graph1.nodes) {
    nodeMap.set(node.id, { ...node });
  }

  // Adiciona nós do segundo grafo, se não existirem
  for (const node of graph2.nodes) {
    if (!nodeMap.has(node.id)) {
      nodeMap.set(node.id, { ...node });
    }
  }

  // Links do primeiro grafo
  for (const link of graph1.links) {
    const key = `${link.source}->${link.target}`;
    linkSet.add(key);
  }

  // Links do segundo grafo, evitando duplicatas
  for (const link of graph2.links) {
    const key = `${link.source}->${link.target}`;
    if (!linkSet.has(key)) {
      linkSet.add(key);
    }
  }

  return {
    nodes: Array.from(nodeMap.values()),
    links: Array.from(linkSet).map(key => {
      const [source, target] = key.split("->");
      return { source, target };
    })
  };
}


// Main function
function main() {
  fetchDataFromSPARQLEndPoint(queryCVE)
    .then(data => {
      console.log("Fetched data:", data);
      const graph = processCVEDataToGraph(data)
      graph.nodes.forEach(node => {
        if (node.type === "Version") {
          //console.log("Version Node:", node);
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