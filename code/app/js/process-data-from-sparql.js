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

SELECT DISTINCT
  ?cve ?description ?base_score ?base_severity ?cvss_version ?cvss_code
  ?product ?product_name
  ?vendor ?vendor_name
  ?version_interval ?version_min ?version_max
WHERE {
  ?cve a cve:CVE ;
       cve:description ?description ;
       cve:base_score ?base_score ;
       cve:base_severity ?base_severity ;
       cve:cvss_version ?cvss_version ;
       cve:cvss_code ?cvss_code ;
       cve:has_affected_product ?product .

  ?product a cve:Product ;
           cve:product_name ?product_name ;
           cve:has_vendor ?vendor ;
           cve:has_version_interval ?version_interval .
  

  ?vendor a cve:Vendor ;
          cve:vendor_name ?vendor_name .

  ?version_interval a cve:Versions ;
                    cve:has_cve_affecting_product ?cve .

  OPTIONAL { ?version_interval cve:min ?version_min . }
  OPTIONAL { ?version_interval cve:max ?version_max . }
}`

const highestSeverityCVEsQuery = `
PREFIX cve: <http://purl.org/cyber/cve#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

SELECT ?cve ?description ?base_score ?base_severity ?cvss_version ?cvss_code
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

function generateCVEQueryByYear(year) {
  if (year === "all") {
    return queryCVE;
  }
  return `
    PREFIX cve: <http://purl.org/cyber/cve#>
    PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

    SELECT ?cve ?pub_date ?description ?base_score ?base_severity ?cvss_version ?cvss_code
           ?product ?product_name
           ?vendor ?vendor_name
    FROM <http://localhost:8890/linpack>
    WHERE {
      ?cve a cve:CVE ;
           cve:description ?description ;
           cve:base_score ?base_score ;
           cve:base_severity ?base_severity ;
           cve:cvss_version ?cvss_version ;
           cve:cvss_code ?cvss_code ;
           cve:pub_date ?pub_date ;
           cve:has_affected_product ?product .

      ?product a cve:Product ;
               cve:product_name ?product_name ;
               cve:has_vendor ?vendor ;
               cve:has_cve ?cve .

      ?vendor a cve:Vendor ;
              cve:vendor_name ?vendor_name .

      FILTER (STRSTARTS(STR(?pub_date), "${year}"))
    }
  `;
}



/**
  * Fetch data from SPARQL endpoint
  * @param {string} query - The SPARQL query to execute
  * @returns {Promise<Array>} - A promise that resolves to the results of the query
 */

async function fetchDataFromSPARQLEndPoint(query, signal) {
  const endpoint = 'http://localhost:3001/sparql?query=' + encodeURIComponent(query);
  const response = await fetch(endpoint, {
    method: 'GET',
    headers: {
      'Accept': 'application/sparql-results+json'
    },
    signal  // passa o signal aqui (undefined se não for passado)
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
  const hashIndex = uri.lastIndexOf('#');
  const slashIndex = uri.lastIndexOf('/');
  return uri.substring(Math.max(hashIndex, slashIndex) + 1);
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
  const productVersionsMap = new Map();

  bindings.forEach(entry => {
    const cveUri = entry.cve.value;
    const cveId = extractLocalName(cveUri);

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

    const productName = entry.product_name?.value;
    const vendorName = entry.vendor_name?.value;
    const productUri = entry.product?.value;
    const productId = `prod_${productName}`;

    if (productName && !nodesMap.has(productId)) {
      nodesMap.set(productId, {
        id: productId,
        type: "Product",
        name: productName,
        vendor: vendorName,
        uri: productUri
      });
      productVersionsMap.set(productId, new Map());
    }

    const versionUri = entry.version_interval?.value;
    if (versionUri) {
      const versionId = extractLocalName(versionUri);

      if (!productVersionsMap.get(productId)?.has(versionId)) {
        nodesMap.set(versionId, {
          id: versionId,
          type: "Version",
          uri: versionUri,
          min: entry.version_min?.value || null,
          max: entry.version_max?.value || null,
        });

        productVersionsMap.get(productId).set(versionId, true);

        links.push({ source: productId, target: versionId, type: "has_version" });
      }

      links.push({ source: versionId, target: cveId, type: "affects" });
    }

    // Aqui a alteração principal da ligação:
    if (productName && cveId) {
      console.log(`Criando link has_affected_product de ${cveId} para ${productId}`);
      links.push({ source: cveId, target: productId, type: "has_affected_product" });
    }
  });

  console.log(`Total nós: ${nodesMap.size}, Total links: ${links.length}`);

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
  const linkMap = new Map(); // chave para links com tipo incluído

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

  // Adiciona links do primeiro grafo (com tipo)
  for (const link of graph1.links) {
    const key = `${link.source}->${link.target}->${link.type}`;
    linkMap.set(key, { ...link });
  }

  // Adiciona links do segundo grafo, evitando duplicatas (com tipo)
  for (const link of graph2.links) {
    const key = `${link.source}->${link.target}->${link.type}`;
    if (!linkMap.has(key)) {
      linkMap.set(key, { ...link });
    }
  }

  return {
    nodes: Array.from(nodeMap.values()),
    links: Array.from(linkMap.values())
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