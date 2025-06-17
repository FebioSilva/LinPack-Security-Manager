import compareVersions from 'dpkg-compare-versions';

export const queryLog = `PREFIX logs: <http://www.semanticweb.org/logs-ontology-v2#>
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
  ?package
  ?package_name
  ?package_version
  ?package_architecture
  ?installed
  ?replaced_by
FROM <http://localhost:8890/linpack>
WHERE {
  ## quatro tipos de evento
  ?log rdf:type ?type .
  FILTER(?type IN (
    logs:StateEvent,
    logs:ActionEvent,
    logs:ConffileEvent,
    logs:StartupEvent
  ))

  ## timestamp comum
  ?log logs:timestamp ?timestamp .

  ## propriedades específicas
  OPTIONAL { ?log logs:action   ?action }     # ActionEvent
  OPTIONAL { ?log logs:state    ?state  }     # StateEvent
  OPTIONAL { ?log logs:decision ?decision }   # ConffileEvent
  OPTIONAL { ?log logs:context  ?context }    # StartupEvent
  OPTIONAL { ?log logs:command  ?command }    # StartupEvent

  ## pacotes (ActionEvent / StateEvent)
  OPTIONAL {
    ?log logs:has_package ?package .
    ?package
      logs:package_name         ?package_name ;
      logs:version              ?package_version ;
      logs:package_architecture ?package_architecture ;
      logs:installed            ?installed .
    OPTIONAL { ?package logs:replaced_by ?replaced_by }
  }
}
ORDER BY ?timestamp
`


export const highestSeverityCVEsQuery = `
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
export const countCVEsPerProductQuery = `
PREFIX : <http://purl.org/cyber/cve#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

SELECT ?product ?productName (COUNT(?cve) AS ?numCVEs)
WHERE {
  ?cve :has_affected_product ?product .
  ?product rdf:type :Product .
  ?product :product_name ?productName .
}
GROUP BY ?product ?productName
ORDER BY DESC(?numCVEs)
`

export const logsAndCVEs = (year) => `
PREFIX cve:     <http://purl.org/cyber/cve#>
PREFIX linpack: <http://www.semanticweb.org/linpack/>
PREFIX logs:    <http://www.semanticweb.org/logs-ontology-v2/>
PREFIX rdf:     <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX xsd:     <http://www.w3.org/2001/XMLSchema#>

SELECT DISTINCT
       ?cve ?description ?cvss_version ?base_score ?base_severity ?cvss_code ?pub_date

       ?product ?product_name
       ?vendor  ?vendor_name

       ?version_interval ?min ?max

       ?package  ?package_name ?package_version ?package_architecture
       ?log      ?event_type   ?timestamp
WHERE {
  #######################################################################
  ## CVE                                                               ##
  #######################################################################
  ?cve  a                     cve:CVE ;
        cve:description       ?description ;
        cve:cvss_version      ?cvss_version ;
        cve:base_score        ?base_score ;
        cve:base_severity     ?base_severity ;
        cve:cvss_code         ?cvss_code ;
        cve:pub_date          ?pub_date ;
        cve:has_affected_product ?product ;
        cve:has_references ?reference .

  ${year ? `FILTER(STRSTARTS(STR(?pub_date), "${year}"))` : ""}

  #######################################################################
  ## Produto + Vendor + versão afeta                                  ##
  #######################################################################
  ?product a                  cve:Product ;
           cve:product_name   ?product_name ;
           cve:has_vendor     ?vendor .

  ?vendor  a                  cve:Vendor ;
           cve:vendor_name    ?vendor_name .

  ?version_interval a cve:Versions ;
                    cve:has_product ?product ;
                    cve:has_cve_affecting_product ?cve .

  OPTIONAL { ?version_interval cve:min ?min . }
  OPTIONAL { ?version_interval cve:max ?max . }

  #######################################################################
  ## Pacotes do sistema + ligação ao produto via nome                 ##
  #######################################################################
  ?package a logs:Package ;
           logs:package_name         ?package_name ;
           logs:version              ?package_version ;
           logs:package_architecture ?package_architecture ;
           logs:installed            True .

  ## Nome do pacote ≈ nome do produto
  FILTER( LCASE(STR(?package_name)) = LCASE(STR(?product_name)) )

  #######################################################################
  ## Eventos de log relacionados (opcional)                           ##
  #######################################################################
  OPTIONAL {
    ?log logs:has_package ?package ;
         rdf:type          ?event_type ;
         logs:timestamp    ?timestamp .
  }
}
`

export const logsAndCVEsMyPkgs = `
PREFIX logs: <http://www.semanticweb.org/logs-ontology-v2#>
PREFIX cve:  <http://purl.org/cyber/cve#>
PREFIX rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX xsd:  <http://www.w3.org/2001/XMLSchema#>

SELECT DISTINCT
  ?log
  ?timestamp
  ?type
  ?package
  ?package_name
  ?package_version
  ?installed
  ?cve
  ?description
  ?base_score
  ?base_severity
  ?cvss_version
  ?cvss_code
WHERE {
  GRAPH <http://localhost:8890/linpack> {
    ## Only ActionEvent and StateEvent with packages
    ?log rdf:type ?type ;
         logs:timestamp ?timestamp ;
         logs:has_package ?package .
    FILTER(?type IN (logs:StateEvent, logs:ActionEvent))

    ## Package details, installed = true
    ?package logs:package_name ?package_name ;
             logs:version ?package_version ;
             logs:installed true .
    BIND(true AS ?installed)
  }

  ## CVE part
  ?cve a cve:CVE ;
       cve:description ?description ;
       cve:base_score ?base_score ;
       cve:base_severity ?base_severity ;
       cve:cvss_version ?cvss_version ;
       cve:cvss_code ?cvss_code ;
       cve:has_affected_product ?product .

  ?product a cve:Product ;
           cve:product_name ?package_name ;
           cve:has_version_interval ?version_interval .

  ?version_interval a cve:Versions ;
                    cve:has_cve_affecting_product ?cve .

  OPTIONAL { ?version_interval cve:min ?version_min . }
  OPTIONAL { ?version_interval cve:max ?version_max . }

  ## Version range filtering (string comparison)
  FILTER (
    (!BOUND(?version_min) || xsd:string(?package_version) >= xsd:string(?version_min)) &&
    (!BOUND(?version_max) || xsd:string(?package_version) <= xsd:string(?version_max))
  )
}
`

export function generateCVEQueryByYear(year) {
  if (year === "all") {
    return logsAndCVEs;
  }
  else if (year && year.length === 4) {
    return logsAndCVEs(year);
  }
}



/**
  * Fetch data from SPARQL endpoint
  * @param {string} query - The SPARQL query to execute
  * @returns {Promise<Array>} - A promise that resolves to the results of the query
 */

export async function fetchDataFromSPARQLEndPoint(query, signal) {
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

export async function fetchAllDataWithPagination(baseQuery, signal, limit = 10000) {
  let offset = 0;
  let allResults = [];
  let hasMore = true;

  while (hasMore) {
    const pagedQuery = `${baseQuery} LIMIT ${limit} OFFSET ${offset}`;
    const pageResults = await fetchDataFromSPARQLEndPoint(pagedQuery, signal);

    allResults = allResults.concat(pageResults);
    hasMore = pageResults.length === limit;
    offset += limit;
  }
  console.log(`Total results fetched: ${allResults.length}`);
  return allResults;
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

export function processLogDataToGraph(bindings) {
  const nodesMap = new Map();
  const links = [];

  bindings.forEach(entry => {
    const logURI = entry.log?.value;
    const logId = extractLocalName(logURI);
    const eventTypeURI = entry.type?.value;
    const eventType = extractLocalName(eventTypeURI);

    if (!nodesMap.has(logId)) {
      const node = {
        id: logId,
        uri: logURI,
        type: eventType,
      };

      if (entry.timestamp) node.timestamp = entry.timestamp.value;
      if (eventType === "ActionEvent" && entry.action) node.action = entry.action.value;
      if (eventType === "StateEvent" && entry.state) node.state = entry.state.value;
      if (eventType === "ConffileEvent" && entry.decision) node.decision = entry.decision.value;
      if (eventType === "StartupEvent") {
        if (entry.context) node.context = entry.context.value;
        if (entry.command) node.command = entry.command.value;
      }

      nodesMap.set(logId, node);
    }

    // Aqui o principal ajuste: nomes corretos conforme queryLog
    const pkgName = entry.package_name?.value;
    const pkgVersion = entry.package_version?.value;
    const pkgArch = entry.package_architecture?.value;

    if (pkgName) {
      const pkgId = `${pkgName}-${pkgVersion}-${pkgArch}`;
      if (!nodesMap.has(pkgId)) {
        nodesMap.set(pkgId, {
          id: pkgId,
          type: "Package",
          package_name: pkgName,
          current_version: pkgVersion,
          package_architecture: pkgArch,
          installed: entry.installed?.value === "true" || entry.installed?.value === "1",
        });
      }

      links.push({
        source: logId,
        target: pkgId,
        type: "has_package",
      });
    }
  });

  return { nodes: Array.from(nodesMap.values()), links };
}




export function processCVEDataToGraph(bindings) {
  const nodesMap = new Map();
  const links = [];
  const productVersionsMap = new Map();
  const cveProductLinks = new Set();  // para evitar duplicados

  bindings.forEach(entry => {
    const cveUri = entry.cve.value;
    const cveId  = extractLocalName(cveUri);

    // Nó CVE
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

    // Produto
    const productName = entry.product_name?.value;
    const vendorName  = entry.vendor_name?.value;
    const productUri  = entry.product?.value;
    const productId   = `prod_${productName}`;

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

    // Versão
    const versionUri = entry.version_interval?.value;
    if (versionUri) {
      const versionId = extractLocalName(versionUri);

      if (!productVersionsMap.get(productId)?.has(versionId)) {
        nodesMap.set(versionId, {
          id: versionId,
          type: "Version",
          uri: versionUri,
          min: entry.min?.value || null,
          max: entry.max?.value || null,
        });
        productVersionsMap.get(productId).set(versionId, true);
        links.push({ source: productId, target: versionId, type: "has_version" });
      }

      links.push({ source: versionId, target: cveId, type: "affects" });
    }

    // Ligação CVE → Product sem duplicados
    const key = `${cveId}->${productId}`;
    if (!cveProductLinks.has(key)) {
      links.push({ source: cveId, target: productId, type: "has_affected_product" });
      cveProductLinks.add(key);
    }
  });

  console.log(`Total nós: ${nodesMap.size}, Total links: ${links.length}`);
  return {
    nodes: Array.from(nodesMap.values()),
    links
  };
}




function isValidVersion(v) {
  return typeof v === "string" && /^\d/.test(v) && !/[^0-9a-zA-Z.-]/.test(v);
}

function versionInRange(version, min, max) {
  if (!version || !isValidVersion(version)) return false;

  if (min && !isValidVersion(min)) {
    min = null;
  }
  if (max && !isValidVersion(max)) {
    max = null;
  }

  if (min && compareVersions(version, min) < 0) {
    return false;
  }
  if (max && compareVersions(version, max) > 0) {
    return false;
  }
  return true;
}


export function processCVEAndLogDataToGraph(bindings) {
  const nodesMap = new Map();
  const links = [];
  const seenLinks = new Set();
  const seenVersions = new Set();

  function debugLog(...args) {
    // console.log(...args); // Ative para debug
  }

  bindings.forEach(entry => {
    // --- CVE node ---
    const cveUri = entry.cve?.value;
    if (!cveUri) return; // Ignorar se não tiver CVE
    const cveId = extractLocalName(cveUri);

    // --- Product node ---
    const productName = entry.product_name?.value;
    const vendorName = entry.vendor_name?.value;
    const productUri = entry.product?.value;
    const productId = productName ? `prod_${productName}` : null;

    // --- Version interval ---
    const versionUri = entry.version_interval?.value;
    const versionId = versionUri ? extractLocalName(versionUri) : null;
    const min = entry.min?.value || null;
    const max = entry.max?.value || null;

    // --- Package info ---
    const pkgUri = entry.package?.value;
    const pkgName = entry.package_name?.value;
    const pkgVersion = entry.package_version?.value;
    const pkgArch = entry.package_architecture?.value;

    // ** FILTRO PRINCIPAL: Só processa se pkgVersion estiver no intervalo [min, max] **
    if (!versionInRange(pkgVersion, min, max)) {
      debugLog(`Ignorando pacote ${pkgName} versão ${pkgVersion} fora do intervalo [${min}, ${max}]`);
      return; // Ignora essa entrada completamente, não cria nodes nem links
    }

    // Cria CVE node (se não existir)
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
        pub_date: entry.pub_date?.value,
      });
    }

    // Cria Product node (se não existir)
    if (productId && !nodesMap.has(productId)) {
      nodesMap.set(productId, {
        id: productId,
        type: "Product",
        name: productName,
        vendor: vendorName,
        uri: productUri,
      });
    }

    // Link CVE -> Product
    if (productId) {
      const cveProductKey = `${cveId}->${productId}`;
      if (!seenLinks.has(cveProductKey)) {
        links.push({ source: cveId, target: productId, type: "has_affected_product" });
        seenLinks.add(cveProductKey);
        debugLog(`Link CVE->Product: ${cveProductKey}`);
      }
    }

    // --- Version node e links relacionados ---
    if (versionId && !seenVersions.has(versionId)) {
      nodesMap.set(versionId, {
        id: versionId,
        type: "Version",
        uri: versionUri,
        min,
        max
      });
      seenVersions.add(versionId);
    }

    // --- Link produto -> versão só da entrada atual ---
    if (productId && versionId) {
      // Só cria link se o pacote que está nessa entrada estiver no range (para garantir coerência)
      if (versionInRange(pkgVersion, min, max)) {
        const productVersionKey = `${productId}->${versionId}`;
        if (!seenLinks.has(productVersionKey)) {
          links.push({ source: productId, target: versionId, type: "has_version" });
          seenLinks.add(productVersionKey);
        }
      }
    }


    // Link Version -> CVE
    if (versionId) {
      const versionCVEKey = `${versionId}->${cveId}`;
      if (!seenLinks.has(versionCVEKey)) {
        links.push({ source: versionId, target: cveId, type: "affects" });
        seenLinks.add(versionCVEKey);
        debugLog(`Link Version->CVE: ${versionCVEKey}`);
      }
    }

    // --- Package node ---
    if (pkgUri && pkgName && pkgVersion && pkgArch) {
      const pkgId = `${pkgName}-${pkgVersion}-${pkgArch}`;

      if (!nodesMap.has(pkgId)) {
        nodesMap.set(pkgId, {
          id: pkgId,
          type: "Package",
          uri: pkgUri,
          package_name: pkgName,
          current_version: pkgVersion,
          package_architecture: pkgArch,
          installed: true,
        });
      }

      // Link Package -> Version
      if (versionId) {
        const pkgVersionKey = `${pkgId}->${versionId}`;
        if (!seenLinks.has(pkgVersionKey)) {
          links.push({ source: pkgId, target: versionId, type: "version_matches" });
          seenLinks.add(pkgVersionKey);
          debugLog(`Link Package->Version: ${pkgVersionKey}`);
        }
      }


      // Link Package -> Product
      if (productId) {
        const pkgProductKey = `${pkgId}->${productId}`;
        if (!seenLinks.has(pkgProductKey)) {
          links.push({ source: pkgId, target: productId, type: "package_of_product" });
          seenLinks.add(pkgProductKey);
          debugLog(`Link Package->Product: ${pkgProductKey}`);
        }
      }
    }

    // --- Log node ---
    const logUri = entry.log?.value;
    if (logUri) {
      const logId = extractLocalName(logUri);
      const eventType = extractLocalName(entry.event_type?.value || '');
      if (!nodesMap.has(logId)) {
        nodesMap.set(logId, {
          id: logId,
          uri: logUri,
          type: eventType || "Log",
          timestamp: entry.timestamp?.value,
        });
      }

      // Link Log -> Package
      if (pkgName && pkgVersion && pkgArch) {
        const pkgId = `${pkgName}-${pkgVersion}-${pkgArch}`;
        const logPkgKey = `${logId}->${pkgId}`;
        if (!seenLinks.has(logPkgKey)) {
          links.push({ source: logId, target: pkgId, type: "has_package" });
          seenLinks.add(logPkgKey);
          debugLog(`Link Log->Package: ${logPkgKey}`);
        }
      }
    }
  });

  console.log(`Total nodes: ${nodesMap.size}, Total links: ${links.length}`);
  return {
    nodes: Array.from(nodesMap.values()),
    links,
  };
}








// Extract needed data for bubbles: productName and count
export function processCountData(bindings) {
  return bindings.map(d => ({
    productName: d.productName.value,
    numCVEs: +d.numCVEs.value
  }));
}

export function processTopCVEsData(bindings) {
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

export function mergeGraphs(graph1, graph2) {
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

  // Adiciona links do segundo grafo, evitando réplicas (com tipo)
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
  fetchDataFromSPARQLEndPoint(logsAndCVEs)
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


//main();
