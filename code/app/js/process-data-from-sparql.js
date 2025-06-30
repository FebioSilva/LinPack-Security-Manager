import compareVersions from 'dpkg-compare-versions';

export const highestSeverityCVEsQuery = `
PREFIX cve:     <http://purl.org/cyber/cve#>
PREFIX logs:    <http://www.semanticweb.org/logs-ontology-v2/>
PREFIX rdf:     <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX linpack: <http://www.semanticweb.org/linpack/>

SELECT DISTINCT
  ?cve
  ?base_score
  ?base_severity
  ?cvss_version
  ?cvss_code
  ?package_name
  ?package_version
   ?min ?max
WHERE {
  ?package a logs:Package ;
           logs:installed true ;
           logs:version              ?package_version ;
           logs:package_name ?package_name;
           linpack:has_related_product ?product .

  ?product a cve:Product ;
           cve:product_name ?product_name ;
           cve:has_version_interval ?version_interval .

  ?version_interval a cve:Versions ;
                    cve:has_cve_affecting_product ?cve ;
                    cve:has_product ?product .

  OPTIONAL { ?version_interval cve:min ?min . }
  OPTIONAL { ?version_interval cve:max ?max . }
  ?cve a cve:CVE ;
       cve:base_score ?base_score ;
       cve:base_severity ?base_severity ;
       cve:cvss_version ?cvss_version ;
       cve:cvss_code ?cvss_code .

}
ORDER BY DESC(?base_score)
`
export const countCVEsPerProductQuery = `PREFIX cve:     <http://purl.org/cyber/cve#>
PREFIX linpack: <http://www.semanticweb.org/linpack/>
PREFIX logs:    <http://www.semanticweb.org/logs-ontology-v2/>
PREFIX rdf:     <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

SELECT  ?version_interval ?min ?max (COUNT(DISTINCT ?cve) AS ?cve_count) ?product ?product_name ?package_name ?package_version
WHERE {
  ?package a logs:Package ;
           logs:package_name         ?package_name ;
           logs:version              ?package_version ;
           logs:installed true ;
           linpack:has_related_product ?product .

  ?product a cve:Product ;
           cve:product_name   ?product_name ;
           cve:has_version_interval ?version_interval .

  ?version_interval a cve:Versions ;
                    cve:has_cve_affecting_product ?cve .

  OPTIONAL { ?version_interval cve:min ?min . }
  OPTIONAL { ?version_interval cve:max ?max . }
}
GROUP BY ?version_interval ?min ?max ?product ?product_name ?package_name ?package_version
ORDER BY DESC(?cve_count)
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
           logs:installed            True ;
           linpack:has_related_product ?product .

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

export function generateCVEQueryByYear(year) {
  console.log("Generating CVE query for year:", year);
  if (year === "all") {
    return logsAndCVEs(); 
  } else if (year && year.length === 4) {
    return logsAndCVEs(year);
  } else {
    throw new Error("Invalid year value");
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

function isValidVersion(v) {
  return typeof v === "string" && /^\d/.test(v);
}

export function versionInRange(version, min, max) {
  if (!version || !isValidVersion(version)) return false;

  if (min === '*' || !min) min = null;
  if (max === '*' || !max) max = null;

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

export function processCountData(bindings) {
  const packageMap = new Map();

  bindings.forEach(entry => {
    const pkgName = entry.package_name?.value + entry.package_version?.value;
    const pkgVersion = entry.package_version?.value;
    const min = entry.min?.value || null;
    const max = entry.max?.value || null;
    const cveCount = parseInt(entry.cve_count?.value || "0", 10);

    if (!pkgName || !pkgVersion || isNaN(cveCount)) return;

    // Aplica o filtro de intervalo [min, max]
    if (!versionInRange(pkgVersion, min, max)) return;

    // Soma os cve_count para cada pacote
    if (!packageMap.has(pkgName)) {
      packageMap.set(pkgName, 0);
    }
    packageMap.set(pkgName, packageMap.get(pkgName) + cveCount);
  });

  return Array.from(packageMap.entries()).map(([productName, totalCVEs]) => ({
    productName,
    numCVEs: totalCVEs
  }));
}


export function processTopCVEsData(bindings) {
  const cveList = [];

  bindings.forEach(entry => {
    const pkgVersion = entry.package_version?.value;
    const min = entry.min?.value || null;
    const max = entry.max?.value || null;

    // Filtrar pelas versões
    if (!versionInRange(pkgVersion, min, max)) return;

    const cveId = entry.cve?.value.split("#")[1];
    const score = parseFloat(entry.base_score?.value || "0");

    if (!cveId || isNaN(score)) return;

    cveList.push({
      id: cveId,
      description: entry.description?.value,
      score,
      severity: entry.base_severity?.value,
      version: entry.cvss_version?.value,
      code: entry.cvss_code?.value,
      packageName: entry.package_name?.value,
      packageVersion: pkgVersion,
    });
  });

  // Ordenar por score decrescente e pegar os 5 primeiros
  const top5 = cveList
    .sort((a, b) => b.score - a.score)
    .slice(0, 5);

  return { cves: top5 };
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

