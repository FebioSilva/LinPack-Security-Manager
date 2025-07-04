import compareVersions from 'dpkg-compare-versions';
import { countNewVulnerableLogsQuery } from './queries.js';


/**
  * Fetch data from SPARQL endpoint
  * @param {string} query - The SPARQL query to execute
  * @returns {Promise<Array>} - A promise that resolves to the results of the query
 */

export async function fetchDataFromSPARQLEndPoint(query, signal) {
  const response = await fetch("http://localhost:3000/sparql", {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Accept': 'application/sparql-results+json',
        },
        body: `query=${encodeURIComponent(query)}`,
        signal: signal
      });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`HTTP error ${response.status}:\n${text}`);
  }

  const data = await response.json();
  return data.results.bindings;
}

/**
 * Fetch all data with pagination, allowing to handle large datasets
 * @param {string} baseQuery - The base SPARQL query to execute
 * @param {AbortSignal} signal - An AbortSignal to cancel the request
 * @param {number} limit - The maximum number of results to fetch per request
 * @returns {Promise<Array>} - A promise that resolves to an array of all fetched results in JSON format
 */
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

/** * Check if a version string is valid
 * @param {string} v - The version string to check
 * @returns {boolean} - True if the version is valid, false otherwise
 * */

function isValidVersion(v) {
  return typeof v === "string" && /^\d/.test(v);
}

/** * Check if a version is within a specified range using dpkg-compare-versions library
 * @param {string} version - The version to check
 * @param {string|null} min - The minimum version (inclusive)
 * @param {string|null} max - The maximum version (inclusive)
 * @returns {boolean} - True if the version is within the range, false otherwise
 */

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

/**
 * Process CVE and log data to create a graph structure. Basically, it creates nodes for CVEs, products, versions, packages, 
 * and logs, and links them based on their relationships.
 * @param {Array} bindings - The SPARQL query results to process
 * @returns {Object} - An object containing a list of nodes and links representing the graph structure
 * */ 

export function processCVEAndLogDataToGraph(bindings) {
  const nodesMap = new Map();
  const links = [];
  const seenLinks = new Set();
  const seenVersions = new Set();

  function debugLog(...args) {
    // console.log(...args); // Uncomment for debugging
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

    // Verifies if the package version is valid, if not, skip this entry
    if (!versionInRange(pkgVersion, min, max)) {
      debugLog(`Ignoring package ${pkgName} version ${pkgVersion} out of range [${min}, ${max}]`);
      return;
    }

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

    if (productId && !nodesMap.has(productId)) {
      nodesMap.set(productId, {
        id: productId,
        type: "Product",
        name: productName,
        vendor: vendorName,
        uri: productUri,
      });
    }

    if (productId) {
      const cveProductKey = `${cveId}->${productId}`;
      if (!seenLinks.has(cveProductKey)) {
        links.push({ source: cveId, target: productId, type: "has_affected_product" });
        seenLinks.add(cveProductKey);
        debugLog(`Link CVE->Product: ${cveProductKey}`);
      }
    }

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

    if (productId && versionId) {
      // Only link if the version is within the specified range
      // This avoids creating links for versions that are not relevant to the product
      if (versionInRange(pkgVersion, min, max)) {
        const productVersionKey = `${productId}->${versionId}`;
        if (!seenLinks.has(productVersionKey)) {
          links.push({ source: productId, target: versionId, type: "has_version" });
          seenLinks.add(productVersionKey);
        }
      }
    }

    if (versionId) {
      const versionCVEKey = `${versionId}->${cveId}`;
      if (!seenLinks.has(versionCVEKey)) {
        links.push({ source: versionId, target: cveId, type: "affects" });
        seenLinks.add(versionCVEKey);
        debugLog(`Link Version->CVE: ${versionCVEKey}`);
      }
    }

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

      if (versionId) {
        const pkgVersionKey = `${pkgId}->${versionId}`;
        if (!seenLinks.has(pkgVersionKey)) {
          links.push({ source: pkgId, target: versionId, type: "version_matches" });
          seenLinks.add(pkgVersionKey);
          debugLog(`Link Package->Version: ${pkgVersionKey}`);
        }
      }

      if (productId) {
        const pkgProductKey = `${pkgId}->${productId}`;
        if (!seenLinks.has(pkgProductKey)) {
          links.push({ source: pkgId, target: productId, type: "package_of_product" });
          seenLinks.add(pkgProductKey);
          debugLog(`Link Package->Product: ${pkgProductKey}`);
        }
      }
    }

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
          action: entry.action?.value,
          state: entry.state?.value,
        });
      }

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

/** * Process the count data to aggregate CVE counts per product
 * @param {Array} bindings - The SPARQL query results to process
 * @returns {Array} - An array of objects with product names and total CVE counts
 */

export function processCountData(bindings) {
  const packageMap = new Map();

  bindings.forEach(entry => {
    const pkgName = entry.package_name?.value + entry.package_version?.value;
    const pkgVersion = entry.package_version?.value;
    const min = entry.min?.value || null;
    const max = entry.max?.value || null;
    const cveCount = parseInt(entry.cve_count?.value || "0", 10);

    if (!pkgName || !pkgVersion || isNaN(cveCount)) return;

    // Applies version filtering, if the version is not in range, skip this entry
    // This ensures we only count CVEs for packages that are within the specified version range
    if (!versionInRange(pkgVersion, min, max)) return;

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

/** * Process the top CVEs data to extract relevant information and return the top 5 CVEs by score
 * @param {Array} bindings - The SPARQL query results to process 
 * @return {Object} - An object containing an array of the top 5 CVEs with their details
 */

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

  // Order by score and take the top 5 CVEs
  const top5 = cveList
    .sort((a, b) => b.score - a.score)
    .slice(0, 5);

  return { cves: top5 };
}

/** * Merge two graph structures, ensuring no duplicate nodes or links
 * @param {Object} graph1 - The first graph with nodes and links
 * @param {Object} graph2 - The second graph with nodes and links
 * @returns {Object} - A new graph containing merged nodes and links
 */

export function mergeGraphs(graph1, graph2) {
  const nodeMap = new Map();
  const linkMap = new Map();

  for (const node of graph1.nodes) {
    nodeMap.set(node.id, { ...node });
  }

  for (const node of graph2.nodes) {
    if (!nodeMap.has(node.id)) {
      nodeMap.set(node.id, { ...node });
    }
  }

  for (const link of graph1.links) {
    const key = `${link.source}->${link.target}->${link.type}`;
    linkMap.set(key, { ...link });
  }

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

/**
 * Process the most recent log data, counting how many new vulnerable logs have been added since the last timestamp.
 * @param {number} lastTimeStamp - The last timestamp in epoch format to compare against
 * @returns {Promise<number>} - The count of new vulnerable logs added since the last timestamp
 */

export async function getMostRecentLogData(lastTimeStamp) {
  if (!lastTimeStamp) {
    console.error("Invalid timeStamp provided:", lastTimeStamp);
    return 0;
  }

  const query = countNewVulnerableLogsQuery(lastTimeStamp);
  try {
    const data = await fetchDataFromSPARQLEndPoint(query);
    console.log("Recent log data:", data[0].logCount?.value);
    const logCount = parseInt(data[0]?.logCount?.value || "0", 10);
    return logCount;
  } catch (err) {
    console.error("Error fetching recent logs:", err);
    return 0;
  }
}



