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

const endpoint = 'http://localhost:3001/sparql?query=' + encodeURIComponent(queryLog);

/**
  * Fetch data from SPARQL endpoint
  * @param {string} query - The SPARQL query to execute
  * @returns {Promise<Array>} - A promise that resolves to the results of the query
 */

async function fetchDataFromSPARQLEndPoint() {
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
  const nodesMap = new Map(); // Usando um Map para garantir a unicidade dos nós
  const links = [];

  bindings.forEach(entry => {
    const logURI = entry.log?.value;
    const logId = extractLocalName(logURI);
    const eventTypeURI = entry.type?.value;
    const eventType = extractLocalName(eventTypeURI);

    // Se o nó ainda não foi adicionado ao Map
    if (!nodesMap.has(logId)) {
      const node = {
        id: logId,
        uri: logURI,
        type: eventType,
      };

      // Campos comuns
      if (entry.timestamp) {
        node["timestamp"] = entry.timestamp.value;
      }

      // Campos específicos por tipo
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

      // Adiciona o nó ao Map
      nodesMap.set(logId, node);
    }

    // Se tiver pacote ligado
    const pkgName = entry.package_name?.value;
    const pkgVersion = entry.package_version?.value;
    const pkgArch = entry.package_architecture?.value;

    if (pkgName) {
      const pkgId = `${pkgName}-${pkgVersion}-${pkgArch}`;

      // Se o pacote ainda não foi adicionado ao Map
      if (!nodesMap.has(pkgId)) {
        const pkgNode = {
          id: pkgId,
          type: "Package",
          "package_name": pkgName,
          "current_version": pkgVersion,
          "package_architecture": pkgArch
        };

        // Adiciona o pacote ao Map
        nodesMap.set(pkgId, pkgNode);
      }

      // Cria o link log → package
      links.push({
        source: logId,
        target: pkgId,
        type: "has_package"
      });
    }
  });

  // Converte o Map de volta para um array de nós
  const nodes = Array.from(nodesMap.values());

  return {
    nodes,
    links
  };
}




// Função principal para executar o código

function main() {
  fetchDataFromSPARQLEndPoint()
    .then(data => {
      console.log("Fetched data:", data);
      const graph = processLogDataToGraph(data);
      // graph.nodes.forEach(node => {
      //   console.log("Node:", node);
      // });
      // graph.links.forEach(link => {
      //   console.log("Link:", link);
      // });
    })
    .catch(error => {
      console.error("Error fetching SPARQL data:", error);
    });
}

main();