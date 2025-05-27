
async function main() {
  try {
    const [logData, cveData, rawData] = await Promise.all([
      fetchDataFromSPARQLEndPoint(queryLog),
      fetchDataFromSPARQLEndPoint(queryCVE),
      fetchDataFromSPARQLEndPoint(countCVEsPerProductQuery)
    ]);

    const logGraph = processLogDataToGraph(logData);
    const cveGraph = processCVEDataToGraph(cveData);
    const { nodes, links } = mergeGraphs(logGraph, cveGraph);

    const processedData = processCountData(rawData);

    renderGraph(nodes, links);

    d3.select("#viewSelect").on("change", (event) => {
      const view = event.target.value;
      const svg = d3.select("svg");
      
      // Resetar zoom antes de limpar e redesenhar
      svg.call(d3.zoom().transform, d3.zoomIdentity);
      
      svg.selectAll("*").remove();

      if (view === "graph") {
        renderGraph(nodes, links);
      } else if (view === "bubble") {
        renderBubbleChart(processedData);
      }
    });

  } catch (err) {
    console.error("Erro ao carregar e processar dados:", err);
  }
}

main();
