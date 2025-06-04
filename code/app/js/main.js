
  d3.select("#yearSelect").on("change", function () {
    const year = this.value;
    const view = d3.select("#viewSelect").property("value");
    loadAndRenderView(view, year);
  });
// ---------------------------------------

function showSpinner(show) {
  const spinner = document.getElementById("loading-spinner");
  spinner.style.display = show ? "block" : "none";
}
let abortController = null;

async function loadAndRenderView(view, year = "all") {
  if (abortController) {
    abortController.abort(); // cancela fetch anterior
  }
  abortController = new AbortController();
  const { signal } = abortController;

  showSpinner(true);

  const svg = d3.select("svg");
  const statsView = d3.select("#stats-view");
  svg.selectAll("*").remove();
  statsView.html("");

  // Controla visibilidade do stats-view
  if (view === "topCVEs") {
    statsView.style("display", "block");
  } else {
    statsView.style("display", "none");
  }

  try {
    if (view === "graph") {
      const queryCVEToUse = (year === "all") ? queryCVE : generateCVEQueryByYear(year);
      const [logData, cveData] = await Promise.all([
        fetchDataFromSPARQLEndPoint(queryLog, signal),
        fetchDataFromSPARQLEndPoint(queryCVEToUse, signal)
      ]);
      const logGraph = processLogDataToGraph(logData);
      const cveGraph = processCVEDataToGraph(cveData);
      const { nodes, links } = mergeGraphs(logGraph, cveGraph);
      renderGraph(nodes, links);
    } else if (view === "bubble") {
      const rawData = await fetchDataFromSPARQLEndPoint(countCVEsPerProductQuery, signal);
      const processedData = processCountData(rawData);
      renderBubbleChart(processedData);
    } else if (view === "topCVEs") {
      const rawTopCVEs = await fetchDataFromSPARQLEndPoint(highestSeverityCVEsQuery, signal);
      const processedTopCVEs = processTopCVEsData(rawTopCVEs);
      renderStatistics(processedTopCVEs);
    }
  } catch (err) {
    if (err.name === "AbortError") {
      console.log("Fetch abortado devido a troca de vista");
    } else {
      console.error("Erro ao carregar dados para view:", view, err);
    }
  } finally {
    showSpinner(false);
  }
}


function updateControlsVisibility(view) {
  const yearFilter = document.getElementById("yearFilter");
  if (view === "graph") {
    yearFilter.style.display = "flex";
  } else {
    yearFilter.style.display = "none";
  }
}

async function main() {

  // Inicializa controles e carregamento
  const initialView = d3.select("#viewSelect").property("value");
  updateControlsVisibility(initialView);
  await loadAndRenderView(initialView, "all");
}

main();
