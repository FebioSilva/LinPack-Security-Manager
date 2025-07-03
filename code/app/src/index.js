import { renderBubbleChart } from '../js/bubble-chart-render.js';
import { renderGraph } from '../js/graph-render.js';
import { renderStatistics } from '../js/statistics-render.js';
import { processTopCVEsData,fetchDataFromSPARQLEndPoint, logsAndCVEs, generateCVEQueryByYear, processCVEAndLogDataToGraph, highestSeverityCVEsQuery, countCVEsPerProductQuery,
  processCountData, fetchAllDataWithPagination, getMostRecentLogData
} from '../js/process-data-from-sparql.js';
import sleep from 'sleep-promise';

// Declara abortController UMA vez no topo do arquivo
let abortController = null;

// Mostra ou esconde spinner
function showSpinner(show) {
  const spinner = document.getElementById("loading-spinner");
  spinner.style.display = show ? "block" : "none";
}

// Atualiza visibilidade dos controles, ex: filtro ano só em 'graph'
function updateControlsVisibility(view) {
  const yearFilter = document.getElementById("yearFilter");
  if (yearFilter) {
    yearFilter.style.display = (view === "graph") ? "flex" : "none";
  }
}

// Função principal de carregar e renderizar a vista
async function loadAndRenderView(view, year) {
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

  // Controla visibilidade do stats-view e svg conforme vista
  if (view === "stats") {
    statsView.style("display", "block");
    svg.style("display", "none");
  } else {
    statsView.style("display", "none");
    svg.style("display", "block");
  }

  try {
    if (view === "graph") {
      const queryCVEToUse = generateCVEQueryByYear(year);
      const cveData = await fetchAllDataWithPagination(queryCVEToUse, signal);
      //const logGraph = processLogDataToGraph(logData);
      //console.log("Log graph processed:", logGraph);
      const cveGraph = processCVEAndLogDataToGraph(cveData);
      console.log("CVE graph processed:", cveGraph)
      const { nodes, links } = cveGraph;
      renderGraph(nodes, links);
    } else if (view === "stats") {
      const rawTopCVEs = await fetchDataFromSPARQLEndPoint(highestSeverityCVEsQuery, signal);
      const processedTopCVEs = processTopCVEsData(rawTopCVEs);
      const rawData = await fetchDataFromSPARQLEndPoint(countCVEsPerProductQuery, signal);
      const processedData = processCountData(rawData);
      renderStatistics(processedTopCVEs, processedData);
    }
  } catch (err) {
    if (err.name === "AbortError") {
      console.log("Fetch abortado devido a troca de vista");
    } else {
      console.error("Erro ao carregar dados para view:", view, err);
    }
  } finally {
    if (!signal.aborted) {
      showSpinner(false);
    }
  }
}

function changeNewVulnerableLogsBlockVisibility(logCount) {
  const newVulnerableLogsBlock = document.getElementById("newVulnerableLogsBlock");
  if (newVulnerableLogsBlock) {
    newVulnerableLogsBlock.style.display = logCount > 0 ? "block" : "none";
  }
}

function dismissNotification() {
  const block = document.getElementById("newVulnerableLogsBlock");
  if (block) {
    block.style.display = "none";
  }
}

function getLocalTimestamp() {
    const now = new Date();
    // getTimezoneOffset retorna minutos de diferença local para UTC (ex: -60 para UTC+1)
    const offsetMinutes = now.getTimezoneOffset();
    // Ajusta o timestamp UTC para local subtraindo offset em milissegundos
    return now.getTime() - offsetMinutes * 60 * 1000;
  }


async function main() {
  // Espera o DOM estar carregado
  document.addEventListener("DOMContentLoaded", async () => {
    const viewSelect = document.getElementById("viewSelect");
    const yearSelect = document.getElementById("yearSelect");
    const dismissBtn = document.getElementById("dismissNotificationBtn");
    const refreshBtn = document.getElementById("refreshPageBtn");
    const notificationBlock = document.getElementById("newVulnerableLogsBlock");

    if (!viewSelect || !yearSelect) {
      console.error("Elementos #viewSelect e/ou #yearSelect não encontrados no DOM");
      return;
    }

    // Listeners
    viewSelect.addEventListener("change", () => {
      const view = viewSelect.value;
      const year = yearSelect.value;
      updateControlsVisibility(view);
      loadAndRenderView(view, year);
    });

    yearSelect.addEventListener("change", () => {
      const year = yearSelect.value;
      const view = viewSelect.value;
      loadAndRenderView(view, year);
    });

    dismissBtn?.addEventListener("click", () => {
      if (notificationBlock) {
        notificationBlock.style.display = "none";
      }
    });

    refreshBtn?.addEventListener("click", () => {
      location.reload();
    });

    // Inicialização
    updateControlsVisibility(viewSelect.value);
    loadAndRenderView(viewSelect.value, yearSelect.value);
    
  });


  let lastTime = getLocalTimestamp();

  while (true) {
    const logCount = await getMostRecentLogData(lastTime);
    if (logCount > 0) {
      changeNewVulnerableLogsBlockVisibility(logCount);
      console.log(`Novos logs vulneráveis detectados: ${logCount}`);
    }
    lastTime = getLocalTimestamp();
    await sleep(5000); // 5 seconds
  }
}


main();
