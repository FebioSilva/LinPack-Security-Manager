import { renderGraph } from '../js/graph-render.js';
import { renderStatistics } from '../js/statistics-render.js';
import { processTopCVEsData,fetchDataFromSPARQLEndPoint, processCVEAndLogDataToGraph,
  processCountData, fetchAllDataWithPagination, getMostRecentLogData
} from '../js/process-data-from-sparql.js';
import {  
  countCVEsPerProductQuery,
  highestSeverityCVEsQuery,
  generateCVEQueryByYear
 } from '../js/queries.js';

import sleep from 'sleep-promise';

// Declares a global variable to manage fetch aborts
// This allows us to cancel previous fetch requests when switching views
let abortController = null;

// Show/Hide spinner
function showSpinner(show) {
  const spinner = document.getElementById("loading-spinner");
  spinner.style.display = show ? "block" : "none";
}

/**
 * Update the visibility of controls based on the current view.
 * @param {} view - The current view (e.g., "graph" or "stats")
 */
function updateControlsVisibility(view) {
  const yearFilter = document.getElementById("yearFilter");
  if (yearFilter) {
    yearFilter.style.display = (view === "graph") ? "flex" : "none";
  }
}

/**
 * Load and render the specified view for a given year, 
 * fetching data from the SPARQL endpoint.
 * This function handles both the graph and statistics views,
 * and manages the fetch requests with an AbortController
 * to cancel previous requests when switching views.
 * @param {string} view - The current view (e.g., "graph" or "stats")
 * @param {number} year - The year to filter data
 * @return {Promise<void>}
 */
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

  // Controls visibility of the SVG and stats view based on the selected view
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
      console.log("Fetch request aborted for view:", view);
    } else {
      console.error("Error loading data for view:", view, err);
    }
  } finally {
    if (!signal.aborted) {
      showSpinner(false);
    }
  }
}

/**
 * Update the visibility of the new vulnerable logs block based on the log count.
 * @param {number} logCount - The count of new vulnerable logs.
 */
function changeNewVulnerableLogsBlockVisibility(logCount) {
  const newVulnerableLogsBlock = document.getElementById("newVulnerableLogsBlock");
  if (newVulnerableLogsBlock) {
    newVulnerableLogsBlock.style.display = logCount > 0 ? "block" : "none";
  }
}

/**
 * Dismiss the notification block for new vulnerable logs.
 * This function hides the block when the dismiss button is clicked.
 */

function dismissNotification() {
  const block = document.getElementById("newVulnerableLogsBlock");
  if (block) {
    block.style.display = "none";
  }
}

/**
 * Get the local timestamp adjusted for the user's timezone.
 * @returns {number} - The local timestamp in milliseconds.
 */
function getLocalTimestamp() {
    const now = new Date();
    const offsetMinutes = now.getTimezoneOffset();
    return now.getTime() - offsetMinutes * 60 * 1000;
  }


async function main() {
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
      dismissNotification();
    });

    refreshBtn?.addEventListener("click", () => {
      location.reload();
    });

    // Inicialização
    updateControlsVisibility(viewSelect.value);
    loadAndRenderView(viewSelect.value, yearSelect.value);
    
  });


  let lastTime = getLocalTimestamp();
  // This loop checks for new vulnerable logs every 2 minutes
  while (true) {
    const logCount = await getMostRecentLogData(lastTime);
    if (logCount > 0) {
      changeNewVulnerableLogsBlockVisibility(logCount);
      console.log(`Novos logs vulneráveis detectados: ${logCount}`);
    }
    lastTime = getLocalTimestamp();
    await sleep(120000); // 2 minutes
  }
}

main();
