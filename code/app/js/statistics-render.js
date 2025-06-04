function renderStatistics(topCriticalCVEs) {
  const container = document.getElementById("stats-view")
  container.innerHTML = "" // Clear stats

  // Top 5 CVEs Div
  const topCVEsDiv = document.createElement("div")
  topCVEsDiv.id = "top-cves"

  const h1 = document.createElement("h2")
  h1.textContent = "Top 5 Most Critical CVEs"
  topCVEsDiv.appendChild(h1)

  const ul = document.createElement("ul")
  topCriticalCVEs.cves.forEach(cve => {
    const li = document.createElement("li")
    li.className = "cve-item"

    li.innerHTML = `
      <div>
        <span class="cve-id">${cve.id}:</span>
        <span class="cve-score">${cve.score}</span>
        <span class="cve-severity">(${cve.severity})</span>
      </div>
      <div class="cvss-version">CVSS Version: ${cve.version}</div>
    `;

    ul.appendChild(li)
  })
  topCVEsDiv.appendChild(ul)

  container.appendChild(topCVEsDiv)

  // Bubble Chart Div
  //const countDiv = document.createElement("div")
  //countDiv.id = "count-cves-on-products"

  //const h2 = document.createElement("h2")
  //h2.textContent = "Vulnerability Count"
  //countDiv.appendChild(h2)

  //const bubbleChart = document.createElement("svg")
  //bubbleChart.id = "bubble-chart-svg"



}  