function renderStatistics(topCriticalCVEs) {
  const container = document.getElementById("stats-view");
  container.innerHTML = ""; // Clear stats

  const h2 = document.createElement("h2")
  h2.textContent = "Top 5 Most Critical CVEs";
  container.appendChild(h2);
  const ul = document.createElement("ul");
  topCriticalCVEs.cves.forEach(cve => {
    const li = document.createElement("li");
    li.className = "cve-item";

    li.innerHTML = `
      <div>
        <span class="cve-id">${cve.id}</span>
        <span class="cve-score-severity">${cve.score} (${cve.severity})</span>
      </div>
      <div class="cvss-version">CVSS Version: ${cve.version}</div>
    `;

    ul.appendChild(li);
  });
  container.appendChild(ul);
}  