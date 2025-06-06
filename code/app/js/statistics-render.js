function renderStatistics(topCriticalCVEs, vulnerabilityCount) {
  const container = document.getElementById("stats-view")
  container.innerHTML = "" // Clear stats

  // Title
  const statsTitle = document.createElement("h1")
  statsTitle.textContent = "System Statistics"
  statsTitle.setAttribute("style", "text-align: center")
  container.appendChild(statsTitle)

  // Top 5 CVEs Div
  const topCVEsDiv = document.createElement("div")
  topCVEsDiv.id = "top-cves"
  const topCVEsDivStyle = "padding: 20px;margin: 20px;background-color: #f9f9f9;border: 1px solid black;border-radius: 8px;background-color: white;box-shadow: 0 2px 4px rgba(0,0,0,0.05)"
  topCVEsDiv.setAttribute("style", topCVEsDivStyle)

  const h1 = document.createElement("h2")
  h1.textContent = "Top 5 Most Critical CVEs"
  h1.setAttribute("style", "text-align: center")
  topCVEsDiv.appendChild(h1)

  const ul = document.createElement("ul")
  ul.setAttribute("style", "list-style-type: none;padding: 0")
  topCriticalCVEs.cves.forEach(cve => {
    const li = document.createElement("li")
    const liStyle = "background: #fff;border: 1px solid #ddd;padding: 12px;margin-bottom: 10px;border-radius: 6px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1)"
    li.setAttribute("style", liStyle)
    li.className = "cve-item"

    li.innerHTML = `
      <div>
        <span class="cve-id" style="font-weight: bold;font-size: 1.1em">${cve.id}:</span>
        <span class="cve-score" style="color: #b00">${cve.score}</span>
        <span class="cve-severity" style="color: rgb(0, 0, 0)">(${cve.severity})</span>
      </div>
      <div class="cvss-version" style="margin-top: 4px;font-size: 0.9em;color: #666;">CVSS Version: ${cve.version}</div>
    `;

    ul.appendChild(li)
  })
  topCVEsDiv.appendChild(ul)

  container.appendChild(topCVEsDiv)

  // Bubble Chart Div
  const countDiv = document.createElement("div")
  countDiv.id = "count-cves-on-products"
  const countDivStyle = "padding: 20px;margin: 20px;background-color: #f9f9f9;border: 1px solid black;border-radius: 8px;background-color: white;box-shadow: 0 2px 4px rgba(0,0,0,0.05)"
  countDiv.setAttribute("style", countDivStyle)

  const h2 = document.createElement("h2")
  h2.textContent = "Vulnerability Count"
  h2.setAttribute("style", "text-align: center")
  countDiv.appendChild(h2)

  const bubbleChartWidth = countDiv.clientWidth;
  const bubbleChartHeight = countDiv.clientHeight;
  const bubbleChart = document.createElement("svg")
  bubbleChart.id = "bubble-chart-svg"
  bubbleChart.setAttribute("width", bubbleChartWidth);
  bubbleChart.setAttribute("height", bubbleChartHeight);
  countDiv.appendChild(bubbleChart)

  container.appendChild(countDiv)

  const svg = d3.select("#bubble-chart-svg")
  
  const maxRadius = 140;

  svg.selectAll("*").remove();

  const svgContainer = svg.append("g");

  const radiusScale = d3.scaleSqrt()
    .domain([0, d3.max(vulnerabilityCount, d => d.numCVEs)])
    .range([15, maxRadius]);

  vulnerabilityCount.forEach(d => {
    d.r = radiusScale(d.numCVEs);
    d.rWithPadding = d.r + 4;
  });

  const layoutNodes = vulnerabilityCount.map(d => ({ ...d, r: d.rWithPadding }));
  d3.packSiblings(layoutNodes);

  const xOffset = bubbleChartWidth / 2 - d3.mean(layoutNodes, d => d.x);
  const yOffset = bubbleChartHeight / 2 - d3.mean(layoutNodes, d => d.y);

  const colorScale = d3.scaleSequential()
    .domain([0, d3.max(vulnerabilityCount, d => d.numCVEs)])
    .interpolator(d3.interpolateBlues);

  console.log(layoutNodes.map(d => ({ name: d.productName, x: d.x, y: d.y })));
  const node = svgContainer.selectAll("g")
    .data(layoutNodes)
    .join("g")
    .attr("transform", d => `translate(${d.x + xOffset},${d.y + yOffset})`);

  node.append("circle")
    .attr("r", d => d.r - 2)
    .attr("fill", d => colorScale(d.numCVEs))
    .attr("stroke", "#333")
    .attr("stroke-width", 1)
    .style("cursor", "default");  // cursor normal, sem drag

  node.append("text")
    .attr("class", "bubble-label")
    .attr("text-anchor", "middle")
    .style("pointer-events", "none")
    .style("font-weight", "bold")
    .style("font-size", d => Math.max(8, (d.r - 4) / 4) + "px")
    .selectAll("tspan")
    .data(d => [
      { text: d.productName, color: d3.hsl(colorScale(d.numCVEs)).l < 0.6 ? "#fff" : "#000" },
      { text: d.numCVEs, color: "#aaa" }
    ])
    .join("tspan")
    .attr("x", 0)
    .attr("y", (d, i) => i === 0 ? "-0.3em" : "1em")
    .attr("fill", d => d.color)
    .text(d => d.text);

  // Apenas zoom e drag no container (mapa todo)
  const zoom = d3.zoom()
    .scaleExtent([0.1, 4])
    .on("zoom", event => {
      svgContainer.attr("transform", event.transform);
    });

  svg.call(zoom);
}  