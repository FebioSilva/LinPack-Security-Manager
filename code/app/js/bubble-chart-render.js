function renderBubbleChart(data) {
  const svg = d3.select("svg");
  const width = window.innerWidth;
  const height = window.innerHeight;
  const maxRadius = 140;

  svg.selectAll("*").remove();

  const container = svg.append("g");

  const radiusScale = d3.scaleSqrt()
    .domain([0, d3.max(data, d => d.numCVEs)])
    .range([15, maxRadius]);

  data.forEach(d => {
    d.r = radiusScale(d.numCVEs);
    d.rWithPadding = d.r + 4;
  });

  const layoutNodes = data.map(d => ({ ...d, r: d.rWithPadding }));
  d3.packSiblings(layoutNodes);

  const xOffset = width / 2 - d3.mean(layoutNodes, d => d.x);
  const yOffset = height / 2 - d3.mean(layoutNodes, d => d.y);

  const colorScale = d3.scaleSequential()
    .domain([0, d3.max(data, d => d.numCVEs)])
    .interpolator(d3.interpolateBlues);

  const node = container.selectAll("g")
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
      container.attr("transform", event.transform);
    });

  svg.call(zoom);
}
