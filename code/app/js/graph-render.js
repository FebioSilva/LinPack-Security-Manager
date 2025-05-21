function renderGraph(nodes, links) {
  const svg = d3.select("svg");
  const width = window.innerWidth;
  const height = window.innerHeight;

  svg.selectAll("*").remove();

  const graphGroup = svg.append("g");

  const zoom = d3.zoom()
    .scaleExtent([0.1, 4])
    .on("zoom", (event) => {
      graphGroup.attr("transform", event.transform);
    });

  svg.call(zoom);

  const simulation = d3.forceSimulation(nodes)
    .force("link", d3.forceLink(links).id(d => d.id).distance(200))
    .force("charge", d3.forceManyBody().strength(-300))
    .force("center", d3.forceCenter(width / 2, height / 2))
    .force("collide", d3.forceCollide().radius(50));

  const link = graphGroup.append("g")
    .attr("stroke", "#aaa")
    .selectAll("line")
    .data(links)
    .join("line");

  const node = graphGroup.append("g")
    .selectAll("g")
    .data(nodes)
    .join("g")
    .attr("class", "node")
    .call(d3.drag()
      .on("start", (event, d) => {
        event.sourceEvent.stopPropagation();
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
      })
      .on("drag", (event, d) => {
        d.fx = event.x;
        d.fy = event.y;
      })
      .on("end", (event, d) => {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
      })
    );

  node.append("circle")
    .attr("r", 10)
    .attr("fill", d => {
      switch (d.type) {
        case "Package": return "steelblue";
        case "ActionEvent": return "green";
        case "StateEvent": return "darkorange";
        case "ConffileEvent": return "purple";
        case "StartupEvent": return "brown";
        case "CVE": return "crimson";
        case "Product": return "darkcyan";
        case "Version": return "goldenrod";
        case "Reference": return "gray";
        default: return "lightgray";
      }
    });

  node.append("text")
    .text(d => d.id)
    .attr("dx", 12)
    .attr("dy", ".35em");

  simulation.on("tick", () => {
    link
      .attr("x1", d => d.source.x)
      .attr("y1", d => d.source.y)
      .attr("x2", d => d.target.x)
      .attr("y2", d => d.target.y);

    node.attr("transform", d => `translate(${d.x},${d.y})`);
  });

  const tooltip = d3.select("#tooltip");

  node
    .on("mouseover", (event, d) => {
      let html = `<strong>${d.id}</strong><br>Type: <em>${d.type}</em>`;
      tooltip
        .html(html)
        .style("left", (event.pageX + 10) + "px")
        .style("top", (event.pageY + 10) + "px")
        .style("display", "block");
    })
    .on("mousemove", event => {
      tooltip
        .style("left", (event.pageX + 10) + "px")
        .style("top", (event.pageY + 10) + "px");
    })
    .on("mouseout", () => {
      tooltip.style("display", "none");
    });
}
