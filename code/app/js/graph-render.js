function renderGraph(nodes, links) {
  document.getElementById("stats-view").innerHTML = ""; // Clear stats
  const svg = d3.select("svg");
  const width = window.innerWidth;
  const height = window.innerHeight;

  svg.selectAll("*").remove();
  const graphGroup = svg.append("g");

  const zoom = d3.zoom().scaleExtent([0.1, 4]).on("zoom", (event) => {
    graphGroup.attr("transform", event.transform);
  });
  svg.call(zoom);

  const nodesMap = new Map(nodes.map(n => [n.id, { ...n, collapsed: true, children: [] }]));

  links.forEach(link => {
    const source = nodesMap.get(link.source);
    const target = nodesMap.get(link.target);
    if (!source || !target) return;

    if (source.type === "Product" && target.type === "Version") {
      source.children.push(target);
    } else if (source.type === "Version" && target.type === "CVE") {
      source.children.push(target);
    }
  });

  const topNodes = Array.from(nodesMap.values()).filter(n => n.type === "Product");

  let visibleNodes = topNodes.slice();
  let visibleLinks = [];

  const simulation = d3.forceSimulation()
    .force("link", d3.forceLink().id(d => d.id).distance(80))
    .force("charge", d3.forceManyBody().strength(-400))
    .force("center", d3.forceCenter(width / 2, height / 2))
    .force("y", d3.forceY().y(d => {
      switch (d.type) {
        case "Product": return height / 4;
        case "Version": return height / 2;
        case "CVE": return (height / 4) * 3;
        default: return height / 2;
      }
    }))
    .force("collide", d3.forceCollide().radius(30))
    .alphaDecay(0.07)
    .on("tick", ticked);

  let nodesMerged, linksMerged;

  function update() {
    visibleNodes = [];
    visibleLinks = [];

    function collectVisible(node) {
      visibleNodes.push(node);
      if (!node.collapsed && node.children) {
        node.children.forEach(child => collectVisible(child));
      }
    }

    topNodes.forEach(collectVisible);

    visibleLinks = links.filter(
      l =>
        visibleNodes.some(n => n.id === (typeof l.source === "object" ? l.source.id : l.source)) &&
        visibleNodes.some(n => n.id === (typeof l.target === "object" ? l.target.id : l.target))
    );

    const nodeSelection = graphGroup.selectAll(".node")
      .data(visibleNodes, d => d.id);

    nodeSelection.exit().remove();

    const nodeEnter = nodeSelection.enter().append("g")
      .attr("class", "node")
      .on("click", (event, d) => {
        if (d.children?.length > 0) {
          d.collapsed = !d.collapsed;

          d3.select(event.currentTarget).select("circle")
            .transition()
            .duration(300)
            .attr("r", d.collapsed ? 12 : 16);

          if (!d.collapsed) {
            const angleStep = (2 * Math.PI) / d.children.length;
            const radius = 150 + d.children.length * 30;
            d.children.forEach((child, i) => {
              const angle = i * angleStep;
              child.x = d.x + radius * Math.cos(angle);
              child.y = d.y + radius * Math.sin(angle);
            });
          }

          update();
        }
      })
      .call(d3.drag()
        .on("start", (event, d) => {
          event.sourceEvent.stopPropagation();
          if (!event.active) simulation.alphaTarget(0.3).restart();
          d.fx = event.x;
          d.fy = event.y;
        })
        .on("drag", (event, d) => {
          d.fx = event.x;
          d.fy = event.y;
        })
        .on("end", (event, d) => {
          if (!event.active) simulation.alphaTarget(0);
          d.fx = null;
          d.fy = null;
        }));

    nodeEnter.append("circle")
      .attr("r", 12)
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
          default: return "lightgray";
        }
      });

    nodeEnter.append("text")
      .text(d => d.id)
      .attr("dx", 18)
      .attr("dy", ".35em");

    nodesMerged = nodeEnter.merge(nodeSelection);

    const linkSelection = graphGroup.selectAll("line")
      .data(visibleLinks, d => `${d.source}-${d.target}`);

    linkSelection.exit().remove();

    const linkEnter = linkSelection.enter().append("line")
      .attr("stroke", "#aaa")
      .attr("stroke-width", 2);

    linksMerged = linkEnter.merge(linkSelection);

    simulation.nodes(visibleNodes);
    simulation.force("link").links(visibleLinks);
    simulation.alpha(0.6).restart();

    // Garantir que os nós fiquem por cima dos links
    graphGroup.selectAll(".node").raise();

    const tooltip = d3.select("#tooltip");

    nodesMerged
      .on("mouseover", (event, d) => {
        let html = `<strong>${d.id}</strong><br><em>Type:</em> ${d.type}`;
        tooltip.html(html)
          .style("left", (event.pageX + 10) + "px")
          .style("top", (event.pageY + 10) + "px")
          .style("display", "block");
      })
      .on("mousemove", event => {
        tooltip.style("left", (event.pageX + 10) + "px")
          .style("top", (event.pageY + 10) + "px");
      })
      .on("mouseout", () => {
        tooltip.style("display", "none");
      });
  }

  function ticked() {
    linksMerged
      .attr("x1", d => (typeof d.source === "object" ? d.source.x : nodesMap.get(d.source)?.x))
      .attr("y1", d => (typeof d.source === "object" ? d.source.y : nodesMap.get(d.source)?.y))
      .attr("x2", d => (typeof d.target === "object" ? d.target.x : nodesMap.get(d.target)?.x))
      .attr("y2", d => (typeof d.target === "object" ? d.target.y : nodesMap.get(d.target)?.y));

    nodesMerged.attr("transform", d => `translate(${d.x},${d.y})`);
  }

  update(); // Inicial
}
