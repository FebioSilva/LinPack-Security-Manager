function renderGraph(nodes, links) {
  document.getElementById("stats-view").innerHTML = "";
  const svg = d3.select("svg");
  const width = window.innerWidth;
  const height = window.innerHeight;

  svg.selectAll("*").remove();
  const graphGroup = svg.append("g");

  const zoom = d3.zoom().scaleExtent([0.1, 4]).on("zoom", (event) => {
    graphGroup.attr("transform", event.transform);
  });
  svg.call(zoom);
  svg.call(zoom.transform, d3.zoomIdentity);
  const nodesMap = new Map(nodes.map(n => [n.id, { ...n, children: [], collapsed: true }]));

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

  // Inicializa posições aleatórias para todos os nodes para evitar concentração
  nodesMap.forEach(node => {
    node.x = Math.random() * width * 0.8 + width * 0.1;
    node.y = Math.random() * height * 0.8 + height * 0.1;
  });

  let visibleNodes = topNodes.slice();
  let visibleLinks = [];

  const simulation = d3.forceSimulation()
    .force("link", d3.forceLink().id(d => d.id).distance(120))
    .force("charge", d3.forceManyBody().strength(-200))
    .force("center", d3.forceCenter(width / 2, height / 2).strength(0.05))
    .force("collide", d3.forceCollide().radius(40))
    .force("x", d3.forceX(width / 2).strength(0.02))
    .force("y", d3.forceY(height / 2).strength(0.02))
    .alphaDecay(0.05)
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
            .transition().duration(300)
            .attr("r", d.collapsed ? 12 : 18);

          if (!d.collapsed) {
            // Posiciona filhos em círculo ao redor do pai
            const angleStep = (2 * Math.PI) / d.children.length;
            const radius = 50 + d.children.length * 10;
            d.children.forEach((child, i) => {
              const angle = i * angleStep;
              child.x = d.x + radius * Math.cos(angle);
              child.y = d.y + radius * Math.sin(angle);
            });
          }

          update();
          simulation.alpha(0.3).restart();
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
    simulation.alpha(0.3).restart();

    graphGroup.selectAll(".node").raise();

    const tooltip = d3.select("#tooltip");

    nodesMerged
  .on("mouseover", (event, d) => {
    let html = `<strong>${d.id}</strong><br><em>Type:</em> ${d.type}<br>`;

    if (d.type === "CVE") {
      html += `
        <strong>Description:</strong> ${d.description || 'N/A'}<br>
        <strong>Base Score:</strong> ${d.base_score || 'N/A'}<br>
        <strong>Base Severity:</strong> ${d.base_severity || 'N/A'}<br>
        <strong>CVSS Version:</strong> ${d.cvss_version || 'N/A'}<br>
        <strong>CVSS Code:</strong> ${d.cvss_code || 'N/A'}<br>
      `;
    } else if (d.type === "Product") {
      html += `
        <strong>Product Name:</strong> ${d.name || 'N/A'}<br>
        <strong>Vendor:</strong> ${d.vendor || 'N/A'}<br>
      `;
    } else if (d.type === "Version") {
      html += `
        <strong>Version Major:</strong> ${d.major || 'N/A'}<br>
        <strong>Version Minor:</strong> ${d.minor || 'N/A'}<br>
        <strong>Version Patch:</strong> ${d.patch || 'N/A'}<br>
      `;
    } else if (d.type === "Vendor") {
      html += `
        <strong>Vendor Name:</strong> ${d.vendor_name || 'N/A'}<br>
      `;
    }
    // Outros tipos podem ser adicionados aqui se precisar

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

  update();
}
