function renderGraph(nodes, links) {
  // ╭──────────────────────────  setup básico  ──────────────────────────╮
  document.getElementById("stats-view").innerHTML = "";
  const svg  = d3.select("svg");
  const W    = window.innerWidth;
  const H    = window.innerHeight;

  svg.selectAll("*").remove();
  const graphGroup = svg.append("g");

  svg.call(
    d3.zoom().scaleExtent([0.1, 4]).on("zoom", e => graphGroup.attr("transform", e.transform))
  ).call(d3.zoom().transform, d3.zoomIdentity);

  // ╭──────────────────────────  estrutura de dados  ────────────────────╮
  const nodesMap = new Map(nodes.map(n => [n.id, { ...n, children: [], collapsed: true }]));

  // — árvore Product→Version→CVE e Event→Package
  links.forEach(l => {
    const s = nodesMap.get(l.source);
    const t = nodesMap.get(l.target);
    if (!s || !t) return;

    if (s.type === "Product" && t.type === "Version")       s.children.push(t);
    else if (s.type === "Version" && t.type === "CVE")      s.children.push(t);
    else if (s.type.endsWith("Event") && t.type === "Package") s.children.push(t);
  });

  // raízes: todos Products + todos Events
  const topRoots = Array.from(nodesMap.values())
    .filter(n => n.type === "Product" || n.type.endsWith("Event"));

  // posição inicial aleatória
  nodesMap.forEach(n => {
    n.x = Math.random() * W * 0.8 + W * 0.1;
    n.y = Math.random() * H * 0.8 + H * 0.1;
  });

  // ╭──────────────────────────  simulação forças  ──────────────────────╮
  let nodesMerged, linksMerged;
  const simulation = d3.forceSimulation()
    .force("link",    d3.forceLink().id(d => d.id).distance(120))
    .force("charge",  d3.forceManyBody().strength(-200))
    .force("center",  d3.forceCenter(W / 2, H / 2).strength(0.05))
    .force("collide", d3.forceCollide().radius(40))
    .alphaDecay(0.05)
    .on("tick", ticked);

  // ——————————— helpers ———————————
  const visibleNodes = [];
  const visibleLinks = [];

  function collectVisible(node) {
    visibleNodes.push(node);
    if (!node.collapsed && node.children.length)
      node.children.forEach(collectVisible);
  }

  // ╭──────────────────────────  update desenha tudo  ───────────────────╮
  function update() {
    visibleNodes.length = 0;
    visibleLinks.length = 0;

    topRoots.forEach(collectVisible);          // raízes + filhos expandidos

    // posiciona filhos em círculo quando pai expandido
    visibleNodes.forEach(n => {
      if (!n.collapsed && n.children.length) {
        const r = 50 + n.children.length * 10;
        const step = (2 * Math.PI) / n.children.length;
        n.children.forEach((c, i) => {
          c.x = n.x + r * Math.cos(i * step);
          c.y = n.y + r * Math.sin(i * step);
        });
      }
    });

    // links cujo source e target estão visíveis
    links.forEach(l => {
      const s = nodesMap.get(l.source);
      const t = nodesMap.get(l.target);
      if (s && t && visibleNodes.includes(s) && visibleNodes.includes(t))
        visibleLinks.push({ ...l });
    });

    // — nodes —
    const nodeSel = graphGroup.selectAll(".node")
      .data(visibleNodes, d => d.id);

    nodeSel.exit().remove();

    const nodeEnter = nodeSel.enter().append("g")
      .attr("class", "node")
      .on("click", (e, d) => {
        if (d.children.length) {
          d.collapsed = !d.collapsed;
          d3.select(e.currentTarget).select("circle")
            .transition().duration(250)
            .attr("r", d.collapsed ? 12 : 18);
          update();
          simulation.alpha(0.5).restart();
        }
      })
      .call(d3.drag()
        .on("start", (e, d) => {
          e.sourceEvent.stopPropagation();
          if (!e.active) simulation.alphaTarget(0.3).restart();
          d.fx = d.x; d.fy = d.y;
        })
        .on("drag", (e, d) => { d.fx = e.x; d.fy = e.y; })
        .on("end",  (e, d) => {
          if (!e.active) simulation.alphaTarget(0);
          d.fx = d.fy = null;
        }));

    nodeEnter.append("circle")
      .attr("r", 12)
      .attr("fill", d => {
        switch (d.type) {
          case "Package":         return "steelblue";
          case "ActionEvent":     return "green";
          case "StateEvent":      return "darkorange";
          case "ConfigFileEvent": return "purple";
          case "StartupEvent":    return "brown";
          case "CVE":             return "crimson";
          case "Product":         return "darkcyan";
          case "Version":         return "goldenrod";
          default:                return "lightgray";
        }
      });

    nodeEnter.append("text")
      .attr("class", "node-label")
      .text(d => d.id)
      .attr("dx", 18)
      .attr("dy", ".35em");

    nodesMerged = nodeEnter.merge(nodeSel);

    // — links —
    const linkSel = graphGroup.selectAll("line")
      .data(visibleLinks, d => `${d.source}-${d.target}-${d.type}`);

    linkSel.exit().remove();

    const linkEnter = linkSel.enter().append("line")
      .attr("stroke", "#aaa")
      .attr("stroke-width", 2);

    linksMerged = linkEnter.merge(linkSel);

    // reinicia simulação
    simulation.nodes(visibleNodes);
    simulation.force("link").links(visibleLinks);
    simulation.alpha(0.5).restart();

    graphGroup.selectAll(".node").raise();

    // — tooltip —
    const tooltip = d3.select("#tooltip");
    nodesMerged
      .on("mouseover", (e, d) => {
        let html = `<strong>${d.id}</strong><br><em>Type:</em> ${d.type}<br>`;
        if (d.type.endsWith("Event")) {
          html += `<strong>Timestamp:</strong> ${d.timestamp || "N/A"}<br>`;
          if (d.action)  html += `<strong>Action:</strong> ${d.action}<br>`;
          if (d.state)   html += `<strong>State:</strong> ${d.state}<br>`;
          if (d.decision)html += `<strong>Decision:</strong> ${d.decision}<br>`;
          if (d.context) html += `<strong>Context:</strong> ${d.context}<br>`;
          if (d.command) html += `<strong>Command:</strong> ${d.command}<br>`;
        }  else if (d.type === "Package") {
          // Mostrar apenas propriedades "originais", excluindo props D3 e internas
          const excludeKeys = new Set(["id", "type", "children", "collapsed", "x", "y", "vx", "vy", "index", "fx", "fy"]);
          for (const [key, value] of Object.entries(d)) {
            if (!excludeKeys.has(key)) {
              html += `<strong>${key.replace(/_/g, " ")}:</strong> ${value}<br>`;
            }
          }
        } else if (d.type === "CVE") {
          html += `<strong>Description:</strong> ${d.description || "N/A"}<br>
                   <strong>Base Score:</strong> ${d.base_score || "N/A"}<br>
                   <strong>Base Severity:</strong> ${d.base_severity || "N/A"}<br>
                   <strong>CVSS Version:</strong> ${d.cvss_version || "N/A"}<br>
                   <strong>CVSS Code:</strong> ${d.cvss_code || "N/A"}<br>`;
        } else if (d.type === "Product") {
          html += `<strong>Product:</strong> ${d.name || "N/A"}<br>
                   <strong>Vendor:</strong> ${d.vendor || "N/A"}<br>`;
        } else if (d.type === "Version") {
          html += `<strong>Min:</strong> ${d.min || "N/A"}<br>
                   <strong>Max:</strong> ${d.max || "N/A"}<br>`;
        }
        tooltip.html(html)
               .style("left", (e.pageX + 10) + "px")
               .style("top",  (e.pageY + 10) + "px")
               .style("display", "block");
      })
      .on("mousemove", e =>
        tooltip.style("left", (e.pageX + 10) + "px")
               .style("top",  (e.pageY + 10) + "px"))
      .on("mouseout", () => tooltip.style("display", "none"));
  }

  // ╭──────────────────────────  tick  ──────────────────────────────────╮
  function ticked() {
    linksMerged
      .attr("x1", d => (typeof d.source === "object" ? d.source.x : nodesMap.get(d.source).x))
      .attr("y1", d => (typeof d.source === "object" ? d.source.y : nodesMap.get(d.source).y))
      .attr("x2", d => (typeof d.target === "object" ? d.target.x : nodesMap.get(d.target).x))
      .attr("y2", d => (typeof d.target === "object" ? d.target.y : nodesMap.get(d.target).y));

    nodesMerged.attr("transform", d => `translate(${d.x},${d.y})`);
  }

  update();
}
