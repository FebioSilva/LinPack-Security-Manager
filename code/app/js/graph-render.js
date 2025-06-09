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

  // Cria mapa de nodes para acesso rápido e inicializa collapsed=true e children=[]
  const nodesMap = new Map(nodes.map(n => [n.id, { ...n, children: [], collapsed: true }]));

  // Constrói árvore de filhos baseada nos links (para expandir/collapse)
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

  // Identifica os nodes topo da hierarquia (Products)
  const topNodes = Array.from(nodesMap.values()).filter(n => n.type === "Product");

  // Posição inicial aleatória para todos os nodes
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

  // Função recursiva para coletar nodes visíveis (expandindo)
  function collectVisible(node) {
    visibleNodes.push(node);
    if (!node.collapsed && node.children?.length > 0) {
      node.children.forEach(collectVisible);
    }
  }

  function update() {
    visibleNodes = [];
    visibleLinks = [];

    // Começa coletando nodes topo visíveis
    topNodes.forEach(collectVisible);

    // Posiciona filhos de nodes expandidos em círculo ao redor do pai
    visibleNodes.forEach(node => {
      if (!node.collapsed && node.children?.length > 0) {
        const angleStep = (2 * Math.PI) / node.children.length;
        const radius = 50 + node.children.length * 10;
        node.children.forEach((child, i) => {
          child.x = node.x + radius * Math.cos(i * angleStep);
          child.y = node.y + radius * Math.sin(i * angleStep);
        });
      }
    });

    // Define links entre nodes visíveis e seus filhos expandidos
    visibleNodes.forEach(node => {
      if (!node.collapsed && node.children) {
        node.children.forEach(child => {
          if (visibleNodes.includes(child)) {
            visibleLinks.push({ source: node.id, target: child.id });
          }
        });
      }
    });

    // Adiciona links extras CVE → Product (mesmo que CVE não seja filho do Product)
    // Para isso, percorremos todos links originais e adicionamos os links do tipo CVE → Product
    links.forEach(link => {
      const source = nodesMap.get(link.source);
      const target = nodesMap.get(link.target);
      if (!source || !target) return;

      if (source.type === "CVE" && target.type === "Product") {
        // Só adiciona o link se ambos os nodes estiverem visíveis
        if (visibleNodes.includes(source) && visibleNodes.includes(target)) {
          visibleLinks.push({ source: source.id, target: target.id });
        }
      }
    });

    // Seleção dos nodes
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

          update();
          simulation.alpha(0.5).restart();
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
      .attr("class", "node-label")
      .text(d => d.id)
      .attr("dx", 18)
      .attr("dy", ".35em");

    nodesMerged = nodeEnter.merge(nodeSelection);

    // Seleção dos links
    const linkSelection = graphGroup.selectAll("line")
      .data(visibleLinks, d => `${d.source}-${d.target}`);

    linkSelection.exit().remove();

    const linkEnter = linkSelection.enter().append("line")
      .attr("stroke", "#aaa")
      .attr("stroke-width", 2);

    linksMerged = linkEnter.merge(linkSelection);

    simulation.nodes(visibleNodes);
    simulation.force("link").links(visibleLinks);
    simulation.alpha(0.5).restart();

    graphGroup.selectAll(".node").raise();

    // Tooltip
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
            <strong>Min:</strong> ${d.min || 'N/A'}<br>
            <strong>Max:</strong> ${d.max || 'N/A'}<br>
          `;
        } else if (d.type === "Vendor") {
          html += `
            <strong>Vendor Name:</strong> ${d.vendor_name || 'N/A'}<br>
          `;
        }

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
