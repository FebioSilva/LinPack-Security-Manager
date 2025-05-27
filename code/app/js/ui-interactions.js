function drag(simulation) {
    function dragstarted(event, d) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      d.fx = d.x;
      d.fy = d.y;
    }
    function dragged(event, d) {
      d.fx = event.x;
      d.fy = event.y;
    }
    function dragended(event, d) {
      if (!event.active) simulation.alphaTarget(0);
      d.fx = null;
      d.fy = null;
    }
    return d3.drag()
      .on("start", dragstarted)
      .on("drag", dragged)
      .on("end", dragended);
  }

  function expandNode(productNode, childNodes, childLinks, simulation, svg) {
  const angleStep = (2 * Math.PI) / childNodes.length;
  const radius = 60;

  childNodes.forEach((node, i) => {
    const angle = i * angleStep;
    node.x = productNode.x + radius * Math.cos(angle);
    node.y = productNode.y + radius * Math.sin(angle);
  });

  // Atualizar os dados da simulação
  const allNodes = simulation.nodes().concat(childNodes);
  const allLinks = simulation.force("link").links().concat(childLinks);

  simulation.nodes(allNodes);
  simulation.force("link").links(allLinks);

  simulation.alpha(1).restart(); // Reiniciar a simulação para reorganizar
}
