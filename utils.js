(() => {
  const NODE_WIDTH = 250;
  const NODE_HEIGHT = 100;
  const HORIZONTAL_GAP = 2000;
  const VERTICAL_GAP = 10;

  function layoutTree(root, startX=0, startY=0) {
    const nodes = [];
    const edges = [];

    function traverse(node, x, y, parent) {
      let childrenSpan = 0;

      if (node.children && node.children.length > 0) {
        const childX = x + NODE_WIDTH + HORIZONTAL_GAP;
        let childY = y;

        for (const child of node.children) {
          const childHeightUsed = traverse(child, childX, childY, node);
          const span = childHeightUsed - childY;
          childY = childHeightUsed;
          childrenSpan += span;
        }

        childrenSpan = Math.max(childrenSpan, NODE_HEIGHT + 20);
      } else {
        childrenSpan = NODE_HEIGHT + 20;
      }

      const myY = y + (childrenSpan / 2) - (NODE_HEIGHT / 2);

      nodes.push({
        id: node.id,
        x,
        y: myY,
        data: node.data
      });

      if (parent) {
        edges.push({
          id: `e-${parent.id}-${node.id}`,
          source: parent.id,
          target: node.id,
          data: {
            label: 'Progression',
            type: 'flow',
            descriptionMd: `From **${parent.data.label}** to **${node.data.label}**.`
          }
        });
      }

      return Math.max(y + childrenSpan, y + VERTICAL_GAP);
    }

    traverse(root, startX, startY, null);
    return { nodes, edges };
  }

  function enforceLandscape(nodes) {
    if (!nodes.length) return;
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const n of nodes) {
      minX = Math.min(minX, n.x);
      minY = Math.min(minY, n.y);
      maxX = Math.max(maxX, n.x);
      maxY = Math.max(maxY, n.y);
    }
    const width = (maxX - minX) + NODE_WIDTH;
    const height = (maxY - minY) + NODE_HEIGHT;
    if (height <= width) return;
    const factor = Math.min((height / width) * 1.03, 2.2);
    for (const n of nodes) {
      n.x = minX + (n.x - minX) * factor;
    }
  }

  function buildGraph(data) {
    if (!data || !data.root) return { nodes: [], edges: [] };
    const layout = layoutTree(data.root, data.startX || 0, data.startY || 0);
    enforceLandscape(layout.nodes);
    const extraEdges = Array.isArray(data.extraEdges) ? data.extraEdges : [];
    return {
      nodes: layout.nodes,
      edges: [...layout.edges, ...extraEdges]
    };
  }

  window.MINDMAP_UTILS = { buildGraph };
})();
