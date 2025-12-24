/*
  Mindblowing (static) - vanilla HTML/JS/CSS version
  - Double-click index.html to run (no build step, no server).
*/

(() => {
  // ---------- Utilities ----------
  const $ = (sel, root=document) => root.querySelector(sel);
  const $$ = (sel, root=document) => Array.from(root.querySelectorAll(sel));

  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));

  // ---------- Data model ----------
  const NODE_WIDTH = 250;
  const NODE_HEIGHT = 100;

  // ---------- Mode data ----------
  const generalData = window.MINDMAP_GENERAL_DATA;
  const adData = window.MINDMAP_AD_DATA;
  const utils = window.MINDMAP_UTILS;

  if (!generalData || !adData || !utils) {
    console.warn("Mindblowing: map data is missing. Check general-map.js/ad-map.js.");
  }

  const MODES = {
    GENERAL: { name: 'General Pentest', data: generalData && utils ? utils.buildGraph(generalData) : { nodes: [], edges: [] } },
    AD: { name: 'Active Directory', data: adData && utils ? utils.buildGraph(adData) : { nodes: [], edges: [] } }
  };

  // ---------- App state ----------
  let modeKey = 'GENERAL';
  let reached = new Set();
  let reachable = new Set();
  let selectedItem = null; // { type: 'node' | 'edge', id }
  let draggingNodeId = null;
  let dragStart = null;
  let dragMoved = false;
  let suppressClickUntil = 0;
  let dragPending = false;
  let dragTarget = null;

  // view transform
  let tx = 0, ty = 0, scale = 1;

  // current map
  let map = null; // {nodes, edges}
  let nodeById = new Map();
  let edgeById = new Map();
  let adjacency = new Map();
  let edgeIdsByNode = new Map();
  let edgePathById = new Map();
  let edgeHitById = new Map();
  let nodeElById = new Map();

  const storageKey = (k) => `mindblowing.static.${k}`;
  const storageReachedKey = () => storageKey(`reached.${modeKey}`);
  const storageThemeKey = () => storageKey('theme');

  // ---------- DOM ----------
  const elCanvas = $('#canvas');
  const elWorld  = $('#world');
  const elEdges  = $('#edges');
  const elEdgesSvg = $('#edgesSvg');
  const elNodes  = $('#nodes');
  const elPanel  = $('#detailPanel');
  const elPanelBody = $('#panelBody');
  const elPanelTitle = $('#panelTitle');
  const elPanelSubtitle = $('#panelSubtitle');
  const elReachedBtn = $('#toggleReached');
  const elModeGeneral = $('#modeGeneral');
  const elModeAd = $('#modeAd');
  const elThemeBtn = $('#themeToggle');

  const elZoomIn = $('#zoomIn');
  const elZoomOut = $('#zoomOut');
  const elZoomFit = $('#zoomFit');
  const elZoomReset = $('#zoomReset');

  // ---------- Theme ----------
  function applyTheme(isDark) {
    document.documentElement.classList.toggle('dark', !!isDark);
    localStorage.setItem(storageThemeKey(), isDark ? 'dark' : 'light');
    elThemeBtn.innerText = isDark ? '🌙 Dark' : '☀️ Light';
  }

  function loadTheme() {
    const t = localStorage.getItem(storageThemeKey());
    applyTheme(t ? t === 'dark' : true);
  }

  // ---------- Rendering ----------
  function setTransform(nextTx, nextTy, nextScale) {
    tx = nextTx; ty = nextTy; scale = nextScale;
    elWorld.style.transform = `translate(${tx}px, ${ty}px) scale(${scale})`;
    $('#zoomLabel').innerText = `${Math.round(scale*100)}%`;
  }

  function computeAdjacency() {
    adjacency = new Map();
    edgeById = new Map();
    edgeIdsByNode = new Map();
    for (const e of map.edges) {
      edgeById.set(e.id, e);
      if (!adjacency.has(e.source)) adjacency.set(e.source, []);
      adjacency.get(e.source).push(e.target);
      if (!edgeIdsByNode.has(e.source)) edgeIdsByNode.set(e.source, []);
      if (!edgeIdsByNode.has(e.target)) edgeIdsByNode.set(e.target, []);
      edgeIdsByNode.get(e.source).push(e.id);
      edgeIdsByNode.get(e.target).push(e.id);
    }
  }

  function computeReachable() {
    reachable = new Set();
    if (reached.size === 0) return;
    for (const id of reached) {
      const neighbors = adjacency.get(id) || [];
      for (const next of neighbors) reachable.add(next);
    }
  }

  function recomputeStatus() {
    // If any reached nodes exist,
    // - reached nodes => reached
    // - reachable nodes from reached => reachable
    // - otherwise => dimmed
    computeReachable();
    for (const n of map.nodes) {
      let status = 'default';
      if (reached.size > 0) {
        if (reached.has(n.id)) status = 'reached';
        else if (reachable.has(n.id)) status = 'reachable';
        else status = 'dimmed';
      }
      n.data.status = status;
    }
  }

  function nodeClass(n) {
    const t = n.data.type || 'technique';
    const s = n.data.status || 'default';

    const classes = ['node', `type-${t}`, `status-${s}`];
    if (selectedItem?.type === 'node' && n.id === selectedItem.id) classes.push('selected');
    return classes.join(' ');
  }

  function edgeClass(e) {
    const classes = ['edge'];
    if (selectedItem?.type === 'edge' && e.id === selectedItem.id) classes.push('edge-selected');
    if (reached.size > 0 && reached.has(e.source)) {
      classes.push('edge-reachable');
    }
    return classes.join(' ');
  }

  function anchorPoint(cx, cy, dx, dy) {
    const hw = NODE_WIDTH / 2;
    const hh = NODE_HEIGHT / 2;
    if (Math.abs(dx) >= Math.abs(dy)) {
      return { x: cx + (dx >= 0 ? hw : -hw), y: cy };
    }
    return { x: cx, y: cy + (dy >= 0 ? hh : -hh) };
  }

  function edgePathForEdge(e) {
    // Smoothstep-ish bezier from node border to node border.
    const sNode = nodeById.get(e.source);
    const tNode = nodeById.get(e.target);
    if (!sNode || !tNode) return null;

    const sCx = sNode.x + NODE_WIDTH / 2;
    const sCy = sNode.y + NODE_HEIGHT / 2;
    const tCx = tNode.x + NODE_WIDTH / 2;
    const tCy = tNode.y + NODE_HEIGHT / 2;

    const s = anchorPoint(sCx, sCy, tCx - sCx, tCy - sCy);
    const t = anchorPoint(tCx, tCy, sCx - tCx, sCy - tCy);

    const midX = (s.x + t.x) / 2;
    const c1x = midX;
    const c1y = s.y;
    const c2x = midX;
    const c2y = t.y;
    return `M ${s.x} ${s.y} C ${c1x} ${c1y}, ${c2x} ${c2y}, ${t.x} ${t.y}`;
  }

  function borderPoint(cx, cy, tx, ty) {
    const dx = tx - cx;
    const dy = ty - cy;
    const hw = NODE_WIDTH / 2;
    const hh = NODE_HEIGHT / 2;
    if (dx === 0 && dy === 0) return { x: cx, y: cy };
    const txScale = dx === 0 ? Infinity : Math.abs(hw / dx);
    const tyScale = dy === 0 ? Infinity : Math.abs(hh / dy);
    const t = Math.min(txScale, tyScale);
    return { x: cx + dx * t, y: cy + dy * t };
  }

  function render() {
    if (!map) return;
    nodeById = new Map(map.nodes.map(n => [n.id, n]));
    edgeById = new Map(map.edges.map(e => [e.id, e]));
    edgePathById = new Map();
    edgeHitById = new Map();
    nodeElById = new Map();

    recomputeStatus();
    // Resize edge SVG so paths are always visible (simple oversized canvas)
    let maxX = 0, maxY = 0;
    for (const n of map.nodes) {
      maxX = Math.max(maxX, n.x + NODE_WIDTH);
      maxY = Math.max(maxY, n.y + NODE_HEIGHT);
    }
    const pad = 2000;
    elEdgesSvg.setAttribute('width', String(maxX + pad));
    elEdgesSvg.setAttribute('height', String(maxY + pad));


    // edges
    elEdges.innerHTML = '';
    for (const e of map.edges) {
      const d = edgePathForEdge(e);
      if (!d) continue;

      const p = document.createElementNS('http://www.w3.org/2000/svg','path');
      p.setAttribute('d', d);
      p.setAttribute('class', edgeClass(e));
      p.setAttribute('marker-end', 'url(#arrowHead)');
      p.dataset.id = e.id;
      elEdges.appendChild(p);
      edgePathById.set(e.id, p);

      const hit = document.createElementNS('http://www.w3.org/2000/svg','path');
      hit.setAttribute('d', d);
      hit.setAttribute('class', 'edge-hit');
      hit.dataset.id = e.id;
      hit.addEventListener('click', (ev) => {
        ev.stopPropagation();
        selectEdge(e.id);
      });
      elEdges.appendChild(hit);
      edgeHitById.set(e.id, hit);
    }

    // nodes
    elNodes.innerHTML = '';
    for (const n of map.nodes) {
      const div = document.createElement('div');
      div.className = nodeClass(n);
      div.style.transform = `translate(${n.x}px, ${n.y}px)`;
      div.dataset.id = n.id;

      const icon = n.data.emoji || '•';
      div.innerHTML = `
        <div class="nodeIcon" aria-hidden="true">${icon}</div>
        <div class="nodeText">
          <div class="nodeLabel">${escapeHtml(n.data.label)}</div>
          <div class="nodeDesc">${escapeHtml(n.data.description)}</div>
        </div>
      `;

      div.addEventListener('pointerdown', (ev) => {
        if (ev.button !== 0) return;
        ev.stopPropagation();
        draggingNodeId = n.id;
        dragStart = { x: ev.clientX, y: ev.clientY, nodeX: n.x, nodeY: n.y };
        dragMoved = false;
        div.classList.add('dragging');
        document.documentElement.classList.add('isDragging');
        div.setPointerCapture(ev.pointerId);
      });

      div.addEventListener('click', (ev) => {
        ev.stopPropagation();
        if (Date.now() < suppressClickUntil) return;
        selectNode(n.id);
      });

      elNodes.appendChild(div);
      nodeElById.set(n.id, div);
    }

    // keep selection styles current
    updateNodeStyles();
    updateEdgeStyles();

    // If nothing selected, hide panel.
    if (selectedItem?.type === 'node' && !nodeById.get(selectedItem.id)) {
      selectedItem = null;
      closePanel();
    }
    if (selectedItem?.type === 'edge' && !edgeById.get(selectedItem.id)) {
      selectedItem = null;
      closePanel();
    }
  }

  function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  function renderMarkdown(input) {
    const lines = String(input ?? '').split(/\r?\n/);
    let html = '';
    let inCode = false;
    let listOpen = false;

    const flushList = () => {
      if (listOpen) {
        html += '</ul>';
        listOpen = false;
      }
    };

    const inlineMd = (text) => {
      let out = escapeHtml(text);
      out = out.replace(/`([^`]+)`/g, '<code>$1</code>');
      out = out.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
      out = out.replace(/\*([^*]+)\*/g, '<em>$1</em>');
      out = out.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noreferrer">$1</a>');
      return out;
    };

    for (const line of lines) {
      if (line.startsWith('```')) {
        if (!inCode) {
          flushList();
          inCode = true;
          html += '<pre><code>';
        } else {
          inCode = false;
          html += '</code></pre>';
        }
        continue;
      }

      if (inCode) {
        html += `${escapeHtml(line)}\n`;
        continue;
      }

      const trimmed = line.trim();
      if (!trimmed) {
        flushList();
        continue;
      }

      const headingMatch = trimmed.match(/^(#{1,3})\s+(.*)$/);
      if (headingMatch) {
        flushList();
        const level = headingMatch[1].length;
        html += `<h${level}>${inlineMd(headingMatch[2])}</h${level}>`;
        continue;
      }

      if (trimmed.startsWith('- ') || trimmed.startsWith('* ')) {
        if (!listOpen) {
          html += '<ul>';
          listOpen = true;
        }
        html += `<li>${inlineMd(trimmed.slice(2))}</li>`;
        continue;
      }

      flushList();
      html += `<p>${inlineMd(trimmed)}</p>`;
    }

    flushList();
    if (inCode) html += '</code></pre>';
    return html;
  }

  function updateNodeStyles() {
    $$('.node', elNodes).forEach(el => {
      const id = el.dataset.id;
      const n = nodeById.get(id);
      if (!n) return;
      el.className = nodeClass(n);
    });
  }

  function updateEdgeStyles() {
    $$('.edge', elEdges).forEach(el => {
      const id = el.dataset.id;
      const e = edgeById.get(id);
      if (!e) return;
      el.setAttribute('class', edgeClass(e));
    });
  }

  function updateEdgesForNode(nodeId) {
    const edgeIds = edgeIdsByNode.get(nodeId) || [];
    for (const edgeId of edgeIds) {
      const e = edgeById.get(edgeId);
      if (!e) continue;
      const d = edgePathForEdge(e);
      if (!d) continue;
      const edgeEl = edgePathById.get(edgeId);
      const hitEl = edgeHitById.get(edgeId);
      if (edgeEl) edgeEl.setAttribute('d', d);
      if (hitEl) hitEl.setAttribute('d', d);
    }
  }

  function scheduleDragFrame() {
    if (dragPending) return;
    dragPending = true;
    requestAnimationFrame(() => {
      dragPending = false;
      if (!draggingNodeId || !dragTarget) return;
      const n = nodeById.get(draggingNodeId);
      const el = nodeElById.get(draggingNodeId);
      if (!n || !el) return;
      n.x = dragTarget.x;
      n.y = dragTarget.y;
      el.style.transform = `translate(${n.x}px, ${n.y}px)`;
      updateEdgesForNode(draggingNodeId);
    });
  }

  // ---------- Detail panel ----------
  function selectNode(id) {
    selectedItem = { type: 'node', id };
    updateNodeStyles();
    updateEdgeStyles();
    const n = nodeById.get(id);
    if (!n) return;

    openNodePanel(n);
  }

  function selectEdge(id) {
    selectedItem = { type: 'edge', id };
    updateNodeStyles();
    updateEdgeStyles();
    const e = edgeById.get(id);
    if (!e) return;
    openEdgePanel(e);
  }

  function openNodePanel(n) {
    elPanel.classList.add('open');
    elPanelTitle.textContent = n.data.label || '';
    elPanelSubtitle.textContent = (n.data.type || '').toLowerCase();

    const isReached = reached.has(n.id);
    elReachedBtn.classList.remove('isHidden');
    elReachedBtn.classList.toggle('isReached', isReached);
    elReachedBtn.innerText = isReached ? '🟢 FOCUSED' : '🟢 Focus';

    const resources = (n.data.resources || []);
    const commands = (n.data.commands || []);
    const descriptionMd = n.data.descriptionMd || n.data.description || '';

    const resHtml = resources.length ? `
      <div class="panelSection">
        <div class="sectionTitle">Resources</div>
        <div class="linkList">
          ${resources.map(r => `
            <a class="linkItem" href="${escapeHtml(r.url)}" target="_blank" rel="noreferrer">
              ${escapeHtml(r.title)} <span class="ext">↗</span>
            </a>`).join('')}
        </div>
      </div>
    ` : '';

    const cmdHtml = commands.length ? `
      <div class="panelSection">
        <div class="sectionTitle">Commands / Payloads</div>
        <div class="cmdList">
          ${commands.map((c, idx) => `
            <div class="cmdCard" data-cmd-index="${idx}">
              <div class="cmdHeader">
                <span class="cmdDesc">${escapeHtml(c.description)}</span>
              </div>
              <pre class="cmdCode"><code>${escapeHtml(c.code)}</code></pre>
            </div>
          `).join('')}
        </div>
      </div>
    ` : '';

    elPanelBody.innerHTML = `
      <div class="panelSection">
        <div class="sectionTitle">Description</div>
        <div class="panelText md">${renderMarkdown(descriptionMd)}</div>
      </div>
      ${resHtml}
      ${cmdHtml}
    `;

  }

  function openEdgePanel(e) {
    elPanel.classList.add('open');
    elPanelTitle.textContent = e.data?.label || 'Connection';
    elPanelSubtitle.textContent = (e.data?.type || 'connection').toLowerCase();
    elReachedBtn.classList.add('isHidden');

    const sourceLabel = nodeById.get(e.source)?.data?.label || e.source;
    const targetLabel = nodeById.get(e.target)?.data?.label || e.target;
    const fallbackMd = `**${sourceLabel}** -> **${targetLabel}**`;
    const descriptionMd = e.data?.descriptionMd || e.data?.description || fallbackMd;
    elPanelBody.innerHTML = `
      <div class="panelSection">
        <div class="sectionTitle">Description</div>
        <div class="panelText md">${renderMarkdown(descriptionMd)}</div>
      </div>
    `;
  }

  function closePanel() {
    elPanel.classList.remove('open');
    selectedItem = null;
    updateNodeStyles();
    updateEdgeStyles();
  }

  $('#closePanel').addEventListener('click', (e) => {
    e.stopPropagation();
    closePanel();
  });

  elReachedBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    if (!selectedItem || selectedItem.type !== 'node') return;
    const id = selectedItem.id;
    if (reached.has(id)) reached.delete(id);
    else reached.add(id);
    persistReached();
    render();
    if (selectedItem?.type === 'node') selectNode(selectedItem.id); // refresh panel state
  });

  // ---------- Mode switching ----------
  function loadReached() {
    try {
      const raw = localStorage.getItem(storageReachedKey());
      const arr = raw ? JSON.parse(raw) : [];
      reached = new Set(Array.isArray(arr) ? arr : []);
    } catch {
      reached = new Set();
    }
  }

  function persistReached() {
    localStorage.setItem(storageReachedKey(), JSON.stringify(Array.from(reached)));
  }

  function setMode(nextModeKey) {
    modeKey = nextModeKey;
    $('#modeLabel').textContent = MODES[modeKey].name;

    elModeGeneral.classList.toggle('active', modeKey === 'GENERAL');
    elModeAd.classList.toggle('active', modeKey === 'AD');

    map = MODES[modeKey].data;
    computeAdjacency();
    loadReached();
    selectedItem = null;
    closePanel();

    render();
    fitToView();
  }

  elModeGeneral.addEventListener('click', () => setMode('GENERAL'));
  elModeAd.addEventListener('click', () => setMode('AD'));

  // ---------- Zoom / pan ----------
  function fitToView(padding=60) {
    if (!map || map.nodes.length === 0) return;

    const cw = elCanvas.clientWidth;
    const ch = elCanvas.clientHeight;

    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const n of map.nodes) {
      minX = Math.min(minX, n.x);
      minY = Math.min(minY, n.y);
      maxX = Math.max(maxX, n.x + NODE_WIDTH);
      maxY = Math.max(maxY, n.y + NODE_HEIGHT);
    }

    const contentW = (maxX - minX);
    const contentH = (maxY - minY);

    const sx = (cw - padding*2) / contentW;
    const sy = (ch - padding*2) / contentH;
    const s = clamp(Math.min(sx, sy), 0.15, 2.5);

    const x = -minX * s + (cw - contentW * s) / 2;
    const y = -minY * s + (ch - contentH * s) / 2;

    setTransform(x, y, s);
  }

  function zoomAt(factor, clientX, clientY) {
    const rect = elCanvas.getBoundingClientRect();
    const mx = clientX - rect.left;
    const my = clientY - rect.top;

    const wx = (mx - tx) / scale;
    const wy = (my - ty) / scale;

    const newScale = clamp(scale * factor, 0.15, 3.5);
    const newTx = mx - wx * newScale;
    const newTy = my - wy * newScale;

    setTransform(newTx, newTy, newScale);
  }

  elZoomIn.addEventListener('click', () => zoomAt(1.15, elCanvas.clientWidth/2, elCanvas.clientHeight/2));
  elZoomOut.addEventListener('click', () => zoomAt(1/1.15, elCanvas.clientWidth/2, elCanvas.clientHeight/2));
  elZoomFit.addEventListener('click', () => fitToView());
  elZoomReset.addEventListener('click', () => setTransform(40, 40, 1));

  let panning = false;
  let panStart = null;

  elCanvas.addEventListener('pointerdown', (e) => {
    if (e.button !== 0) return;
    const onNode = e.target.closest('.node');
    if (onNode) return;
    const onEdge = e.target.closest('.edge-hit, .edge');
    if (onEdge) return;
    const onControls = e.target.closest('.zoomDock, .hintDock');
    if (onControls) return;

    panning = true;
    panStart = { x: e.clientX, y: e.clientY, tx, ty };
    elCanvas.setPointerCapture(e.pointerId);
  });

  elCanvas.addEventListener('pointermove', (e) => {
    if (draggingNodeId && dragStart) {
      const dx = (e.clientX - dragStart.x) / scale;
      const dy = (e.clientY - dragStart.y) / scale;
      if (Math.abs(dx) > 2 || Math.abs(dy) > 2) dragMoved = true;
      dragTarget = { x: dragStart.nodeX + dx, y: dragStart.nodeY + dy };
      scheduleDragFrame();
      return;
    }
    if (!panning || !panStart) return;
    const dx = e.clientX - panStart.x;
    const dy = e.clientY - panStart.y;
    setTransform(panStart.tx + dx, panStart.ty + dy, scale);
  });

  elCanvas.addEventListener('pointerup', (e) => {
    if (draggingNodeId) {
      const el = nodeElById.get(draggingNodeId);
      if (el) {
        el.classList.remove('dragging');
        try { el.releasePointerCapture(e.pointerId); } catch {}
      }
      draggingNodeId = null;
      dragStart = null;
      if (dragMoved) suppressClickUntil = Date.now() + 200;
      dragMoved = false;
      dragTarget = null;
      document.documentElement.classList.remove('isDragging');
      return;
    }
    panning = false;
    panStart = null;
    try { elCanvas.releasePointerCapture(e.pointerId); } catch {}
  });

  elCanvas.addEventListener('wheel', (e) => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.10 : 1/1.10;
    zoomAt(factor, e.clientX, e.clientY);
  }, { passive: false });

  // background click closes panel
  elCanvas.addEventListener('click', (e) => {
    if (e.target.closest('.zoomDock, .hintDock')) return;
    closePanel();
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closePanel();
  });

  // ---------- Theme button ----------
  elThemeBtn.addEventListener('click', () => {
    const isDark = document.documentElement.classList.contains('dark');
    applyTheme(!isDark);
  });

  // ---------- Init ----------
  function init() {
    loadTheme();
    setTransform(40, 40, 1);
    setMode('GENERAL');
  }

  init();
})();
