/*
  Mindblowing (static) - vanilla HTML/JS/CSS version
  - Double-click index.html to run (no build step, no server).
*/

(() => {
  // ---------- Utilities ----------
  const $ = (sel, root=document) => root.querySelector(sel);
  const $$ = (sel, root=document) => Array.from(root.querySelectorAll(sel));

  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));

  function safeCopy(text) {
    // Clipboard API is often blocked on file:// (not a secure context).
    // Fallback to execCommand copy.
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).catch(() => fallback());
    } else {
      fallback();
    }
    function fallback() {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', 'true');
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); } catch (e) {}
      document.body.removeChild(ta);
    }
  }

  // ---------- Data model (ported from the TS project) ----------
  const NODE_WIDTH = 250;
  const NODE_HEIGHT = 100;
  const HORIZONTAL_GAP = 100;
  const VERTICAL_GAP = 150;

  function buildMindMap(root, startX=0, startY=0) {
    const nodes = [];
    const edges = [];

    function traverse(node, x, y, parentId) {
      let childrenSpan = 0;

      if (node.children && node.children.length > 0) {
        const childX = x + NODE_WIDTH + HORIZONTAL_GAP;
        let childY = y;

        for (const child of node.children) {
          const childHeightUsed = traverse(child, childX, childY, node.id);
          const span = childHeightUsed - childY;
          childY = childHeightUsed;
          childrenSpan += span;
        }

        // If a category has children, ensure it has at least one "row"
        childrenSpan = Math.max(childrenSpan, NODE_HEIGHT + 20);
      } else {
        childrenSpan = NODE_HEIGHT + 20; // leaf node height with padding
      }

      const myY = y + (childrenSpan / 2) - (NODE_HEIGHT / 2);

      nodes.push({
        id: node.id,
        x,
        y: myY,
        data: { ...node.data, status: 'default' }
      });

      if (parentId) {
        edges.push({
          id: `e-${parentId}-${node.id}`,
          source: parentId,
          target: node.id
        });
      }

      return Math.max(y + childrenSpan, y + VERTICAL_GAP);
    }

    traverse(root, startX, startY, undefined);
    return { nodes, edges };
  }

  // ---------- Mode data ----------
  const generalTree = window.MINDMAP_GENERAL_TREE;
  const adTree = window.MINDMAP_AD_TREE;

  if (!generalTree || !adTree) {
    console.warn("Mindblowing: map data is missing. Check general-map.js/ad-map.js.");
  }

  const generalPentestData = generalTree ? buildMindMap(generalTree) : { nodes: [], edges: [] };
  const adPentestData = adTree ? buildMindMap(adTree) : { nodes: [], edges: [] };

  const MODES = {
    GENERAL: { name: 'General Pentest', data: generalPentestData },
    AD: { name: 'Active Directory', data: adPentestData }
  };

  // ---------- Icons (offline-friendly; simple emoji mapping) ----------
  const ICON = {
    Shield: '🛡️',
    Search: '🔎',
    Eye: '👁️',
    Globe: '🌐',
    List: '📋',
    Activity: '📈',
    Target: '🎯',
    Folder: '📁',
    Sword: '⚔️',
    Database: '🗄️',
    Code: '💻',
    Upload: '⬆️',
    Wifi: '📶',
    Lock: '🔒',
    Terminal: '🧑‍💻',
    Flag: '🚩',
    Server: '🖥️',
    Clock: '⏱️',
    Monitor: '🖥️',
    User: '👤',
    Castle: '🏰',
    Key: '🔑',
    Radio: '📡',
    ArrowRight: '➡️',
    Network: '🕸️',
    Map: '🗺️',
    Share2: '🔀',
    Flame: '🔥',
    Unlock: '🔓',
    Repeat: '🔁',
    Hash: '#️⃣',
    Cpu: '🧠',
    Crown: '👑',
    Download: '⬇️',
    Ticket: '🎟️',
    File: '📄',
    Bomb: '💣'
  };

  // ---------- App state ----------
  let modeKey = 'GENERAL';
  let reached = new Set();
  let selectedId = null;

  // view transform
  let tx = 0, ty = 0, scale = 1;

  // current map
  let map = null; // {nodes, edges}
  let nodeById = new Map();
  let parentById = new Map();

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

  function computeParents() {
    parentById = new Map();
    for (const e of map.edges) {
      parentById.set(e.target, e.source);
    }
  }

  function recomputeStatus() {
    // Match the original: if any reached nodes exist,
    // - reached nodes => reached
    // - root or parent is reached => accessible
    // - otherwise => dimmed
    for (const n of map.nodes) {
      let status = 'default';
      if (reached.size > 0) {
        if (reached.has(n.id)) status = 'reached';
        else {
          const isRoot = (n.data.type === 'root');
          const parent = parentById.get(n.id);
          const parentIsReached = parent && reached.has(parent);
          status = (isRoot || parentIsReached) ? 'accessible' : 'dimmed';
        }
      }
      n.data.status = status;
    }
  }

  function nodeClass(n) {
    const t = n.data.type || 'technique';
    const s = n.data.status || 'default';

    const classes = ['node', `type-${t}`, `status-${s}`];
    if (n.id === selectedId) classes.push('selected');
    return classes.join(' ');
  }

  function edgePath(sx, sy, tx2, ty2) {
    // Smoothstep-ish bezier
    const x1 = sx + NODE_WIDTH;
    const y1 = sy + NODE_HEIGHT / 2;
    const x2 = tx2;
    const y2 = ty2 + NODE_HEIGHT / 2;

    const midX = (x1 + x2) / 2;
    const c1x = midX;
    const c1y = y1;
    const c2x = midX;
    const c2y = y2;
    return `M ${x1} ${y1} C ${c1x} ${c1y}, ${c2x} ${c2y}, ${x2} ${y2}`;
  }

  function render() {
    if (!map) return;
    nodeById = new Map(map.nodes.map(n => [n.id, n]));

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
      const s = nodeById.get(e.source);
      const t = nodeById.get(e.target);
      if (!s || !t) continue;

      const p = document.createElementNS('http://www.w3.org/2000/svg','path');
      p.setAttribute('d', edgePath(s.x, s.y, t.x, t.y));
      p.setAttribute('class', 'edge');
      elEdges.appendChild(p);
    }

    // nodes
    elNodes.innerHTML = '';
    for (const n of map.nodes) {
      const div = document.createElement('div');
      div.className = nodeClass(n);
      div.style.left = `${n.x}px`;
      div.style.top  = `${n.y}px`;
      div.dataset.id = n.id;

      const icon = ICON[n.data.icon] || '•';
      div.innerHTML = `
        <div class="nodeIcon" aria-hidden="true">${icon}</div>
        <div class="nodeText">
          <div class="nodeLabel">${escapeHtml(n.data.label)}</div>
          <div class="nodeDesc">${escapeHtml(n.data.description)}</div>
        </div>
      `;

      div.addEventListener('click', (ev) => {
        ev.stopPropagation();
        selectNode(n.id);
      });

      elNodes.appendChild(div);
    }

    // keep selection styles current
    updateNodeStyles();

    // If nothing selected, hide panel.
    if (selectedId && !nodeById.get(selectedId)) {
      selectedId = null;
      closePanel();
    }
  }

  function escapeHtml(s) {
    return String(s ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  function updateNodeStyles() {
    $$('.node', elNodes).forEach(el => {
      const id = el.dataset.id;
      const n = nodeById.get(id);
      if (!n) return;
      el.className = nodeClass(n);
    });
  }

  // ---------- Detail panel ----------
  function selectNode(id) {
    selectedId = id;
    updateNodeStyles();
    const n = nodeById.get(id);
    if (!n) return;

    openPanel(n);
  }

  function openPanel(n) {
    elPanel.classList.add('open');
    elPanelTitle.textContent = n.data.label || '';
    elPanelSubtitle.textContent = (n.data.type || '').toLowerCase();

    const isReached = reached.has(n.id);
    elReachedBtn.classList.toggle('isReached', isReached);
    elReachedBtn.innerText = isReached ? '✅ COMPROMISED' : '⭕ Mark Status';

    const resources = (n.data.resources || []);
    const commands = (n.data.commands || []);

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
                <button class="btn btnSmall copyBtn" type="button">Copy</button>
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
        <div class="panelText">${escapeHtml(n.data.description)}</div>
      </div>
      ${resHtml}
      ${cmdHtml}
    `;

    $$('.copyBtn', elPanelBody).forEach((btn) => {
      btn.addEventListener('click', (ev) => {
        const card = ev.target.closest('.cmdCard');
        if (!card) return;
        const idx = Number(card.dataset.cmdIndex);
        const cmd = commands[idx];
        if (cmd) safeCopy(cmd.code);
      });
    });
  }

  function closePanel() {
    elPanel.classList.remove('open');
    selectedId = null;
    updateNodeStyles();
  }

  $('#closePanel').addEventListener('click', (e) => {
    e.stopPropagation();
    closePanel();
  });

  elReachedBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    if (!selectedId) return;
    if (reached.has(selectedId)) reached.delete(selectedId);
    else reached.add(selectedId);
    persistReached();
    render();
    if (selectedId) selectNode(selectedId); // refresh panel state
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
    computeParents();
    loadReached();
    selectedId = null;
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
    const onControls = e.target.closest('.zoomDock, .hintDock');
    if (onControls) return;

    panning = true;
    panStart = { x: e.clientX, y: e.clientY, tx, ty };
    elCanvas.setPointerCapture(e.pointerId);
  });

  elCanvas.addEventListener('pointermove', (e) => {
    if (!panning || !panStart) return;
    const dx = e.clientX - panStart.x;
    const dy = e.clientY - panStart.y;
    setTransform(panStart.tx + dx, panStart.ty + dy, scale);
  });

  elCanvas.addEventListener('pointerup', (e) => {
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
