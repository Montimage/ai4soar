/* CACAO 2.0 workflow → SVG graph.
 *
 * Renders a playbook's `cacao.workflow` as a node/edge diagram: one node per step,
 * edges for the on_success / on_failure / on_completion transitions. Self-contained —
 * no layout library, no CDN — because the workflows in this library are small
 * (4–6 steps) and strictly top-down, so a layered walk from `workflow_start` is enough.
 *
 * Public API:
 *   CacaoGraph.render(cacao)            → { svg, steps, order }
 *   CacaoGraph.stepDetailHtml(cacao, id) → HTML for one step's contents
 *   CacaoGraph.openModal(pb, {onSave})   → the Workflow view; with onSave, an Edit mode
 *                                          that changes nodes and hands back the playbook
 */
const CacaoGraph = (() => {
  'use strict';

  const NODE_W = 290, NODE_H = 58, V_GAP = 54, H_GAP = 40, PAD = 16;

  /* Every branching field CACAO 2.0 defines, not just the three the current library
     happens to use. workflow-step.json gives on_completion / on_success / on_failure to
     every step type; the branching types add their own:
       if-condition / while-condition → on_true, on_false
       parallel                       → next_steps (array, 2+)
       switch-condition               → cases (map of case value → step id)
     A field that is not read here is an edge that silently vanishes from the diagram,
     so the full set is handled even though no bundled template uses the last three. */
  const EDGE_KINDS = [
    { key: 'on_success',    label: 'success',    color: '#1a7f37', dash: ''    },
    { key: 'on_failure',    label: 'failure',    color: '#cf222e', dash: '4 3' },
    { key: 'on_completion', label: 'completion', color: '#57606a', dash: ''    },
    { key: 'on_true',       label: 'true',       color: '#1a7f37', dash: ''    },
    { key: 'on_false',      label: 'false',      color: '#9a6700', dash: '4 3' },
  ];
  const PARALLEL_KIND = { label: 'parallel', color: '#8250df', dash: '2 3' };
  const CASE_KIND     = { label: 'case',     color: '#0969da', dash: ''     };

  function esc(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
  }

  /* Highlight {{param}} placeholders so it is obvious what the parameterizer fills. */
  function escWithParams(s) {
    return esc(s).replace(/\{\{([^}]+)\}\}/g,
      '<span class="cacao-param">{{$1}}</span>');
  }

  // -------------------------------------------------------------------------
  // Graph model
  // -------------------------------------------------------------------------
  function edgesOf(step) {
    const out = [];
    for (const kind of EDGE_KINDS) {
      const target = step[kind.key];
      if (target) out.push({ ...kind, target });
    }
    // parallel: fan out to every branch
    if (Array.isArray(step.next_steps)) {
      for (const target of step.next_steps) {
        if (target) out.push({ ...PARALLEL_KIND, target });
      }
    }
    // switch-condition: one edge per case, labelled with the case value
    if (step.cases && typeof step.cases === 'object' && !Array.isArray(step.cases)) {
      for (const [value, target] of Object.entries(step.cases)) {
        if (target) out.push({ ...CASE_KIND, label: `case ${value}`, target });
      }
    }

    // Two transitions to the SAME step are one arrow, labelled with both — drawing
    // them separately would stack identical paths. "success · failure" therefore means
    // the template declared both, i.e. continue regardless of outcome.
    const merged = [];
    for (const e of out) {
      const twin = merged.find(m => m.target === e.target);
      if (twin) {
        twin.label = `${twin.label} · ${e.label}`;
        twin.color = '#57606a';
        twin.dash  = '';
      } else {
        merged.push({ ...e });
      }
    }
    return merged;
  }

  /* Edges that close a loop, found by DFS (target is still on the stack). A
     while-condition's on_true legitimately jumps back to an earlier step; counting
     such an edge when layering would push its target down a row on every pass and
     stretch the diagram pointlessly. They are excluded from layering and drawn as
     routed edges instead. */
  function backEdges(workflow, start) {
    const back = new Set();
    const state = {};                       // 0/undefined = new, 1 = on stack, 2 = done
    const visit = (id) => {
      state[id] = 1;
      for (const e of edgesOf(workflow[id] || {})) {
        if (!workflow[e.target]) continue;
        const st = state[e.target] || 0;
        if (st === 1) back.add(`${id}\u0000${e.target}`);
        else if (st === 0) visit(e.target);
      }
      state[id] = 2;
    };
    if (workflow[start]) visit(start);
    for (const id of Object.keys(workflow)) if (!state[id]) visit(id);
    return back;
  }

  /* Depth = longest path from the start step over the acyclic part, so every layering
     edge points downward. Steps unreachable from workflow_start are placed on a final
     row rather than dropped — an orphan step is a defect worth seeing, not hiding. */
  function layout(workflow, start) {
    const ids = Object.keys(workflow);
    const back = backEdges(workflow, start);
    const depth = {};
    ids.forEach(id => { depth[id] = -1; });

    if (start && workflow[start]) depth[start] = 0;
    // Relax repeatedly; bounded by node count so a cyclic workflow cannot hang.
    for (let pass = 0; pass < ids.length + 1; pass++) {
      let changed = false;
      for (const id of ids) {
        if (depth[id] < 0) continue;
        for (const e of edgesOf(workflow[id] || {})) {
          if (back.has(`${id}\u0000${e.target}`)) continue;
          if (workflow[e.target] && depth[e.target] < depth[id] + 1) {
            depth[e.target] = depth[id] + 1;
            changed = true;
          }
        }
      }
      if (!changed) break;
    }

    const maxDepth = Math.max(0, ...Object.values(depth));
    ids.forEach(id => { if (depth[id] < 0) depth[id] = maxDepth + 1; });

    const rows = {};
    ids.forEach(id => { (rows[depth[id]] ||= []).push(id); });

    /* Order each row so a node sits near the average position of its parents
       (barycentre heuristic). Without it, rows keep YAML order and edges cross
       needlessly — e.g. a switch whose cases land on the far side of a parallel
       fan-out. Two sweeps is plenty at this size. */
    const depths = Object.keys(rows).map(Number).sort((a, b) => a - b);
    const parentsOf = {};
    for (const id of ids) {
      for (const e of edgesOf(workflow[id] || {})) {
        if (workflow[e.target]) (parentsOf[e.target] ||= []).push(id);
      }
    }
    for (let sweep = 0; sweep < 2; sweep++) {
      const indexIn = {};
      depths.forEach(d => rows[d].forEach((id, i) => { indexIn[id] = i; }));
      for (const d of depths.slice(1)) {
        rows[d].sort((a, b) => {
          const bary = id => {
            const ps = (parentsOf[id] || []).filter(x => depth[x] < d);
            if (!ps.length) return indexIn[id];
            return ps.reduce((acc, x) => acc + indexIn[x], 0) / ps.length;
          };
          return bary(a) - bary(b) || String(a).localeCompare(String(b));
        });
      }
    }

    const pos = {};
    const widest = Math.max(...Object.values(rows).map(r => r.length), 1);
    const canvasW = PAD * 2 + widest * NODE_W + (widest - 1) * H_GAP;
    depths.forEach(d => {
      const row = rows[d];
      const rowW = row.length * NODE_W + (row.length - 1) * H_GAP;
      let x = (canvasW - rowW) / 2;
      row.forEach(id => {
        pos[id] = { x, y: PAD + d * (NODE_H + V_GAP), depth: d };
        x += NODE_W + H_GAP;
      });
    });

    return {
      pos,
      width:  canvasW,
      height: PAD * 2 + (maxDepth + 2) * (NODE_H + V_GAP),
      order:  ids.sort((a, b) => depth[a] - depth[b]),
    };
  }

  // -------------------------------------------------------------------------
  // SVG
  // -------------------------------------------------------------------------
  /* Shape and colour carry the step type, following flowchart convention: a decision
     is a diamond, everything else a box. Without this an if-condition would look
     exactly like an action, which is the whole point of having the type. */
  const NODE_STYLE = {
    'start':            { icon: '▶', stroke: '#1a7f37', fill: '#dafbe1', shape: 'rect'    },
    'end':              { icon: '■', stroke: '#cf222e', fill: '#ffebe9', shape: 'rect'    },
    'action':           { icon: '▸', stroke: '#d0d7de', fill: '#ffffff', shape: 'rect'    },
    'playbook-action':  { icon: '⧉', stroke: '#0969da', fill: '#ddf4ff', shape: 'rect'    },
    'parallel':         { icon: '⑂', stroke: '#8250df', fill: '#faf5ff', shape: 'rect'    },
    'if-condition':     { icon: '',  stroke: '#9a6700', fill: '#fff8c5', shape: 'diamond' },
    'while-condition':  { icon: '',  stroke: '#9a6700', fill: '#fff8c5', shape: 'diamond' },
    'switch-condition': { icon: '',  stroke: '#9a6700', fill: '#fff8c5', shape: 'diamond' },
  };

  function truncate(label, max) {
    return label.length > max ? label.slice(0, max - 1) + '…' : label;
  }

  function nodeSvg(id, step, p, isStart) {
    const type  = step.type || 'action';
    const st    = NODE_STYLE[type] || NODE_STYLE.action;
    const label = step.name || id;
    const cx    = p.x + NODE_W / 2, cy = p.y + NODE_H / 2;

    let body;
    if (st.shape === 'diamond') {
      // A diamond has little room at top and bottom, so the label sits on the centre
      // line and the step id moves into the tooltip.
      const pts = `${cx},${p.y} ${p.x + NODE_W},${cy} ${cx},${p.y + NODE_H} ${p.x},${cy}`;
      body = `
        <polygon points="${pts}" fill="${st.fill}" stroke="${st.stroke}" stroke-width="1.5"/>
        <text x="${cx}" y="${cy + 4}" font-size="11.5" font-weight="600"
              text-anchor="middle" fill="#24292f">${esc(truncate(label, 30))}</text>`;
    } else {
      body = `
        <rect x="${p.x}" y="${p.y}" width="${NODE_W}" height="${NODE_H}" rx="8"
              fill="${st.fill}" stroke="${st.stroke}"
              stroke-width="${isStart ? 2 : 1}"/>
        ${isStart ? `<rect x="${p.x}" y="${p.y}" width="4" height="${NODE_H}"
              rx="2" fill="${st.stroke}"/>` : ''}
        <text x="${p.x + 14}" y="${p.y + 23}" font-size="12.5" font-weight="600"
              fill="#24292f">${st.icon} ${esc(truncate(label, 34))}</text>
        <text x="${p.x + 14}" y="${p.y + 41}" font-size="10.5"
              fill="#57606a" font-family="ui-monospace,monospace">${esc(id)}</text>`;
    }

    return `
      <g class="cacao-node cacao-node-${esc(type)}" data-step="${esc(id)}" style="cursor:pointer">
        ${body}
        <title>${esc(label)}\n${esc(id)} (${esc(type)})</title>
      </g>`;
  }

  /* An edge is "direct" only when it joins adjacent rows. Anything else — an
     on_failure that skips past the next step, or a backward jump — cannot be drawn
     straight down: its path would run through the node boxes in between, and since
     nodes are painted after edges, the opaque box hides it. Those edges get routed
     through a vertical lane to the right of the diagram instead. */
  function isDirect(a, b) {
    return b.depth - a.depth === 1;
  }

  /* Give each routed edge a lane that no vertically-overlapping edge already uses,
     so two skip edges never share a line. */
  function assignLanes(routed, pos) {
    const lanes = [];
    for (const e of routed) {
      const a = pos[e.from], b = pos[e.to];
      const y1 = Math.min(a.y, b.y);
      const y2 = Math.max(a.y + NODE_H, b.y + NODE_H);
      let idx = 0;
      for (;; idx++) {
        if (!lanes[idx]) lanes[idx] = [];
        if (lanes[idx].every(([s, t]) => y2 < s || y1 > t)) {
          lanes[idx].push([y1, y2]);
          break;
        }
      }
      e.lane = idx;
    }
    return lanes.length;
  }

  /* Anchor a node's edges across its width instead of stacking them all on the
     centre: the i-th of n edges leaves (or arrives) at width*(i+1)/(n+1). A parallel
     fan-out of three therefore leaves from three distinct points, and two edges
     converging on the same step no longer arrive on top of each other. */
  function anchorX(p, i, n) {
    return p.x + (NODE_W * (i + 1)) / (n + 1);
  }

  function directEdgeSvg(a, b, e) {
    const x1 = anchorX(a, e.outIdx, e.outCnt), y1 = a.y + NODE_H;
    const x2 = anchorX(b, e.inIdx,  e.inCnt),  y2 = b.y;
    const mid = (y1 + y2) / 2;
    // Stagger the label along the curve so parallel siblings do not print on top
    // of one another.
    const t = e.outCnt > 1 ? 0.34 + 0.32 * (e.outIdx / Math.max(1, e.outCnt - 1)) : 0.5;
    return {
      d: `M ${x1} ${y1} C ${x1} ${mid}, ${x2} ${mid}, ${x2} ${y2}`,
      labelX: x1 + (x2 - x1) * t + 8,
      labelY: y1 + (y2 - y1) * t + 4,
      anchor: 'middle',
    };
  }

  /* Orthogonal detour: out of the source's right edge, down (or up) the lane, back
     into the target's right edge. Rounded corners keep it readable at this size. */
  function laneEdgeSvg(a, b, e, laneX) {
    const r  = 8;
    const x0 = a.x + NODE_W, y0 = a.y + NODE_H / 2;
    const x1 = b.x + NODE_W, y1 = b.y + NODE_H / 2;
    const dir = y1 > y0 ? 1 : -1;
    return {
      d: `M ${x0} ${y0} L ${laneX - r} ${y0} Q ${laneX} ${y0} ${laneX} ${y0 + r * dir}`
       + ` L ${laneX} ${y1 - r * dir} Q ${laneX} ${y1} ${laneX - r} ${y1} L ${x1} ${y1}`,
      labelX: laneX + 5,
      labelY: (y0 + y1) / 2 + 3,
      anchor: 'start',
    };
  }

  function edgeSvg(geom, e) {
    return `
      <path d="${geom.d}" fill="none" stroke="${e.color}" stroke-width="1.6"
            ${e.dash ? `stroke-dasharray="${e.dash}"` : ''}
            marker-end="url(#cacao-arrow-${e.color.slice(1)})"/>
      <text x="${geom.labelX}" y="${geom.labelY}" font-size="10" fill="${e.color}"
            text-anchor="${geom.anchor}">${esc(e.label)}</text>`;
  }

  function render(cacao) {
    const workflow = (cacao && cacao.workflow) || {};
    const start    = cacao && cacao.workflow_start;
    const ids      = Object.keys(workflow);
    if (!ids.length) {
      return { svg: '<div class="text-muted small p-3">This playbook has no workflow steps.</div>',
               steps: {}, order: [] };
    }

    const { pos, width, height, order } = layout(workflow, start);

    // Split edges by how they have to be drawn, then reserve lanes for the routed ones.
    const direct = [], routed = [];
    for (const id of ids) {
      for (const e of edgesOf(workflow[id] || {})) {
        if (!pos[id] || !pos[e.target]) continue;
        const edge = { ...e, from: id, to: e.target };
        (isDirect(pos[id], pos[e.target]) ? direct : routed).push(edge);
      }
    }
    const laneCount = assignLanes(routed, pos);

    /* Assign each direct edge its slot on the source's bottom edge and the target's
       top edge. Sorting by the other end's x keeps a fan monotonic, so the edges
       within one fan never cross each other. */
    const outs = {}, ins = {};
    for (const e of direct) {
      (outs[e.from] ||= []).push(e);
      (ins[e.to]    ||= []).push(e);
    }
    for (const [id, list] of Object.entries(outs)) {
      list.sort((p, q) => pos[p.to].x - pos[q.to].x);
      list.forEach((e, i) => { e.outIdx = i; e.outCnt = list.length; });
    }
    for (const [id, list] of Object.entries(ins)) {
      list.sort((p, q) => pos[p.from].x - pos[q.from].x);
      list.forEach((e, i) => { e.inIdx = i; e.inCnt = list.length; });
    }
    for (const e of direct) {
      e.outIdx ??= 0; e.outCnt ??= 1; e.inIdx ??= 0; e.inCnt ??= 1;
    }

    const LANE_GAP = 26;
    const laneX = i => width + 18 + i * LANE_GAP;
    // The lanes and their labels live outside the node area, so the canvas grows.
    const totalW = laneCount
      ? laneX(laneCount - 1) + 78
      : width;

    let edges = '';
    for (const e of direct) edges += edgeSvg(directEdgeSvg(pos[e.from], pos[e.to], e), e);
    for (const e of routed) {
      edges += edgeSvg(laneEdgeSvg(pos[e.from], pos[e.to], e, laneX(e.lane)), e);
    }

    let nodes = '';
    for (const id of ids) {
      nodes += nodeSvg(id, workflow[id] || {}, pos[id], id === start);
    }

    const markers = [...new Set(EDGE_KINDS.map(k => k.color).concat('#57606a'))]
      .map(c => `
        <marker id="cacao-arrow-${c.slice(1)}" viewBox="0 0 10 10" refX="9" refY="5"
                markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M 0 0 L 10 5 L 0 10 z" fill="${c}"/>
        </marker>`).join('');

    const svg = `
      <svg viewBox="0 0 ${totalW} ${height}" width="100%" height="100%"
           style="display:block" xmlns="http://www.w3.org/2000/svg"
           role="img" aria-label="CACAO workflow graph">
        <defs>${markers}</defs>
        ${edges}
        ${nodes}
      </svg>`;

    return { svg, steps: workflow, order };
  }

  // -------------------------------------------------------------------------
  // Step detail
  // -------------------------------------------------------------------------
  function commandHtml(cmd, i) {
    const type = cmd.type || 'command';
    const body = cmd.command || '';
    const extras = [];
    if (cmd.headers) {
      extras.push(`<div class="mt-2"><div class="cacao-sub">headers</div>
        <pre class="cacao-pre">${escWithParams(JSON.stringify(cmd.headers, null, 2))}</pre></div>`);
    }
    const payload = cmd.content ?? cmd.body;   // CACAO 2.0 calls it "content"
    if (payload) {
      extras.push(`<div class="mt-2"><div class="cacao-sub">content</div>
        <pre class="cacao-pre">${escWithParams(String(payload).trim())}</pre></div>`);
    }
    const badge = type === 'bash'
      ? '<span class="badge" style="background:#24292f;color:#fff;font-size:.62rem">bash</span>'
      : `<span class="badge" style="background:#0969da;color:#fff;font-size:.62rem">${esc(type)}</span>`;
    return `
      <div class="cacao-cmd">
        <div class="d-flex align-items-center gap-2 mb-1">
          ${badge}<span class="text-muted" style="font-size:.68rem">command ${i + 1}</span>
        </div>
        <pre class="cacao-pre">${escWithParams(String(body).trim())}</pre>
        ${extras.join('')}
      </div>`;
  }

  function stepDetailHtml(cacao, id) {
    const workflow = (cacao && cacao.workflow) || {};
    const step = workflow[id];
    if (!step) return '<div class="text-muted small">Step not found.</div>';

    const cmds = (step.commands || []).map(commandHtml).join('')
      || '<div class="text-muted small">No commands — this step only routes control.</div>';

    // Who executes the commands: http-api commands are sent to the agent's address
    const agent = step.agent && ((cacao.agent_definitions || {})[step.agent]);
    const agentHtml = agent ? `
      <div class="cacao-sub mt-3">Agent</div>
      <div class="small">${esc(agent.name || agent.type || step.agent)}</div>
      ${Object.entries(agent.address || {}).map(([kind, vals]) =>
        `<pre class="cacao-pre mt-1">${esc(kind)}: ${escWithParams([].concat(vals).join(', '))}</pre>`).join('')}` : '';

    return `
      <div class="mb-2">
        <div class="fw-semibold">${esc(step.name || id)}</div>
        <code class="text-muted" style="font-size:.7rem">${esc(id)}</code>
        <span class="badge bg-secondary ms-1" style="font-size:.62rem">${esc(step.type || 'action')}</span>
      </div>
      ${agentHtml}
      <div class="cacao-sub mt-3">Commands${(step.commands || []).length > 1
        ? ' <span class="text-muted text-lowercase fw-normal">· all run, in this order</span>' : ''}</div>
      ${cmds}`;
  }

  /* Literal "{{name}}" for display. Built here rather than in a Jinja template,
     where a bare {{ … }} would be consumed as a server-side expression. */
  function paramLabel(name) {
    return '{' + '{' + String(name ?? '') + '}' + '}';
  }

  // -------------------------------------------------------------------------
  // Graph modal (markup in templates/_cacao_graph_modal.html)
  // -------------------------------------------------------------------------
  let modalPlaybook = null;
  let modalOpts = {};
  let draft = null;          // working copy of the CACAO while in Edit mode
  let dirty = false;
  let selectedStep = null;

  /* "cacao-2.0" → "CACAO 2.0" */
  function specVersion(pb) {
    const v = pb.cacao && pb.cacao.spec_version;
    return v ? String(v).replace(/^cacao-/i, 'CACAO ') : '—';
  }

  /* `pb` is either a library template ({id, name, version, parameters, cacao}) or a
     recommended playbook already filled from an alert ({id, name, cacao,
     parameters_filled, parameters_missing}). */
  function openModal(pb, opts = {}) {
    if (!pb) return;
    modalPlaybook = pb;
    modalOpts = opts || {};
    draft = null; dirty = false;
    document.getElementById('graph-title').textContent = pb.name || pb.id;
    document.getElementById('graph-id').textContent    = pb.id;
    setEditButtons();
    note('');

    const order = drawGraph();
    // Open on the entry step so the panel is never empty.
    selectModalStep((pb.cacao || {}).workflow_start || order[0]);
    const el = document.getElementById('graphModal');
    if (!el.dataset.editGuard) {          // once: do not lose unsaved edits on close
      el.dataset.editGuard = '1';
      el.addEventListener('hide.bs.modal', e => {
        if (draft && dirty && !confirm('Discard the unsaved changes to this playbook?')) {
          e.preventDefault();
          return;
        }
        draft = null; dirty = false;
      });
    }
    bootstrap.Modal.getOrCreateInstance(el).show();
  }

  function shown() { return draft || (modalPlaybook && modalPlaybook.cacao) || {}; }

  function drawGraph() {
    const { svg, order } = render(shown());
    const canvas = document.getElementById('graph-canvas');
    canvas.innerHTML = svg;
    canvas.querySelectorAll('.cacao-node').forEach(node => {
      node.addEventListener('click', () => selectModalStep(node.dataset.step));
    });
    canvas.querySelectorAll('.cacao-node').forEach(n => {
      n.classList.toggle('cacao-node-active', n.dataset.step === selectedStep);
    });
    renderModalMeta({ ...modalPlaybook, cacao: shown() });
    return order;
  }

  function selectModalStep(stepId) {
    if (!modalPlaybook || !stepId) return;
    selectedStep = stepId;
    document.getElementById('graph-detail').innerHTML = draft
      ? stepEditHtml(draft, stepId) : stepDetailHtml(modalPlaybook.cacao || {}, stepId);
    document.querySelectorAll('#graph-canvas .cacao-node').forEach(n => {
      n.classList.toggle('cacao-node-active', n.dataset.step === stepId);
    });
  }

  // -------------------------------------------------------------------------
  // Edit mode: change a node's name, description and commands, add or delete
  // commands and steps. The page's onSave(cacao) decides what saving means.
  // -------------------------------------------------------------------------
  const show = (id, on) => document.getElementById(id).classList.toggle('d-none', !on);

  function setEditButtons() {
    const can = !!modalOpts.onSave;
    show('graph-edit-btn', can && !draft);
    show('graph-discard-btn', !!draft);
    show('graph-save-btn', !!draft);
  }

  function note(text, kind) {
    const el = document.getElementById('graph-edit-note');
    el.textContent = text;
    el.className = `small ${kind === 'error' ? 'text-danger' : 'text-muted'}${text ? '' : ' d-none'}`;
  }

  function startEdit() {
    draft = JSON.parse(JSON.stringify(modalPlaybook.cacao || {}));
    dirty = false;
    setEditButtons();
    note(modalOpts.editNote || 'Editing: click a node to change it');
    drawGraph();
    selectModalStep(selectedStep);
  }

  function discardEdit() {
    if (dirty && !confirm('Discard the unsaved changes to this playbook?')) return;
    draft = null; dirty = false;
    setEditButtons();
    note('');
    drawGraph();
    selectModalStep(selectedStep);
  }

  async function saveEdit() {
    const btn = document.getElementById('graph-save-btn');
    btn.disabled = true;
    note('Saving…');
    try {
      const msg = await modalOpts.onSave(draft);
      modalPlaybook.cacao = draft;
      draft = null; dirty = false;
      setEditButtons();
      note(msg || 'Saved');
      drawGraph();
      selectModalStep(selectedStep);
    } catch (e) {
      note(`Not saved: ${e.message || e}`, 'error');
    } finally {
      btn.disabled = false;
    }
  }

  function changed() {
    dirty = true;
    note('Unsaved changes');
  }

  const b64decode = s => { try { return decodeURIComponent(escape(atob(s))); } catch (_) { return ''; } };

  function cmdEditHtml(cmd, i, count) {
    const type = cmd.type || 'bash';
    const http = type === 'http-api';
    const text = cmd.command ?? (cmd.command_b64 ? b64decode(cmd.command_b64) : '');
    const content = cmd.content ?? (cmd.content_b64 ? b64decode(cmd.content_b64) : '');
    const rows = Math.min(14, Math.max(3, String(text).split('\n').length + 1));
    return `
      <div class="cacao-cmd">
        <div class="d-flex align-items-center gap-2 mb-1">
          <span class="badge" style="background:${type === 'bash' ? '#24292f' : '#0969da'};color:#fff;font-size:.62rem">${esc(type)}</span>
          <span class="text-muted" style="font-size:.68rem">command ${i + 1}</span>
          ${count > 1 ? `<button type="button" class="btn btn-link btn-sm text-danger p-0 ms-auto text-decoration-none"
              style="font-size:.72rem" onclick="CacaoGraph._delCmd(${i})"><i class="bi bi-trash me-1"></i>Remove</button>` : ''}
        </div>
        ${http
          ? `<input class="form-control form-control-sm font-monospace" data-c="${i}:command"
                    value="${esc(text)}" oninput="CacaoGraph._field(this)" placeholder="POST /path HTTP/1.1">
             <div class="cacao-sub mt-2">content</div>
             <textarea class="form-control form-control-sm font-monospace" rows="6" data-c="${i}:content"
                       oninput="CacaoGraph._field(this)">${esc(content)}</textarea>`
          : `<textarea class="form-control form-control-sm font-monospace" rows="${rows}" data-c="${i}:command"
                       oninput="CacaoGraph._field(this)" placeholder="One command per line">${esc(text)}</textarea>`}
      </div>`;
  }

  function stepEditHtml(cacao, id) {
    const step = (cacao.workflow || {})[id];
    if (!step) return '<div class="text-muted small">Step not found.</div>';
    const type = step.type || 'action';
    if (type === 'start' || type === 'end') {
      return stepDetailHtml(cacao, id)
        + `<div class="text-muted small mt-3">The ${type} step has nothing to edit: select another node.</div>`;
    }
    const cmds = step.commands || [];
    return `
      <div class="mb-2 d-flex align-items-center gap-2">
        <code class="text-muted" style="font-size:.7rem">${esc(id)}</code>
        <span class="badge bg-secondary" style="font-size:.62rem">${esc(type)}</span>
      </div>
      <label class="cacao-sub mb-1">Name</label>
      <input class="form-control form-control-sm mb-2" data-f="name" value="${esc(step.name || '')}"
             oninput="CacaoGraph._field(this)">
      <label class="cacao-sub mb-1">Description</label>
      <textarea class="form-control form-control-sm mb-2" rows="3" data-f="description"
                oninput="CacaoGraph._field(this)">${esc(step.description || '')}</textarea>
      ${type === 'action' ? `
        <div class="cacao-sub mt-3">Commands${cmds.length > 1
          ? ' <span class="text-muted text-lowercase fw-normal">· all run, in this order</span>' : ''}</div>
        ${cmds.map((c, i) => cmdEditHtml(c, i, cmds.length)).join('')}
        <div class="d-flex flex-wrap gap-2 mt-2">
          <button type="button" class="btn btn-sm btn-outline-primary" onclick="CacaoGraph._addCmd()">
            <i class="bi bi-plus-lg me-1"></i>Command</button>
          <button type="button" class="btn btn-sm btn-outline-primary" onclick="CacaoGraph._addStep()">
            <i class="bi bi-node-plus me-1"></i>Step after this one</button>
          <button type="button" class="btn btn-sm btn-outline-danger ms-auto" onclick="CacaoGraph._delStep()">
            <i class="bi bi-trash me-1"></i>Delete step</button>
        </div>` : `
        <div class="text-muted small mt-3">Only the name and description of a ${esc(type)} step can be edited here.</div>`}`;
  }

  function editedStep() { return draft && (draft.workflow || {})[selectedStep]; }

  function _field(el) {
    const step = editedStep();
    if (!step) return;
    if (el.dataset.f) {
      step[el.dataset.f] = el.value;
      if (el.dataset.f === 'name') drawGraph();      // label in the graph; keeps the form's focus
    } else if (el.dataset.c) {
      const [i, key] = el.dataset.c.split(':');
      const cmd = step.commands[Number(i)];
      cmd[key] = el.value;
      delete cmd[`${key}_b64`];
    }
    changed();
  }

  function _addCmd() {
    const step = editedStep();
    if (!step) return;
    (step.commands ||= []).push({ type: 'bash', command: '' });
    changed();
    selectModalStep(selectedStep);
  }

  function _delCmd(i) {
    const step = editedStep();
    if (!step || (step.commands || []).length < 2) return;
    step.commands.splice(i, 1);
    changed();
    selectModalStep(selectedStep);
  }

  const newId = type => `${type}--${crypto.randomUUID ? crypto.randomUUID()
    : 'xxxxxxxx-xxxx-4xxx-8xxx-xxxxxxxxxxxx'.replace(/x/g, () => (Math.random() * 16 | 0).toString(16))}`;

  /* A new action between this step and the one it continues to, acting on the same
     machine(s) with the same agent. */
  function _addStep() {
    const step = editedStep();
    if (!step) return;
    const next = step.on_completion || step.on_success;
    const id = newId('action');
    const added = { type: 'action', name: 'New step', description: '',
                    commands: [{ type: 'bash', command: '' }] };
    if (step.agent) added.agent = step.agent;
    if (step.targets) added.targets = [...step.targets];
    if (next) added.on_completion = next;
    for (const k of ['on_completion', 'on_success']) if (step[k] === next) step[k] = id;
    if (!next) step.on_completion = id;
    // Insert right after the current step, so the YAML/JSON reads in workflow order
    const wf = {};
    for (const [k, v] of Object.entries(draft.workflow)) {
      wf[k] = v;
      if (k === selectedStep) wf[id] = added;
    }
    draft.workflow = wf;
    changed();
    selectedStep = id;
    drawGraph();
    selectModalStep(id);
  }

  /* Remove the step; whatever pointed to it now points to the step it continued to. */
  function _delStep() {
    const step = editedStep();
    if (!step) return;
    const next = step.on_completion || step.on_success || step.on_failure;
    if (!next) { note('This step has no next step to reconnect to', 'error'); return; }
    if (!confirm(`Delete the step "${step.name || selectedStep}"?`)) return;
    const gone = selectedStep;
    delete draft.workflow[gone];
    for (const s of Object.values(draft.workflow)) {
      for (const k of ['on_completion', 'on_success', 'on_failure', 'on_true', 'on_false']) {
        if (s[k] === gone) s[k] = next;
      }
      if (Array.isArray(s.next_steps)) s.next_steps = s.next_steps.map(t => t === gone ? next : t);
      if (s.cases) for (const c of Object.keys(s.cases)) if (s.cases[c] === gone) s.cases[c] = next;
    }
    if (draft.workflow_start === gone) draft.workflow_start = next;
    changed();
    selectedStep = next;
    drawGraph();
    selectModalStep(next);
  }

  function chip(text, title, style) {
    return `<span class="badge me-1 mb-1 font-monospace" style="font-size:.62rem;${style}"
                  title="${esc(title || '')}">${text}</span>`;
  }

  function renderModalMeta(pb) {
    const c = pb.cacao || {};
    const cell = (label, value) => `
      <div class="col-6 col-md-3">
        <div class="text-muted" style="font-size:.68rem;text-transform:uppercase;letter-spacing:.4px">${label}</div>
        <div>${value}</div>
      </div>`;
    const types = (c.playbook_types || []).map(t =>
      `<span class="badge bg-secondary me-1" style="font-size:.62rem">${esc(t)}</span>`).join('') || '—';

    let paramsTitle, paramsHtml;
    if (pb.parameters_filled) {
      // Recommended playbook: show the values taken from the alert, and what is still open
      const filled  = pb.parameters_filled || {};
      const missing = pb.parameters_missing || [];
      const rejected = pb.parameters_rejected || [];
      const leftover = [...new Set((JSON.stringify(c).match(/\{\{([^}]+)\}\}/g) || [])
        .map(m => m.slice(2, -2)))].filter(n => !(n in filled) && !missing.includes(n) && !rejected.includes(n));
      paramsTitle = 'Parameters filled from this alert';
      const settings = pb.parameters_settings || [];
      paramsHtml =
          Object.entries(filled).map(([k, v]) => settings.includes(k)
            ? chip(`${esc(k)} = ${esc(v)}`, 'Deployment setting from .env (the same for every alert)',
                   'background:#f6f8fa;color:#57606a;border:1px solid #d0d7de')
            : chip(`${esc(k)} = ${esc(v)}`, 'From the alert IoCs',
                   'background:#dafbe1;color:#116329;border:1px solid #4ac26b')).join('')
        + missing.map(n => chip(`${esc(paramLabel(n))} *`, 'Required, not found in the alert',
            'background:#ffebe9;color:#cf222e;border:1px solid #ff8182')).join('')
        + rejected.map(n => chip(`${esc(paramLabel(n))} rejected`, 'The alert value was unsafe for a shell command and was not used',
            'background:#ffebe9;color:#cf222e;border:1px dashed #ff8182')).join('')
        + leftover.map(n => chip(esc(paramLabel(n)), 'Optional, not found in the alert',
            'background:#f6f8fa;color:#57606a;border:1px solid #d0d7de')).join('')
        || '—';
    } else {
      paramsTitle = 'Parameters substituted into the commands (* required)';
      paramsHtml = (pb.parameters || []).map(p => chip(
        `${esc(paramLabel(p.name))}${p.required ? ' *' : ''}`, p.description,
        'background:#ddf4ff;color:#0969da;border:1px solid #54aeff')).join('') || '—';
    }

    document.getElementById('graph-meta').innerHTML =
        cell('Spec',        esc(specVersion(pb)))
      + (pb.version ? cell('Template', 'v' + esc(pb.version)) : '')
      + cell('Steps',       Object.keys(c.workflow || {}).length)
      + cell('Entry step',  `<code style="font-size:.7rem">${esc(c.workflow_start || '—')}</code>`)
      + cell('Playbook types', types)
      + `<div class="col-12 col-md-9">
           <div class="text-muted" style="font-size:.68rem;text-transform:uppercase;letter-spacing:.4px">${paramsTitle}</div>
           <div class="mt-1">${paramsHtml}</div>
         </div>`;
  }

  return { render, stepDetailHtml, escWithParams, paramLabel, openModal, specVersion,
           startEdit, discardEdit, saveEdit, _field, _addCmd, _delCmd, _addStep, _delStep };
})();
