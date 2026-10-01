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
    if (cmd.body) {
      extras.push(`<div class="mt-2"><div class="cacao-sub">body</div>
        <pre class="cacao-pre">${escWithParams(String(cmd.body).trim())}</pre></div>`);
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

    return `
      <div class="mb-2">
        <div class="fw-semibold">${esc(step.name || id)}</div>
        <code class="text-muted" style="font-size:.7rem">${esc(id)}</code>
        <span class="badge bg-secondary ms-1" style="font-size:.62rem">${esc(step.type || 'action')}</span>
      </div>
      <div class="cacao-sub mt-3">Commands</div>
      ${cmds}`;
  }

  /* Literal "{{name}}" for display. Built here rather than in a Jinja template,
     where a bare {{ … }} would be consumed as a server-side expression. */
  function paramLabel(name) {
    return '{' + '{' + String(name ?? '') + '}' + '}';
  }

  return { render, stepDetailHtml, escWithParams, paramLabel };
})();
