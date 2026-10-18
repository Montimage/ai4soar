/**
 * AI4SOAR web UI — shared utilities loaded on every page.
 */

const API_BASE = '/api';

/**
 * Thin wrapper around fetch that targets the REST API.
 * Throws on non-2xx responses with the server's error message.
 */
async function apiFetch(path, options = {}) {
  const resp = await fetch(API_BASE + path, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({ error: resp.statusText }));
    throw new Error(body.error || `HTTP ${resp.status}`);
  }
  return resp.json();
}

/**
 * Extract display-friendly fields from any alert structure:
 *   - AI4SOAR normalized MongoDB docs  (top-level rule / data / timestamp)
 *   - Wazuh / OpenSearch docs          (_source.rule / _source.data)
 *   - Raw Windows event logs           (EventID, Category, SourceAddress …)
 *   - ECS / generic JSON
 *
 * Returns: { timestamp, severity, severityLabel, description,
 *            tactic, technique, host, event_id, channel, process,
 *            src_ip, dst_ip }
 */
function extractAlertFields(alert) {
  // Normalized envelope lives at top level; raw original event is in _source.
  const rule  = alert.rule  || (alert._source || {}).rule  || {};
  const data  = alert.data  || (alert._source || {}).data  || {};
  const mitre = rule.mitre  || {};
  const raw   = alert._source || alert;   // fallback to raw fields

  // ── Severity ──────────────────────────────────────────────────────────────
  const rawLevel      = rule.level ?? raw.Severity ?? raw.severity ?? raw.level ?? null;
  const severityLabel = classifySeverity(rawLevel);

  // ── Technique ─────────────────────────────────────────────────────────────
  let techniques = mitre.technique || raw.technique || [];
  if (!Array.isArray(techniques)) techniques = techniques ? [techniques] : [];
  if (!techniques.length && Array.isArray(raw.tags)) {
    techniques = raw.tags
      .filter(t => String(t).startsWith('attack.t'))
      .map(t => t.replace('attack.', '').toUpperCase());
  }

  // ── Tactic ────────────────────────────────────────────────────────────────
  const tacticRaw =
    mitre.tactic ||
    (alert._ai4soar || {}).tactic ||
    (techniques.length ? techniques[0] : '') ||
    '—';
  const tactic = Array.isArray(tacticRaw) ? (tacticRaw[0] || '—') : tacticRaw;

  // ── Description ───────────────────────────────────────────────────────────
  const eventId  = raw.EventID  || '';
  const category = raw.Category || '';
  let description = rule.description || '';
  // If rule.description is just the bare EventID number, build a nicer label
  if (!description || description === String(eventId)) {
    if (category) {
      description = eventId ? `[${eventId}] ${category}` : category;
    } else {
      // Fall back to the Message field (first 120 chars)
      const msg = raw.Message || raw.message || raw.description || '';
      description = msg
        ? (eventId ? `[${eventId}] ${msg.substring(0, 120)}` : msg.substring(0, 120))
        : (String(eventId) || '—');
    }
  }

  // ── Timestamp ─────────────────────────────────────────────────────────────
  const timestamp =
    alert.timestamp || raw['@timestamp'] || raw.EventTime || raw.EventReceivedTime || '—';

  // ── Host ──────────────────────────────────────────────────────────────────
  const host =
    data.hostname ||
    raw.Hostname  ||
    raw.host      ||
    (raw.agent || {}).hostname ||
    (raw.agent || {}).name     ||      // Wazuh: the agent is the host the alert is about
    '—';

  // ── Event ID / Channel / Process ──────────────────────────────────────────
  const event_id = raw.EventID   ? String(raw.EventID) : '—';
  const channel  = raw.Channel   || data.channel       || '—';
  const process  =
    (raw.Application || '').split('\\').pop() ||   // Windows: \device\...\lsass.exe → lsass.exe
    raw.ProcessName  ||
    raw.Image        ||
    '—';

  // ── Network ───────────────────────────────────────────────────────────────
  const src_ip = data.srcip || raw.SourceAddress || raw.srcip || (raw.source || {}).ip || '—';
  const dst_ip = data.dstip || raw.DestAddress   || raw.dstip || (raw.destination || {}).ip || '—';

  // ── Technique IDs (T-codes) ───────────────────────────────────────────────
  let technique_ids = mitre.id || raw['mitre.id'] || [];
  if (!Array.isArray(technique_ids)) technique_ids = technique_ids ? [technique_ids] : [];

  return {
    timestamp,
    severity     : rawLevel !== null && rawLevel !== undefined ? rawLevel : '—',
    severityLabel,
    description,
    tactic,
    technique    : techniques.length ? techniques.join(', ') : '—',
    technique_ids,
    host,
    event_id,
    channel,
    process,
    src_ip,
    dst_ip,
  };
}

function classifySeverity(level) {
  if (level === null || level === undefined) return 'info';
  const n = parseInt(level, 10);
  if (!isNaN(n)) {
    if (n >= 13) return 'critical';
    if (n >= 10) return 'high';
    if (n >= 7)  return 'medium';
    if (n >= 4)  return 'low';
    return 'info';
  }
  const s = String(level).toLowerCase();
  if (['critical', 'high', 'medium', 'low', 'info', 'informational'].includes(s)) return s;
  return 'info';
}

/** Returns a Bootstrap badge HTML string for a severity label. */
function severityBadge(label) {
  const cls = {
    critical     : 'badge-sev-critical',
    high         : 'badge-sev-high',
    medium       : 'badge-sev-medium',
    low          : 'badge-sev-low',
    info         : 'badge-sev-info',
    informational: 'badge-sev-informational',
  }[label] || 'badge-sev-info';
  return `<span class="badge ${cls}">${label}</span>`;
}

/** Returns an HTML badge for a confidence tier + numeric score. */
function tierBadge(tier, score) {
  const pct = score != null ? ` (${(score * 100).toFixed(0)}%)` : '';
  return `<span class="tier-badge tier-${tier}">${tier}${pct}</span>`;
}

/**
 * Show a transient toast notification.
 * type: 'success' | 'warning' | 'error'
 */
function showToast(message, type = 'success') {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    document.body.appendChild(container);
  }
  const colorMap = { success: 'bg-success', warning: 'bg-warning text-dark', error: 'bg-danger' };
  const color = colorMap[type] || 'bg-secondary';
  const id = `toast-${Date.now()}`;
  container.insertAdjacentHTML('beforeend', `
    <div id="${id}" class="toast align-items-center text-white ${color} border-0 mb-2 show" role="alert">
      <div class="d-flex">
        <div class="toast-body small">${message}</div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto"
                onclick="document.getElementById('${id}').remove()"></button>
      </div>
    </div>`);
  setTimeout(() => document.getElementById(id)?.remove(), 5000);
}

/* ── Incident tickets (POST /api/v1/incidents, e.g. from a playbook run in Shuffle) ──
   Every page polls for new tickets and pops each one up at the top right. Only tickets
   received after the first poll of this browser session are shown, each once. */
const INCIDENT_SINCE_KEY = 'ai4soar_incidents_since';

function incidentToast(inc) {
  let box = document.getElementById('incident-toasts');
  if (!box) {
    box = document.createElement('div');
    box.id = 'incident-toasts';
    document.body.appendChild(box);
  }
  const t = inc.ticket || {};
  const esc = s => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const sev = String(t.severity || '').toLowerCase();
  const sevCls = { critical: 'bg-danger', high: 'bg-danger', medium: 'bg-warning text-dark', low: 'bg-secondary' }[sev] || 'bg-secondary';
  const skip = new Set(['title', 'severity', 'technique', 'priority']);
  const fields = Object.entries(t).filter(([k, v]) => !skip.has(k) && v !== '' && v != null && typeof v !== 'object').slice(0, 6);
  const at = new Date(inc.received_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const el = document.createElement('div');
  el.className = 'incident-toast card shadow';
  el.innerHTML = `
    <div class="card-header py-1 px-2 d-flex align-items-center gap-2">
      <i class="bi bi-ticket-detailed-fill text-danger"></i>
      <span class="fw-semibold">New incident ticket</span>
      <code class="text-muted ms-auto" style="font-size:.65rem">${esc(inc.id)}</code>
      <button type="button" class="btn-close ms-1" style="font-size:.6rem" aria-label="Close"></button>
    </div>
    <div class="card-body py-2 px-2">
      <div class="fw-semibold mb-1">${esc(t.title || 'Incident')}</div>
      <div class="mb-1">
        ${sev ? `<span class="badge ${sevCls} me-1">${esc(sev)}</span>` : ''}
        ${t.technique ? `<span class="badge font-monospace text-dark me-1" style="background:#e2e8f0;border:1px solid #94a3b8">${esc(t.technique)}</span>` : ''}
        ${t.priority ? `<span class="badge bg-dark me-1">${esc(t.priority)}</span>` : ''}
      </div>
      ${fields.map(([k, v]) => `<div class="text-muted"><span>${esc(k)}</span>
        <span class="font-monospace text-dark">${esc(v)}</span></div>`).join('')}
      <div class="text-muted mt-1" style="font-size:.68rem">received ${esc(at)} from ${esc(inc.from || '?')}</div>
    </div>`;
  el.querySelector('.btn-close').onclick = () => el.remove();
  box.prepend(el);
  setTimeout(() => el.remove(), 8000);
}

async function pollIncidents() {
  let since = null;
  try { since = sessionStorage.getItem(INCIDENT_SINCE_KEY); } catch (_) {}
  try {
    const r = await fetch(API_BASE + '/v1/incidents' + (since ? `?since=${encodeURIComponent(since)}` : '?limit=1'));
    if (!r.ok) return;
    const data = await r.json();
    if (since) (data.incidents || []).slice().reverse().forEach(incidentToast);
    const newest = (data.incidents || [])[0];
    const next = newest && since ? newest.received_at : (since || data.now);
    try { sessionStorage.setItem(INCIDENT_SINCE_KEY, next); } catch (_) {}
  } catch (_) { /* server unreachable: try again next time */ }
}
pollIncidents();
setInterval(pollIncidents, 4000);

/* Technique tags (.tech-tag, every page): the technique's name in a tooltip as soon as
   the mouse is over the tag (the browser's own title tooltip waits about a second) */
document.addEventListener('mouseover', e => {
  const el = e.target.closest && e.target.closest('.tech-tag');
  if (!el || !window.bootstrap || bootstrap.Tooltip.getInstance(el)) return;
  const tip = bootstrap.Tooltip.getOrCreateInstance(el, { placement: 'top' });
  tip.show();
});

/* "T1110 — Brute Force" for a technique tag's tooltip (static ATT&CK names) */
function techTitle(id, prefix = '') {
  const name = (typeof MITRE_NAMES !== 'undefined' && MITRE_NAMES[id]) || '';
  return `${prefix}${id}${name ? ` — ${name}` : ''}`;
}
