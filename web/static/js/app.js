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
