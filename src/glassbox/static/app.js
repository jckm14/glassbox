const PAGE_SIZE = 50;
const POLL_MS = 5000;
const state = {
  events: [], total: 0, nextBeforeId: null, stats: null, verification: null,
  config: { show_diffs: false }, selected: null, headHash: undefined, lastVerifiedAt: 0,
};
const $ = (selector) => document.querySelector(selector);

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
}

function when(value) {
  const date = new Date(value);
  return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(date);
}

function shortHash(value) { return value ? `${value.slice(0, 10)}…${value.slice(-6)}` : '—'; }
function shortSession(value) { return value.length > 14 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value; }

function toast(message) {
  const el = $('#toast');
  el.textContent = message;
  el.classList.add('show');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => el.classList.remove('show'), 3200);
}

async function getJson(path) {
  const response = await fetch(path, { headers: { Accept: 'application/json' } });
  if (!response.ok) throw new Error('The local API did not respond');
  return response.json();
}

function filterQuery() {
  const params = new URLSearchParams();
  const term = $('#search').value.trim();
  const risk = $('#risk-filter').value;
  if (term) params.set('q', term);
  if (risk === 'reversible') params.set('reversible', 'true');
  else if (risk !== 'all') params.set('risk', risk);
  if ($('#agent-filter').value) params.set('agent', $('#agent-filter').value);
  if ($('#session-filter').value) params.set('session', $('#session-filter').value);
  return params;
}

function setOptions(select, label, values, describe) {
  const current = select.value;
  // Option text is assigned through textContent, so event-sourced names are never parsed as markup.
  select.replaceChildren(new Option(label, ''), ...values.map(item => new Option(describe(item), item.value)));
  select.value = values.some(item => item.value === current) ? current : '';
}

function updateMetrics() {
  const stats = state.stats;
  $('#metric-total').textContent = stats ? stats.total : '—';
  $('#metric-reversible').textContent = stats ? stats.reversible : '—';
  $('#metric-risk').textContent = stats ? stats.high : '—';
  const valid = state.verification?.valid;
  $('#metric-chain').textContent = valid === undefined ? '—' : valid ? 'Valid' : 'Broken';
  const badge = $('#chain-badge');
  badge.className = `chain-badge ${valid === undefined ? 'checking' : valid ? 'valid' : 'invalid'}`;
  badge.querySelector('span:last-child').textContent = valid === undefined ? 'Checking chain…' : valid ? `Chain verified · ${state.verification.event_count} receipts` : `Chain broken at #${state.verification.broken_at}`;
  if (stats) {
    setOptions($('#agent-filter'), 'All agents', stats.agents.map(item => ({ value: item.agent, count: item.count })), item => `${item.value} (${item.count})`);
    const sessions = stats.sessions.map(item => ({ value: item.session_id, count: item.count }));
    setOptions($('#session-filter'), 'All sessions', sessions, item => `Session ${shortSession(item.value)} (${item.count})`);
    $('#session-filter').hidden = sessions.length === 0;
  }
}

function stateChip(event) {
  if (event.rolled_back_by) return `<span class="state-chip">ROLLED BACK · #${escapeHtml(event.rolled_back_by)}</span>`;
  if (event.reversible) return '<span class="undo-chip">UNDO ELIGIBLE</span>';
  if (event.snapshot_pruned) return '<span class="state-chip">CONTENT PRUNED</span>';
  return '';
}

function renderTimeline() {
  // All event-sourced values interpolated below pass through escapeHtml; only app-owned markup remains raw.
  const events = state.events;
  const list = $('#timeline-list');
  const filtered = filterQuery().toString() !== '';
  $('#timeline-count').textContent = state.total
    ? `Showing ${events.length} of ${state.total} ${filtered ? 'matching ' : ''}receipts, newest first.`
    : 'Newest agent actions appear first.';
  $('#timeline-footer').hidden = state.nextBeforeId === null;
  if (!events.length) {
    list.innerHTML = `<div class="empty"><div><strong>No matching receipts</strong><br><span>Record an agent action or change the filter.</span></div></div>`;
    return;
  }
  const grouped = !$('#session-filter').value && events.some(event => typeof event.metadata?.session_id === 'string');
  let previousSession;
  list.innerHTML = events.map(event => {
    const session = typeof event.metadata?.session_id === 'string' ? event.metadata.session_id : '';
    let header = '';
    if (grouped && session !== previousSession) {
      header = session
        ? `<div class="session-row"><span>Session ${escapeHtml(shortSession(session))}</span><button type="button" data-session="${escapeHtml(session)}">Show only this session</button></div>`
        : '<div class="session-row"><span>No session</span></div>';
    }
    previousSession = session;
    return `${header}
    <article class="receipt" data-id="${escapeHtml(event.id)}" tabindex="0" role="button" aria-label="Open receipt ${escapeHtml(event.id)}">
      <time class="receipt-time">${escapeHtml(when(event.created_at))}</time>
      <div class="receipt-main">
        <div class="receipt-title"><span class="risk ${escapeHtml(event.risk)}">${escapeHtml(event.risk)}</span>${stateChip(event)}<span>${escapeHtml(event.action)}</span><span class="risk-reason">${escapeHtml(event.risk_reason ?? '')}</span></div>
        <div class="receipt-summary">${escapeHtml(event.summary)}</div>
        <div class="receipt-target">${escapeHtml(event.target)}</div>
      </div>
      <div class="receipt-agent"><b>${escapeHtml(event.agent)}</b>receipt #${escapeHtml(event.id)}</div>
    </article>`;
  }).join('');
  list.querySelectorAll('.receipt').forEach(row => {
    const open = () => openReceipt(Number(row.dataset.id));
    row.addEventListener('click', open);
    row.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); open(); } });
  });
  list.querySelectorAll('.session-row button').forEach(button => {
    button.addEventListener('click', () => { $('#session-filter').value = button.dataset.session; reload(); });
  });
}

function undoLabel(event) {
  if (event.action === 'file.create') return 'Safely remove this created file';
  if (event.action === 'file.delete') return 'Safely restore this deleted file';
  return 'Safely undo this change';
}

function undoStatus(event) {
  if (event.rolled_back_by) return `Rolled back by receipt #${event.rolled_back_by}`;
  if (event.reversible) return 'Eligible; live checks apply';
  if (event.snapshot_pruned) return 'Stored content was pruned';
  return 'Not available';
}

function renderDiff(diff) {
  const lines = diff.diff.split('\n');
  if (lines[lines.length - 1] === '') lines.pop();
  const body = lines.map(line => {
    const kind = line.startsWith('+++') || line.startsWith('---') ? 'file'
      : line.startsWith('@@') ? 'hunk'
      : line.startsWith('+') ? 'add'
      : line.startsWith('-') ? 'del' : 'ctx';
    return `<span class="${kind}">${escapeHtml(line) || ' '}</span>`;
  }).join('');
  return `<h3>Recorded change <span class="added">+${escapeHtml(diff.lines_added)}</span><span class="removed">−${escapeHtml(diff.lines_removed)}</span></h3><pre class="diff">${body || '<span class="ctx">No textual difference.</span>'}</pre>`;
}

async function showDiff(event) {
  const panel = $('#dialog-diff');
  panel.hidden = !event.has_diff;
  if (!event.has_diff) return;
  if (!state.config.show_diffs) {
    panel.innerHTML = `<p class="diff-note">A diff was recorded for this receipt. File contents are not served by default: start Glassbox with <code>--show-diffs</code> to view it here, or run <code>glassbox show ${escapeHtml(event.id)} --diff</code>.</p>`;
    return;
  }
  panel.innerHTML = '<p class="diff-note">Loading the recorded change…</p>';
  try {
    const diff = await getJson(`/api/events/${event.id}/diff`);
    if (state.selected !== event) return;
    panel.innerHTML = diff.available ? renderDiff(diff) : `<p class="diff-note">${escapeHtml(diff.reason)}</p>`;
  } catch (error) {
    panel.innerHTML = `<p class="diff-note">${escapeHtml(error.message)}</p>`;
  }
}

function openReceipt(id) {
  const event = state.events.find(item => item.id === id);
  if (!event) return;
  state.selected = event;
  const metadata = event.metadata && Object.keys(event.metadata).length ? JSON.stringify(event.metadata, null, 2) : '';
  $('#dialog-title').textContent = `Receipt #${event.id}`;
  $('#dialog-content').innerHTML = `<dl class="detail-grid">
    <dt>Summary</dt><dd>${escapeHtml(event.summary)}</dd>
    <dt>Agent</dt><dd>${escapeHtml(event.agent)}</dd>
    <dt>Action</dt><dd>${escapeHtml(event.action)}</dd>
    <dt>Target</dt><dd>${escapeHtml(event.target)}</dd>
    <dt>Recorded</dt><dd>${escapeHtml(event.created_at)}</dd>
    <dt>Risk</dt><dd>${escapeHtml(event.risk)}${event.risk_reason ? ` — ${escapeHtml(event.risk_reason)}` : ''}</dd>
    <dt>Undo</dt><dd>${escapeHtml(undoStatus(event))}</dd>
    <dt>Before hash</dt><dd>${escapeHtml(shortHash(event.before_sha256))}</dd>
    <dt>After hash</dt><dd>${escapeHtml(shortHash(event.after_sha256))}</dd>
    <dt>Receipt</dt><dd>${escapeHtml(event.receipt_hash)}</dd>
    <dt>Previous</dt><dd>${escapeHtml(event.previous_hash)}</dd>
    ${metadata ? `<dt>Metadata</dt><dd><pre>${escapeHtml(metadata)}</pre></dd>` : ''}
  </dl>`;
  $('#rollback-button').hidden = !event.reversible;
  $('#rollback-button').textContent = undoLabel(event);
  showDiff(event);
  $('#receipt-dialog').showModal();
}

async function loadEvents({ append = false, limit = PAGE_SIZE } = {}) {
  const params = filterQuery();
  params.set('limit', String(limit));
  if (append && state.nextBeforeId !== null) params.set('before_id', String(state.nextBeforeId));
  const page = await getJson(`/api/events?${params}`);
  state.events = append ? state.events.concat(page.events) : page.events;
  state.total = page.total;
  state.nextBeforeId = page.next_before_id;
  renderTimeline();
}

async function verifyChain() {
  state.verification = await getJson('/api/verify');
  state.lastVerifiedAt = Date.now();
  updateMetrics();
}

async function reload() {
  try {
    const [stats] = await Promise.all([getJson('/api/stats'), loadEvents()]);
    state.stats = stats;
    state.headHash = stats.head_hash;
    updateMetrics();
    await verifyChain();
    setLive(true);
  } catch (error) {
    $('#timeline-list').innerHTML = `<div class="empty"><div><strong>Could not load receipts</strong><br><span>${escapeHtml(error.message)}</span></div></div>`;
    toast('Could not connect to the Glassbox API');
    setLive(false);
  }
}

function setLive(connected) {
  const status = $('#live-status');
  status.textContent = connected ? 'Updates automatically.' : 'Disconnected; retrying.';
  status.classList.toggle('stale', !connected);
}

async function poll() {
  if (document.visibilityState !== 'visible' || $('#receipt-dialog').open) return;
  try {
    const stats = await getJson('/api/stats');
    setLive(true);
    if (stats.head_hash === state.headHash) return;
    state.stats = stats;
    state.headHash = stats.head_hash;
    // Refresh what is on screen without discarding pages the reader already loaded.
    await loadEvents({ limit: Math.min(500, Math.max(PAGE_SIZE, state.events.length)) });
    updateMetrics();
    await verifyChain();
  } catch {
    setLive(false);
  }
}

async function start() {
  try {
    state.config = await getJson('/api/config');
    const workspace = String(state.config.workspace || '').split('/').filter(Boolean).pop();
    if (workspace) { $('#workspace-name').textContent = workspace; $('#workspace-name').title = state.config.workspace; }
  } catch { /* the timeline load below reports connection problems */ }
  await reload();
  setInterval(poll, POLL_MS);
}

let searchTimer;
$('#search').addEventListener('input', () => { clearTimeout(searchTimer); searchTimer = setTimeout(reload, 250); });
['#risk-filter', '#agent-filter', '#session-filter'].forEach(id => $(id).addEventListener('change', reload));
$('#load-more').addEventListener('click', async () => {
  try { await loadEvents({ append: true }); } catch { toast('Could not load older receipts'); }
});
$('#dialog-close').addEventListener('click', () => $('#receipt-dialog').close());
$('#receipt-dialog').addEventListener('click', event => { if (event.target === $('#receipt-dialog')) $('#receipt-dialog').close(); });
$('#receipt-dialog').addEventListener('close', () => { state.selected = null; });
$('#verify-button').addEventListener('click', async () => {
  try { await verifyChain(); toast(state.verification.valid ? 'Receipt chain is valid' : 'Receipt chain verification failed'); }
  catch { toast('Could not connect to the Glassbox API'); }
});
$('#export-button').addEventListener('click', async () => {
  try {
    const payload = JSON.stringify(await getJson('/api/export'), null, 2);
    const url = URL.createObjectURL(new Blob([payload], { type: 'application/json' }));
    const link = Object.assign(document.createElement('a'), { href: url, download: `glassbox-receipts-${new Date().toISOString().slice(0,10)}.json` });
    link.click(); URL.revokeObjectURL(url); toast('Signed receipts exported');
  } catch { toast('Could not export receipts'); }
});
$('#copy-code').addEventListener('click', async () => { await navigator.clipboard.writeText($('#integration-code').textContent); toast('Integration snippet copied'); });
$('#rollback-button').addEventListener('click', async () => {
  const event = state.selected;
  if (!event) return;
  const question = event.action === 'file.create'
    ? `Remove ${event.target}, which was created by receipt #${event.id}? Glassbox will refuse if the file changed later and keeps the removed file in a protected recovery folder.`
    : event.action === 'file.delete'
      ? `Restore ${event.target} as it was before receipt #${event.id} deleted it? Glassbox will refuse if anything exists at that path now.`
      : `Restore ${event.target} to its state before receipt #${event.id}? Glassbox will refuse if the file changed later and retain a protected recovery copy of the displaced file.`;
  if (!confirm(question)) return;
  const response = await fetch(`/api/events/${event.id}/rollback`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({confirm:true}) });
  const body = await response.json();
  if (!response.ok) { toast(body.detail || 'Rollback failed'); return; }
  $('#receipt-dialog').close();
  toast(body.displaced_path ? `Rollback receipt #${body.rollback_receipt_id}; recovery file: ${body.displaced_path}` : `Rollback receipt #${body.rollback_receipt_id}; restored ${body.restored_path}`);
  await reload();
});

start();
