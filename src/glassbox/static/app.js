const state = { events: [], selected: null, verification: null };
const $ = (selector) => document.querySelector(selector);

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
}

function when(value) {
  const date = new Date(value);
  return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(date);
}

function shortHash(value) { return value ? `${value.slice(0, 10)}…${value.slice(-6)}` : '—'; }

function toast(message) {
  const el = $('#toast');
  el.textContent = message;
  el.classList.add('show');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => el.classList.remove('show'), 2400);
}

function updateMetrics() {
  const events = state.events;
  $('#metric-total').textContent = events.length;
  $('#metric-reversible').textContent = events.filter(e => e.reversible).length;
  $('#metric-risk').textContent = events.filter(e => e.risk === 'high').length;
  const valid = state.verification?.valid;
  $('#metric-chain').textContent = valid === undefined ? '—' : valid ? 'Valid' : 'Broken';
  const badge = $('#chain-badge');
  badge.className = `chain-badge ${valid === undefined ? 'checking' : valid ? 'valid' : 'invalid'}`;
  badge.querySelector('span:last-child').textContent = valid === undefined ? 'Checking chain…' : valid ? `Chain verified · ${state.verification.event_count} receipts` : `Chain broken at #${state.verification.broken_at}`;
}

function filteredEvents() {
  const term = $('#search').value.trim().toLowerCase();
  const filter = $('#risk-filter').value;
  return state.events.filter(event => {
    const searchable = `${event.summary} ${event.target} ${event.agent} ${event.action}`.toLowerCase();
    const riskMatch = filter === 'all' || event.risk === filter || (filter === 'reversible' && event.reversible);
    return riskMatch && (!term || searchable.includes(term));
  });
}

function renderTimeline() {
  // All event-sourced values interpolated below pass through escapeHtml; only app-owned markup remains raw.
  const events = filteredEvents();
  const list = $('#timeline-list');
  if (!events.length) {
    list.innerHTML = `<div class="empty"><div><strong>No matching receipts</strong><br><span>Record an agent action or change the filter.</span></div></div>`;
    return;
  }
  list.innerHTML = events.map(event => `
    <article class="receipt" data-id="${escapeHtml(event.id)}" tabindex="0" role="button" aria-label="Open receipt ${escapeHtml(event.id)}">
      <time class="receipt-time">${escapeHtml(when(event.created_at))}</time>
      <div class="receipt-main">
        <div class="receipt-title"><span class="risk ${escapeHtml(event.risk)}">${escapeHtml(event.risk)}</span>${event.reversible ? '<span class="undo-chip">UNDO ELIGIBLE</span>' : ''}<span>${escapeHtml(event.action)}</span></div>
        <div class="receipt-summary">${escapeHtml(event.summary)}</div>
        <div class="receipt-target">${escapeHtml(event.target)}</div>
      </div>
      <div class="receipt-agent"><b>${escapeHtml(event.agent)}</b>receipt #${escapeHtml(event.id)}</div>
    </article>`).join('');
  list.querySelectorAll('.receipt').forEach(row => {
    const open = () => openReceipt(Number(row.dataset.id));
    row.addEventListener('click', open);
    row.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') open(); });
  });
}

function openReceipt(id) {
  const event = state.events.find(item => item.id === id);
  if (!event) return;
  state.selected = event;
  $('#dialog-title').textContent = `Receipt #${event.id}`;
  $('#dialog-content').innerHTML = `<dl class="detail-grid">
    <dt>Summary</dt><dd>${escapeHtml(event.summary)}</dd>
    <dt>Agent</dt><dd>${escapeHtml(event.agent)}</dd>
    <dt>Action</dt><dd>${escapeHtml(event.action)}</dd>
    <dt>Target</dt><dd>${escapeHtml(event.target)}</dd>
    <dt>Risk</dt><dd>${escapeHtml(event.risk)}</dd>
    <dt>Before hash</dt><dd>${escapeHtml(shortHash(event.before_sha256))}</dd>
    <dt>After hash</dt><dd>${escapeHtml(shortHash(event.after_sha256))}</dd>
    <dt>Receipt</dt><dd>${escapeHtml(event.receipt_hash)}</dd>
    <dt>Previous</dt><dd>${escapeHtml(event.previous_hash)}</dd>
  </dl>`;
  $('#rollback-button').hidden = !event.reversible;
  $('#receipt-dialog').showModal();
}

async function load() {
  try {
    const [eventResponse, verifyResponse] = await Promise.all([fetch('/api/events'), fetch('/api/verify')]);
    if (!eventResponse.ok || !verifyResponse.ok) throw new Error('The local API did not respond');
    state.events = (await eventResponse.json()).events;
    state.verification = await verifyResponse.json();
    updateMetrics();
    renderTimeline();
  } catch (error) {
    $('#timeline-list').innerHTML = `<div class="empty"><div><strong>Could not load receipts</strong><br><span>${escapeHtml(error.message)}</span></div></div>`;
    toast('Could not connect to the Glassbox API');
  }
}

$('#search').addEventListener('input', renderTimeline);
$('#risk-filter').addEventListener('change', renderTimeline);
$('#dialog-close').addEventListener('click', () => $('#receipt-dialog').close());
$('#receipt-dialog').addEventListener('click', event => { if (event.target === $('#receipt-dialog')) $('#receipt-dialog').close(); });
$('#verify-button').addEventListener('click', async () => { state.verification = await (await fetch('/api/verify')).json(); updateMetrics(); toast(state.verification.valid ? 'Receipt chain is valid' : 'Receipt chain verification failed'); });
$('#export-button').addEventListener('click', () => {
  const payload = JSON.stringify({ exported_at: new Date().toISOString(), verification: state.verification, events: state.events }, null, 2);
  const url = URL.createObjectURL(new Blob([payload], { type: 'application/json' }));
  const link = Object.assign(document.createElement('a'), { href: url, download: `glassbox-receipts-${new Date().toISOString().slice(0,10)}.json` });
  link.click(); URL.revokeObjectURL(url); toast('Signed receipts exported');
});
$('#copy-code').addEventListener('click', async () => { await navigator.clipboard.writeText($('#integration-code').textContent); toast('Integration snippet copied'); });
$('#rollback-button').addEventListener('click', async () => {
  const event = state.selected;
  if (!event || !confirm(`Restore ${event.target} to its state before receipt #${event.id}? Glassbox will refuse if the file changed later and retain a protected recovery copy of the displaced file.`)) return;
  const response = await fetch(`/api/events/${event.id}/rollback`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({confirm:true}) });
  const body = await response.json();
  if (!response.ok) { toast(body.detail || 'Rollback failed'); return; }
  $('#receipt-dialog').close(); toast(`Rollback receipt #${body.rollback_receipt_id}; recovery file: ${body.displaced_path}`); await load();
});

load();
