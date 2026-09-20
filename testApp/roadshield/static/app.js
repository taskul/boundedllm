// The browser holds no model key. It sends authenticated requests only to RoadShield's backend.
const loginView = document.querySelector('#login-view');
const appView = document.querySelector('#app-view');
const $ = selector => document.querySelector(selector);

function csrf() {
  return document.cookie.split('; ').find(value => value.startsWith('roadshield_csrf='))?.split('=')[1] || '';
}

function operationId() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return [...bytes].map(value => value.toString(16).padStart(2, '0')).join('');
}

// FormData retains the browser-generated multipart boundary. JSON requests receive
// an explicit content type and every state-changing request receives CSRF.
async function api(path, options = {}) {
  const isForm = options.body instanceof FormData;
  const headers = {...(options.headers || {})};
  if (!isForm) headers['Content-Type'] = 'application/json';
  if (options.method && options.method !== 'GET') headers['X-CSRF-Token'] = csrf();
  const response = await fetch(path, {credentials: 'same-origin', ...options, headers});
  const data = await response.json();
  if (!response.ok) throw new Error(data.detail || 'Request failed');
  return data;
}

// Model output is assigned as text and is never interpreted as HTML.
function text(tag, value, className) {
  const node = document.createElement(tag);
  node.textContent = value;
  if (className) node.className = className;
  return node;
}

function addRecord(parent, title, lines) {
  const record = text('div', '', 'record');
  record.append(text('strong', title));
  lines.forEach(line => record.append(text('span', line)));
  parent.append(record);
}

async function loadDashboard() {
  const data = await api('/api/dashboard');
  loginView.classList.add('hidden');
  appView.classList.remove('hidden');
  $('#logout').classList.remove('hidden');
  $('#signed-in-name').textContent = data.profile.display_name;
  $('#first-name').textContent = data.profile.display_name.split(' ')[0];

  if (data.security_admin) {
    $('#customer-dashboard').classList.add('hidden');
    $('#customer-agent').classList.add('hidden');
    $('#customer-history').classList.add('hidden');
    $('#security-console').classList.remove('hidden');
    await loadSecurityConsole();
    return;
  }

  const profile = $('#profile');
  profile.replaceChildren();
  Object.entries(data.profile).forEach(([key, value]) => {
    profile.append(text('dt', key.replace('_', ' ')), text('dd', value));
  });
  const policy = $('#policies');
  policy.replaceChildren();
  data.policies.forEach(item => addRecord(policy, item.policy_number, [
    item.vehicle,
    item.coverage,
    `Premium $${(item.premium_cents / 100).toFixed(2)} · Deductible $${(item.deductible_cents / 100).toFixed(2)}`,
    `Renews ${item.renewal_date}`,
  ]));
  const claim = $('#claims');
  claim.replaceChildren();
  data.claims.forEach(item => addRecord(claim, item.claim_number, [
    item.summary,
    `${item.status} · ${item.incident_date}`,
  ]));
  const agent = await api('/api/agent/status');
  $('#model-status').textContent = `Connected: ${agent.provider}`;
  await loadScenarios();
  await loadHistory();
}

async function loadSecurityConsole(eventType = '', severity = '', model = '', subject = '', since = '') {
  const params = new URLSearchParams({limit: '100'});
  if (eventType) params.set('event_type', eventType);
  if (severity) params.set('severity', severity);
  if (model) params.set('model', model);
  if (subject) params.set('subject_fingerprint', subject);
  if (since) params.set('since', String(new Date(since).getTime() / 1000));
  const [overview, listing] = await Promise.all([
    api('/api/security/overview'),
    api(`/api/security/events?${params}`),
  ]);
  $('#security-count').textContent = overview.stats.count;
  $('#security-integrity').textContent = overview.integrity.valid ? 'valid' : 'attention';
  $('#security-integrity').className = overview.integrity.valid ? 'integrity-ok' : 'integrity-bad';
  $('#security-quarantine').textContent = overview.quarantined.length;
  const body = $('#security-events');
  body.replaceChildren();
  listing.events.forEach(event => {
    const row = document.createElement('tr');
    const values = [
      event.sequence,
      new Date(event.timestamp * 1000).toLocaleString(),
      event.event_type,
      event.status || event.code || '—',
      event.severity || 'info',
      event.request_id,
    ];
    values.forEach(value => row.append(text('td', String(value))));
    const caseCell = document.createElement('td');
    if (event.case) {
      caseCell.append(text('span', event.case.state));
    } else if (['high', 'critical'].includes(event.severity)) {
      const acknowledge = text('button', 'Acknowledge', 'case-button');
      acknowledge.type = 'button';
      acknowledge.addEventListener('click', async () => {
        acknowledge.disabled = true;
        await api(`/api/security/events/${event.event_id}/case`, {
          method: 'POST',
          body: JSON.stringify({state: 'acknowledged', case_id: null}),
        });
        await loadSecurityConsole(eventType, severity, model, subject, since);
      });
      caseCell.append(acknowledge);
    } else {
      caseCell.textContent = '—';
    }
    row.append(caseCell);
    body.append(row);
  });
  const quarantine = $('#quarantine-list');
  quarantine.replaceChildren();
  if (!overview.quarantined.length) quarantine.append(text('p', 'No quarantined documents.', 'muted'));
  overview.quarantined.forEach(doc => addRecord(quarantine, doc.doc_id, [
    `${doc.classification} · ${doc.source}`,
    `SHA-256 ${doc.content_hash}`,
    `Retention ${doc.retention_policy}`,
  ]));
}

async function loadScenarios() {
  const data = await api('/api/attacks');
  const list = $('#scenarios');
  list.replaceChildren();
  data.scenarios.forEach(item => {
    const row = text('div', '', 'scenario');
    const copy = text('div', '');
    copy.append(text('strong', item.title), text('small', item.description));
    const button = text('button', 'Run');
    button.type = 'button';
    button.addEventListener('click', () => runAttack(item, button));
    row.append(copy, button);
    list.append(row);
  });
}

async function runAttack(item, button) {
  button.disabled = true;
  button.textContent = 'Running…';
  try {
    const result = await api(`/api/attacks/${encodeURIComponent(item.name)}`, {method: 'POST', body: '{}'});
    const message = `${result.protected ? 'PROTECTED' : 'FAILED'} · ${result.provider} returned ${result.actual}. ${result.answer}`;
    button.closest('.scenario').after(
      text('div', message, `result ${result.protected ? 'ok' : 'fail'}`),
    );
    await loadHistory();
  } catch (error) {
    button.closest('.scenario').after(text('div', error.message, 'result fail'));
  } finally {
    button.disabled = false;
    button.textContent = 'Run';
  }
}

async function loadHistory() {
  const data = await api('/api/attacks/history');
  const area = $('#history');
  area.replaceChildren();
  if (!data.runs.length) {
    area.append(text('p', 'No simulations run yet.', 'muted'));
    return;
  }
  data.runs.forEach(run => {
    const item = text('div', '', `run ${run.protected ? 'ok' : 'fail'}`);
    item.append(
      text('strong', run.scenario),
      text('div', `${run.result_status} · ${run.protected ? 'protected' : 'failed'}`),
    );
    area.append(item);
  });
}

async function uploadSelectedPDF() {
  const input = $('#chat-file');
  if (!input.files.length) return null;
  const form = new FormData();
  form.append('file', input.files[0]);
  $('#upload-status').textContent = `Inspecting ${input.files[0].name}…`;
  const uploaded = await api('/api/chat/upload', {method: 'POST', body: form});
  input.value = '';
  const suffix = uploaded.pages === 1 ? 'page' : 'pages';
  $('#upload-status').textContent = `${uploaded.filename}: ${uploaded.message} (${uploaded.pages} ${suffix}).`;
  return uploaded;
}

$('#login-form').addEventListener('submit', async event => {
  event.preventDefault();
  $('#login-error').textContent = '';
  try {
    await api('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        tenant_id: $('#tenant').value,
        email: $('#email').value,
        password: $('#password').value,
        mfa_code: $('#mfa-code').value || null,
      }),
    });
    await loadDashboard();
  } catch (error) {
    $('#login-error').textContent = error.message;
  }
});

$('#event-filter').addEventListener('submit', async event => {
  event.preventDefault();
  await loadSecurityConsole(
    $('#event-type').value.trim(),
    $('#event-severity').value,
    $('#event-model').value.trim(),
    $('#event-subject').value.trim(),
    $('#event-since').value,
  );
});

$('#chat-form').addEventListener('submit', async event => {
  event.preventDefault();
  const input = $('#chat-input');
  const message = input.value;
  const log = $('#chat-log');
  input.value = '';
  log.append(text('p', message, 'user'));
  try {
    const uploaded = await uploadSelectedPDF();
    const result = await api('/api/chat', {
      method: 'POST',
      body: JSON.stringify({
        message,
        operation_id: operationId(),
        attachment_ids: uploaded ? [uploaded.document_id] : [],
      }),
    });
    log.append(text('p', `${result.status}: ${result.answer}`, 'assistant'));
    if (result.attachment_results.length) {
      const attachment = result.attachment_results[0];
      const explanation = attachment.status === 'used'
        ? 'The uploaded PDF was scanned and used in this answer.'
        : attachment.status === 'quarantined'
          ? `The uploaded PDF was quarantined (${attachment.code}). It was not sent to the model.`
          : `The uploaded PDF was rejected (${attachment.code}).`;
      $('#upload-status').textContent = explanation;
    }
  } catch (error) {
    log.append(text('p', error.message, 'assistant'));
  }
  log.scrollTop = log.scrollHeight;
});

$('#chat-file').addEventListener('change', event => {
  const selected = event.target.files[0];
  $('#upload-status').textContent = selected
    ? `Ready to upload ${selected.name} with your next message.`
    : 'PDFs are extracted as untrusted, tenant-scoped RAG data.';
});

$('#logout').addEventListener('click', async () => {
  try {
    await api('/api/auth/logout', {method: 'POST', body: '{}'});
  } finally {
    location.reload();
  }
});

loadDashboard().catch(() => {});
