// Interceptor - Burp Suite-style HTTP traffic inspector for Toolbelt
// Tabs: HTTP History, Intercept (observe & replay — MV3 read-only), Repeater, Console
// Communication: long-lived port to background service worker

let requests = [];
let nextId = 1;
let capturing = false;
let intercepting = false;
let selectedRequest = null;
const interceptQueue = [];
let currentIntercept = null;
let activeDetailTab = 'request';
let repeaterHeaders = [{ name: 'User-Agent', value: 'Toolbelt-Interceptor/1.0' }];
let repeaterReqTab = 'headers';
let repeaterResTab = 'headers';
let lastRepeaterResponse = null;
let port = null;
let renderPending = false;
let autoScroll = true;
let consoleEntries = [];
let consoleErrorCount = 0;
let scopeTabId = null;
let scopeTabTitle = '';
const wsConnections = new Map(); // requestId -> { url, tabId, frames: [] }

document.addEventListener('DOMContentLoaded', () => {
  connectToBackground();
  setupTabs();
  setupCapture();
  setupFilters();
  setupDetail();
  setupIntercept();
  setupRepeater();
  setupConsole();
  setupCompare();
  setupAnalyze();
  setupSessions();
  setupKeyboard();
  loadState();
});

// ─── Background Connection (long-lived port) ────────────

function connectToBackground() {
  port = chrome.runtime.connect({ name: 'interceptor' });

  port.onMessage.addListener((msg) => {
    switch (msg.action) {
      case 'interceptor:state':
        syncState(msg.data);
        break;
      case 'interceptor:request':
        addRequest(msg.data);
        break;
      case 'interceptor:requestHeaders':
        updateRequestHeaders(msg.data);
        break;
      case 'interceptor:response':
        updateResponse(msg.data);
        break;
      case 'interceptor:intercepted':
        handleIntercepted(msg.data);
        break;
      case 'interceptor:responseBody':
        updateResponseBody(msg.data);
        break;
      case 'interceptor:console':
        addConsoleEntry(msg.data);
        break;
      case 'interceptor:websocket':
        handleWebSocketEvent(msg.data);
        break;
    }
  });

  port.onDisconnect.addListener(() => {
    // Service worker restarted — reconnect after a brief delay
    setTimeout(connectToBackground, 500);
  });
}

function syncState(state) {
  capturing = state.capturing;
  intercepting = state.intercepting;
  scopeTabId = state.scopeTabId ?? null;

  if (state.scope) document.getElementById('scopeInput').value = state.scope;

  // Restore scope mode from state
  const scopeMode = document.getElementById('scopeMode');
  if (scopeTabId != null) {
    scopeMode.value = 'tab';
  } else if (state.scope) {
    scopeMode.value = 'domain';
  } else {
    scopeMode.value = 'all';
  }
  updateScopeModeUI();

  const toggle = document.getElementById('captureToggle');
  toggle.classList.toggle('active', capturing);
  document.getElementById('captureLabel').textContent = capturing ? 'Capturing...' : 'Capture Off';
  updateInterceptUI();
}

// ─── Tab Navigation ──────────────────────────────────────

function setupTabs() {
  document.querySelectorAll('.tab-btn[data-tab]').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn[data-tab]').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
    });
  });
}

// ─── Capture Control ─────────────────────────────────────

function setupCapture() {
  const toggle = document.getElementById('captureToggle');
  const clearBtn = document.getElementById('clearBtn');
  const exportBtn = document.getElementById('exportBtn');
  const scopeMode = document.getElementById('scopeMode');

  toggle.addEventListener('click', async () => {
    capturing = !capturing;
    toggle.classList.toggle('active', capturing);
    document.getElementById('captureLabel').textContent = capturing ? 'Capturing...' : 'Capture Off';

    // Resolve scope based on mode
    await resolveScopeFromMode();

    chrome.runtime.sendMessage({
      action: 'interceptor:setCapture',
      enabled: capturing,
      scope: document.getElementById('scopeInput').value.trim(),
      scopeTabId: scopeTabId
    }).catch(() => {});
    saveState();
  });

  scopeMode.addEventListener('change', async () => {
    await resolveScopeFromMode();
    updateScopeModeUI();
    if (capturing) {
      chrome.runtime.sendMessage({
        action: 'interceptor:setCapture',
        enabled: true,
        scope: document.getElementById('scopeInput').value.trim(),
        scopeTabId: scopeTabId
      }).catch(() => {});
    }
    saveState();
  });

  document.getElementById('scopeInput').addEventListener('change', () => {
    if (capturing) {
      chrome.runtime.sendMessage({
        action: 'interceptor:setCapture',
        enabled: true,
        scope: document.getElementById('scopeInput').value.trim(),
        scopeTabId: scopeTabId
      }).catch(() => {});
    }
    saveState();
  });

  document.getElementById('autoScrollToggle').addEventListener('change', (e) => {
    autoScroll = e.target.checked;
  });

  clearBtn.addEventListener('click', () => {
    requests = [];
    nextId = 1;
    selectedRequest = null;
    consoleEntries = [];
    consoleErrorCount = 0;
    wsConnections.clear();
    updateConsoleErrorBadge();
    renderHistory();
    renderConsole();
    hideDetail();
  });

  exportBtn.addEventListener('click', exportHar);
}

async function resolveScopeFromMode() {
  const mode = document.getElementById('scopeMode').value;
  if (mode === 'tab') {
    const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    if (tab) {
      scopeTabId = tab.id;
      scopeTabTitle = tab.title || tab.url || `Tab ${tab.id}`;
    }
  } else {
    scopeTabId = null;
    scopeTabTitle = '';
  }
}

function updateScopeModeUI() {
  const mode = document.getElementById('scopeMode').value;
  const scopeInput = document.getElementById('scopeInput');
  const tabLabel = document.getElementById('scopeTabLabel');

  if (mode === 'domain') {
    scopeInput.style.display = '';
    tabLabel.style.display = 'none';
  } else if (mode === 'tab') {
    scopeInput.style.display = 'none';
    tabLabel.style.display = '';
    tabLabel.textContent = scopeTabTitle ? `Tab: ${scopeTabTitle}` : 'Tab: (none)';
    tabLabel.title = scopeTabTitle;
  } else {
    scopeInput.style.display = 'none';
    tabLabel.style.display = 'none';
  }
}

function addRequest(data) {
  const entry = {
    id: nextId++,
    method: data.method || 'GET',
    url: data.url,
    type: data.type || 'other',
    requestHeaders: data.requestHeaders || [],
    requestBody: data.requestBody || null,
    statusCode: 0,
    responseHeaders: [],
    responseBody: null,
    responseSize: 0,
    startTime: data.timeStamp || Date.now(),
    endTime: null,
    duration: null,
    tabId: data.tabId,
    requestId: data.requestId
  };
  requests.push(entry);
  scheduleRender();
}

function updateRequestHeaders(data) {
  const entry = requests.find(r => r.requestId === data.requestId);
  if (!entry) return;
  entry.requestHeaders = data.requestHeaders || [];
  if (selectedRequest && selectedRequest.requestId === data.requestId) {
    renderDetailBody(entry);
  }
}

function updateResponse(data) {
  const entry = requests.find(r => r.requestId === data.requestId);
  if (!entry) return;
  entry.statusCode = data.statusCode || 0;
  entry.responseHeaders = data.responseHeaders || [];
  entry.responseSize = data.responseSize || 0;
  entry.endTime = data.timeStamp || Date.now();
  entry.duration = entry.endTime - entry.startTime;
  entry.responseBody = data.responseBody || null;

  // Detect content type from response headers
  const ct = (entry.responseHeaders.find(h => h.name.toLowerCase() === 'content-type') || {}).value || '';
  if (ct.includes('json')) entry.type = 'xhr';
  else if (ct.includes('html')) entry.type = 'document';
  else if (ct.includes('javascript')) entry.type = 'script';
  else if (ct.includes('css')) entry.type = 'stylesheet';
  else if (ct.includes('image')) entry.type = 'image';
  else if (ct.includes('font')) entry.type = 'font';

  scheduleRender();
  if (selectedRequest && selectedRequest.requestId === data.requestId) {
    showDetail(entry);
  }
}

function updateResponseBody(data) {
  // Match by URL since CDP requestIds don't map to session-unique requestIds
  const entry = requests.findLast(r => r.url === data.url && r.tabId === data.tabId);
  if (!entry) return;
  entry.responseBody = data.body;
  if (selectedRequest && selectedRequest.id === entry.id) {
    renderDetailBody(entry);
  }
}

// ─── History Rendering (debounced) ───────────────────────

function scheduleRender() {
  if (!renderPending) {
    renderPending = true;
    requestAnimationFrame(() => {
      renderPending = false;
      renderHistory();
    });
  }
}

function renderHistory() {
  const tbody = document.getElementById('requestBody');
  const empty = document.getElementById('historyEmpty');
  const countBadge = document.getElementById('historyCount');
  const filtered = getFilteredRequests();

  countBadge.textContent = filtered.length;

  if (filtered.length === 0) {
    tbody.innerHTML = '';
    empty.style.display = 'flex';
    return;
  }

  empty.style.display = 'none';

  // Build rows efficiently
  const fragment = document.createDocumentFragment();
  for (const r of filtered) {
    const tr = document.createElement('tr');
    tr.dataset.id = r.id;
    if (selectedRequest && selectedRequest.id === r.id) tr.classList.add('selected');
    // Row highlighting by status class
    if (r.statusCode >= 500) tr.classList.add('row-error');
    else if (r.statusCode >= 400) tr.classList.add('row-client-error');
    else if (r.statusCode >= 300) tr.classList.add('row-redirect');
    tr.innerHTML = `
      <td class="col-id">${r.id}</td>
      <td class="col-method"><span class="method-badge method-${r.method}">${r.method}</span></td>
      <td title="${escHtml(r.url)}">${escHtml(truncateUrl(r.url))}</td>
      <td>${r.statusCode ? `<span class="status-badge status-${statusClass(r.statusCode)}">${r.statusCode}</span>` : '<span class="status-badge status-0">...</span>'}</td>
      <td><span class="type-badge">${r.type}</span></td>
      <td>${formatSize(r.responseSize)}</td>
      <td>${r.duration != null ? r.duration + 'ms' : '...'}</td>
    `;
    tr.addEventListener('click', () => {
      selectedRequest = r;
      renderHistory();
      showDetail(r);
    });
    fragment.appendChild(tr);
  }
  tbody.innerHTML = '';
  tbody.appendChild(fragment);

  // Auto-scroll to bottom when capturing
  if (autoScroll && capturing) {
    const list = document.getElementById('requestList');
    list.scrollTop = list.scrollHeight;
  }
}

function getFilteredRequests() {
  const text = document.getElementById('filterInput').value.trim();
  const method = document.getElementById('methodFilter').value;
  const status = document.getElementById('statusFilter').value;
  const type = document.getElementById('typeFilter').value;

  let regex = null;
  if (text) {
    try { regex = new RegExp(text, 'i'); } catch { regex = null; }
  }

  return requests.filter(r => {
    if (method && r.method !== method) return false;
    if (type && r.type !== type) return false;
    if (status) {
      if (!r.statusCode) return false;
      const s = String(r.statusCode);
      if (status === '2xx' && !s.startsWith('2')) return false;
      if (status === '3xx' && !s.startsWith('3')) return false;
      if (status === '4xx' && !s.startsWith('4')) return false;
      if (status === '5xx' && !s.startsWith('5')) return false;
    }
    if (regex) {
      const matchUrl = regex.test(r.url);
      const matchMethod = regex.test(r.method);
      const matchStatus = r.statusCode ? regex.test(String(r.statusCode)) : false;
      if (!matchUrl && !matchMethod && !matchStatus) return false;
    }
    return true;
  });
}

function setupFilters() {
  ['filterInput', 'methodFilter', 'statusFilter', 'typeFilter'].forEach(id => {
    document.getElementById(id).addEventListener('input', scheduleRender);
    document.getElementById(id).addEventListener('change', scheduleRender);
  });
}

// ─── Detail Panel ────────────────────────────────────────

function setupDetail() {
  document.getElementById('closeDetailBtn').addEventListener('click', hideDetail);
  document.getElementById('sendToRepeaterBtn').addEventListener('click', () => {
    if (selectedRequest) sendToRepeater(selectedRequest);
  });

  document.getElementById('copyUrlBtn').addEventListener('click', () => {
    if (selectedRequest) {
      copyToClipboard(selectedRequest.url, 'URL copied');
    }
  });

  document.getElementById('copyCurlBtn').addEventListener('click', () => {
    if (selectedRequest) {
      copyToClipboard(buildCurlCommand(selectedRequest), 'cURL copied');
    }
  });

  document.getElementById('copyResponseBtn').addEventListener('click', () => {
    if (selectedRequest) {
      const body = selectedRequest.responseBody;
      if (body) {
        const str = typeof body === 'string' ? body : JSON.stringify(body, null, 2);
        copyToClipboard(str, 'Response copied');
      } else {
        showToast('No response body');
      }
    }
  });

  document.querySelectorAll('.detail-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.detail-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      activeDetailTab = tab.dataset.detail;
      if (selectedRequest) renderDetailBody(selectedRequest);
    });
  });
}

function showDetail(req) {
  const panel = document.getElementById('detailPanel');
  const list = document.getElementById('requestList');
  panel.classList.add('visible');
  list.classList.add('split-mode');
  document.getElementById('detailTitle').textContent = `${req.method} ${truncateUrl(req.url, 60)}`;
  renderDetailBody(req);
}

function hideDetail() {
  document.getElementById('detailPanel').classList.remove('visible');
  document.getElementById('requestList').classList.remove('split-mode');
  selectedRequest = null;
  renderHistory();
}

function renderDetailBody(req) {
  const body = document.getElementById('detailBody');

  if (activeDetailTab === 'request') {
    body.innerHTML = `
      <div class="detail-section">
        <h4>Request Line</h4>
        <div class="body-content">${escHtml(req.method)} ${escHtml(req.url)} HTTP/1.1</div>
      </div>
      <div class="detail-section">
        <h4>Request Headers</h4>
        ${renderHeadersTable(req.requestHeaders)}
      </div>
      ${req.requestBody ? `
      <div class="detail-section">
        <h4>Request Body</h4>
        <div class="body-content">${formatBody(req.requestBody)}</div>
      </div>` : ''}
    `;
  } else if (activeDetailTab === 'response') {
    if (!req.statusCode) {
      body.innerHTML = '<div class="empty-state"><h3>Waiting for response...</h3></div>';
      return;
    }
    body.innerHTML = `
      <div class="detail-section">
        <h4>Status</h4>
        <div class="body-content">HTTP/1.1 <span class="status-badge status-${statusClass(req.statusCode)}">${req.statusCode}</span></div>
      </div>
      <div class="detail-section">
        <h4>Response Headers</h4>
        ${renderHeadersTable(req.responseHeaders)}
      </div>
      ${req.responseBody ? `
      <div class="detail-section">
        <h4>Response Body</h4>
        <div class="body-content">${formatBody(req.responseBody)}</div>
      </div>` : ''}
    `;
  } else if (activeDetailTab === 'cookies') {
    const reqCookies = parseCookieHeader(req.requestHeaders);
    const resCookies = parseSetCookieHeaders(req.responseHeaders);

    body.innerHTML = `
      <div class="detail-section">
        <h4>Request Cookies (${reqCookies.length})</h4>
        ${reqCookies.length > 0 ? `<table class="headers-table">${reqCookies.map(c =>
          `<tr><td class="header-name">${escHtml(c.name)}</td><td class="header-value">${escHtml(c.value)}</td></tr>`
        ).join('')}</table>` : '<p style="color: var(--text-muted); font-size: 12px;">No request cookies</p>'}
      </div>
      <div class="detail-section">
        <h4>Response Cookies (${resCookies.length})</h4>
        ${resCookies.length > 0 ? `<table class="headers-table">${resCookies.map(c =>
          `<tr>
            <td class="header-name">${escHtml(c.name)}</td>
            <td class="header-value">
              ${escHtml(c.value)}
              ${c.attrs.length > 0 ? `<br><span style="color: var(--text-muted); font-size: 10px;">${escHtml(c.attrs.join('; '))}</span>` : ''}
            </td>
          </tr>`
        ).join('')}</table>` : '<p style="color: var(--text-muted); font-size: 12px;">No response cookies</p>'}
      </div>
    `;
  } else if (activeDetailTab === 'timing') {
    body.innerHTML = `
      <div class="detail-section">
        <h4>Timing</h4>
        <table class="headers-table">
          <tr><td class="header-name">Started</td><td class="header-value">${new Date(req.startTime).toLocaleTimeString()}</td></tr>
          ${req.endTime ? `<tr><td class="header-name">Completed</td><td class="header-value">${new Date(req.endTime).toLocaleTimeString()}</td></tr>` : ''}
          ${req.duration != null ? `<tr><td class="header-name">Duration</td><td class="header-value">${req.duration}ms</td></tr>` : ''}
        </table>
      </div>
    `;
  }
}

function renderHeadersTable(headers) {
  if (!headers || headers.length === 0) return '<p style="color: var(--text-muted); font-size: 12px;">No headers</p>';
  const sensitiveNames = /^(authorization|cookie|set-cookie|x-api-key|x-auth-token|proxy-authorization)$/i;
  return `<table class="headers-table">${headers.map(h => {
    const isSensitive = sensitiveNames.test(h.name);
    const value = highlightSensitive(escHtml(h.value));
    return `<tr><td class="header-name${isSensitive ? ' header-sensitive' : ''}">${escHtml(h.name)}${isSensitive ? ' <span class="sensitive-badge">sensitive</span>' : ''}</td><td class="header-value">${value}</td></tr>`;
  }).join('')}</table>`;
}

// ─── Intercept Tab (observe & replay — MV3 limitation) ───

function setupIntercept() {
  const toggleBtn = document.getElementById('interceptToggleBtn');
  const replayBtn = document.getElementById('forwardBtn');
  const dismissBtn = document.getElementById('dropBtn');

  toggleBtn.addEventListener('click', () => {
    intercepting = !intercepting;
    chrome.runtime.sendMessage({
      action: 'interceptor:setIntercept',
      enabled: intercepting
    }).catch(() => {});
    updateInterceptUI();
  });

  // "Forward" = send to Repeater for replay (since MV3 can't actually block/forward)
  replayBtn.addEventListener('click', replayIntercepted);
  dismissBtn.addEventListener('click', dismissIntercepted);
}

function handleIntercepted(data) {
  interceptQueue.push(data);
  if (!currentIntercept) showNextIntercept();
  updateInterceptUI();
}

function showNextIntercept() {
  if (interceptQueue.length === 0) {
    currentIntercept = null;
    updateInterceptUI();
    return;
  }
  currentIntercept = interceptQueue.shift();
  const textarea = document.getElementById('interceptTextarea');

  // Format as raw HTTP request for display
  let raw = `${currentIntercept.method} ${currentIntercept.url} HTTP/1.1\r\n`;
  if (currentIntercept.requestHeaders) {
    currentIntercept.requestHeaders.forEach(h => {
      raw += `${h.name}: ${h.value}\r\n`;
    });
  }
  raw += '\r\n';
  if (currentIntercept.requestBody) {
    raw += typeof currentIntercept.requestBody === 'string'
      ? currentIntercept.requestBody
      : JSON.stringify(currentIntercept.requestBody, null, 2);
  }
  textarea.value = raw;
  updateInterceptUI();
}

function replayIntercepted() {
  if (!currentIntercept) return;
  // Send the (potentially edited) request to Repeater for actual replay
  const raw = document.getElementById('interceptTextarea').value;
  const parsed = parseRawRequest(raw);

  // Populate Repeater with the intercepted request
  sendToRepeater({
    method: parsed.method || currentIntercept.method,
    url: parsed.url || currentIntercept.url,
    requestHeaders: parsed.headers,
    requestBody: parsed.body
  });

  showNextIntercept();
}

function dismissIntercepted() {
  if (!currentIntercept) return;
  showNextIntercept();
}

function updateInterceptUI() {
  const status = document.getElementById('interceptStatus');
  const editor = document.getElementById('interceptEditor');
  const empty = document.getElementById('interceptEmpty');
  const toggleBtn = document.getElementById('interceptToggleBtn');
  const queueInfo = document.getElementById('interceptQueueInfo');

  if (!intercepting) {
    status.classList.remove('intercepting');
    status.querySelector('.status-icon').textContent = '\u23f8';
    status.querySelector('h3').textContent = 'Intercept is off';
    status.querySelector('p').textContent = 'Enable intercept to observe requests in real-time. Edit and send to Repeater for replay.';
    toggleBtn.textContent = 'Enable Intercept';
    toggleBtn.className = 'btn btn-warning';
    editor.style.display = 'none';
    empty.style.display = 'none';
  } else if (!capturing) {
    status.classList.add('intercepting');
    status.querySelector('.status-icon').textContent = '\u26a0';
    status.querySelector('h3').textContent = 'Capture is not running';
    status.querySelector('p').textContent = 'Enable Capture first (top-right) to receive requests.';
    toggleBtn.textContent = 'Disable Intercept';
    toggleBtn.className = 'btn btn-danger';
    editor.style.display = 'none';
    empty.style.display = 'none';
  } else if (currentIntercept) {
    status.classList.add('intercepting');
    status.querySelector('.status-icon').textContent = '\u270b';
    status.querySelector('h3').textContent = 'Request observed';
    status.querySelector('p').textContent = `${currentIntercept.method} ${truncateUrl(currentIntercept.url, 60)}`;
    toggleBtn.textContent = 'Disable Intercept';
    toggleBtn.className = 'btn btn-danger';
    editor.style.display = 'flex';
    empty.style.display = 'none';
    queueInfo.textContent = interceptQueue.length > 0 ? `+${interceptQueue.length} queued` : '';
  } else {
    status.classList.add('intercepting');
    status.querySelector('.status-icon').textContent = '\u23f3';
    status.querySelector('h3').textContent = 'Intercept is active';
    status.querySelector('p').textContent = 'Waiting for requests matching your scope...';
    toggleBtn.textContent = 'Disable Intercept';
    toggleBtn.className = 'btn btn-danger';
    editor.style.display = 'none';
    empty.style.display = 'flex';
  }
}

// ─── Repeater Tab ────────────────────────────────────────

function setupRepeater() {
  document.getElementById('repeaterSendBtn').addEventListener('click', sendRepeaterRequest);

  // Request section tabs (headers / body)
  document.querySelectorAll('[data-rq]').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('[data-rq]').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      repeaterReqTab = tab.dataset.rq;
      renderRepeaterRequest();
    });
  });

  // Response section tabs
  document.querySelectorAll('[data-rs]').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('[data-rs]').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      repeaterResTab = tab.dataset.rs;
      renderRepeaterResponse();
    });
  });

  renderRepeaterHeaders();
}

function sendToRepeater(req) {
  // Switch to Repeater tab
  document.querySelectorAll('.tab-btn[data-tab]').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  document.querySelector('[data-tab="repeater"]').classList.add('active');
  document.getElementById('tab-repeater').classList.add('active');

  // Populate repeater
  document.getElementById('repeaterMethod').value = req.method;
  document.getElementById('repeaterUrl').value = req.url;
  repeaterHeaders = (req.requestHeaders || []).map(h => ({ name: h.name, value: h.value }));
  if (repeaterHeaders.length === 0) {
    repeaterHeaders = [{ name: 'User-Agent', value: 'Toolbelt-Interceptor/1.0' }];
  }
  renderRepeaterHeaders();

  // Set body if present
  if (req.requestBody) {
    repeaterReqTab = 'body';
    document.querySelectorAll('[data-rq]').forEach(t => t.classList.remove('active'));
    document.querySelector('[data-rq="body"]').classList.add('active');
    renderRepeaterRequest();
    const bodyArea = document.getElementById('repeaterReqBody').querySelector('textarea');
    if (bodyArea) {
      bodyArea.value = typeof req.requestBody === 'string' ? req.requestBody : JSON.stringify(req.requestBody, null, 2);
    }
  }
}

function renderRepeaterHeaders() {
  const container = document.getElementById('repeaterHeadersEditor');
  if (!container || repeaterReqTab !== 'headers') return;

  container.innerHTML = repeaterHeaders.map((h, i) => `
    <div class="header-row">
      <input type="text" placeholder="Header name" value="${escHtml(h.name)}" data-idx="${i}" data-field="name">
      <input type="text" placeholder="Header value" value="${escHtml(h.value)}" data-idx="${i}" data-field="value">
      <button class="remove-header" data-idx="${i}" title="Remove">&times;</button>
    </div>
  `).join('') + `
    <div class="header-row">
      <input type="text" placeholder="+ Add header name" data-idx="new" data-field="name">
      <input type="text" placeholder="Value" data-idx="new" data-field="value">
      <button class="remove-header" style="visibility: hidden;">&times;</button>
    </div>
  `;

  container.querySelectorAll('input').forEach(input => {
    input.addEventListener('change', () => {
      const idx = input.dataset.idx;
      const field = input.dataset.field;
      if (idx === 'new') {
        const nameVal = container.querySelector('[data-idx="new"][data-field="name"]').value;
        const valVal = container.querySelector('[data-idx="new"][data-field="value"]').value;
        if (nameVal.trim()) {
          repeaterHeaders = [...repeaterHeaders, { name: nameVal, value: valVal }];
          renderRepeaterHeaders();
        }
      } else {
        repeaterHeaders = repeaterHeaders.map((h, i) =>
          i === parseInt(idx) ? { ...h, [field]: input.value } : h
        );
      }
    });
  });

  container.querySelectorAll('.remove-header[data-idx]').forEach(btn => {
    btn.addEventListener('click', () => {
      const idx = parseInt(btn.dataset.idx);
      if (!isNaN(idx)) {
        repeaterHeaders = repeaterHeaders.filter((_, i) => i !== idx);
        renderRepeaterHeaders();
      }
    });
  });
}

function renderRepeaterRequest() {
  const body = document.getElementById('repeaterReqBody');
  if (repeaterReqTab === 'headers') {
    body.innerHTML = '<div id="repeaterHeadersEditor" class="repeater-headers-editor"></div>';
    renderRepeaterHeaders();
  } else {
    body.innerHTML = '<textarea class="repeater-textarea" id="repeaterBodyTextarea" placeholder="Request body (JSON, form data, etc.)" spellcheck="false"></textarea>';
  }
}

function renderRepeaterResponse() {
  const body = document.getElementById('repeaterResBody');
  const meta = document.getElementById('repeaterResponseMeta');

  if (!lastRepeaterResponse) {
    meta.style.display = 'none';
    body.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">&#x1f4e8;</div>
        <h3>No response yet</h3>
        <p>Configure a request and click <strong>Send</strong> or press <kbd>Ctrl+Enter</kbd>.</p>
      </div>
    `;
    return;
  }

  const res = lastRepeaterResponse;

  meta.style.display = 'flex';
  meta.innerHTML = `
    <span class="meta-item">Status: <span class="meta-value"><span class="status-badge status-${statusClass(res.status)}">${res.status} ${res.statusText || ''}</span></span></span>
    <span class="meta-item">Time: <span class="meta-value">${res.duration}ms</span></span>
    <span class="meta-item">Size: <span class="meta-value">${formatSize(res.size)}</span></span>
  `;

  if (repeaterResTab === 'headers') {
    body.innerHTML = renderHeadersTable(res.headers);
    body.style.padding = '12px 16px';
  } else if (repeaterResTab === 'body') {
    body.innerHTML = `<div class="body-content" style="margin: 12px 16px;">${formatBody(res.body)}</div>`;
    body.style.padding = '0';
  } else if (repeaterResTab === 'rendered') {
    // Sandboxed blob URL to prevent XSS in extension context
    if (res.contentType && res.contentType.includes('html')) {
      const blob = new Blob([res.body || ''], { type: 'text/html' });
      const blobUrl = URL.createObjectURL(blob);
      body.innerHTML = `<iframe sandbox src="${blobUrl}" style="width: 100%; height: 100%; border: none; background: #fff;"></iframe>`;
      // Clean up blob URL after iframe loads
      const iframe = body.querySelector('iframe');
      iframe.addEventListener('load', () => URL.revokeObjectURL(blobUrl));
    } else {
      body.innerHTML = `<div class="body-content" style="margin: 12px 16px;">${formatBody(res.body)}</div>`;
    }
    body.style.padding = '0';
  }
}

async function sendRepeaterRequest() {
  const method = document.getElementById('repeaterMethod').value;
  const url = document.getElementById('repeaterUrl').value.trim();
  if (!url) return;

  const sendBtn = document.getElementById('repeaterSendBtn');
  sendBtn.disabled = true;
  sendBtn.textContent = 'Sending...';

  const bodyTextarea = document.getElementById('repeaterBodyTextarea');
  const reqBody = bodyTextarea ? bodyTextarea.value : null;

  const headers = {};
  repeaterHeaders.forEach(h => {
    if (h.name.trim()) headers[h.name] = h.value;
  });

  try {
    const response = await chrome.runtime.sendMessage({
      action: 'interceptor:repeater',
      method,
      url,
      headers,
      body: (method !== 'GET' && method !== 'HEAD') ? reqBody : undefined
    });

    lastRepeaterResponse = response;
    renderRepeaterResponse();
  } catch (err) {
    lastRepeaterResponse = {
      status: 0,
      statusText: 'Error',
      headers: [],
      body: `Error: ${err.message}`,
      duration: 0,
      size: 0,
      contentType: 'text/plain'
    };
    renderRepeaterResponse();
  } finally {
    sendBtn.disabled = false;
    sendBtn.textContent = 'Send';
  }
}

// ─── WebSocket Capture ───────────────────────────────────

function handleWebSocketEvent(data) {
  const { event, requestId, tabId } = data;

  switch (event) {
    case 'created': {
      wsConnections.set(requestId, {
        url: data.url,
        tabId,
        frames: [],
        startTime: data.timestamp
      });
      addConsoleEntry({
        type: 'websocket',
        args: [`WS Connected: ${data.url}`],
        timestamp: data.timestamp,
        tabId,
        wsEvent: 'created',
        wsRequestId: requestId,
        url: data.url
      });
      break;
    }

    case 'sent': {
      const conn = wsConnections.get(requestId);
      const frame = {
        direction: 'sent',
        data: data.data,
        opcode: data.opcode,
        timestamp: data.timestamp
      };
      if (conn) conn.frames.push(frame);
      addConsoleEntry({
        type: 'websocket',
        args: [`WS \u2191 ${truncateWsData(data.data)}`],
        timestamp: data.timestamp,
        tabId,
        wsEvent: 'sent',
        wsRequestId: requestId,
        wsData: data.data,
        url: conn?.url || ''
      });
      break;
    }

    case 'received': {
      const conn = wsConnections.get(requestId);
      const frame = {
        direction: 'received',
        data: data.data,
        opcode: data.opcode,
        timestamp: data.timestamp
      };
      if (conn) conn.frames.push(frame);
      addConsoleEntry({
        type: 'websocket',
        args: [`WS \u2193 ${truncateWsData(data.data)}`],
        timestamp: data.timestamp,
        tabId,
        wsEvent: 'received',
        wsRequestId: requestId,
        wsData: data.data,
        url: conn?.url || ''
      });
      break;
    }

    case 'closed': {
      const conn = wsConnections.get(requestId);
      addConsoleEntry({
        type: 'websocket',
        args: [`WS Closed${conn ? ': ' + conn.url : ''} (${conn ? conn.frames.length + ' frames' : ''})`],
        timestamp: data.timestamp,
        tabId,
        wsEvent: 'closed',
        wsRequestId: requestId,
        url: conn?.url || ''
      });
      break;
    }

    case 'error': {
      const conn = wsConnections.get(requestId);
      addConsoleEntry({
        type: 'websocket',
        args: [`WS Error: ${data.errorMessage || 'Unknown error'}${conn ? ' (' + conn.url + ')' : ''}`],
        timestamp: data.timestamp,
        tabId,
        wsEvent: 'error',
        wsRequestId: requestId,
        url: conn?.url || ''
      });
      break;
    }
  }
}

function truncateWsData(data) {
  if (!data) return '[empty]';
  if (data.length <= 120) return data;
  return data.slice(0, 117) + '...';
}

// ─── Console Tab ─────────────────────────────────────────

function setupConsole() {
  document.getElementById('clearConsoleBtn').addEventListener('click', () => {
    consoleEntries = [];
    consoleErrorCount = 0;
    renderConsole();
    updateConsoleErrorBadge();
  });

  document.getElementById('consoleLevelFilter').addEventListener('change', renderConsole);
  document.getElementById('consoleFilterInput').addEventListener('input', renderConsole);
}

function addConsoleEntry(data) {
  const entry = {
    type: data.type || 'log',
    args: data.args || [],
    timestamp: data.timestamp || Date.now(),
    url: data.url || (data.stackTrace && data.stackTrace[0] ? data.stackTrace[0].url : ''),
    lineNumber: data.lineNumber || (data.stackTrace && data.stackTrace[0] ? data.stackTrace[0].lineNumber : null),
    source: data.source || 'javascript',
    tabId: data.tabId,
    stackTrace: data.stackTrace
  };

  consoleEntries.push(entry);

  // Track error count for badge
  if (entry.type === 'error' || entry.type === 'exception') {
    consoleErrorCount++;
    updateConsoleErrorBadge();
  }

  renderConsole();
}

function updateConsoleErrorBadge() {
  const badge = document.getElementById('consoleErrorCount');
  if (consoleErrorCount > 0) {
    badge.textContent = consoleErrorCount;
    badge.style.display = 'inline';
  } else {
    badge.style.display = 'none';
  }
}

let consoleRenderPending = false;

function renderConsole() {
  if (consoleRenderPending) return;
  consoleRenderPending = true;
  requestAnimationFrame(() => {
    consoleRenderPending = false;
    doRenderConsole();
  });
}

function doRenderConsole() {
  const output = document.getElementById('consoleOutput');
  const empty = document.getElementById('consoleEmpty');
  const levelFilter = document.getElementById('consoleLevelFilter').value;
  const textFilter = document.getElementById('consoleFilterInput').value.trim().toLowerCase();

  let filtered = consoleEntries;

  if (levelFilter) {
    filtered = filtered.filter(e => e.type === levelFilter);
  }

  if (textFilter) {
    filtered = filtered.filter(e =>
      e.args.some(a => String(a).toLowerCase().includes(textFilter)) ||
      (e.url && e.url.toLowerCase().includes(textFilter))
    );
  }

  if (filtered.length === 0) {
    output.innerHTML = '';
    output.appendChild(empty);
    empty.style.display = 'flex';
    return;
  }

  empty.style.display = 'none';

  const fragment = document.createDocumentFragment();
  for (const entry of filtered) {
    const div = document.createElement('div');
    const wsSubclass = entry.wsEvent ? ` ws-${entry.wsEvent}` : '';
    div.className = `console-entry level-${entry.type}${wsSubclass}`;

    const time = new Date(entry.timestamp).toLocaleTimeString();
    const msg = entry.args.map(a => String(a)).join(' ');
    const source = entry.url ? shortenUrl(entry.url) + (entry.lineNumber != null ? ':' + entry.lineNumber : '') : '';

    // For WebSocket data frames, show expandable data
    if (entry.type === 'websocket' && entry.wsData && entry.wsData.length > 120) {
      div.innerHTML = `
        <span class="console-time">${time}</span>
        <span class="console-level ws-badge">${entry.wsEvent === 'sent' ? '\u2191 WS' : '\u2193 WS'}</span>
        <span class="console-message ws-message">${escHtml(truncateWsData(entry.wsData))}</span>
        <span class="console-source" title="${escHtml(entry.url || '')}">${escHtml(source)}</span>
      `;
      div.style.cursor = 'pointer';
      div.title = 'Click to expand';
      div.addEventListener('click', () => {
        const msgSpan = div.querySelector('.ws-message');
        const isExpanded = div.dataset.expanded === '1';
        if (isExpanded) {
          msgSpan.textContent = truncateWsData(entry.wsData);
          div.dataset.expanded = '0';
        } else {
          try {
            const parsed = JSON.parse(entry.wsData);
            msgSpan.textContent = JSON.stringify(parsed, null, 2);
          } catch {
            msgSpan.textContent = entry.wsData;
          }
          msgSpan.style.whiteSpace = 'pre-wrap';
          div.dataset.expanded = '1';
        }
      });
    } else {
      div.innerHTML = `
        <span class="console-time">${time}</span>
        <span class="console-level">${escHtml(entry.type === 'websocket' ? 'WS' : entry.type)}</span>
        <span class="console-message">${escHtml(msg)}</span>
        <span class="console-source" title="${escHtml(entry.url || '')}">${escHtml(source)}</span>
      `;
    }

    fragment.appendChild(div);
  }

  output.innerHTML = '';
  output.appendChild(fragment);

  // Auto-scroll
  if (autoScroll) {
    output.scrollTop = output.scrollHeight;
  }
}

function shortenUrl(url) {
  if (!url) return '';
  try {
    const u = new URL(url);
    const path = u.pathname.split('/').pop() || u.pathname;
    return path;
  } catch {
    return url.length > 40 ? '...' + url.slice(-37) : url;
  }
}

// ─── Compare Tab ─────────────────────────────────────────

function setupCompare() {
  document.getElementById('compareRunBtn').addEventListener('click', runCompare);

  // Refresh dropdowns when switching to compare tab
  document.querySelector('[data-tab="compare"]').addEventListener('click', refreshCompareDropdowns);
}

function refreshCompareDropdowns() {
  const leftSel = document.getElementById('compareLeft');
  const rightSel = document.getElementById('compareRight');
  const leftVal = leftSel.value;
  const rightVal = rightSel.value;

  const options = '<option value="">Select request</option>' + requests.map(r =>
    `<option value="${r.id}">#${r.id} ${escHtml(r.method)} ${escHtml(truncateUrl(r.url, 40))}</option>`
  ).join('');

  leftSel.innerHTML = options;
  rightSel.innerHTML = options;
  if (leftVal) leftSel.value = leftVal;
  if (rightVal) rightSel.value = rightVal;
}

function runCompare() {
  const leftId = parseInt(document.getElementById('compareLeft').value);
  const rightId = parseInt(document.getElementById('compareRight').value);
  const focus = document.getElementById('compareFocus').value;
  const result = document.getElementById('compareResult');

  if (!leftId || !rightId) {
    showToast('Select two requests to compare');
    return;
  }
  if (leftId === rightId) {
    showToast('Select two different requests');
    return;
  }

  const left = requests.find(r => r.id === leftId);
  const right = requests.find(r => r.id === rightId);
  if (!left || !right) return;

  let leftText, rightText;
  const leftLabel = `#${left.id} ${left.method} ${truncateUrl(left.url, 50)}`;
  const rightLabel = `#${right.id} ${right.method} ${truncateUrl(right.url, 50)}`;

  if (focus === 'headers') {
    leftText = formatHeadersForDiff(left);
    rightText = formatHeadersForDiff(right);
  } else if (focus === 'body') {
    leftText = formatBodyForDiff(left.responseBody);
    rightText = formatBodyForDiff(right.responseBody);
  } else {
    leftText = formatFullRequestForDiff(left);
    rightText = formatFullRequestForDiff(right);
  }

  const diff = computeLineDiff(leftText, rightText);

  result.innerHTML = `
    <div class="compare-header">
      <div class="compare-label compare-left-label">${escHtml(leftLabel)}</div>
      <div class="compare-label compare-right-label">${escHtml(rightLabel)}</div>
    </div>
    <div class="compare-body">
      <div class="compare-pane compare-left">${diff.left}</div>
      <div class="compare-pane compare-right">${diff.right}</div>
    </div>
  `;
}

function formatHeadersForDiff(req) {
  const lines = [];
  lines.push(`${req.method} ${req.url}`);
  lines.push('');
  lines.push('--- Request Headers ---');
  (req.requestHeaders || []).forEach(h => lines.push(`${h.name}: ${h.value}`));
  lines.push('');
  lines.push('--- Response Headers ---');
  (req.responseHeaders || []).forEach(h => lines.push(`${h.name}: ${h.value}`));
  return lines.join('\n');
}

function formatBodyForDiff(body) {
  if (!body) return '(empty)';
  const str = typeof body === 'string' ? body : JSON.stringify(body);
  try {
    return JSON.stringify(JSON.parse(str), null, 2);
  } catch {
    return str;
  }
}

function formatFullRequestForDiff(req) {
  const lines = [];
  lines.push(`${req.method} ${req.url} HTTP/1.1`);
  (req.requestHeaders || []).forEach(h => lines.push(`${h.name}: ${h.value}`));
  lines.push('');
  if (req.requestBody) {
    lines.push(typeof req.requestBody === 'string' ? req.requestBody : JSON.stringify(req.requestBody, null, 2));
    lines.push('');
  }
  lines.push(`--- Response: ${req.statusCode} ---`);
  (req.responseHeaders || []).forEach(h => lines.push(`${h.name}: ${h.value}`));
  lines.push('');
  if (req.responseBody) {
    lines.push(formatBodyForDiff(req.responseBody));
  }
  return lines.join('\n');
}

function computeLineDiff(leftText, rightText) {
  const leftLines = leftText.split('\n');
  const rightLines = rightText.split('\n');
  const maxLen = Math.max(leftLines.length, rightLines.length);

  let leftHtml = '';
  let rightHtml = '';

  for (let i = 0; i < maxLen; i++) {
    const l = i < leftLines.length ? leftLines[i] : null;
    const r = i < rightLines.length ? rightLines[i] : null;

    if (l === r) {
      leftHtml += `<div class="diff-line">${escHtml(l)}</div>`;
      rightHtml += `<div class="diff-line">${escHtml(r)}</div>`;
    } else if (l == null) {
      leftHtml += `<div class="diff-line diff-empty">&nbsp;</div>`;
      rightHtml += `<div class="diff-line diff-added">${escHtml(r)}</div>`;
    } else if (r == null) {
      leftHtml += `<div class="diff-line diff-removed">${escHtml(l)}</div>`;
      rightHtml += `<div class="diff-line diff-empty">&nbsp;</div>`;
    } else {
      leftHtml += `<div class="diff-line diff-removed">${escHtml(l)}</div>`;
      rightHtml += `<div class="diff-line diff-added">${escHtml(r)}</div>`;
    }
  }

  return { left: leftHtml, right: rightHtml };
}

// ─── AI Analyze Tab ──────────────────────────────────────

function setupAnalyze() {
  const focusSelect = document.getElementById('analyzeFocus');
  const customPrompt = document.getElementById('analyzeCustomPrompt');
  const runBtn = document.getElementById('analyzeRunBtn');
  const copyBtn = document.getElementById('analyzeCopyBtn');
  const copyResultBtn = document.getElementById('analyzeCopyResultBtn');
  const selectAllBtn = document.getElementById('analyzeSelectAll');

  focusSelect.addEventListener('change', () => {
    customPrompt.style.display = focusSelect.value === 'custom' ? 'block' : 'none';
  });

  runBtn.addEventListener('click', runAiAnalysis);
  copyBtn.addEventListener('click', () => {
    const prompt = buildAnalysisPrompt();
    if (!prompt) return;
    copyToClipboard(prompt, 'Prompt copied — paste into any AI chat');
  });

  copyResultBtn.addEventListener('click', () => {
    const result = document.getElementById('analyzeResult');
    const text = result.innerText || result.textContent;
    copyToClipboard(text, 'Analysis copied');
  });

  selectAllBtn.addEventListener('click', () => {
    document.getElementById('analyzeIncludeRequests').checked = true;
    document.getElementById('analyzeIncludeHeaders').checked = true;
    document.getElementById('analyzeIncludeBodies').checked = true;
    document.getElementById('analyzeOnlyErrors').checked = false;
    document.getElementById('analyzeIncludeConsole').checked = true;
    document.getElementById('analyzeOnlyConsoleErrors').checked = false;
  });

  // Update counts when switching to analyze tab and when checkboxes change
  document.querySelector('[data-tab="analyze"]').addEventListener('click', updateAnalyzeCounts);
  document.getElementById('analyzeOnlyErrors').addEventListener('change', updateAnalyzeCounts);
  document.getElementById('analyzeOnlyConsoleErrors').addEventListener('change', updateAnalyzeCounts);
}

function updateAnalyzeCounts() {
  const onlyErrors = document.getElementById('analyzeOnlyErrors').checked;
  const reqCount = onlyErrors
    ? requests.filter(r => r.statusCode >= 400).length
    : requests.length;

  const onlyConsoleErrors = document.getElementById('analyzeOnlyConsoleErrors').checked;
  const consCount = onlyConsoleErrors
    ? consoleEntries.filter(e => e.type === 'error' || e.type === 'exception').length
    : consoleEntries.length;

  document.getElementById('analyzeRequestCount').textContent = reqCount;
  document.getElementById('analyzeConsoleCount').textContent = consCount;
}

function getAnalysisRequests() {
  const onlyErrors = document.getElementById('analyzeOnlyErrors').checked;
  const includeHeaders = document.getElementById('analyzeIncludeHeaders').checked;
  const includeBodies = document.getElementById('analyzeIncludeBodies').checked;

  let reqs = onlyErrors
    ? requests.filter(r => r.statusCode >= 400)
    : [...requests];

  // Limit to last 50 to avoid token explosion
  if (reqs.length > 50) reqs = reqs.slice(-50);

  return reqs.map(r => {
    const entry = {
      id: r.id,
      method: r.method,
      url: r.url,
      status: r.statusCode,
      type: r.type,
      size: r.responseSize,
      duration: r.duration
    };
    if (includeHeaders && r.requestHeaders.length > 0) {
      entry.requestHeaders = r.requestHeaders.map(h => `${h.name}: ${h.value}`);
    }
    if (includeHeaders && r.responseHeaders.length > 0) {
      entry.responseHeaders = r.responseHeaders.map(h => `${h.name}: ${h.value}`);
    }
    if (includeBodies && r.responseBody) {
      // Truncate large bodies
      const body = typeof r.responseBody === 'string' ? r.responseBody : JSON.stringify(r.responseBody);
      entry.responseBody = body.length > 2000 ? body.slice(0, 2000) + '...[truncated]' : body;
    }
    if (includeBodies && r.requestBody) {
      const body = typeof r.requestBody === 'string' ? r.requestBody : JSON.stringify(r.requestBody);
      entry.requestBody = body.length > 1000 ? body.slice(0, 1000) + '...[truncated]' : body;
    }
    return entry;
  });
}

function getAnalysisConsoleEntries() {
  const onlyErrors = document.getElementById('analyzeOnlyConsoleErrors').checked;
  let entries = onlyErrors
    ? consoleEntries.filter(e => e.type === 'error' || e.type === 'exception')
    : [...consoleEntries];

  // Limit to last 30
  if (entries.length > 30) entries = entries.slice(-30);

  return entries.map(e => {
    let message = e.args.map(a => String(a)).join(' ');
    if (message.length > 2000) message = message.slice(0, 2000) + '...[truncated]';
    return {
      type: e.type,
      message,
      source: e.url || '',
      line: e.lineNumber
    };
  });
}

function getFocusPrompt() {
  const focus = document.getElementById('analyzeFocus').value;
  switch (focus) {
    case 'security':
      return 'Focus on SECURITY: Look for sensitive data in URLs/headers/bodies, insecure headers (missing HSTS, CSP, X-Frame-Options), exposed API keys/tokens, CORS issues, mixed content, suspicious redirects, and potential injection vectors.';
    case 'performance':
      return 'Focus on PERFORMANCE: Analyze request timing, identify slow requests, check for unnecessary requests, evaluate caching headers (Cache-Control, ETag), find large payloads, detect render-blocking resources, and suggest optimization opportunities.';
    case 'errors':
      return 'Focus on ERROR DIAGNOSIS: Analyze all error responses (4xx/5xx) and console errors. Identify root causes, correlate related errors, check for cascading failures, and provide actionable fix suggestions.';
    case 'api':
      return 'Focus on API HEALTH: Evaluate API response patterns, check for consistent error handling, validate response formats, identify rate limiting issues, check authentication patterns, and assess overall API design quality.';
    case 'custom':
      return document.getElementById('analyzeCustomPrompt').value.trim() || 'Provide a general analysis.';
    default:
      return 'Provide a comprehensive analysis covering security, performance, errors, and any notable patterns.';
  }
}

function buildAnalysisPrompt() {
  const includeRequests = document.getElementById('analyzeIncludeRequests').checked;
  const includeConsole = document.getElementById('analyzeIncludeConsole').checked;

  if (!includeRequests && !includeConsole) {
    showToast('Select at least requests or console entries');
    return null;
  }

  const parts = [];
  parts.push('You are analyzing HTTP traffic and browser console output captured from a web application. Provide a structured, actionable analysis.\n');
  parts.push(getFocusPrompt());
  parts.push('');

  if (includeRequests) {
    const reqs = getAnalysisRequests();
    if (reqs.length > 0) {
      parts.push(`## HTTP Requests (${reqs.length} captured)\n`);
      parts.push('```json');
      parts.push(JSON.stringify(reqs, null, 2));
      parts.push('```\n');
    } else {
      parts.push('## HTTP Requests\nNo requests captured.\n');
    }
  }

  if (includeConsole) {
    const entries = getAnalysisConsoleEntries();
    if (entries.length > 0) {
      parts.push(`## Console Output (${entries.length} entries)\n`);
      parts.push('```json');
      parts.push(JSON.stringify(entries, null, 2));
      parts.push('```\n');
    } else {
      parts.push('## Console Output\nNo console entries.\n');
    }
  }

  parts.push('## Instructions');
  parts.push('1. Summarize what the application is doing based on the traffic');
  parts.push('2. Highlight any issues found (prioritized by severity)');
  parts.push('3. Provide specific, actionable recommendations');
  parts.push('4. Use markdown formatting with headers and bullet points');

  const prompt = parts.join('\n');

  // ~4 chars per token, limit to ~30K tokens input (~120K chars)
  const MAX_PROMPT_CHARS = 120_000;
  if (prompt.length > MAX_PROMPT_CHARS) {
    showToast(`Prompt too large (${(prompt.length / 1000).toFixed(0)}K chars). Reduce selections or disable bodies.`);
    return null;
  }

  return prompt;
}

async function runAiAnalysis() {
  const prompt = buildAnalysisPrompt();
  if (!prompt) return;

  // Warn if prompt contains potentially sensitive data
  const sensitivePattern = /(?:Bearer |Basic |api[_-]?key|password|token|secret|authorization|cookie|set-cookie)/i;
  if (sensitivePattern.test(prompt)) {
    const proceed = confirm(
      'The captured data may contain sensitive information (tokens, cookies, API keys).\n' +
      'This will be sent to an external AI provider.\n\nContinue?'
    );
    if (!proceed) return;
  }

  updateAnalyzeCounts();

  const resultDiv = document.getElementById('analyzeResult');
  const copyResultBtn = document.getElementById('analyzeCopyResultBtn');
  const runBtn = document.getElementById('analyzeRunBtn');

  // Show loading state
  resultDiv.innerHTML = '<div class="analyze-loading"><div class="spinner"></div>Analyzing traffic with AI...</div>';
  copyResultBtn.style.display = 'none';
  runBtn.disabled = true;
  runBtn.textContent = 'Analyzing...';

  try {
    const response = await chrome.runtime.sendMessage({
      action: 'aiGenerate',
      prompt: prompt
    });

    if (response && response.success) {
      const aiText = response.text || response.message || '';
      if (!aiText.trim()) {
        resultDiv.innerHTML = '<div class="analyze-error">AI returned an empty response. Try again or adjust the analysis scope.</div>';
      } else {
        resultDiv.innerHTML = `<div class="ai-response">${renderMarkdown(aiText)}</div>`;
        copyResultBtn.style.display = 'inline-block';
      }
    } else {
      const error = response?.error || 'Unknown error';
      if (error.includes('API key') || error.includes('No API key')) {
        resultDiv.innerHTML = `
          <div class="analyze-error">
            <strong>No API key configured</strong><br>
            Go to Toolbelt Settings &gt; API Keys and add a Claude, OpenAI, or Gemini API key.<br><br>
            Alternatively, use <strong>Copy prompt for AI</strong> to paste the analysis into any AI chat.
          </div>
        `;
      } else {
        resultDiv.innerHTML = `<div class="analyze-error">${escHtml(error)}</div>`;
      }
    }
  } catch (err) {
    resultDiv.innerHTML = `<div class="analyze-error">Failed to connect to AI service: ${escHtml(err.message)}</div>`;
  } finally {
    runBtn.disabled = false;
    runBtn.textContent = 'Analyze with AI';
  }
}

// Markdown-to-HTML renderer (escape-first to prevent XSS from AI responses)
function renderMarkdown(text) {
  if (!text) return '';

  // Step 1: Extract fenced code blocks before escaping (they get their own escaping)
  const codeBlocks = [];
  let processed = text.replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) => {
    const idx = codeBlocks.length;
    codeBlocks.push(`<pre><code>${escHtml(code.trim())}</code></pre>`);
    return `\x00CB${idx}\x00`;
  });

  // Step 2: Escape ALL remaining HTML (this makes all AI output safe)
  processed = escHtml(processed);

  // Step 3: Apply markdown rules (content is already escaped, tags we insert are safe)
  processed = processed
    // Lists first (before italic, so * list markers aren't consumed by italic)
    .replace(/^[*-] (.+)$/gm, '<li>$1</li>')
    .replace(/^\d+\. (.+)$/gm, '<li>$1</li>')
    .replace(/((?:<li>.*<\/li>\n?)+)/g, '<ul>$1</ul>')
    // Inline code
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    // Headers
    .replace(/^### (.+)$/gm, '<h3>$1</h3>')
    .replace(/^## (.+)$/gm, '<h2>$1</h2>')
    .replace(/^# (.+)$/gm, '<h1>$1</h1>')
    // Bold (must come before italic)
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    // Italic (non-greedy, won't cross lines)
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
    // Paragraphs (double newlines)
    .replace(/\n\n/g, '</p><p>')
    // Single newlines to <br>
    .replace(/\n/g, '<br>');

  // Step 4: Restore code blocks
  codeBlocks.forEach((block, i) => {
    processed = processed.replace(`\x00CB${i}\x00`, block);
  });

  return `<p>${processed}</p>`;
}

// ─── Keyboard Shortcuts ──────────────────────────────────

function setupKeyboard() {
  document.addEventListener('keydown', (e) => {
    const activeTab = document.querySelector('.tab-content.active');
    if (!activeTab) return;

    // Ctrl+Enter: send repeater request
    if (e.ctrlKey && e.key === 'Enter' && activeTab.id === 'tab-repeater') {
      e.preventDefault();
      sendRepeaterRequest();
    }

    // Ctrl+R: replay intercepted to Repeater
    if (e.ctrlKey && e.key === 'r' && activeTab.id === 'tab-intercept' && currentIntercept) {
      e.preventDefault();
      replayIntercepted();
    }

    // Ctrl+D: dismiss intercepted
    if (e.ctrlKey && e.key === 'd' && activeTab.id === 'tab-intercept' && currentIntercept) {
      e.preventDefault();
      dismissIntercepted();
    }
  });
}

// ─── HAR Export ──────────────────────────────────────────

function exportHar() {
  const har = {
    log: {
      version: '1.2',
      creator: { name: 'Toolbelt Interceptor', version: '1.0' },
      entries: requests.map(r => ({
        startedDateTime: new Date(r.startTime).toISOString(),
        time: r.duration || 0,
        request: {
          method: r.method,
          url: r.url,
          httpVersion: 'HTTP/1.1',
          cookies: [],
          headers: r.requestHeaders.map(h => ({ name: h.name, value: h.value })),
          queryString: parseQueryString(r.url),
          bodySize: r.requestBody ? new Blob([typeof r.requestBody === 'string' ? r.requestBody : JSON.stringify(r.requestBody)]).size : 0,
          postData: r.requestBody ? { mimeType: 'application/json', text: typeof r.requestBody === 'string' ? r.requestBody : JSON.stringify(r.requestBody) } : undefined
        },
        response: {
          status: r.statusCode,
          statusText: '',
          httpVersion: 'HTTP/1.1',
          cookies: [],
          headers: r.responseHeaders.map(h => ({ name: h.name, value: h.value })),
          redirectURL: '',
          content: {
            size: r.responseSize,
            mimeType: (r.responseHeaders.find(h => h.name.toLowerCase() === 'content-type') || {}).value || '',
            text: r.responseBody || ''
          },
          bodySize: r.responseSize
        },
        timings: { send: 0, wait: r.duration || 0, receive: 0 }
      }))
    }
  };

  const blob = new Blob([JSON.stringify(har, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement('a');
    a.href = url;
    a.download = `interceptor-${new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-')}.har`;
    a.click();
  } finally {
    URL.revokeObjectURL(url);
  }
}

// ─── State Persistence ───────────────────────────────────

function saveState() {
  chrome.storage.local.set({
    interceptor_scope: document.getElementById('scopeInput').value,
    interceptor_scopeMode: document.getElementById('scopeMode').value
  });
}

function loadState() {
  chrome.storage.local.get(['interceptor_scope', 'interceptor_scopeMode'], (result) => {
    if (result.interceptor_scope) {
      document.getElementById('scopeInput').value = result.interceptor_scope;
    }
    if (result.interceptor_scopeMode) {
      document.getElementById('scopeMode').value = result.interceptor_scopeMode;
      updateScopeModeUI();
    }
  });

  // Sync with background state (in case service worker is already capturing)
  chrome.runtime.sendMessage({ action: 'interceptor:getState' })
    .then(state => { if (state) syncState(state); })
    .catch(() => {});
}

// ─── Session Management ──────────────────────────────────

function setupSessions() {
  document.getElementById('saveSessionBtn').addEventListener('click', saveSession);
  document.getElementById('loadSessionBtn').addEventListener('click', showSessionModal);
  document.getElementById('sessionModalClose').addEventListener('click', hideSessionModal);
  document.getElementById('sessionModal').addEventListener('click', (e) => {
    if (e.target.id === 'sessionModal') hideSessionModal();
  });
}

async function saveSession() {
  if (requests.length === 0 && consoleEntries.length === 0) {
    showToast('Nothing to save');
    return;
  }

  const name = prompt('Session name:', `Session ${new Date().toLocaleString()}`);
  if (!name) return;

  const session = {
    name,
    timestamp: Date.now(),
    requests: requests.map(r => ({
      ...r,
      // Truncate large response bodies to keep storage manageable
      responseBody: r.responseBody && r.responseBody.length > 50000
        ? r.responseBody.slice(0, 50000) + '...[truncated]'
        : r.responseBody
    })),
    consoleEntries: consoleEntries.slice(-500), // Keep last 500 console entries
    requestCount: requests.length,
    consoleCount: consoleEntries.length
  };

  try {
    const result = await chrome.storage.local.get('interceptor_sessions');
    const sessions = result.interceptor_sessions || [];
    sessions.push(session);

    // Keep max 20 sessions
    while (sessions.length > 20) sessions.shift();

    await chrome.storage.local.set({ interceptor_sessions: sessions });
    showToast(`Session "${name}" saved`);
  } catch (err) {
    showToast('Failed to save: ' + err.message);
  }
}

async function showSessionModal() {
  const modal = document.getElementById('sessionModal');
  const body = document.getElementById('sessionModalBody');

  try {
    const result = await chrome.storage.local.get('interceptor_sessions');
    const sessions = result.interceptor_sessions || [];

    if (sessions.length === 0) {
      body.innerHTML = '<div class="empty-state"><p>No saved sessions</p></div>';
    } else {
      body.innerHTML = sessions.map((s, i) => `
        <div class="session-item" data-index="${i}">
          <div class="session-item-info">
            <strong>${escHtml(s.name)}</strong>
            <span class="session-meta">
              ${new Date(s.timestamp).toLocaleString()} &middot;
              ${s.requestCount || s.requests?.length || 0} requests &middot;
              ${s.consoleCount || s.consoleEntries?.length || 0} console entries
            </span>
          </div>
          <div class="session-item-actions">
            <button class="btn btn-primary btn-sm session-load-btn" data-index="${i}">Load</button>
            <button class="btn btn-ghost btn-sm session-delete-btn" data-index="${i}">Delete</button>
          </div>
        </div>
      `).reverse().join('');

      body.querySelectorAll('.session-load-btn').forEach(btn => {
        btn.addEventListener('click', () => loadSession(parseInt(btn.dataset.index)));
      });
      body.querySelectorAll('.session-delete-btn').forEach(btn => {
        btn.addEventListener('click', () => deleteSession(parseInt(btn.dataset.index)));
      });
    }
  } catch {
    body.innerHTML = '<div class="empty-state"><p>Error loading sessions</p></div>';
  }

  modal.style.display = 'flex';
}

function hideSessionModal() {
  document.getElementById('sessionModal').style.display = 'none';
}

async function loadSession(index) {
  try {
    const result = await chrome.storage.local.get('interceptor_sessions');
    const sessions = result.interceptor_sessions || [];
    const session = sessions[index];
    if (!session) return;

    // Confirm if there's existing data
    if (requests.length > 0 || consoleEntries.length > 0) {
      if (!confirm('Loading a session will replace current data. Continue?')) return;
    }

    requests = session.requests || [];
    nextId = requests.length > 0 ? Math.max(...requests.map(r => r.id)) + 1 : 1;
    consoleEntries = session.consoleEntries || [];
    consoleErrorCount = consoleEntries.filter(e => e.type === 'error' || e.type === 'exception').length;
    selectedRequest = null;
    wsConnections.clear();

    renderHistory();
    renderConsole();
    updateConsoleErrorBadge();
    hideDetail();
    hideSessionModal();
    showToast(`Loaded "${session.name}"`);
  } catch (err) {
    showToast('Failed to load: ' + err.message);
  }
}

async function deleteSession(index) {
  try {
    const result = await chrome.storage.local.get('interceptor_sessions');
    const sessions = result.interceptor_sessions || [];
    const name = sessions[index]?.name || 'session';

    if (!confirm(`Delete "${name}"?`)) return;

    sessions.splice(index, 1);
    await chrome.storage.local.set({ interceptor_sessions: sessions });
    showToast(`Deleted "${name}"`);
    showSessionModal(); // Refresh list
  } catch (err) {
    showToast('Failed to delete: ' + err.message);
  }
}

// ─── Utilities ───────────────────────────────────────────

function escHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function truncateUrl(url, maxLen = 80) {
  if (!url) return '';
  try {
    const u = new URL(url);
    const display = u.origin + u.pathname + u.search;
    return display.length > maxLen ? display.slice(0, maxLen) + '...' : display;
  } catch {
    return url.length > maxLen ? url.slice(0, maxLen) + '...' : url;
  }
}

function statusClass(code) {
  if (code >= 200 && code < 300) return '2xx';
  if (code >= 300 && code < 400) return '3xx';
  if (code >= 400 && code < 500) return '4xx';
  if (code >= 500) return '5xx';
  return '0';
}

function formatSize(bytes) {
  if (bytes == null || bytes === undefined) return '-';
  if (bytes === 0) return '0B';
  if (bytes < 1024) return bytes + 'B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + 'KB';
  return (bytes / (1024 * 1024)).toFixed(1) + 'MB';
}

function formatBody(body) {
  if (!body) return '<span style="color: var(--text-muted);">Empty body</span>';
  const str = typeof body === 'string' ? body : JSON.stringify(body);
  try {
    const parsed = JSON.parse(str);
    return highlightSensitive(escHtml(JSON.stringify(parsed, null, 2)));
  } catch {
    return highlightSensitive(escHtml(str));
  }
}

function parseQueryString(url) {
  try {
    return Array.from(new URL(url).searchParams.entries()).map(([name, value]) => ({ name, value }));
  } catch {
    return [];
  }
}

function parseRawRequest(raw) {
  const lines = raw.split(/\r?\n/);
  const parts = (lines[0] || '').split(' ');
  const method = parts[0] || 'GET';
  // parts[1] could be a full URL or a path — reconstruct from Host header if needed
  let url = parts[1] || '/';
  const headers = [];
  let bodyStart = -1;

  for (let i = 1; i < lines.length; i++) {
    if (lines[i].trim() === '') {
      bodyStart = i + 1;
      break;
    }
    const colonIdx = lines[i].indexOf(':');
    if (colonIdx > 0) {
      headers.push({
        name: lines[i].slice(0, colonIdx).trim(),
        value: lines[i].slice(colonIdx + 1).trim()
      });
    }
  }

  // If URL is relative (path only), reconstruct from Host header
  if (url.startsWith('/')) {
    const hostHeader = headers.find(h => h.name.toLowerCase() === 'host');
    if (hostHeader) {
      url = `https://${hostHeader.value}${url}`;
    }
  }

  const body = bodyStart > 0 ? lines.slice(bodyStart).join('\n') : null;

  return { method, url, headers, body };
}

// ─── Sensitive Data Highlighting ─────────────────────────

const SENSITIVE_PATTERNS = [
  // Auth tokens
  { re: /(Bearer\s+)([A-Za-z0-9\-._~+/]+=*)/g, label: 'token' },
  { re: /(Basic\s+)([A-Za-z0-9+/]+=*)/g, label: 'credentials' },
  // API keys (common formats)
  { re: /((?:api[_-]?key|apikey|api_secret|access[_-]?token|secret[_-]?key)\s*[:=]\s*)([^\s&"',;]{8,})/gi, label: 'api-key' },
  // AWS-style keys
  { re: /(AKIA[0-9A-Z]{16})/g, label: 'aws-key' },
  // JWT tokens (3 base64 segments separated by dots)
  { re: /(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)/g, label: 'jwt' },
  // Password fields
  { re: /((?:password|passwd|pwd|secret)\s*[:=]\s*)([^\s&"',;]+)/gi, label: 'password' },
];

function highlightSensitive(escapedHtml) {
  let result = escapedHtml;
  for (const { re, label } of SENSITIVE_PATTERNS) {
    re.lastIndex = 0;
    result = result.replace(re, (match, prefix, value) => {
      if (value) {
        return `${prefix}<mark class="sensitive-mark" title="${label}">${value}</mark>`;
      }
      return `<mark class="sensitive-mark" title="${label}">${match}</mark>`;
    });
  }
  return result;
}

// ─── Cookie Parsing ──────────────────────────────────────

function parseCookieHeader(headers) {
  if (!headers) return [];
  const cookieHeader = headers.find(h => h.name.toLowerCase() === 'cookie');
  if (!cookieHeader) return [];
  return cookieHeader.value.split(';').map(pair => {
    const eq = pair.indexOf('=');
    if (eq < 0) return { name: pair.trim(), value: '' };
    return { name: pair.slice(0, eq).trim(), value: pair.slice(eq + 1).trim() };
  }).filter(c => c.name);
}

function parseSetCookieHeaders(headers) {
  if (!headers) return [];
  return headers
    .filter(h => h.name.toLowerCase() === 'set-cookie')
    .map(h => {
      const parts = h.value.split(';').map(s => s.trim());
      const main = parts[0] || '';
      const eq = main.indexOf('=');
      const name = eq >= 0 ? main.slice(0, eq) : main;
      const value = eq >= 0 ? main.slice(eq + 1) : '';
      return { name, value, attrs: parts.slice(1) };
    });
}

// ─── Copy & Toast ────────────────────────────────────────

function buildCurlCommand(req) {
  const parts = [`curl '${req.url}'`];

  if (req.method !== 'GET') {
    parts.push(`-X ${req.method}`);
  }

  if (req.requestHeaders) {
    for (const h of req.requestHeaders) {
      // Skip pseudo-headers and host (curl adds it)
      const name = h.name.toLowerCase();
      if (name === 'host' || name.startsWith(':')) continue;
      parts.push(`-H '${h.name}: ${h.value.replace(/'/g, "'\\''")}'`);
    }
  }

  if (req.requestBody) {
    const body = typeof req.requestBody === 'string'
      ? req.requestBody
      : JSON.stringify(req.requestBody);
    parts.push(`--data-raw '${body.replace(/'/g, "'\\''")}'`);
  }

  return parts.join(' \\\n  ');
}

async function copyToClipboard(text, successMsg) {
  try {
    await navigator.clipboard.writeText(text);
    showToast(successMsg || 'Copied');
  } catch {
    // Fallback for clipboard API failure
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
    showToast(successMsg || 'Copied');
  }
}

let toastTimeout = null;

function showToast(msg) {
  const toast = document.getElementById('toast');
  toast.textContent = msg;
  toast.classList.add('visible', 'success');
  clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => {
    toast.classList.remove('visible', 'success');
  }, 2000);
}
