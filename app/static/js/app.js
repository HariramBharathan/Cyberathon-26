(() => {
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
  const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character]);
  const formatTime = (value, options = {}) => {
    if (!value) return 'Never';
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? 'Unknown' : new Intl.DateTimeFormat(undefined, {
      dateStyle: options.dateOnly ? 'medium' : 'short',
      timeStyle: options.dateOnly ? undefined : 'short',
    }).format(date);
  };
  const api = async (path, options = {}) => {
    const headers = { 'Content-Type': 'application/json', 'X-CSRFToken': csrf, ...(options.headers || {}) };
    const response = await fetch(`/api${path}`, { credentials: 'same-origin', ...options, headers });
    let result;
    try { result = await response.json(); } catch { result = { ok: false, error: { message: 'The server returned an unreadable response.' } }; }
    if (!response.ok || !result.ok) throw Object.assign(new Error(result.error?.message || 'Request failed.'), { status: response.status, payload: result });
    return result.data;
  };
  const notify = (message, kind = '') => {
    const region = document.getElementById('toast-region');
    if (!region) return;
    const toast = document.createElement('div');
    toast.className = `toast ${kind}`;
    toast.textContent = message;
    region.append(toast);
    window.setTimeout(() => toast.remove(), 4500);
  };
  const showMessage = (node, text, kind = '') => {
    if (!node) return;
    node.textContent = text;
    node.className = `form-message ${kind}`;
  };
  const setBusy = (button, busy, label = 'Working…') => {
    if (!button) return;
    if (busy) {
      button.dataset.originalText = button.textContent.trim();
      button.textContent = label;
      button.disabled = true;
    } else {
      button.textContent = button.dataset.originalText || button.textContent;
      button.disabled = false;
    }
  };
  const methodLabel = (method) => ({ email_otp: 'Email OTP', phone_otp: 'Phone OTP', qr: 'QR approval', email_verification: 'Email verification', device_management: 'Device management' })[method] || method;
  const statusLabel = (status) => `<span class="status-pill status-${escapeHtml(status)}">${escapeHtml(status)}</span>`;

  function initAuth() {
    const config = window.SENTINEL_AUTH;
    if (!config) return;
    const message = document.getElementById('auth-status');
    if (config.mode === 'register') {
      const form = document.getElementById('register-form');
      form?.addEventListener('submit', async (event) => {
        event.preventDefault();
        const button = form.querySelector('[type="submit"]');
        setBusy(button, true, 'Creating account…');
        showMessage(message, '');
        const data = Object.fromEntries(new FormData(form).entries());
        try {
          const result = await api('/register', { method: 'POST', body: JSON.stringify(data) });
          form.innerHTML = `<div class="challenge-note">${escapeHtml(result.message)}</div><label>Verification code<input id="registration-code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" required></label><button id="verify-registration" class="button button-primary button-wide" type="button">Verify email</button>`;
          const verify = async () => {
            const code = document.getElementById('registration-code').value;
            const verifyButton = document.getElementById('verify-registration');
            setBusy(verifyButton, true, 'Verifying…');
            try {
              const verified = await api('/otp/verify', { method: 'POST', body: JSON.stringify({ challenge_id: result.challenge_id, code }) });
              showMessage(message, 'Email verified. Signing you in…', 'success');
              window.setTimeout(() => { window.location.assign(verified.next || '/app'); }, 700);
            } catch (error) { showMessage(message, error.message, 'error'); setBusy(verifyButton, false); }
          };
          document.getElementById('verify-registration').addEventListener('click', verify);
          document.getElementById('registration-code').addEventListener('keydown', (keyEvent) => { if (keyEvent.key === 'Enter') verify(); });
          showMessage(message, result.message, 'success');
        } catch (error) { showMessage(message, error.message, 'error'); setBusy(button, false); }
      });
      return;
    }

    let method = 'email';
    let challengeId = '';
    let qrPoll = null;
    const requestForm = document.getElementById('otp-request-form');
    const verifyForm = document.getElementById('otp-verify-form');
    const qrPanel = document.getElementById('qr-login');
    const destinationLabel = document.getElementById('destination-label');
    const tabs = [...document.querySelectorAll('[data-method]')];
    const stopPolling = () => { if (qrPoll) window.clearInterval(qrPoll); qrPoll = null; };
    const selectMethod = (selected) => {
      method = selected;
      tabs.forEach((tab) => {
        const active = tab.dataset.method === method;
        tab.classList.toggle('active', active);
        tab.setAttribute('aria-selected', String(active));
      });
      stopPolling();
      requestForm.classList.toggle('hidden', method === 'qr');
      verifyForm.classList.add('hidden');
      qrPanel.classList.toggle('hidden', method !== 'qr');
      destinationLabel.innerHTML = method === 'phone'
        ? 'Phone number<input name="destination" type="tel" autocomplete="tel" required placeholder="+1 555 010 2040">'
        : 'Email address<input name="destination" type="email" autocomplete="email" required placeholder="you@company.com">';
      showMessage(message, '');
    };
    tabs.forEach((tab) => tab.addEventListener('click', () => selectMethod(tab.dataset.method)));
    requestForm?.addEventListener('submit', async (event) => {
      event.preventDefault();
      const button = requestForm.querySelector('[type="submit"]');
      setBusy(button, true, 'Sending code…');
      const destination = new FormData(requestForm).get('destination');
      try {
        const result = await api('/otp/request', { method: 'POST', body: JSON.stringify({ method, destination, purpose: 'login' }) });
        if (!result.challenge_id) {
          showMessage(message, result.message, 'success');
          setBusy(button, false);
          return;
        }
        challengeId = result.challenge_id;
        requestForm.classList.add('hidden');
        verifyForm.classList.remove('hidden');
        document.getElementById('challenge-note').textContent = result.message;
        verifyForm.querySelector('input[name="code"]').focus();
        showMessage(message, '');
      } catch (error) { showMessage(message, error.message, 'error'); }
      setBusy(button, false);
    });
    verifyForm?.addEventListener('submit', async (event) => {
      event.preventDefault();
      const button = verifyForm.querySelector('[type="submit"]');
      setBusy(button, true, 'Checking security signals…');
      try {
        const result = await api('/otp/verify', { method: 'POST', body: JSON.stringify({ challenge_id: challengeId, code: new FormData(verifyForm).get('code') }) });
        if (result.step_up_required) {
          challengeId = result.challenge_id;
          document.getElementById('challenge-note').textContent = `${result.message} Risk ${result.risk_score}/100. A new code has been sent.`;
          verifyForm.reset();
          showMessage(message, result.decision === 'require_additional_verification' ? 'Additional verification is required for this device.' : '', '');
          return;
        }
        showMessage(message, 'Verification complete. Opening your security overview…', 'success');
        window.location.assign(config.next || result.next || '/app');
      } catch (error) { showMessage(message, error.message, 'error'); }
      finally { setBusy(button, false); }
    });
    document.getElementById('request-again')?.addEventListener('click', () => {
      verifyForm.classList.add('hidden');
      requestForm.classList.remove('hidden');
      requestForm.reset();
      showMessage(message, '');
    });
    document.getElementById('create-qr')?.addEventListener('click', async (event) => {
      const button = event.currentTarget;
      setBusy(button, true, 'Creating bound request…');
      const container = document.getElementById('qr-result');
      container.innerHTML = '';
      try {
        const result = await api('/qr', { method: 'POST', body: '{}' });
        container.innerHTML = `<img alt="QR code for a short-lived desktop login request" src="${result.qr_image}"><span class="mono">EXPIRES IN ${result.expires_in} SECONDS</span><div id="qr-state" class="form-message">Waiting for a registered device</div>`;
        const stateNode = document.getElementById('qr-state');
        const poll = async () => {
          try {
            const status = await api(`/qr/${encodeURIComponent(result.request_id)}`);
            if (status.authenticated) {
              stopPolling();
              stateNode.textContent = 'Approved. Opening the authenticated desktop session…';
              window.location.assign(status.next);
            } else if (status.state !== 'pending') {
              stopPolling();
              stateNode.textContent = status.state === 'approved' ? 'Approval received; validating desktop binding…' : `Request ${status.state}. Start a new request to continue.`;
              if (status.state === 'approved') qrPoll = window.setInterval(poll, 900);
            }
          } catch (error) { stopPolling(); stateNode.textContent = error.message; }
        };
        qrPoll = window.setInterval(poll, 1100);
        window.setTimeout(() => { if (qrPoll) { stopPolling(); stateNode.textContent = 'Request expired. Create a new request to continue.'; } }, result.expires_in * 1000);
      } catch (error) { showMessage(message, error.message, 'error'); }
      finally { setBusy(button, false); }
    });
  }

  async function initApproval() {
    if (!window.SENTINEL_QR) return;
    const requestId = window.SENTINEL_QR;
    const token = window.location.hash.slice(1);
    const message = document.getElementById('approval-message');
    const actions = document.getElementById('approval-actions');
    if (!token) {
      showMessage(message, 'The QR approval token is missing. Scan the current code from the desktop screen.', 'error');
      return;
    }
    try {
      const request = await api(`/qr/${encodeURIComponent(requestId)}/review`, { method: 'POST', body: JSON.stringify({ token }) });
      document.getElementById('request-browser').textContent = request.browser;
      document.getElementById('request-expiry').textContent = `Expires ${formatTime(request.expires_at)}${request.ip_address ? ` · ${request.ip_address}` : ''}`;
      actions.classList.remove('hidden');
      showMessage(message, 'Confirm only if this is the desktop you are signing in to.');
    } catch (error) {
      showMessage(message, error.status === 401 ? 'Sign in on this registered device to review the request.' : error.message, 'error');
      if (error.status === 401) {
        const link = document.createElement('a');
        link.href = `/login?next=${encodeURIComponent(`/approve/${requestId}#${token}`)}`;
        link.className = 'button button-outline button-wide';
        link.textContent = 'Sign in to review';
        document.querySelector('.auth-panel').insertBefore(link, document.querySelector('.back-link'));
      }
      return;
    }
    const submit = async (approve) => {
      const button = document.getElementById(approve ? 'approve-request' : 'deny-request');
      if (!window.confirm(approve ? 'Approve this desktop login request?' : 'Deny this desktop login request?')) return;
      setBusy(button, true, approve ? 'Validating request…' : 'Recording denial…');
      try {
        const result = await api(`/qr/${encodeURIComponent(requestId)}/${approve ? 'approve' : 'deny'}`, {
          method: 'POST', body: JSON.stringify({ token }),
        });
        actions.classList.add('hidden');
        showMessage(message, result.message, 'success');
        window.history.replaceState(null, '', window.location.pathname);
      } catch (error) { showMessage(message, error.message, 'error'); setBusy(button, false); }
    };
    document.getElementById('approve-request').addEventListener('click', () => submit(true));
    document.getElementById('deny-request').addEventListener('click', () => submit(false));
  }

  function initConsole() {
    if (!window.SENTINEL_DASHBOARD) return;
    const root = document.getElementById('view-root');
    const pageTitle = document.getElementById('page-title');
    const section = document.getElementById('header-section');
    const links = [...document.querySelectorAll('[data-view]')];
    const titles = { overview: 'Security overview', authenticate: 'Authenticate', history: 'Login history', devices: 'Trusted devices', security: 'Security center', timeline: 'Decision timeline', settings: 'Account settings' };
    let timelineCorrelation = '';
    let historyPage = 1;

    const setView = (view) => {
      const selected = titles[view] ? view : 'overview';
      pageTitle.textContent = titles[selected];
      section.textContent = selected.toUpperCase();
      links.forEach((link) => link.classList.toggle('active', link.dataset.view === selected));
      document.getElementById('sidebar').classList.remove('open');
      if (selected === 'overview') renderOverview();
      if (selected === 'authenticate') renderAuthenticate();
      if (selected === 'history') renderHistory();
      if (selected === 'devices') renderDevices();
      if (selected === 'security') renderSecurity();
      if (selected === 'timeline') renderTimeline();
      if (selected === 'settings') renderSettings();
    };
    links.forEach((link) => link.addEventListener('click', () => setView(link.dataset.view)));
    window.addEventListener('hashchange', () => setView(window.location.hash.slice(1)));
    document.getElementById('menu-toggle').addEventListener('click', () => document.getElementById('sidebar').classList.toggle('open'));
    document.getElementById('alerts-shortcut').addEventListener('click', () => { location.hash = 'security'; });
    document.getElementById('account-shortcut').addEventListener('click', () => { location.hash = 'settings'; });
    document.getElementById('logout-button').addEventListener('click', async () => {
      try { await api('/logout', { method: 'POST', body: '{}' }); location.assign('/login'); }
      catch (error) { notify(error.message, 'error'); }
    });

    const fail = (error) => {
      root.innerHTML = `<div class="view-placeholder">${escapeHtml(error.message)} <a class="text-button" href="/login">Sign in again</a></div>`;
    };
    const heading = (title, subtitle, actions = '') => `<div class="view-heading"><div><h2>${title}</h2><p>${subtitle}</p></div>${actions ? `<div class="view-heading-actions">${actions}</div>` : ''}</div>`;
    const loadUser = async () => {
      const { user } = await api('/me');
      document.getElementById('sidebar-name').textContent = user.full_name;
      document.getElementById('sidebar-email').textContent = user.email;
      document.getElementById('user-avatar').textContent = user.full_name.split(/\s+/).slice(0, 2).map((word) => word[0]).join('').toUpperCase();
      document.getElementById('account-shortcut').textContent = user.full_name.split(/\s+/).slice(0, 2).map((word) => word[0]).join('').toUpperCase();
      const dashboard = await api('/dashboard/summary?days=30');
      document.getElementById('notification-dot').classList.toggle('hidden', dashboard.open_alerts === 0);
      return dashboard;
    };

    async function renderOverview() {
      root.innerHTML = '<div class="loading-state"><span class="spinner"></span>Loading security data</div>';
      try {
        const data = await loadUser();
        root.innerHTML = `${heading('Your authentication posture', 'Recent activity and decisions from your account · last 30 days', '<select class="filter-control" id="overview-range" aria-label="Date range"><option value="30">Last 30 days</option><option value="7">Last 7 days</option><option value="90">Last 90 days</option></select>')}
          <div class="stat-grid"><div class="stat-cell"><label>AUTHENTICATION ATTEMPTS</label><strong>${data.total_attempts}</strong><small>Recorded in selected period</small></div><div class="stat-cell"><label>SUCCESSFUL</label><strong class="stat-accent">${data.successful}</strong><small>Required checks passed</small></div><div class="stat-cell"><label>FAILED / BLOCKED</label><strong>${data.failed}</strong><small>Denied, failed, or expired</small></div><div class="stat-cell"><label>TRUSTED DEVICES</label><strong>${data.active_trusted_devices}</strong><small>${data.open_alerts} open security alerts</small></div></div>
          <div class="content-grid"><section class="section-panel"><div class="panel-header"><h3>Recent authentication activity</h3><a class="mono text-button" href="#history">VIEW HISTORY ↗</a></div><div class="event-list">${data.recent_events.length ? data.recent_events.map((event) => `<div class="event-row"><span class="event-time">${escapeHtml(formatTime(event.timestamp))}</span><span class="event-method">${escapeHtml(methodLabel(event.method))}</span><span>${statusLabel(event.outcome)}</span><span class="event-decision" title="${escapeHtml(event.decision)}">${escapeHtml(event.decision)}</span><button class="text-button event-timeline" data-correlation="${escapeHtml(event.correlation_id)}">Timeline ↗</button></div>`).join('') : '<div class="empty-state">No authentication activity in this period.</div>'}</div></section>
          <section class="section-panel"><div class="panel-header"><h3>Successful methods</h3><span>LAST 30 DAYS</span></div><div class="signal-list">${Object.keys(data.method_distribution).length ? Object.entries(data.method_distribution).map(([method, count]) => `<div class="signal-row"><span>${escapeHtml(methodLabel(method))}</span><strong>${count}</strong></div>`).join('') : '<div class="empty-state">No successful sign-ins yet.</div>'}<div class="policy-note"><strong>LIAE · Explainable policy</strong><br>Unknown device +30 · repeated failures +25 · unusual context +15 · browser change +10. Medium risk requires an additional code. High risk is denied. IP changes alone are not penalized.</div></div></section></div>`;
        root.querySelectorAll('.event-timeline').forEach((button) => button.addEventListener('click', () => { timelineCorrelation = button.dataset.correlation; location.hash = 'timeline'; }));
        document.getElementById('overview-range').addEventListener('change', async (event) => {
          const updated = await api(`/dashboard/summary?days=${event.target.value}`);
          root.querySelectorAll('.stat-cell strong').forEach((node, index) => { node.textContent = [updated.total_attempts, updated.successful, updated.failed, updated.active_trusted_devices][index]; });
          root.querySelector('.stat-cell:nth-child(4) small').textContent = `${updated.open_alerts} open security alerts`;
        });
      } catch (error) { fail(error); }
    }

    function renderAuthenticate() {
      root.innerHTML = `${heading('Choose an authentication path', 'Start a real passwordless sign-in or enroll this browser as trusted after a recent login.')}
        <div class="content-grid"><section class="section-panel"><div class="panel-header"><h3>Start sign-in</h3><span>NO PASSWORD REQUIRED</span></div><div class="auth-method-grid"><a class="method-tile" href="/login"><span class="method-icon">✉</span><span>EMAIL CODE</span><strong>One-time verification</strong><small>Short-lived · single use</small></a><a class="method-tile" href="/login"><span class="method-icon">▤</span><span>PHONE CODE</span><strong>Verified number only</strong><small>Provider or labeled demo adapter</small></a><a class="method-tile" href="/login"><span class="method-icon">▦</span><span>QR DESKTOP</span><strong>Mobile intent approval</strong><small>Request-bound · two-minute expiry</small></a><a class="method-tile" href="#devices" data-enroll-hint><span class="method-icon">▣</span><span>DEVICE TRUST</span><strong>Register this browser</strong><small>Requires recent authentication</small></a></div></section><section class="section-panel"><div class="panel-header"><h3>Authentication controls</h3><span>ACTIVE POLICY</span></div><div class="signal-list"><div class="signal-row"><span>Session token</span><strong>Opaque · revocable</strong></div><div class="signal-row"><span>OTP lifetime</span><strong>5 minutes</strong></div><div class="signal-row"><span>QR intent</span><strong>2 minutes</strong></div><div class="signal-row"><span>Step-up threshold</span><strong>25 risk points</strong></div><div class="policy-note">An unrecognized device requires a second code. Trust is never inferred from an IP address. Existing sessions can be revoked in account settings.</div></div></section></div>`;
    }

    async function renderHistory(page = 1, params = {}) {
      historyPage = page;
      root.innerHTML = '<div class="loading-state"><span class="spinner"></span>Loading authentication history</div>';
      try {
        const query = new URLSearchParams({ page, ...params });
        const data = await api(`/history?${query}`);
        root.innerHTML = `${heading('Login history', 'Server-filtered authentication events for this account.')}
          <section class="section-panel"><div class="filter-bar"><div class="table-tools"><input class="filter-control search-control" id="history-search" placeholder="Search decision text" value="${escapeHtml(params.q || '')}" aria-label="Search login history"><select class="filter-control" id="history-method" aria-label="Filter by method"><option value="">All methods</option>${['email_otp','phone_otp','qr','email_verification'].map((value) => `<option value="${value}" ${params.method === value ? 'selected' : ''}>${escapeHtml(methodLabel(value))}</option>`).join('')}</select><select class="filter-control" id="history-outcome" aria-label="Filter by outcome"><option value="">All outcomes</option>${['success','failed','challenge','denied','rejected','expired','approved'].map((value) => `<option value="${value}" ${params.outcome === value ? 'selected' : ''}>${value}</option>`).join('')}</select></div><span class="muted">${data.total} events</span></div><div class="table-wrap"><table class="data-table"><thead><tr><th>TIME</th><th>METHOD</th><th>OUTCOME</th><th>DEVICE</th><th>RISK</th><th>DECISION</th><th></th></tr></thead><tbody>${data.items.map((item) => `<tr><td class="mono">${escapeHtml(formatTime(item.timestamp))}</td><td>${escapeHtml(methodLabel(item.method))}</td><td>${statusLabel(item.outcome)}</td><td>${escapeHtml(item.device)}</td><td class="risk-score ${item.risk_score >= 50 ? 'risk-high' : item.risk_score >= 25 ? 'risk-medium' : 'risk-low'}">${item.risk_score}</td><td title="${escapeHtml(item.decision)}">${escapeHtml(item.decision.slice(0, 76))}${item.decision.length > 76 ? '…' : ''}</td><td><button class="text-button event-timeline" data-correlation="${escapeHtml(item.correlation_id)}">Timeline</button></td></tr>`).join('') || '<tr><td colspan="7" class="empty-state">No matching events.</td></tr>'}</tbody></table></div><div class="pagination"><span>Page ${data.page} of ${Math.max(data.pages, 1)}</span><button class="subtle-button" id="history-prev" ${page <= 1 ? 'disabled' : ''}>Previous</button><button class="subtle-button" id="history-next" ${page >= data.pages ? 'disabled' : ''}>Next</button></div></section>`;
        const readFilters = () => ({ q: document.getElementById('history-search').value, method: document.getElementById('history-method').value, outcome: document.getElementById('history-outcome').value });
        document.getElementById('history-method').addEventListener('change', () => renderHistory(1, readFilters()));
        document.getElementById('history-outcome').addEventListener('change', () => renderHistory(1, readFilters()));
        document.getElementById('history-search').addEventListener('keydown', (event) => { if (event.key === 'Enter') renderHistory(1, readFilters()); });
        document.getElementById('history-prev').addEventListener('click', () => renderHistory(page - 1, readFilters()));
        document.getElementById('history-next').addEventListener('click', () => renderHistory(page + 1, readFilters()));
        root.querySelectorAll('.event-timeline').forEach((button) => button.addEventListener('click', () => { timelineCorrelation = button.dataset.correlation; location.hash = 'timeline'; }));
      } catch (error) { fail(error); }
    }

    async function renderDevices() {
      root.innerHTML = '<div class="loading-state"><span class="spinner"></span>Loading trusted devices</div>';
      try {
        const data = await api('/devices');
        root.innerHTML = `${heading('Trusted devices', 'Device credentials are random, stored as hashes, expire, and can be revoked.', '<button class="subtle-button" id="enroll-device">Register this browser</button><button class="subtle-button" id="revoke-others">Revoke other devices</button>')}
          <section class="section-panel"><div class="panel-header"><h3>Registered browsers</h3><span>${data.items.filter((device) => device.active).length} ACTIVE</span></div><div class="table-wrap"><table class="data-table"><thead><tr><th>DEVICE</th><th>REGISTERED</th><th>LAST USED</th><th>EXPIRES</th><th>STATUS</th><th></th></tr></thead><tbody>${data.items.map((device) => `<tr><td><span class="device-name">${escapeHtml(device.name)}${device.current ? ' · THIS DEVICE' : ''}</span><span class="device-sub">${escapeHtml(device.browser)}</span></td><td>${escapeHtml(formatTime(device.created_at))}</td><td>${escapeHtml(formatTime(device.last_used_at))}</td><td>${escapeHtml(formatTime(device.expires_at))}</td><td>${statusLabel(device.active ? 'success' : 'denied')}</td><td><div class="device-actions">${device.active ? `<button class="text-button rename-device" data-id="${device.id}" data-name="${escapeHtml(device.name)}">Rename</button><button class="text-button revoke-device" data-id="${device.id}" data-name="${escapeHtml(device.name)}">Revoke</button>` : '—'}</div></td></tr>`).join('') || '<tr><td colspan="6" class="empty-state">No device registrations yet. Sign in and enroll a browser to enable QR approval.</td></tr>'}</tbody></table></div></section>
          <div class="risk-banner">A browser becomes trusted only after an authenticated session and an explicit enrollment action. Matching IP addresses or browser characteristics never grant trust.</div>`;
        document.getElementById('revoke-others').addEventListener('click', async () => {
          if (!window.confirm('Revoke every other trusted device?')) return;
          try { const result = await api('/devices/revoke-others', { method: 'POST', body: '{}' }); notify(`${result.revoked} other device(s) revoked.`, 'success'); renderDevices(); }
          catch (error) { notify(error.message, 'error'); }
        });
        document.getElementById('enroll-device').addEventListener('click', async () => {
          const name = window.prompt('Name this trusted browser', 'Personal browser');
          if (!name) return;
          try {
            await api('/devices', { method: 'POST', body: JSON.stringify({ name }) });
            notify('This browser is now trusted.', 'success');
            renderDevices();
          } catch (error) { notify(error.message, 'error'); }
        });
        root.querySelectorAll('.rename-device').forEach((button) => button.addEventListener('click', async () => {
          const name = window.prompt('New device name', button.dataset.name);
          if (!name) return;
          try { await api(`/devices/${button.dataset.id}`, { method: 'PATCH', body: JSON.stringify({ name }) }); notify('Device name updated.', 'success'); renderDevices(); }
          catch (error) { notify(error.message, 'error'); }
        }));
        root.querySelectorAll('.revoke-device').forEach((button) => button.addEventListener('click', async () => {
          if (!window.confirm(`Revoke ${button.dataset.name}? Existing sessions for this device will stop working.`)) return;
          try { await api(`/devices/${button.dataset.id}`, { method: 'DELETE' }); notify('Device revoked.', 'success'); renderDevices(); }
          catch (error) { notify(error.message, 'error'); }
        }));
      } catch (error) { fail(error); }
    }

    async function renderSecurity() {
      root.innerHTML = '<div class="loading-state"><span class="spinner"></span>Loading security events</div>';
      try {
        const [alertData, summary] = await Promise.all([api('/alerts'), api('/dashboard/summary?days=30')]);
        root.innerHTML = `${heading('Security center', 'Signals and risk outcomes recorded from actual authentication activity.')}
          <div class="stat-grid"><div class="stat-cell"><label>OPEN ALERTS</label><strong class="${alertData.items.length ? 'risk-medium' : ''}">${alertData.items.length}</strong><small>Unresolved security events</small></div><div class="stat-cell"><label>BLOCKED / FAILED</label><strong>${summary.failed}</strong><small>Last 30 days</small></div><div class="stat-cell"><label>ACTIVE DEVICES</label><strong>${summary.active_trusted_devices}</strong><small>Trusted and unexpired</small></div><div class="stat-cell"><label>RECORDED ATTEMPTS</label><strong>${summary.total_attempts}</strong><small>Last 30 days</small></div></div>
          <section class="section-panel"><div class="filter-bar"><div class="table-tools"><select class="filter-control" id="alert-severity"><option value="">All severities</option><option>high</option><option>medium</option><option>low</option></select><select class="filter-control" id="alert-status"><option value="open">Open alerts</option><option value="all">All alerts</option><option value="resolved">Resolved</option></select></div><span class="muted">Actual backend events</span></div><div id="security-alert-list" class="event-list">${alertData.items.length ? alertData.items.map((item) => alertRow(item)).join('') : '<div class="empty-state">No open alerts. New alerts appear when authentication produces a security event.</div>'}</div></section>
          <section class="section-panel"><div class="panel-header"><h3>Policy and recommended response</h3><span>LIAE V1</span></div><div class="signal-list"><div class="signal-row"><span>Unknown device (+30)</span><strong>Require second code</strong></div><div class="signal-row"><span>3+ failures in 15 min (+25)</span><strong>Step-up or deny</strong></div><div class="signal-row"><span>Unusual context (+15)</span><strong>Step-up or deny</strong></div><div class="signal-row"><span>Browser change (+10)</span><strong>Contributes to score</strong></div><div class="policy-note">Inspect the associated decision timeline before resolving an alert. The prototype uses deterministic rules, not an AI or empirically calibrated model.</div></div></section>`;
        const loadAlerts = async () => {
          const query = new URLSearchParams({ severity: document.getElementById('alert-severity').value, status: document.getElementById('alert-status').value });
          const filtered = await api(`/alerts?${query}`);
          document.getElementById('security-alert-list').innerHTML = filtered.items.map((item) => alertRow(item)).join('') || '<div class="empty-state">No security events match these filters.</div>';
          bindAlertActions();
        };
        document.getElementById('alert-severity').addEventListener('change', loadAlerts);
        document.getElementById('alert-status').addEventListener('change', loadAlerts);
        bindAlertActions();
      } catch (error) { fail(error); }
    }
    function alertRow(item) {
      return `<div class="event-row"><span class="event-time">${escapeHtml(formatTime(item.created_at))}</span><span class="status-pill status-${item.severity === 'high' ? 'denied' : 'challenge'}">${escapeHtml(item.severity)} severity</span><span class="event-decision">${escapeHtml(item.description)}</span><span>${item.resolved_at ? 'Resolved' : 'Open'}</span>${item.resolved_at ? '' : `<button class="text-button resolve-alert" data-id="${item.id}">Resolve</button>`}</div>`;
    }
    function bindAlertActions() {
      root.querySelectorAll('.resolve-alert').forEach((button) => button.addEventListener('click', async () => {
        try { await api(`/alerts/${button.dataset.id}/resolve`, { method: 'POST', body: '{}' }); notify('Alert resolved.', 'success'); renderSecurity(); }
        catch (error) { notify(error.message, 'error'); }
      }));
    }

    async function renderTimeline() {
      const correlation = timelineCorrelation || new URLSearchParams(location.hash.split('?')[1] || '').get('id') || '';
      root.innerHTML = `${heading('Decision timeline', 'Inspect the checks and policy decisions recorded for one authentication attempt.', '<input class="filter-control" id="timeline-id" placeholder="Correlation ID" aria-label="Timeline correlation ID"><button class="subtle-button" id="timeline-load">Load timeline</button>')}<div id="timeline-result" class="section-panel"><div class="empty-state">Choose a timeline from login history, or enter its correlation ID.</div></div>`;
      const load = async (selected = document.getElementById('timeline-id').value.trim()) => {
        if (!selected) return;
        document.getElementById('timeline-id').value = selected;
        const target = document.getElementById('timeline-result');
        target.innerHTML = '<div class="loading-state"><span class="spinner"></span>Loading recorded decisions</div>';
        try {
          const data = await api(`/timeline/${encodeURIComponent(selected)}`);
          target.innerHTML = `<div class="panel-header"><h3>Authentication decision</h3><span>${escapeHtml(data.correlation_id)}</span></div><div class="timeline-list">${data.items.map((item) => `<div class="timeline-event"><time class="timeline-time">${escapeHtml(formatTime(item.timestamp))}</time><span class="timeline-point"></span><div class="timeline-content"><strong>${escapeHtml(item.check)} · ${escapeHtml(item.result)}</strong><p>${escapeHtml(item.explanation)}</p><div class="timeline-meta"><span>${escapeHtml(item.event_type)}</span><span>POLICY ${escapeHtml(item.policy)}</span><span>NEXT ${escapeHtml(item.next_action)}</span></div></div></div>`).join('') || '<div class="empty-state">No recorded decision events.</div>'}</div>`;
        } catch (error) { target.innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`; }
      };
      document.getElementById('timeline-load').addEventListener('click', () => load());
      document.getElementById('timeline-id').addEventListener('keydown', (event) => { if (event.key === 'Enter') load(); });
      if (correlation) load(correlation);
    }

    async function renderSettings() {
      root.innerHTML = '<div class="loading-state"><span class="spinner"></span>Loading account settings</div>';
      try {
        const data = await api('/settings');
        const user = data.user;
        root.innerHTML = `${heading('Account settings', 'Manage identity verification and active sessions.')}
          <div class="settings-grid"><section class="section-panel"><div class="panel-header"><h3>Account identity</h3><span>NO PASSWORD STORED</span></div><form class="settings-form" id="settings-form"><label>Full name<input name="full_name" value="${escapeHtml(user.full_name)}" required minlength="2" maxlength="120"></label><label>Email address<input value="${escapeHtml(user.email)}" readonly></label><div class="signal-row"><span>Email ownership</span>${statusLabel(user.email_verified ? 'success' : 'denied')}</div><div class="signal-row"><span>Phone ownership</span>${statusLabel(user.phone_verified ? 'success' : 'challenge')}</div><button class="button button-primary" type="submit">Save account details</button><p class="inline-note">Phone-code sign-in is enabled only after ownership verification.</p></form><form class="settings-form" id="phone-form"><label>Phone number<input name="phone" type="tel" value="${escapeHtml(user.phone || '')}" placeholder="+1 555 010 2040" required></label><button class="subtle-button" type="submit">${user.phone_verified ? 'Change and verify phone' : 'Send phone verification code'}</button></form><form class="settings-form hidden" id="phone-verify-form"><label>Phone verification code<input name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" required></label><button class="button button-primary" type="submit">Verify phone ownership</button></form></section>
          <section class="section-panel"><div class="panel-header"><h3>Active sessions</h3><span>${data.sessions.length} ACTIVE</span></div><div class="event-list">${data.sessions.map((session) => `<div class="signal-list"><div class="signal-row"><span>${escapeHtml(session.device)}${session.current ? ' · THIS SESSION' : ''}</span><strong>${escapeHtml(formatTime(session.created_at))}</strong></div><div class="inline-note">Expires ${escapeHtml(formatTime(session.expires_at))}</div></div>`).join('') || '<div class="empty-state">No active sessions.</div>'}</div><div class="panel-header"><h3>Session control</h3><span>REVOCABLE</span></div><div class="danger-zone-content">Revoke every active session for this account. This browser will be signed out too.<br><button class="button button-danger-outline" id="logout-all">Revoke all sessions</button></div></section>
          <section class="section-panel danger-zone"><div class="panel-header"><h3>Delete account</h3><span>IRREVERSIBLE</span></div><div class="danger-zone-content">Account access and trusted devices will be revoked. Authentication audit events are retained with identifying account details detached, according to the prototype retention policy.<br><button class="button button-danger-outline" id="delete-account">Delete account</button></div></section></div>`;
        document.getElementById('settings-form').addEventListener('submit', async (event) => {
          event.preventDefault();
          try { await api('/settings', { method: 'PATCH', body: JSON.stringify({ full_name: new FormData(event.currentTarget).get('full_name') }) }); notify('Account details updated.', 'success'); loadUser(); }
          catch (error) { notify(error.message, 'error'); }
        });
        let phoneChallenge = '';
        document.getElementById('phone-form').addEventListener('submit', async (event) => {
          event.preventDefault();
          try {
            const result = await api('/settings/phone', { method: 'POST', body: JSON.stringify({ phone: new FormData(event.currentTarget).get('phone') }) });
            phoneChallenge = result.challenge_id;
            document.getElementById('phone-verify-form').classList.remove('hidden');
            notify(result.message, 'success');
          } catch (error) { notify(error.message, 'error'); }
        });
        document.getElementById('phone-verify-form').addEventListener('submit', async (event) => {
          event.preventDefault();
          try {
            const result = await api('/otp/verify', { method: 'POST', body: JSON.stringify({ challenge_id: phoneChallenge, code: new FormData(event.currentTarget).get('code') }) });
            notify(result.message, 'success');
            renderSettings();
          } catch (error) { notify(error.message, 'error'); }
        });
        document.getElementById('logout-all').addEventListener('click', async () => {
          if (!window.confirm('Revoke all active sessions?')) return;
          try { await api('/logout-all', { method: 'POST', body: '{}' }); location.assign('/login'); }
          catch (error) { notify(error.message, 'error'); }
        });
        document.getElementById('delete-account').addEventListener('click', async () => {
          const email = window.prompt(`Type ${user.email} to confirm permanent account deletion.`);
          if (email !== user.email) return;
          try { await api('/account', { method: 'DELETE', body: JSON.stringify({ confirm: email }) }); location.assign('/'); }
          catch (error) { notify(error.message, 'error'); }
        });
      } catch (error) { fail(error); }
    }

    setView(window.location.hash.slice(1) || 'overview');
  }

  initAuth();
  initApproval();
  initConsole();
})();