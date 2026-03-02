document.addEventListener('DOMContentLoaded', () => {
    TotpModal.init();

    const loginScreen = document.getElementById('login-screen');
    const appEl = document.getElementById('app');
    const loginBtn = document.getElementById('btn-login');
    const loginError = document.getElementById('login-error');
    const apiKeyInput = document.getElementById('api-key-input');

    let dashboardInterval = null;

    // --- Login ---
    function checkLogin() {
        const key = API.getKey();
        if (key) {
            showApp();
        }
    }

    loginBtn.addEventListener('click', async () => {
        const key = apiKeyInput.value.trim();
        if (!key) return;
        loginBtn.disabled = true;
        loginError.classList.add('hidden');
        try {
            API.setKey(key);
            await API.get('/api/v1/devices');
            showApp();
        } catch (e) {
            API.clearKey();
            loginError.textContent = 'Invalid API key';
            loginError.classList.remove('hidden');
        }
        loginBtn.disabled = false;
    });

    apiKeyInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') loginBtn.click();
    });

    function showApp() {
        loginScreen.classList.add('hidden');
        appEl.classList.remove('hidden');
        loadDashboard();
        dashboardInterval = setInterval(loadDashboard, 30000);
    }

    // --- Tabs ---
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            tab.classList.add('active');
            document.getElementById('tab-' + tab.dataset.tab).classList.add('active');

            if (tab.dataset.tab === 'dashboard') loadDashboard();
            if (tab.dataset.tab === 'ssh-keys') loadKeys();
            if (tab.dataset.tab === 'ssh-config') loadPasswordAuth();
        });
    });

    // --- Dashboard ---
    async function loadDashboard() {
        try {
            const [overview, sessions, fail2ban, firewall] = await Promise.all([
                API.get('/api/v1/system/overview'),
                API.get('/api/v1/system/sessions'),
                API.get('/api/v1/system/fail2ban'),
                API.get('/api/v1/system/firewall'),
            ]);
            renderOverview(overview);
            renderSessions(sessions);
            renderFail2ban(fail2ban);
            renderFirewall(firewall);
        } catch (e) {
            console.error('Dashboard load error:', e);
        }
    }

    function setGauge(id, percent) {
        const arc = document.getElementById('arc-' + id);
        const val = document.getElementById('val-' + id);
        const maxLen = 110;
        const len = (percent / 100) * maxLen;
        arc.setAttribute('stroke-dasharray', len + ' ' + maxLen);
        val.textContent = Math.round(percent) + '%';

        let color = '#00d4aa';
        if (percent > 80) color = '#ff6b6b';
        else if (percent > 60) color = '#feca57';
        arc.setAttribute('stroke', color);
    }

    function renderOverview(data) {
        setGauge('cpu', data.cpu.percent);
        setGauge('mem', data.memory.percent);
        setGauge('disk', data.disk.percent);
        document.getElementById('val-uptime').textContent = data.uptime;
    }

    function renderSessions(data) {
        const el = document.getElementById('sessions-list');
        if (!data.sessions.length) {
            el.innerHTML = '<div class="empty-state">No active SSH sessions</div>';
            return;
        }
        el.innerHTML = data.sessions.map(s =>
            `<div class="session-item">
                <strong>${esc(s.user)}</strong> from <code>${esc(s.ip)}</code>
                <span style="color:var(--text-secondary)"> (${esc(s.terminal)}, ${esc(s.login_time)})</span>
            </div>`
        ).join('');
    }

    function renderFail2ban(data) {
        const el = document.getElementById('fail2ban-status');
        if (!data.active) {
            el.innerHTML = `<div class="empty-state">${data.error || 'Fail2Ban not active'}</div>`;
            return;
        }
        if (!data.banned_ips.length) {
            el.innerHTML = '<div class="empty-state">No banned IPs</div>';
            return;
        }
        el.innerHTML = data.banned_ips.map(ip =>
            `<div class="ban-item"><span class="ban-ip">${esc(ip)}</span></div>`
        ).join('');
    }

    function renderFirewall(data) {
        const el = document.getElementById('firewall-rules');
        if (!data.active) {
            el.innerHTML = '<div class="empty-state">Firewall not active</div>';
            return;
        }
        if (!data.rules.length) {
            el.innerHTML = '<div class="empty-state">No rules configured</div>';
            return;
        }
        el.innerHTML = data.rules.map(r =>
            `<div class="rule-item">[${esc(r.number)}] ${esc(r.rule)}</div>`
        ).join('');
    }

    // --- SSH Keys ---
    async function loadKeys() {
        const el = document.getElementById('keys-list');
        el.innerHTML = '<div class="loading">Loading...</div>';
        try {
            const data = await API.get('/api/v1/devices');
            renderKeys(data.devices);
        } catch (e) {
            el.innerHTML = '<div class="alert alert-error">Failed to load keys</div>';
        }
    }

    function renderKeys(devices) {
        const el = document.getElementById('keys-list');
        if (!devices.length) {
            el.innerHTML = '<div class="empty-state">No SSH keys found</div>';
            return;
        }
        el.innerHTML = devices.map(d => `
            <div class="data-item">
                <div class="data-item-info">
                    <div class="data-item-name">${esc(d.name)}</div>
                    <div class="data-item-meta">${esc(d.type)} &middot; ${esc(d.fingerprint)}</div>
                </div>
                <div class="data-item-actions">
                    <span class="status-badge ${d.enabled ? 'status-enabled' : 'status-disabled'}">
                        ${d.enabled ? 'Active' : 'Disabled'}
                    </span>
                    <button class="btn btn-sm" onclick="toggleKey('${esc(d.id)}', ${!d.enabled})">
                        ${d.enabled ? 'Disable' : 'Enable'}
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deleteKey('${esc(d.id)}')">Del</button>
                </div>
            </div>
        `).join('');
    }

    window.toggleKey = async (id, enabled) => {
        try {
            const code = await TotpModal.prompt('TOTP to ' + (enabled ? 'enable' : 'disable') + ' key');
            await API.patch('/api/v1/devices/' + id, { enabled }, { 'X-TOTP-Code': code });
            loadKeys();
        } catch (e) {
            if (e.message !== 'cancelled') alert(e.message);
        }
    };

    window.deleteKey = async (id) => {
        if (!confirm('Delete this SSH key?')) return;
        try {
            const code = await TotpModal.prompt('TOTP to delete key');
            await API.delete('/api/v1/devices/' + id, {}, { 'X-TOTP-Code': code });
            loadKeys();
        } catch (e) {
            if (e.message !== 'cancelled') alert(e.message);
        }
    };

    // Add key modal
    const addKeyModal = document.getElementById('add-key-modal');
    document.getElementById('btn-add-key').addEventListener('click', () => {
        document.getElementById('new-key-name').value = '';
        document.getElementById('new-key-data').value = '';
        document.getElementById('add-key-error').classList.add('hidden');
        addKeyModal.classList.remove('hidden');
        document.getElementById('new-key-name').focus();
    });

    document.getElementById('add-key-cancel').addEventListener('click', () => {
        addKeyModal.classList.add('hidden');
    });
    addKeyModal.querySelector('.modal-backdrop').addEventListener('click', () => {
        addKeyModal.classList.add('hidden');
    });

    document.getElementById('add-key-submit').addEventListener('click', async () => {
        const name = document.getElementById('new-key-name').value.trim();
        const key = document.getElementById('new-key-data').value.trim();
        const errEl = document.getElementById('add-key-error');
        if (!name || !key) {
            errEl.textContent = 'Name and key are required';
            errEl.classList.remove('hidden');
            return;
        }
        try {
            const code = await TotpModal.prompt('TOTP to add key');
            await API.post('/api/v1/devices', { name, key }, { 'X-TOTP-Code': code });
            addKeyModal.classList.add('hidden');
            loadKeys();
        } catch (e) {
            if (e.message !== 'cancelled') {
                errEl.textContent = e.message;
                errEl.classList.remove('hidden');
            }
        }
    });

    // --- SSH Config ---
    async function loadPasswordAuth() {
        try {
            const data = await API.get('/api/v1/ssh/password-auth');
            const badge = document.getElementById('password-auth-status');
            badge.textContent = data.enabled ? 'Enabled' : 'Disabled';
            badge.className = 'status-badge ' + (data.enabled ? 'status-enabled' : 'status-disabled');
        } catch (e) {
            console.error(e);
        }
    }

    document.getElementById('btn-toggle-password').addEventListener('click', async () => {
        try {
            const current = await API.get('/api/v1/ssh/password-auth');
            const newState = !current.enabled;
            const code = await TotpModal.prompt('TOTP to ' + (newState ? 'enable' : 'disable') + ' password auth');
            await API.post('/api/v1/ssh/password-auth', { enabled: newState }, { 'X-TOTP-Code': code });
            loadPasswordAuth();
        } catch (e) {
            if (e.message !== 'cancelled') alert(e.message);
        }
    });

    // --- Settings ---
    document.getElementById('btn-view-qr').addEventListener('click', async () => {
        try {
            const code = await TotpModal.prompt('TOTP to view QR code');
            const data = await API.request('GET', '/api/v1/settings/totp-qr', null, { 'X-TOTP-Code': code });
            document.getElementById('settings-qr-img').src = 'data:image/png;base64,' + data.qr_code;
            document.getElementById('settings-qr').classList.remove('hidden');
            document.getElementById('settings-totp-secret').classList.add('hidden');
        } catch (e) {
            if (e.message !== 'cancelled') alert(e.message);
        }
    });

    document.getElementById('btn-regen-totp').addEventListener('click', async () => {
        if (!confirm('Regenerate TOTP? Your current authenticator entry will stop working.')) return;
        try {
            const code = await TotpModal.prompt('TOTP to regenerate (current code)');
            const data = await API.post('/api/v1/settings/totp-regenerate', {}, { 'X-TOTP-Code': code });
            document.getElementById('settings-qr-img').src = 'data:image/png;base64,' + data.qr_code;
            const secretEl = document.getElementById('settings-totp-secret');
            secretEl.textContent = 'New secret: ' + data.totp_secret;
            secretEl.classList.remove('hidden');
            document.getElementById('settings-qr').classList.remove('hidden');
        } catch (e) {
            if (e.message !== 'cancelled') alert(e.message);
        }
    });

    document.getElementById('btn-logout').addEventListener('click', () => {
        API.clearKey();
        if (dashboardInterval) clearInterval(dashboardInterval);
        appEl.classList.add('hidden');
        loginScreen.classList.remove('hidden');
        apiKeyInput.value = '';
    });

    // --- Helpers ---
    function esc(str) {
        const div = document.createElement('div');
        div.textContent = str || '';
        return div.innerHTML;
    }
    window.esc = esc;

    // Auto-login if key stored
    checkLogin();
});
