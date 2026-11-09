let riskChart;
let attackChart;

function csrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.content : '';
}

function csrfFetch(url, options = {}) {
    const headers = Object.assign({ 'X-CSRFToken': csrfToken() }, options.headers || {});
    if (options.body && !(options.body instanceof FormData) && !headers['Content-Type']) {
        headers['Content-Type'] = 'application/json';
    }
    return fetch(url, Object.assign({}, options, { headers }));
}

function showToast(message, title = 'MFA Guard') {
    const toastEl = document.getElementById('appToast');
    if (!toastEl || !window.bootstrap) return;
    setText('appToastTitle', title);
    setText('appToastBody', message || 'Action complete');
    bootstrap.Toast.getOrCreateInstance(toastEl, { delay: 3500 }).show();
}

function confirmAction(title, message, onConfirm, danger = true) {
    const modalEl = document.getElementById('confirmModal');
    const actionBtn = document.getElementById('confirmModalAction');
    if (!modalEl || !actionBtn || !window.bootstrap) return;
    setText('confirmModalTitle', title);
    setText('confirmModalBody', message);
    actionBtn.className = danger ? 'btn btn-danger' : 'btn btn-primary';
    actionBtn.onclick = () => {
        bootstrap.Modal.getOrCreateInstance(modalEl).hide();
        onConfirm();
    };
    bootstrap.Modal.getOrCreateInstance(modalEl).show();
}

function permanentlyDeleteUser(userId, username) {
    confirmAction(
        'Permanently delete user',
        `Permanently delete ${username}? This removes the account and ALL associated logs sessions, anomalies, SIM swap events, and security events. This cannot be undone.`,
        () => csrfFetch(`/api/users/${userId}/delete-permanent`, { method: 'POST' })
            .then(r => r.json())
            .then(data => reloadAfterToast(data.message || data.error))
    ); // danger defaults to true — good, this one should look scary
}

function reloadAfterToast(message) {
    showToast(message);
    setTimeout(() => location.reload(), 650);
}

function initDashboardCharts() {
    const riskCtx = document.getElementById('riskTimeline');
    if (riskCtx && !riskChart) {
        riskChart = new Chart(riskCtx, {
            type: 'line',
            data: { labels: [], datasets: [{ label: 'Average risk', data: [], borderColor: '#2563eb', backgroundColor: 'rgba(37,99,235,.12)', tension: .35, fill: true }] },
            options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, max: 100 } } }
        });
    }
    const attackCtx = document.getElementById('attackTypes');
    if (attackCtx && !attackChart) {
        attackChart = new Chart(attackCtx, {
            type: 'doughnut',
            data: { labels: [], datasets: [{ data: [], backgroundColor: ['#ef4444', '#f59e0b', '#2563eb', '#14b8a6', '#64748b'] }] },
            options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom' } } }
        });
    }
}

function updateDashboard() {
    if (!document.getElementById('riskTimeline')) return;
    fetch('/api/stats/realtime')
        .then(r => r.ok ? r.json() : Promise.reject(r))
        .then(data => {
            setText('active-sessions', data.active_sessions);
            setText('anomalies-today', data.anomalies_today);
            setText('avg-risk', `${data.avg_risk_score || 0}%`);
            if (riskChart) {
                riskChart.data.labels = (data.risk_score_history || []).map(x => x.time);
                riskChart.data.datasets[0].data = (data.risk_score_history || []).map(x => x.avg_risk);
                riskChart.update();
            }
            if (attackChart) {
                attackChart.data.labels = (data.attack_types || []).map(x => x.anomaly_type);
                attackChart.data.datasets[0].data = (data.attack_types || []).map(x => x.count);
                attackChart.update();
            }
            renderRecentAnomalies(data.recent_anomalies || []);
        })
        .catch(() => {});
}

function renderRecentAnomalies(items) {
    const tbody = document.getElementById('anomalies-tbody');
    if (!tbody || !items.length) return;
    tbody.innerHTML = items.map(a => `
        <tr>
            <td>${escapeHtml(a.detected_at || '')}</td>
            <td>${escapeHtml(a.username || '')}</td>
            <td>${escapeHtml(a.anomaly_type || '')}</td>
            <td><span class="risk-badge ${riskClass(a.risk_score)}">${a.risk_score}%</span></td>
            <td><span class="status-pill">${escapeHtml(a.status || 'open')}</span></td>
        </tr>`).join('');
}

function simulateAttack() {
    const attacks = [
        { type: 'session_hijacking', risk: 85, description: 'Session token replayed from a new country after MFA' },
        { type: 'impossible_travel', risk: 90, description: 'Employee appears in New York and Tokyo minutes apart' },
        { type: 'device_mismatch', risk: 68, description: 'Browser fingerprint changed during an active session' },
        { type: 'vpn_tor_datacenter', risk: 72, description: 'Session moved to anonymized infrastructure' }
    ];
    const attack = attacks[Math.floor(Math.random() * attacks.length)];
    csrfFetch('/api/simulate-attack', { method: 'POST', body: JSON.stringify(attack) })
        .then(r => r.json())
        .then(data => { showToast(data.message || data.error); updateDashboard(); });
}

function simulateSIMSwap() {
    const payload = {
        user_id: 3,
        old_carrier: 'Verizon',
        new_carrier: 'Unknown MVNO',
        old_imsi: '310410123456789',
        new_imsi: '310260987654321',
        password_reset_recent: true,
        new_device_detected: true,
        geo_velocity: 900
    };
    csrfFetch('/api/check-sim-swap', { method: 'POST', body: JSON.stringify(payload) })
        .then(r => r.json())
        .then(data => reloadAfterToast(`SIM swap risk: ${data.risk_score}%. Signals: ${(data.signals || []).join(', ')}`));
}

function terminateSession(sessionId, isCurrent = false) {
    const message = isCurrent
        ? 'Terminating this session will log you out. You will need to sign in again to continue. Terminate this session?'
        : 'Terminate this session?';
    confirmAction('Terminate session', message, () => csrfFetch(`/api/sessions/${sessionId}/terminate`, { method: 'POST' })
        .then(r => r.json())
        .then(data => {
            if (data.logout && data.redirect) {
                window.location.href = data.redirect;
            } else {
                reloadAfterToast(data.message || data.error);
            }
        }));
}

function resolveAnomaly(anomalyId) {
    csrfFetch(`/api/anomalies/${anomalyId}/resolve`, { method: 'POST' })
        .then(r => r.json())
        .then(data => reloadAfterToast(data.message || data.error));
}

function flagFalsePositive(anomalyId) {
    csrfFetch(`/api/anomalies/${anomalyId}/false-positive`, { method: 'POST' })
        .then(r => r.json())
        .then(data => reloadAfterToast(data.message || data.error));
}

function triggerReauth(userId) {
    confirmAction('Force re-authentication', 'Require this user to complete step-up verification before continuing?', () => csrfFetch('/api/force-reauth', { method: 'POST', body: JSON.stringify({ user_id: userId }) })
        .then(r => r.json())
        .then(data => reloadAfterToast(data.message || data.error)), false);
}

function resolveUserIssues(userId) {
    confirmAction('Resolve user issues', 'Resolve open alerts and clear active session risk for this user?', () => csrfFetch(`/api/users/${userId}/resolve-issues`, { method: 'POST' })
        .then(r => r.json())
        .then(data => reloadAfterToast(data.message || data.error)), false);
}

function deleteUser(userId, username) {
    confirmAction('Deactivate user', `Deactivate ${username}? Their active sessions will be terminated, but audit history is retained.`, () => csrfFetch(`/api/users/${userId}/delete`, { method: 'POST' })
        .then(r => r.json())
        .then(data => reloadAfterToast(data.message || data.error)));
}

function reactivateUser(userId, username) {
    confirmAction('Reactivate user', `Restore account access for ${username}?`, () => csrfFetch(`/api/users/${userId}/reactivate`, { method: 'POST' })
        .then(r => r.json())
        .then(data => reloadAfterToast(data.message || data.error)), false);
}

function resetPassword(userId, username) {
    setValue('resetUserId', userId);
    setValue('resetPasswordValue', '');
    setText('resetPasswordLabel', `Set a new temporary password for ${username}. Active sessions will be terminated.`);
    bootstrap.Modal.getOrCreateInstance(document.getElementById('resetPasswordModal')).show();
}

function submitPasswordReset() {
    const userId = document.getElementById('resetUserId').value;
    const password = document.getElementById('resetPasswordValue').value;
    csrfFetch(`/api/users/${userId}/reset-password`, { method: 'POST', body: JSON.stringify({ password }) })
        .then(r => r.json())
        .then(data => data.error ? showToast(data.error, 'Password reset failed') : reloadAfterToast(data.message));
}

function openEditUser(user) {
    setValue('editUserId', user.id);
    setValue('editEmail', user.email || '');
    setValue('editPhone', user.phone || '');
    setValue('editRole', user.role || 'employee');
    setValue('editDepartment', user.department || 'Engineering');
    setValue('editMfaMethod', user.mfa_method || 'Authenticator App');
    bootstrap.Modal.getOrCreateInstance(document.getElementById('editUserModal')).show();
}

function saveEditUser() {
    const userId = document.getElementById('editUserId').value;
    const payload = {
        email: document.getElementById('editEmail').value,
        phone: document.getElementById('editPhone').value,
        role: document.getElementById('editRole').value,
        department: document.getElementById('editDepartment').value,
        mfa_method: document.getElementById('editMfaMethod').value
    };
    csrfFetch(`/api/users/${userId}/edit`, { method: 'POST', body: JSON.stringify(payload) })
        .then(r => r.json())
        .then(data => data.error ? showToast(data.error, 'Update failed') : reloadAfterToast(data.message));
}

function loadSecurityEvents() {
    const tbody = document.getElementById('securityEvents');
    if (!tbody) return;
    fetch('/api/security-events')
        .then(r => r.json())
        .then(events => {
            tbody.innerHTML = events.map(e => `
                <tr><td>${escapeHtml(e.timestamp || '')}</td><td>${escapeHtml(e.username || '')}</td><td>${escapeHtml((e.event_type || '').replaceAll('_', ' '))}</td><td>${escapeHtml(e.details || '')}</td><td><span class="severity ${escapeHtml(e.severity || 'info')}">${escapeHtml(e.severity || 'info')}</span></td></tr>
            `).join('') || '<tr><td colspan="5" class="empty-state">No security events.</td></tr>';
        });
}

function initTableSearch() {
    const input = document.getElementById('sessionSearch');
    if (input) {
        input.addEventListener('input', () => {
            document.querySelectorAll('#sessionsTable tbody tr').forEach(row => {
                row.style.display = row.textContent.toLowerCase().includes(input.value.toLowerCase()) ? '' : 'none';
            });
        });
    }
    const filter = document.getElementById('filterType');
    if (filter) {
        filter.addEventListener('change', () => {
            document.querySelectorAll('.anomaly-row').forEach(row => {
                row.style.display = filter.value === 'all' || row.dataset.type === filter.value ? '' : 'none';
            });
        });
    }
    const userSearch = document.getElementById('userSearch');
    if (userSearch) {
        userSearch.addEventListener('input', () => {
            document.querySelectorAll('#usersTable tbody tr').forEach(row => {
                row.style.display = row.textContent.toLowerCase().includes(userSearch.value.toLowerCase()) ? '' : 'none';
            });
        });
    }
}

function riskClass(score) {
    score = Number(score || 0);
    if (score >= 70) return 'high';
    if (score >= 40) return 'medium';
    return 'low';
}

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

function setValue(id, value) {
    const el = document.getElementById(id);
    if (el) el.value = value;
}

function escapeHtml(value) {
    return String(value).replace(/[&<>'"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[c]));
}

document.addEventListener('DOMContentLoaded', () => {
    initDashboardCharts();
    initTableSearch();
    loadSecurityEvents();
    updateDashboard();
    if (document.getElementById('riskTimeline')) setInterval(updateDashboard, 5000);
});
