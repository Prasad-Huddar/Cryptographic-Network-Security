/**
 * SecureShop — Admin Cybersecurity Attack Simulation & Defence Centre
 * Connects all 8 interactive security modules and the Live SOC Monitoring Dashboard
 * directly to real backend Flask API endpoints with CSRF protection and auto-polling.
 */
(function () {
    'use strict';

    const API_BASE = '/admin/security-lab/api';
    const CSRF_TOKEN = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';

    const state = {
        activeModule: 'aes_gcm',
        selectedAttacks: {
            aes_gcm: 'data_theft_interception',
            rsa_oaep: 'session_key_interception',
            rsa_pss: 'signature_forgery',
            pbkdf2: 'brute_force_simulation',
            hmac_sha256: 'message_tampering',
            ciphertext_tampering: 'interactive_ciphertext_tamper',
            nonce_replay: 'captured_request_replay',
            expired_timestamp: 'expired_request_replay',
        },
        pollingEnabled: true,
        pollIntervalId: null,
        charts: {
            byModule: null,
            byCategory: null,
            mitigations: null,
            overTime: null,
        },
    };

    // ---------- Safe Escaping Helpers ----------
    function escapeHtml(value) {
        return String(value ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function formatKeyLabel(key) {
        return String(key)
            .replace(/_/g, ' ')
            .replace(/\b\w/g, (c) => c.toUpperCase());
    }

    function formatValue(val) {
        if (val === null || val === undefined) return '—';
        if (typeof val === 'boolean') return val ? 'TRUE' : 'FALSE';
        if (typeof val === 'object') return JSON.stringify(val);
        return String(val);
    }

    async function apiFetch(url, options = {}) {
        const headers = Object.assign(
            {
                'Accept': 'application/json',
            },
            options.headers || {}
        );
        if (options.method && options.method.toUpperCase() !== 'GET') {
            headers['Content-Type'] = 'application/json';
            headers['X-CSRFToken'] = CSRF_TOKEN;
        }
        const resp = await fetch(url, Object.assign({}, options, { headers, credentials: 'same-origin' }));
        const contentType = resp.headers.get('content-type') || '';
        const payload = contentType.includes('application/json') ? await resp.json() : { success: false, error: `HTTP ${resp.status}` };
        if (!resp.ok || payload.success === false) {
            throw new Error(payload.error || `Request failed with HTTP ${resp.status}`);
        }
        return payload;
    }

    // ---------- Visual Status Helpers (Strict 4-Color Semantics) ----------
    // GREEN: MITIGATED (detected & blocked)
    // RED: DEFENCE_FAILED (not mitigated)
    // ORANGE: Executing / awaiting verification
    // BLUE: Informational / idle
    function applyStatusClass(el, color) {
        if (!el) return;
        el.classList.remove('soc-status-green', 'soc-status-red', 'soc-status-orange', 'soc-status-blue');
        el.classList.add(`soc-status-${color}`);
    }

    function setModuleExecuting(moduleKey, attackName) {
        const badge = document.getElementById(`statusBadge-${moduleKey}`);
        const banner = document.getElementById(`verdictBanner-${moduleKey}`);
        const title = document.getElementById(`verdictTitle-${moduleKey}`);
        const subtitle = document.getElementById(`verdictSubtitle-${moduleKey}`);
        const meta = document.getElementById(`verdictMeta-${moduleKey}`);
        const logEl = document.getElementById(`execLog-${moduleKey}`);

        applyStatusClass(badge, 'orange');
        applyStatusClass(banner, 'orange');
        if (badge) badge.innerHTML = '<i class="bi bi-hourglass-split me-1"></i><span>EXECUTING ATTACK...</span>';
        if (title) title.textContent = `Executing: ${attackName || 'Attack Simulation'}`;
        if (subtitle) subtitle.textContent = 'Running real cryptographic verification on isolated backend sandbox...';
        if (meta) meta.textContent = 'RUNNING';
        if (logEl) logEl.textContent = 'Contacting Flask backend security engine... awaiting verified response...';
    }

    function renderKVBox(containerId, obj) {
        const el = document.getElementById(containerId);
        if (!el) return;
        if (!obj || typeof obj !== 'object' || Object.keys(obj).length === 0) {
            el.innerHTML = '<span class="text-muted small">No structured data returned.</span>';
            return;
        }
        const rows = Object.entries(obj).map(([k, v]) => {
            const valStr = formatValue(v);
            let badgeHtml = `<code class="soc-kv-val">${escapeHtml(valStr)}</code>`;
            if (typeof v === 'boolean') {
                const cls = v ? 'badge bg-success' : 'badge bg-danger';
                badgeHtml = `<span class="${cls}">${v ? 'TRUE' : 'FALSE'}</span>`;
            }
            return `
                <div class="soc-kv-row">
                    <div class="soc-kv-key">${escapeHtml(formatKeyLabel(k))}</div>
                    <div class="soc-kv-data">${badgeHtml}</div>
                </div>
            `;
        });
        el.innerHTML = rows.join('');
    }

    function renderModuleSimulationResult(moduleKey, sim) {
        const badge = document.getElementById(`statusBadge-${moduleKey}`);
        const banner = document.getElementById(`verdictBanner-${moduleKey}`);
        const title = document.getElementById(`verdictTitle-${moduleKey}`);
        const subtitle = document.getElementById(`verdictSubtitle-${moduleKey}`);
        const meta = document.getElementById(`verdictMeta-${moduleKey}`);
        const defEl = document.getElementById(`defenceMech-${moduleKey}`);
        const mitEl = document.getElementById(`mitigationAction-${moduleKey}`);
        const logEl = document.getElementById(`execLog-${moduleKey}`);
        const uidEl = document.getElementById(`logEventUid-${moduleKey}`);

        // Strictly enforce color semantics based on REAL backend result
        const isMitigated = sim.final_result === 'MITIGATED' && sim.blocked === true && sim.detected === true;
        const statusColor = isMitigated ? 'green' : 'red';

        applyStatusClass(badge, statusColor);
        applyStatusClass(banner, statusColor);

        if (badge) {
            badge.innerHTML = isMitigated
                ? '<i class="bi bi-shield-fill-check me-1"></i><span>DETECTED &amp; BLOCKED</span>'
                : '<i class="bi bi-exclamation-octagon-fill me-1"></i><span>DEFENCE FAILED</span>';
        }
        if (title) {
            title.textContent = isMitigated
                ? `${sim.attack_type} — Attack Successfully Detected & Blocked`
                : `${sim.attack_type} — Defence Failed / Not Mitigated`;
        }
        if (subtitle) {
            subtitle.textContent = sim.mitigation_action || sim.description || '';
        }
        if (meta) {
            meta.textContent = `${sim.event_id} • ${sim.execution_ms} ms`;
        }
        if (defEl) defEl.textContent = sim.defence_mechanism || '—';
        if (mitEl) mitEl.textContent = sim.mitigation_action || '—';
        if (uidEl) uidEl.textContent = `Event ID: ${sim.event_id} | HMAC: ${sim.hmac_valid ? 'VALID' : 'INVALID'}`;

        renderKVBox(`payloadBox-${moduleKey}`, sim.payload || {});
        renderKVBox(`evidenceBox-${moduleKey}`, sim.evidence || {});

        if (logEl) {
            const logLines = Array.isArray(sim.logs) && sim.logs.length ? sim.logs : ['Simulation completed.'];
            logEl.textContent = logLines.join('\n');
        }
    }

    function renderModuleError(moduleKey, errMessage) {
        const badge = document.getElementById(`statusBadge-${moduleKey}`);
        const banner = document.getElementById(`verdictBanner-${moduleKey}`);
        const title = document.getElementById(`verdictTitle-${moduleKey}`);
        const subtitle = document.getElementById(`verdictSubtitle-${moduleKey}`);
        const logEl = document.getElementById(`execLog-${moduleKey}`);

        applyStatusClass(badge, 'red');
        applyStatusClass(banner, 'red');
        if (badge) badge.innerHTML = '<i class="bi bi-x-octagon-fill me-1"></i><span>EXECUTION ERROR</span>';
        if (title) title.textContent = 'Backend Request Rejected / Error';
        if (subtitle) subtitle.textContent = errMessage;
        if (logEl) logEl.textContent = `[ERROR] ${errMessage}`;
    }

    function formatDateIST(dateObj) {
        const d = dateObj instanceof Date ? dateObj : new Date(dateObj);
        if (isNaN(d.getTime())) return '';
        const parts = new Intl.DateTimeFormat('en-GB', {
            timeZone: 'Asia/Kolkata',
            day: '2-digit',
            month: 'short',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: true,
        }).formatToParts(d);
        const map = {};
        parts.forEach((p) => { map[p.type] = p.value; });
        const period = (map.dayPeriod || '').toUpperCase();
        return `${map.day} ${map.month} ${map.year}, ${map.hour}:${map.minute}:${map.second} ${period} IST`;
    }

    // ---------- Live SOC Dashboard Rendering ----------
    function renderOverview(overview) {
        if (!overview || !overview.metrics) return;
        const m = overview.metrics;

        const setText = (id, val) => {
            const el = document.getElementById(id);
            if (el) el.textContent = val;
        };

        setText('kpiTotalSimulated', m.total_attacks_simulated);
        setText('kpiDetected', m.attacks_detected);
        setText('kpiBlocked', m.attacks_blocked);
        setText('kpiFailedDefence', m.failed_defence_attempts);
        setText('kpiTotalTests', m.total_security_tests_executed);
        setText('kpiDetectionRate', `${m.detection_rate}%`);
        setText('kpiMitigationRate', `${m.mitigation_rate}%`);

        const barDet = document.getElementById('barDetectionRate');
        const barMit = document.getElementById('barMitigationRate');
        if (barDet) barDet.style.width = `${Math.min(100, Math.max(0, m.detection_rate))}%`;
        if (barMit) barMit.style.width = `${Math.min(100, Math.max(0, m.mitigation_rate))}%`;

        setText('lastSyncTimestamp', `Last synced: ${overview.server_time_ist || formatDateIST(new Date())}`);

        renderLiveThreatActivity(overview.live_threat_activity || []);
        renderEventLogsTable(overview.event_logs || []);
        renderCharts(overview.analytics || {});
    }

    function renderLiveThreatActivity(items) {
        const list = document.getElementById('liveThreatActivityList');
        const countBadge = document.getElementById('threatFeedCount');
        if (countBadge) countBadge.textContent = `${items.length} Recent`;
        if (!list) return;

        if (!items.length) {
            list.innerHTML = '<div class="p-4 text-center text-muted small">No attack simulations recorded yet. Launch a module above to see real-time threat events.</div>';
            return;
        }

        list.innerHTML = items.map((ev) => {
            const mitigated = ev.final_result === 'MITIGATED' && ev.blocked;
            const statusBadge = mitigated
                ? '<span class="badge bg-success">BLOCKED</span>'
                : '<span class="badge bg-danger">DEFENCE FAILED</span>';
            const detectBadge = ev.detected
                ? '<span class="badge badge-soft-blue">DETECTED</span>'
                : '<span class="badge bg-warning text-dark">UNDETECTED</span>';

            return `
                <div class="list-group-item px-3 py-2 border-bottom">
                    <div class="d-flex justify-content-between align-items-center gap-1 mb-1">
                        <span class="fw-semibold text-navy small text-truncate">${escapeHtml(ev.attack_type)}</span>
                        <div class="d-flex gap-1 flex-shrink-0">${detectBadge}${statusBadge}</div>
                    </div>
                    <div class="d-flex justify-content-between align-items-center text-muted" style="font-size: 0.74rem;">
                        <span class="text-truncate me-2">${escapeHtml(ev.attack_category)} &bull; ${escapeHtml(ev.module_name)}</span>
                        <span class="font-monospace flex-shrink-0">${escapeHtml(ev.execution_ms)} ms</span>
                    </div>
                    <div class="text-muted font-monospace mt-1" style="font-size: 0.7rem;" title="UTC Audit: ${escapeHtml(ev.executed_at_utc || '')}">
                        <i class="bi bi-clock me-1"></i>${escapeHtml(ev.executed_at)}
                    </div>
                </div>
            `;
        }).join('');
    }

    function renderEventLogsTable(logs) {
        const tbody = document.getElementById('securityEventLogsBody');
        if (!tbody) return;

        if (!logs.length) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted py-4">No persisted attack simulation events match the current filter.</td></tr>';
            return;
        }

        tbody.innerHTML = logs.map((ev) => {
            const mitigated = ev.final_result === 'MITIGATED' && ev.blocked;
            const detHtml = ev.detected
                ? '<span class="badge badge-soft-blue"><i class="bi bi-check2-circle me-1"></i>Detected</span>'
                : '<span class="badge bg-warning text-dark">Not Detected</span>';
            const finalHtml = mitigated
                ? '<span class="badge bg-success"><i class="bi bi-shield-fill-check me-1"></i>MITIGATED</span>'
                : '<span class="badge bg-danger"><i class="bi bi-exclamation-octagon-fill me-1"></i>DEFENCE FAILED</span>';

            return `
                <tr>
                    <td class="ps-3">
                        <button type="button" class="btn btn-link btn-sm p-0 font-monospace fw-semibold text-decoration-none soc-inspect-event" data-event-uid="${escapeHtml(ev.event_uid)}">
                            ${escapeHtml(ev.event_id)}
                        </button>
                    </td>
                    <td class="fw-semibold text-navy small">${escapeHtml(ev.attack_type)}</td>
                    <td><span class="badge badge-soft-blue">${escapeHtml(ev.module_name)}</span></td>
                    <td class="small text-muted" style="max-width: 240px;">${escapeHtml(ev.description)}</td>
                    <td class="small font-monospace text-muted text-nowrap" title="UTC Audit: ${escapeHtml(ev.executed_at_utc || '')}">${escapeHtml(ev.executed_at)}</td>
                    <td>${detHtml}</td>
                    <td class="small text-navy" style="max-width: 220px;">${escapeHtml(ev.mitigation_action)}</td>
                    <td class="pe-3 text-nowrap">${finalHtml}</td>
                </tr>
            `;
        }).join('');

        tbody.querySelectorAll('.soc-inspect-event').forEach((btn) => {
            btn.addEventListener('click', () => inspectEventDetail(btn.dataset.eventUid));
        });
    }

    // ---------- Chart.js Real-Data Analytics ----------
    function renderCharts(analytics) {
        if (typeof Chart === 'undefined') return;

        const palette = ['#2563eb', '#132b47', '#28b885', '#3b82f6', '#0ea5e9', '#6366f1', '#14b8a6', '#f59e0b'];

        // 1. Attacks by Cryptographic Module (Horizontal Bar)
        const modData = analytics.by_module || { labels: [], counts: [] };
        const modLabels = modData.labels.length ? modData.labels : ['No simulations yet'];
        const modCounts = modData.counts.length ? modData.counts : [0];
        updateOrCreateChart('byModule', 'chartByModule', {
            type: 'bar',
            data: {
                labels: modLabels,
                datasets: [{
                    label: 'Simulations',
                    data: modCounts,
                    backgroundColor: '#2563eb',
                    borderRadius: 6,
                }],
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { beginAtZero: true, ticks: { precision: 0 } },
                    y: { ticks: { font: { size: 11 } } },
                },
            },
        });

        // 2. Security Activity Over Time (Line)
        const timeData = analytics.activity_over_time || { labels: [], simulated: [], blocked: [], failed: [] };
        const timeLabels = timeData.labels.length ? timeData.labels : ['Now'];
        updateOrCreateChart('overTime', 'chartOverTime', {
            type: 'line',
            data: {
                labels: timeLabels,
                datasets: [
                    {
                        label: 'Simulated',
                        data: timeData.simulated.length ? timeData.simulated : [0],
                        borderColor: '#2563eb',
                        backgroundColor: 'rgba(37,99,235,0.12)',
                        fill: true,
                        tension: 0.3,
                    },
                    {
                        label: 'Blocked',
                        data: timeData.blocked.length ? timeData.blocked : [0],
                        borderColor: '#28b885',
                        backgroundColor: 'rgba(40,184,133,0.12)',
                        fill: false,
                        tension: 0.3,
                    },
                    {
                        label: 'Failed Defence',
                        data: timeData.failed.length ? timeData.failed : [0],
                        borderColor: '#dc2626',
                        backgroundColor: 'rgba(220,38,38,0.12)',
                        fill: false,
                        tension: 0.3,
                    },
                ],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { beginAtZero: true, ticks: { precision: 0 } },
                },
            },
        });

        // 3. Attacks by Category (Doughnut)
        const catData = analytics.by_category || { labels: [], counts: [] };
        const hasCat = catData.labels && catData.labels.length > 0;
        updateOrCreateChart('byCategory', 'chartByCategory', {
            type: 'doughnut',
            data: {
                labels: hasCat ? catData.labels : ['No Data'],
                datasets: [{
                    data: hasCat ? catData.counts : [1],
                    backgroundColor: hasCat ? palette : ['#e6ecf2'],
                    borderWidth: 2,
                    borderColor: '#ffffff',
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom', labels: { boxWidth: 10, font: { size: 11 } } },
                },
            },
        });

        // 4. Successful vs Failed Mitigations (Doughnut)
        const mitSum = analytics.mitigation_summary || { mitigated: 0, failed_defence: 0 };
        const hasMit = (mitSum.mitigated + mitSum.failed_defence) > 0;
        updateOrCreateChart('mitigations', 'chartMitigations', {
            type: 'doughnut',
            data: {
                labels: hasMit ? ['Mitigated (Blocked)', 'Failed Defence'] : ['No Tests Yet'],
                datasets: [{
                    data: hasMit ? [mitSum.mitigated, mitSum.failed_defence] : [1],
                    backgroundColor: hasMit ? ['#28b885', '#dc2626'] : ['#e6ecf2'],
                    borderWidth: 2,
                    borderColor: '#ffffff',
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom', labels: { boxWidth: 10, font: { size: 11 } } },
                },
            },
        });
    }

    function updateOrCreateChart(key, canvasId, config) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        if (state.charts[key]) {
            state.charts[key].data = config.data;
            state.charts[key].update('none');
        } else {
            state.charts[key] = new Chart(canvas.getContext('2d'), config);
        }
    }

    // ---------- Backend API Interactions ----------
    async function refreshOverview() {
        const modFilter = (document.getElementById('filterLogModule') || {}).value || '';
        const resFilter = (document.getElementById('filterLogResult') || {}).value || '';
        const params = new URLSearchParams();
        if (modFilter) params.set('module', modFilter);
        if (resFilter) params.set('result', resFilter);
        params.set('limit', '50');
        try {
            const data = await apiFetch(`${API_BASE}/overview?${params.toString()}`, { method: 'GET' });
            renderOverview(data);
        } catch (err) {
            console.error('SOC overview refresh failed:', err);
        }
    }

    async function launchAttackForModule(moduleKey) {
        const attackKey = state.selectedAttacks[moduleKey];
        const selectedBtn = document.querySelector(`.soc-attack-btn[data-module-key="${moduleKey}"][data-attack-key="${attackKey}"]`);
        const attackLabel = selectedBtn ? selectedBtn.querySelector('.fw-semibold')?.textContent : attackKey;
        const launchBtn = document.querySelector(`.soc-launch-btn[data-module-key="${moduleKey}"]`);

        setModuleExecuting(moduleKey, attackLabel);
        if (launchBtn) launchBtn.disabled = true;

        try {
            let response;
            if (moduleKey === 'ciphertext_tampering') {
                const labTxId = (document.getElementById('mod6LabTxId') || {}).value || '';
                const byteOffset = parseInt((document.getElementById('mod6ByteOffset') || {}).value || '0', 10) || 0;
                const xorMask = (document.getElementById('mod6XorMask') || {}).value || '0xFF';
                const ctBox = document.getElementById('mod6CiphertextBox');
                const customB64 = ctBox && ctBox.dataset.userEdited === 'true' ? ctBox.value.trim() : null;

                response = await apiFetch(`${API_BASE}/module6/tamper-execute`, {
                    method: 'POST',
                    body: JSON.stringify({
                        lab_tx_id: labTxId || null,
                        byte_offset: byteOffset,
                        xor_mask: xorMask,
                        custom_tampered_b64: customB64,
                    }),
                });
            } else if (moduleKey === 'nonce_replay') {
                const labTxId = (document.getElementById('mod7LabTxId') || {}).value || '';
                response = await apiFetch(`${API_BASE}/module7/replay`, {
                    method: 'POST',
                    body: JSON.stringify({
                        lab_tx_id: labTxId || null,
                        attack_key: attackKey,
                        burst_count: attackKey === 'concurrent_replay_burst' ? 5 : 1,
                    }),
                });
            } else {
                const options = {};
                if (moduleKey === 'pbkdf2') {
                    options.weak_profile = (document.getElementById('mod4WeakProfile') || {}).value || 'common_word';
                    options.enforce_policy = Boolean((document.getElementById('mod4EnforcePolicy') || {}).checked);
                } else if (moduleKey === 'expired_timestamp') {
                    options.offset_seconds = parseInt((document.getElementById('mod8OffsetSeconds') || {}).value || '900', 10) || 900;
                }
                response = await apiFetch(`${API_BASE}/simulate`, {
                    method: 'POST',
                    body: JSON.stringify({
                        module_key: moduleKey,
                        attack_key: attackKey,
                        options,
                    }),
                });
            }

            if (response.simulation) {
                renderModuleSimulationResult(moduleKey, response.simulation);
            }
            // Refresh overview respecting any active table filters
            const modFilter = (document.getElementById('filterLogModule') || {}).value || '';
            const resFilter = (document.getElementById('filterLogResult') || {}).value || '';
            if (!modFilter && !resFilter && response.overview) {
                renderOverview(response.overview);
            } else {
                await refreshOverview();
            }
        } catch (err) {
            renderModuleError(moduleKey, err.message);
        } finally {
            if (launchBtn) launchBtn.disabled = false;
        }
    }

    async function handleMod6Generate() {
        const btn = document.getElementById('btnMod6Generate');
        const itemName = (document.getElementById('mod6ItemName') || {}).value || 'Wireless Bluetooth Headphones (Lab)';
        const amount = parseFloat((document.getElementById('mod6Amount') || {}).value || '2999') || 2999;
        if (btn) btn.disabled = true;

        try {
            const res = await apiFetch(`${API_BASE}/module6/generate`, {
                method: 'POST',
                body: JSON.stringify({ item_name: itemName, amount_inr: amount }),
            });
            const tx = res.transaction;
            const idInput = document.getElementById('mod6LabTxId');
            const ctBox = document.getElementById('mod6CiphertextBox');
            const offsetInput = document.getElementById('mod6ByteOffset');
            if (idInput) idInput.value = tx.lab_tx_id;
            if (ctBox) {
                ctBox.value = tx.ciphertext_b64;
                ctBox.dataset.userEdited = 'false';
            }
            if (offsetInput) offsetInput.max = Math.max(0, (tx.ciphertext_byte_length || 1) - 1);

            const banner = document.getElementById('verdictBanner-ciphertext_tampering');
            const title = document.getElementById('verdictTitle-ciphertext_tampering');
            const subtitle = document.getElementById('verdictSubtitle-ciphertext_tampering');
            applyStatusClass(banner, 'blue');
            if (title) title.textContent = `Encrypted Transaction Generated (${tx.lab_tx_id.slice(0, 8).toUpperCase()})`;
            if (subtitle) subtitle.textContent = `Intercepted ${tx.ciphertext_byte_length} ciphertext bytes. Select a byte offset / XOR mask and click "Launch Attack Simulation".`;
            renderKVBox('payloadBox-ciphertext_tampering', {
                lab_tx_id: tx.lab_tx_id,
                ciphertext_bytes: tx.ciphertext_byte_length,
                original_ciphertext_sha256: tx.original_ciphertext_sha256,
                gcm_nonce_b64: tx.gcm_nonce_b64,
                auth_tag_b64: tx.auth_tag_b64,
            });
        } catch (err) {
            renderModuleError('ciphertext_tampering', err.message);
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    async function handleMod7GenerateSubmit() {
        const btn = document.getElementById('btnMod7SubmitOriginal');
        if (btn) btn.disabled = true;
        try {
            const res = await apiFetch(`${API_BASE}/module7/generate-and-submit`, {
                method: 'POST',
                body: JSON.stringify({}),
            });
            const cap = res.captured;
            const idInput = document.getElementById('mod7LabTxId');
            const box = document.getElementById('mod7CapturedBox');
            if (idInput) idInput.value = cap.lab_tx_id;
            if (box) {
                box.textContent = `Tx: ${cap.lab_tx_id} | Nonce: ${cap.original_nonce} | 1st Submit: ACCEPTED`;
            }

            const banner = document.getElementById('verdictBanner-nonce_replay');
            const title = document.getElementById('verdictTitle-nonce_replay');
            const subtitle = document.getElementById('verdictSubtitle-nonce_replay');
            applyStatusClass(banner, 'blue');
            if (title) title.textContent = 'Legitimate Transaction Accepted & Request Captured';
            if (subtitle) subtitle.textContent = `UUID Nonce ${cap.original_nonce} atomically consumed. Click "Launch Attack Simulation" to replay this exact request.`;
            renderKVBox('payloadBox-nonce_replay', cap.captured_request_preview);
        } catch (err) {
            renderModuleError('nonce_replay', err.message);
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    async function inspectEventDetail(eventUid) {
        try {
            const data = await apiFetch(`${API_BASE}/events/${encodeURIComponent(eventUid)}`, { method: 'GET' });
            const ev = data.event;
            const modalIdEl = document.getElementById('modalEventId');
            const modalBody = document.getElementById('modalEventContent');
            if (modalIdEl) modalIdEl.textContent = ev.event_id;
            if (modalBody) {
                modalBody.innerHTML = `
                    <div class="p-3 bg-white rounded-3 border mb-3">
                        <div class="d-flex justify-content-between flex-wrap gap-2 mb-2">
                            <strong class="text-navy">${escapeHtml(ev.attack_type)}</strong>
                            <span class="badge ${ev.final_result === 'MITIGATED' ? 'bg-success' : 'bg-danger'}">${escapeHtml(ev.final_result)}</span>
                        </div>
                        <div class="text-muted mb-1">${escapeHtml(ev.description)}</div>
                        <div class="small"><strong>Defence:</strong> ${escapeHtml(ev.defence_mechanism)}</div>
                        <div class="small"><strong>Mitigation:</strong> ${escapeHtml(ev.mitigation_action)}</div>
                        <div class="small"><strong>Executed (IST):</strong> ${escapeHtml(ev.executed_at)} (${escapeHtml(ev.execution_ms)} ms) &bull; <strong>HMAC Integrity:</strong> ${ev.hmac_valid ? 'VERIFIED' : 'INVALID'}</div>
                        <div class="text-muted" style="font-size: 0.74rem;"><strong>UTC Audit Timestamp:</strong> <code>${escapeHtml(ev.executed_at_utc || ev.executed_at_iso || '')}</code></div>
                    </div>
                    <div class="mb-3">
                        <div class="fw-bold text-navy mb-1">Attack Payload</div>
                        <pre class="crypto-artifact-box mb-0">${escapeHtml(JSON.stringify(ev.payload || {}, null, 2))}</pre>
                    </div>
                    <div class="mb-3">
                        <div class="fw-bold text-navy mb-1">Detection &amp; Verification Evidence</div>
                        <pre class="crypto-artifact-box mb-0">${escapeHtml(JSON.stringify(ev.evidence || {}, null, 2))}</pre>
                    </div>
                    <div>
                        <div class="fw-bold text-navy mb-1">Execution Log</div>
                        <pre class="soc-console mb-0">${escapeHtml((ev.logs || []).join('\n'))}</pre>
                    </div>
                `;
            }
            const modalEl = document.getElementById('eventDetailModal');
            if (modalEl && typeof bootstrap !== 'undefined') {
                bootstrap.Modal.getOrCreateInstance(modalEl).show();
            }
        } catch (err) {
            console.error('Failed to load event detail:', err);
        }
    }

    // ---------- Event Listeners & Initialization ----------
    function startPolling() {
        stopPolling();
        state.pollIntervalId = setInterval(() => {
            if (state.pollingEnabled && document.visibilityState === 'visible') {
                refreshOverview();
            }
        }, 10000);
    }

    function stopPolling() {
        if (state.pollIntervalId) {
            clearInterval(state.pollIntervalId);
            state.pollIntervalId = null;
        }
    }

    document.addEventListener('DOMContentLoaded', function () {
        // Module tab switching
        document.querySelectorAll('.soc-module-tab').forEach((tab) => {
            tab.addEventListener('click', () => {
                const modKey = tab.dataset.moduleKey;
                state.activeModule = modKey;
                document.querySelectorAll('.soc-module-tab').forEach((t) => t.classList.toggle('active', t === tab));
                document.querySelectorAll('.soc-module-pane').forEach((pane) => {
                    pane.classList.toggle('d-none', pane.dataset.paneKey !== modKey);
                });
            });
        });

        // Attack scenario selection buttons
        document.querySelectorAll('.soc-attack-btn').forEach((btn) => {
            btn.addEventListener('click', () => {
                const modKey = btn.dataset.moduleKey;
                const atkKey = btn.dataset.attackKey;
                state.selectedAttacks[modKey] = atkKey;
                document.querySelectorAll(`.soc-attack-btn[data-module-key="${modKey}"]`).forEach((b) => {
                    b.classList.toggle('selected', b === btn);
                });
            });
        });

        // Launch Attack Simulation buttons
        document.querySelectorAll('.soc-launch-btn').forEach((btn) => {
            btn.addEventListener('click', () => launchAttackForModule(btn.dataset.moduleKey));
        });

        // Module 6 & 7 interactive step buttons
        const btnMod6Gen = document.getElementById('btnMod6Generate');
        if (btnMod6Gen) btnMod6Gen.addEventListener('click', handleMod6Generate);

        const mod6CtBox = document.getElementById('mod6CiphertextBox');
        if (mod6CtBox) {
            mod6CtBox.addEventListener('input', () => {
                mod6CtBox.dataset.userEdited = 'true';
            });
        }

        const btnMod7Gen = document.getElementById('btnMod7SubmitOriginal');
        if (btnMod7Gen) btnMod7Gen.addEventListener('click', handleMod7GenerateSubmit);

        // Log table filters
        const filterMod = document.getElementById('filterLogModule');
        const filterRes = document.getElementById('filterLogResult');
        if (filterMod) filterMod.addEventListener('change', refreshOverview);
        if (filterRes) filterRes.addEventListener('change', refreshOverview);

        // Manual refresh & polling toggle
        const btnRefresh = document.getElementById('btnRefreshOverview');
        if (btnRefresh) btnRefresh.addEventListener('click', refreshOverview);

        const btnPoll = document.getElementById('btnTogglePolling');
        if (btnPoll) {
            btnPoll.addEventListener('click', () => {
                state.pollingEnabled = !state.pollingEnabled;
                const pill = document.getElementById('socPollingIndicator');
                if (state.pollingEnabled) {
                    btnPoll.innerHTML = '<i class="bi bi-pause-circle me-1"></i>Pause Poll';
                    if (pill) pill.innerHTML = '<span class="soc-pulse-dot"></span><span class="small fw-semibold">Live Polling: ON</span>';
                    refreshOverview();
                } else {
                    btnPoll.innerHTML = '<i class="bi bi-play-circle me-1"></i>Resume Poll';
                    if (pill) pill.innerHTML = '<span class="soc-pulse-dot paused"></span><span class="small fw-semibold">Live Polling: PAUSED</span>';
                }
            });
        }

        // Initial render from server-embedded real DB telemetry
        if (window.__INITIAL_SOC_OVERVIEW__) {
            renderOverview(window.__INITIAL_SOC_OVERVIEW__);
        } else {
            refreshOverview();
        }
        startPolling();
    });
})();
