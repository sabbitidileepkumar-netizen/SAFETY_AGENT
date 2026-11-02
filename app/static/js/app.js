/**
 * Guard AI Command Centre — Unified Frontend Controller
 */
const GuardApp = {
    currentTheme: 'dark',
    activeView: 'soc',
    activePrivateTabId: null,
    activeIsolationSessionId: null,

    init() {
        this.initTheme();
        this.bindNavigation();
        this.bindActions();
        this.refreshStatus();
        this.refreshBlockchain();
        this.refreshPrivateTabs();
        this.refreshIsolationSessions();
        this.refreshSandboxReports();

        // Periodic telemetry refresh
        setInterval(() => {
            this.refreshStatus();
        }, 8000);
    },

    // -------------------------------------------------------------
    // THEME MANAGEMENT (Void Command vs Crystal Defence)
    // -------------------------------------------------------------
    initTheme() {
        const saved = localStorage.getItem('guard_ai_theme') || 'dark';
        this.setTheme(saved);
    },

    setTheme(theme) {
        this.currentTheme = theme;
        if (theme === 'system') {
            const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            document.documentElement.setAttribute('data-theme', prefersDark ? 'dark' : 'light');
        } else {
            document.documentElement.setAttribute('data-theme', theme);
        }
        localStorage.setItem('guard_ai_theme', theme);

        document.querySelectorAll('.theme-btn').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.theme === theme);
        });
    },

    // -------------------------------------------------------------
    // NAVIGATION
    // -------------------------------------------------------------
    bindNavigation() {
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const view = item.dataset.view;
                this.switchView(view);
            });
        });
    },

    switchView(viewName) {
        this.activeView = viewName;
        document.querySelectorAll('.nav-item').forEach(n => {
            n.classList.toggle('active', n.dataset.view === viewName);
        });
        document.querySelectorAll('.view-section').forEach(s => {
            s.classList.toggle('active', s.id === `view-${viewName}`);
        });

        // Trigger view-specific refreshes
        if (viewName === 'blockchain') this.refreshBlockchain();
        if (viewName === 'private-space') this.refreshPrivateTabs();
        if (viewName === 'isolation') this.refreshIsolationSessions();
        if (viewName === 'sandbox') this.refreshSandboxReports();
    },

    // -------------------------------------------------------------
    // ACTION BINDINGS
    // -------------------------------------------------------------
    bindActions() {
        // Theme buttons
        document.querySelectorAll('.theme-btn').forEach(btn => {
            btn.addEventListener('click', () => this.setTheme(btn.dataset.theme));
        });

        // Quick Triage Form
        const triageBtn = document.getElementById('btn-triage-execute');
        if (triageBtn) {
            triageBtn.addEventListener('click', () => this.executeTriage());
        }

        // Private Space Controls
        const newTabBtn = document.getElementById('btn-new-private-tab');
        if (newTabBtn) newTabBtn.addEventListener('click', () => this.openNewPrivateTab());
        
        const navTabBtn = document.getElementById('btn-private-nav');
        if (navTabBtn) navTabBtn.addEventListener('click', () => this.navigatePrivateTab());

        const clearPrivateBtn = document.getElementById('btn-clear-private-space');
        if (clearPrivateBtn) clearPrivateBtn.addEventListener('click', () => this.clearAllPrivateTabs());

        // Isolation Chamber Controls
        const launchIsoBtn = document.getElementById('btn-launch-isolation');
        if (launchIsoBtn) launchIsoBtn.addEventListener('click', () => this.launchIsolationSession());

        // File Sandbox Upload
        const fileInput = document.getElementById('sandbox-file-input');
        if (fileInput) {
            fileInput.addEventListener('change', (e) => this.handleFileUpload(e.target.files[0]));
        }

        // Crypto Maze Controls
        const sealMazeBtn = document.getElementById('btn-maze-seal');
        if (sealMazeBtn) sealMazeBtn.addEventListener('click', () => this.sealMaze());

        const solveMazeBtn = document.getElementById('btn-maze-solve');
        if (solveMazeBtn) solveMazeBtn.addEventListener('click', () => this.solveMaze());

        const rotateKeyBtn = document.getElementById('btn-rotate-key');
        if (rotateKeyBtn) rotateKeyBtn.addEventListener('click', () => this.rotateMasterKey());

        // Blockchain Controls
        const verifyChainBtn = document.getElementById('btn-verify-chain');
        if (verifyChainBtn) verifyChainBtn.addEventListener('click', () => this.verifyEntireChain());

        const tamperDemoBtn = document.getElementById('btn-tamper-demo');
        if (tamperDemoBtn) tamperDemoBtn.addEventListener('click', () => this.simulateTamperingDemo());
    },

    // -------------------------------------------------------------
    // STATUS & AGENT TELEMETRY
    // -------------------------------------------------------------
    async refreshStatus() {
        try {
            const res = await fetch('/api/status');
            if (!res.ok) return;
            const data = await res.json();

            // Update Agent Tiles
            for (const [agentKey, agent] of Object.entries(data.agents)) {
                const badgeEl = document.getElementById(`badge-agent-${agentKey}`);
                if (badgeEl) {
                    badgeEl.textContent = agent.status;
                    badgeEl.className = `agent-badge badge-${agent.status.toLowerCase()}`;
                }
            }

            // Update Controller telemetry
            const decEl = document.getElementById('stat-decisions-count');
            if (decEl) decEl.textContent = data.telemetry.decisions_count;

            const contEl = document.getElementById('stat-containment-count');
            if (contEl) contEl.textContent = data.telemetry.containment_actions_count;

            const recsEl = document.getElementById('stat-audit-count');
            if (recsEl) recsEl.textContent = data.engines.blockchain_audit.total_audit_records;

        } catch (err) {
            console.error('[GuardApp] Status fetch failed:', err);
        }
    },

    // -------------------------------------------------------------
    // CONTROLLER TRIAGE PIPELINE
    // -------------------------------------------------------------
    async executeTriage() {
        const inputEl = document.getElementById('triage-input');
        const value = inputEl ? inputEl.value.trim() : '';
        if (!value) return;

        const resultEl = document.getElementById('triage-result');
        if (resultEl) resultEl.innerHTML = '<span style="color:var(--accent-cyan)">Analyzing security indicators with Finder AI & Controller AI...</span>';

        try {
            const isUrl = value.startsWith('http://') || value.startsWith('https://');
            const payload = isUrl ? { url: value } : { text: value };
            const res = await fetch('/api/triage', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await res.json();

            const riskColor = data.risk_level === 'Danger' ? 'var(--color-danger)' : 
                             (data.risk_level === 'Careful' ? 'var(--color-careful)' : 'var(--color-safe)');

            let html = `
                <div style="margin-top:10px; padding:14px; border-radius:8px; background:var(--bg-surface-elevated); border:1px solid ${riskColor}">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                        <strong style="color:${riskColor}; font-size:14px;">DECISION: ${data.action_taken} (${data.risk_level})</strong>
                        <span style="font-size:12px; font-family:monospace;">Routing: <strong>${data.recommended_environment}</strong></span>
                    </div>
                    <p style="font-size:13px; margin-bottom:6px;">${data.announcement.action_explanation}</p>
                    <p style="font-size:12px; color:var(--text-secondary); margin-bottom:10px;">${data.announcement.reason_en}</p>
                    <div style="display:flex; gap:8px;">
                        <button class="btn-secondary" style="font-size:11px;" onclick="InformerVoice.speakEnglish('${data.announcement.voice.english.text.replace(/'/g, "\\'")}')">🔊 English Voice</button>
                        <button class="btn-secondary" style="font-size:11px;" onclick="InformerVoice.speakTelugu('${data.announcement.voice.telugu.text.replace(/'/g, "\\'")}')">🔊 Telugu Voice</button>
                    </div>
                </div>
            `;
            if (resultEl) resultEl.innerHTML = html;
            this.refreshStatus();
        } catch (err) {
            if (resultEl) resultEl.innerHTML = `<span style="color:var(--color-danger)">Triage error: ${err}</span>`;
        }
    },

    // -------------------------------------------------------------
    // PRIVATE SPACE
    // -------------------------------------------------------------
    async refreshPrivateTabs() {
        try {
            const res = await fetch('/api/private-space/tabs');
            const data = await res.json();
            const tabListEl = document.getElementById('private-tabs-header');
            if (!tabListEl) return;

            let tabsHtml = '';
            data.tabs.forEach(t => {
                const isActive = t.tab_id === this.activePrivateTabId;
                tabsHtml += `
                    <div class="private-tab-item ${isActive ? 'active-tab' : ''}" style="display:inline-flex; align-items:center; gap:8px; padding:6px 12px; background:${isActive ? 'var(--accent-blue)' : 'var(--bg-surface-elevated)'}; border-radius:6px; margin-right:6px; cursor:pointer;" onclick="GuardApp.selectPrivateTab('${t.tab_id}', '${t.current_url}')">
                        <span style="font-size:12px; font-weight:600;">${t.title}</span>
                        <span style="font-size:11px; cursor:pointer;" onclick="event.stopPropagation(); GuardApp.closePrivateTab('${t.tab_id}')">✕</span>
                    </div>
                `;
            });
            tabListEl.innerHTML = tabsHtml || '<span style="font-size:12px; color:var(--text-muted)">No active private tabs. Click "New Tab".</span>';

            const countEl = document.getElementById('stat-private-tab-count');
            if (countEl) countEl.textContent = data.active_tab_count;
        } catch (err) {
            console.error('[PrivateSpace] Tabs refresh failed:', err);
        }
    },

    async openNewPrivateTab() {
        try {
            const res = await fetch('/api/private-space/tabs', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ initial_url: 'about:blank' })
            });
            const tab = await res.json();
            this.activePrivateTabId = tab.tab_id;
            this.refreshPrivateTabs();
        } catch (err) {
            alert('Error opening private tab: ' + err);
        }
    },

    selectPrivateTab(tabId, url) {
        this.activePrivateTabId = tabId;
        const urlInput = document.getElementById('private-url-input');
        if (urlInput) urlInput.value = url;
        this.refreshPrivateTabs();
    },

    async navigatePrivateTab() {
        if (!this.activePrivateTabId) {
            await this.openNewPrivateTab();
        }
        const urlInput = document.getElementById('private-url-input');
        const targetUrl = urlInput ? urlInput.value.trim() : '';
        if (!targetUrl) return;

        const frame = document.getElementById('private-browser-viewport');
        if (frame) frame.srcdoc = '<p style="padding:20px; font-family:sans-serif;">Evaluating URL security and loading in Private Space...</p>';

        try {
            const res = await fetch('/api/private-space/navigate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ tab_id: this.activePrivateTabId, url: targetUrl })
            });
            const data = await res.json();
            if (data.warning) {
                alert('GUARD WARNING: ' + data.warning);
            }
            if (frame) {
                frame.srcdoc = data.content || `<p style="padding:20px;">Loaded ${data.url}</p>`;
            }
            this.refreshPrivateTabs();
        } catch (err) {
            alert('Navigation failed: ' + err);
        }
    },

    async closePrivateTab(tabId) {
        try {
            await fetch(`/api/private-space/tabs/${tabId}`, { method: 'DELETE' });
            if (this.activePrivateTabId === tabId) this.activePrivateTabId = null;
            this.refreshPrivateTabs();
        } catch (err) {
            console.error('Failed to close private tab:', err);
        }
    },

    async clearAllPrivateTabs() {
        if (!confirm('Purge and scrub all private browsing tabs and temporary storage?')) return;
        try {
            await fetch('/api/private-space/clear', { method: 'POST' });
            this.activePrivateTabId = null;
            const frame = document.getElementById('private-browser-viewport');
            if (frame) frame.srcdoc = '';
            this.refreshPrivateTabs();
        } catch (err) {
            alert('Failed to clear private space: ' + err);
        }
    },

    // -------------------------------------------------------------
    // ISOLATION CHAMBER
    // -------------------------------------------------------------
    async refreshIsolationSessions() {
        try {
            const res = await fetch('/api/isolation/sessions');
            const data = await res.json();
            const bodyEl = document.getElementById('isolation-sessions-tbody');
            if (!bodyEl) return;

            let html = '';
            data.sessions.forEach(s => {
                html += `
                    <tr>
                        <td>${s.session_id}</td>
                        <td style="max-width:200px; overflow:hidden; text-overflow:ellipsis;">${s.target_url}</td>
                        <td><span style="color:${s.health === 'Nominal' ? 'var(--color-safe)' : 'var(--color-danger)'}">${s.health}</span></td>
                        <td>${s.filesystem}</td>
                        <td>
                            <button class="btn-secondary" style="font-size:11px; padding:4px 8px;" onclick="GuardApp.renderIsolatedSession('${s.session_id}')">View</button>
                            <button class="btn-danger" style="font-size:11px; padding:4px 8px;" onclick="GuardApp.incinerateIsolationSession('${s.session_id}')">Incinerate</button>
                        </td>
                    </tr>
                `;
            });
            bodyEl.innerHTML = html || '<tr><td colspan="5" style="text-align:center; padding:16px;">No active isolated sessions.</td></tr>';
        } catch (err) {
            console.error('[Isolation] Refresh failed:', err);
        }
    },

    async launchIsolationSession() {
        const inputEl = document.getElementById('isolation-url-input');
        const url = inputEl ? inputEl.value.trim() : '';
        if (!url) return;

        try {
            const res = await fetch('/api/isolation/launch', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url, allow_clipboard: false })
            });
            const session = await res.json();
            this.activeIsolationSessionId = session.session_id;
            this.refreshIsolationSessions();
            this.renderIsolatedSession(session.session_id);
        } catch (err) {
            alert('Error launching isolation session: ' + err);
        }
    },

    async renderIsolatedSession(sessionId) {
        const frame = document.getElementById('isolation-viewer-frame');
        if (frame) frame.srcdoc = '<p style="padding:20px;">Fetching and neutralizing untrusted content inside chamber...</p>';

        try {
            const res = await fetch(`/api/isolation/render/${sessionId}`);
            const data = await res.json();
            if (data.success && frame) {
                frame.srcdoc = data.isolated_html;
            } else if (frame) {
                frame.srcdoc = `<p style="padding:20px; color:red;">Isolation Failure: ${data.error || 'Blocked by security policy'}</p>`;
            }
        } catch (err) {
            if (frame) frame.srcdoc = `<p style="padding:20px; color:red;">Chamber error: ${err}</p>`;
        }
    },

    async incinerateIsolationSession(sessionId) {
        try {
            await fetch(`/api/isolation/terminate/${sessionId}`, { method: 'POST' });
            this.refreshIsolationSessions();
            const frame = document.getElementById('isolation-viewer-frame');
            if (frame) frame.srcdoc = '<p style="padding:20px;">Session destroyed. Ephemeral staging wiped.</p>';
        } catch (err) {
            alert('Error incinerating session: ' + err);
        }
    },

    // -------------------------------------------------------------
    // SANDBOX LAB
    // -------------------------------------------------------------
    async handleFileUpload(file) {
        if (!file) return;
        const displayEl = document.getElementById('sandbox-report-container');
        if (displayEl) displayEl.innerHTML = '<p style="padding:20px; color:var(--accent-cyan)">Inspecting file metadata, SHA-256 digest, entropy, and YARA signatures...</p>';

        const formData = new FormData();
        formData.append('file', file);

        try {
            const res = await fetch('/api/sandbox/inspect', {
                method: 'POST',
                body: formData
            });
            const report = await res.json();
            this.renderSandboxReport(report);
            this.refreshSandboxReports();
            this.refreshStatus();
        } catch (err) {
            if (displayEl) displayEl.innerHTML = `<p style="color:red; padding:20px;">Upload & analysis error: ${err}</p>`;
        }
    },

    renderSandboxReport(r) {
        const displayEl = document.getElementById('sandbox-report-container');
        if (!displayEl) return;

        const riskColor = r.risk_level === 'Malicious' ? 'var(--color-malicious)' :
                         (r.risk_level === 'Suspicious' ? 'var(--color-careful)' : 'var(--color-safe)');

        let indHtml = r.indicators.map(i => `
            <li style="margin-bottom:4px;"><strong>[${i.severity}]</strong> ${i.description}</li>
        `).join('') || '<li>No suspicious signatures matched. Baseline clean.</li>';

        displayEl.innerHTML = `
            <div style="padding:20px; border-radius:10px; background:var(--bg-surface-elevated); border:1px solid ${riskColor}">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                    <h3 style="font-size:16px;">${r.filename}</h3>
                    <span style="background:${riskColor}; color:#fff; font-size:12px; font-weight:700; padding:4px 10px; border-radius:12px;">${r.risk_level} (SCORE: ${r.risk_score}/100)</span>
                </div>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; font-size:12px; margin-bottom:14px; font-family:monospace;">
                    <div><strong>SHA-256:</strong> ${r.sha256}</div>
                    <div><strong>File Type:</strong> ${r.detected_file_type}</div>
                    <div><strong>Size:</strong> ${(r.file_size_bytes/1024).toFixed(2)} KB</div>
                    <div><strong>Shannon Entropy:</strong> ${r.entropy} / 8.0</div>
                    <div><strong>Antivirus Status:</strong> ${r.antivirus_status}</div>
                    <div><strong>Cleanup Status:</strong> ${r.cleanup_status}</div>
                </div>
                <div style="margin-bottom:14px;">
                    <h4 style="font-size:13px; margin-bottom:6px;">Static Threat Indicators (${r.indicators.length})</h4>
                    <ul style="font-size:12px; padding-left:20px;">${indHtml}</ul>
                </div>
                <div>
                    <h4 style="font-size:13px; margin-bottom:6px;">Sanitized Text / Structure Preview</h4>
                    <pre style="background:var(--bg-base); padding:10px; border-radius:6px; font-size:11px; max-height:160px; overflow-y:auto; border:1px solid var(--border-subtle);">${r.safe_preview}</pre>
                </div>
            </div>
        `;
    },

    async refreshSandboxReports() {
        try {
            const res = await fetch('/api/sandbox/reports');
            const data = await res.json();
            const listEl = document.getElementById('sandbox-history-tbody');
            if (!listEl) return;

            let html = '';
            data.forEach(r => {
                html += `
                    <tr>
                        <td>${r.report_id}</td>
                        <td>${r.filename}</td>
                        <td>${(r.file_size_bytes/1024).toFixed(1)} KB</td>
                        <td><strong>${r.risk_level}</strong> (${r.risk_score})</td>
                        <td><button class="btn-secondary" style="font-size:11px; padding:3px 8px;" onclick="GuardApp.fetchSandboxReport('${r.report_id}')">View</button></td>
                    </tr>
                `;
            });
            listEl.innerHTML = html || '<tr><td colspan="5" style="text-align:center; padding:12px;">No file inspection records yet.</td></tr>';
        } catch (err) {
            console.error('[Sandbox] Reports refresh error:', err);
        }
    },

    async fetchSandboxReport(reportId) {
        try {
            const res = await fetch(`/api/sandbox/reports/${reportId}`);
            const report = await res.json();
            this.renderSandboxReport(report);
        } catch (err) {
            alert('Failed to load report: ' + err);
        }
    },

    // -------------------------------------------------------------
    // CRYPTOGRAPHIC MAZE
    // -------------------------------------------------------------
    lastMazeArtifact: null,

    async sealMaze() {
        const inputEl = document.getElementById('maze-plaintext-input');
        const text = inputEl ? inputEl.value : '';
        if (!text) return;

        try {
            const res = await fetch('/api/crypto/maze/seal', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ plaintext: text, compartment_size: 16 })
            });
            const artifact = await res.json();
            this.lastMazeArtifact = artifact;

            const resEl = document.getElementById('maze-output-display');
            if (resEl) {
                resEl.innerHTML = `
                    <div style="background:var(--bg-surface-elevated); padding:14px; border-radius:8px; border:1px solid var(--border-accent); font-family:monospace; font-size:12px;">
                        <p style="color:var(--accent-cyan); font-weight:bold; margin-bottom:8px;">✓ 3-LAYER CRYPTOGRAPHIC MAZE SEALED</p>
                        <p><strong>Maze ID:</strong> ${artifact.maze_id}</p>
                        <p><strong>Compartment Segments:</strong> ${artifact.segments.length} chunks (HKDF-derived isolated sub-keys)</p>
                        <p><strong>Core Vault Signature:</strong> ${artifact.root_signature.signature_hex.slice(0, 32)}... [Ed25519]</p>
                        <p><strong>Integrity Seal:</strong> ${artifact.integrity_seal}</p>
                        <p><strong>Dual Recovery Share A:</strong> ${artifact.recovery_shares[0].slice(0, 24)}...</p>
                        <p><strong>Dual Recovery Share B:</strong> ${artifact.recovery_shares[1].slice(0, 24)}...</p>
                    </div>
                `;
            }
        } catch (err) {
            alert('Error sealing maze: ' + err);
        }
    },

    async solveMaze() {
        if (!this.lastMazeArtifact) {
            alert('Please seal data into the maze first!');
            return;
        }

        try {
            const res = await fetch('/api/crypto/maze/solve', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ artifact: this.lastMazeArtifact })
            });
            const data = await res.json();
            const resEl = document.getElementById('maze-solve-display');
            if (resEl) {
                resEl.innerHTML = `
                    <div style="background:var(--bg-surface-elevated); padding:14px; border-radius:8px; border:1px solid var(--color-safe); font-family:monospace; font-size:12px;">
                        <p style="color:var(--color-safe); font-weight:bold; margin-bottom:6px;">✓ MAZE NAVIGATED & AUTHENTICATED</p>
                        <p><strong>Decrypted Plaintext:</strong> ${data.decrypted_text}</p>
                        <p><strong>Integrity Status:</strong> ${data.integrity_status}</p>
                    </div>
                `;
            }
        } catch (err) {
            alert('Decryption failed: ' + err);
        }
    },

    async rotateMasterKey() {
        try {
            const res = await fetch('/api/crypto/rotate-key', { method: 'POST' });
            const data = await res.json();
            alert(`Key rotated successfully! New active key version: ${data.version} (${data.key_id})`);
            this.refreshCryptoKeys();
        } catch (err) {
            alert('Key rotation error: ' + err);
        }
    },

    async refreshCryptoKeys() {
        try {
            const res = await fetch('/api/crypto/keys');
            const data = await res.json();
            const tbody = document.getElementById('crypto-keys-tbody');
            if (!tbody) return;

            let html = '';
            data.rotation_history.forEach(k => {
                html += `
                    <tr>
                        <td>${k.version}</td>
                        <td>${k.key_id}</td>
                        <td>${k.status}</td>
                        <td>${k.fingerprint}</td>
                        <td>${k.created_at.slice(0, 19)}</td>
                    </tr>
                `;
            });
            tbody.innerHTML = html;
        } catch (err) {
            console.error('Keys fetch error:', err);
        }
    },

    // -------------------------------------------------------------
    // BLOCKCHAIN & AUDIT REGISTRY
    // -------------------------------------------------------------
    async refreshBlockchain() {
        try {
            const res = await fetch('/api/blockchain/records');
            const records = await res.json();
            const tbody = document.getElementById('blockchain-records-tbody');
            if (!tbody) return;

            let html = '';
            records.forEach(r => {
                html += `
                    <tr>
                        <td>#${r.record_index}</td>
                        <td>${r.record_id}</td>
                        <td>${r.event_type}</td>
                        <td title="${r.data_hash}">${r.data_hash.slice(0, 14)}...</td>
                        <td title="${r.tx_hash}">${r.tx_hash.slice(0, 16)}...</td>
                        <td><span style="color:var(--accent-cyan)">${r.verification_tier}</span></td>
                    </tr>
                `;
            });
            tbody.innerHTML = html || '<tr><td colspan="6" style="text-align:center; padding:12px;">No audit records registered yet.</td></tr>';
        } catch (err) {
            console.error('[Blockchain] Refresh error:', err);
        }
    },

    async verifyEntireChain() {
        const outEl = document.getElementById('blockchain-verify-result');
        if (outEl) outEl.innerHTML = 'Verifying cryptographic hash-chain and digital signatures from genesis...';

        try {
            const res = await fetch('/api/blockchain/verify-chain');
            const data = await res.json();
            if (outEl) {
                outEl.innerHTML = data.intact ? 
                    `<strong style="color:var(--color-safe)">✓ CHAIN INTACT: Verified all ${data.total_records} records securely. Tip: ${data.tip_hash.slice(0, 16)}...</strong>` :
                    `<strong style="color:var(--color-danger)">✗ INTEGRITY FAILURE: ${data.reason} (At index ${data.failed_at_index})</strong>`;
            }
        } catch (err) {
            if (outEl) outEl.innerHTML = `<span style="color:red">Verification error: ${err}</span>`;
        }
    },

    async simulateTamperingDemo() {
        const outEl = document.getElementById('blockchain-verify-result');
        if (outEl) outEl.innerHTML = 'Tampering with a historical database record to test cryptographic detection...';

        try {
            const res = await fetch('/api/blockchain/tamper-demo', { method: 'POST' });
            const data = await res.json();
            if (data.success) {
                // Now run verify to show the detection!
                const verifyRes = await fetch('/api/blockchain/verify-chain');
                const vData = await verifyRes.json();
                if (outEl) {
                    outEl.innerHTML = `
                        <div style="background:rgba(239,68,68,0.15); border:1px solid var(--color-danger); padding:10px; border-radius:6px; margin-top:8px;">
                            <strong style="color:var(--color-danger)">🚨 TAMPERING DETECTED BY CRYPTOGRAPHIC AUDIT ENGINE:</strong>
                            <p style="font-size:12px; margin-top:4px;">${vData.reason}</p>
                        </div>
                    `;
                }
            }
        } catch (err) {
            if (outEl) outEl.innerHTML = `<span style="color:red">Tampering demo error: ${err}</span>`;
        }
    }
};

window.GuardApp = GuardApp;
document.addEventListener('DOMContentLoaded', () => GuardApp.init());
