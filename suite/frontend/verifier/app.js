(() => {
    // Theme toggle
    const html = document.documentElement;
    const saved = localStorage.getItem('fikua-theme');
    if (saved) {
        html.setAttribute('data-theme', saved);
    } else if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
        html.setAttribute('data-theme', 'dark');
    }
    document.getElementById('theme-toggle').addEventListener('click', () => {
        const next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
        html.setAttribute('data-theme', next);
        localStorage.setItem('fikua-theme', next);
    });

    // --- Tabs ---
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
            tab.classList.add('active');
            document.getElementById(`tab-${tab.dataset.tab}`).classList.remove('hidden');
        });
    });

    // --- Radio selection ---
    function setupRadioGroup(name) {
        document.querySelectorAll(`input[name="${name}"]`).forEach(input => {
            input.addEventListener('change', () => {
                const container = input.closest('.radio-cards, .radio-pills');
                container.querySelectorAll('.radio-card, .radio-pill').forEach(el => el.classList.remove('selected'));
                input.closest('.radio-card, .radio-pill').classList.add('selected');
                logEvent('info', `${name}: ${input.value}`);
            });
        });
    }

    setupRadioGroup('cred-type');
    setupRadioGroup('query-mode');
    setupRadioGroup('client-scheme');
    setupRadioGroup('response-mode');

    // --- Get selected values ---
    function getConfig() {
        return {
            credType: document.querySelector('input[name="cred-type"]:checked')?.value,
            queryMode: document.querySelector('input[name="query-mode"]:checked')?.value,
            clientScheme: document.querySelector('input[name="client-scheme"]:checked')?.value,
            responseMode: document.querySelector('input[name="response-mode"]:checked')?.value,
            clientId: document.getElementById('verifier-client-id')?.value,
            verifierUrl: document.getElementById('verifier-url')?.value
        };
    }

    // --- API helper ---
    async function api(method, path, body) {
        const opts = { method, headers: {} };
        if (body) {
            opts.headers['Content-Type'] = 'application/json';
            opts.body = JSON.stringify(body);
        }
        const res = await fetch(path, opts);
        return res.json();
    }

    // --- QR rendering (loads qrcode-generator from CDN) ---
    function generateQR(canvas, text) {
        if (window.qrcode) { renderQR(canvas, text); return; }
        const script = document.createElement('script');
        script.src = 'https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js';
        script.onload = () => renderQR(canvas, text);
        script.onerror = () => {
            canvas.width = 200; canvas.height = 200;
            const ctx = canvas.getContext('2d');
            ctx.fillStyle = '#f1f5f9'; ctx.fillRect(0, 0, 200, 200);
            ctx.fillStyle = '#64748b'; ctx.font = '12px sans-serif'; ctx.textAlign = 'center';
            ctx.fillText('QR unavailable', 100, 105);
        };
        document.head.appendChild(script);
    }

    function renderQR(canvas, text) {
        try {
            const qr = qrcode(0, 'M');
            qr.addData(text);
            qr.make();
            const modules = qr.getModuleCount();
            const cellSize = Math.max(4, Math.floor(240 / modules));
            const margin = cellSize * 4;
            const size = modules * cellSize + margin * 2;
            canvas.width = size; canvas.height = size;
            const ctx = canvas.getContext('2d');
            ctx.fillStyle = '#ffffff'; ctx.fillRect(0, 0, size, size);
            ctx.fillStyle = '#000000';
            for (let row = 0; row < modules; row++) {
                for (let col = 0; col < modules; col++) {
                    if (qr.isDark(row, col)) {
                        ctx.fillRect(margin + col * cellSize, margin + row * cellSize, cellSize, cellSize);
                    }
                }
            }
        } catch {
            canvas.width = 200; canvas.height = 200;
            const ctx = canvas.getContext('2d');
            ctx.fillStyle = '#f1f5f9'; ctx.fillRect(0, 0, 200, 200);
            ctx.fillStyle = '#64748b'; ctx.font = '12px sans-serif'; ctx.textAlign = 'center';
            ctx.fillText('QR error', 100, 105);
        }
    }

    // --- Polling state ---
    let pollTimer = null;

    function stopPolling() {
        if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    }

    // --- Request Presentation ---
    document.getElementById('btn-verify').addEventListener('click', async () => {
        const config = getConfig();
        stopPolling();

        logEvent('info', `Starting OID4VP request: ${config.credType} via ${config.queryMode}`);
        logEvent('info', `Client scheme: ${config.clientScheme}, Response mode: ${config.responseMode}`);

        // Show QR section
        document.getElementById('qr-section').classList.remove('hidden');
        document.getElementById('result-section').classList.add('hidden');

        const statusDot = document.getElementById('qr-status-dot');
        const statusText = document.getElementById('qr-status-text');
        statusDot.className = 'status-dot status-dot--pending';
        statusText.textContent = 'Creating session...';

        try {
            // Map credential type from radio value to VCT
            const credentialType = config.credType === 'pid'
                ? 'urn:eu.europa.ec.eudi:pid:1'
                : 'urn:eu.europa.ec.eudi:lear:1';

            const claims = config.credType === 'pid'
                ? ['given_name', 'family_name', 'birth_date']
                : ['role', 'organization', 'employee_id'];

            // Create session via backend
            const session = await api('POST', '/oid4vp/v1/session', {
                credential_type: credentialType,
                claims: claims
            });

            logEvent('info', `Session created: ${session.session_id}`);

            // Build OID4VP deeplink
            const clientId = config.clientId || session.client_id || '';
            const oid4vpUrl = `openid4vp://?client_id=${encodeURIComponent(clientId)}&request_uri=${encodeURIComponent(session.request_uri)}`;

            document.getElementById('qr-link-input').value = oid4vpUrl;
            generateQR(document.getElementById('qr-canvas'), oid4vpUrl);

            statusText.textContent = 'Scan with wallet...';
            logEvent('info', `Request URI: ${session.request_uri}`);
            logEvent('info', 'Waiting for wallet response...');

            // Poll for result
            pollTimer = setInterval(async () => {
                try {
                    const result = await api('GET', `/oid4vp/v1/result/${session.session_id}`);
                    if (result.status === 'success') {
                        stopPolling();
                        statusDot.className = 'status-dot status-dot--success';
                        statusText.textContent = 'Presentation received!';
                        logEvent('success', 'VP Token received');
                        showResult(true, config, result.claims);
                    } else if (result.status === 'failed' || result.error === 'verification_failed') {
                        stopPolling();
                        statusDot.className = 'status-dot status-dot--error';
                        statusText.textContent = 'Verification failed';
                        logEvent('error', `Verification failed: ${result.error_description || result.error}`);
                        showResult(false, config);
                    }
                    // else status is "pending" — keep polling
                } catch (err) {
                    logEvent('error', `Polling error: ${err.message}`);
                }
            }, 2000);

        } catch (err) {
            statusDot.className = 'status-dot status-dot--error';
            statusText.textContent = 'Failed to create session';
            logEvent('error', `Session creation failed: ${err.message}`);
        }
    });

    function showResult(success, config, resultClaims) {
        document.getElementById('qr-section').classList.add('hidden');
        const resultSection = document.getElementById('result-section');
        resultSection.classList.remove('hidden');

        const icon = document.getElementById('result-icon');
        const title = document.getElementById('result-title');
        const claimsEl = document.getElementById('result-claims');

        if (success) {
            icon.className = 'result-icon success';
            icon.innerHTML = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>';
            title.textContent = 'Presentation Verified';

            // Show real claims from backend if available, otherwise show config info
            const entries = resultClaims && typeof resultClaims === 'object'
                ? Object.entries(resultClaims)
                : [];

            // Append protocol config info
            entries.push(['query_mode', config.queryMode]);
            entries.push(['client_id_scheme', config.clientScheme]);
            entries.push(['response_mode', config.responseMode]);

            claimsEl.innerHTML = entries.map(([k, v]) =>
                `<div class="claim-row"><span class="claim-label">${esc(k)}</span><span class="claim-value">${esc(String(v))}</span></div>`
            ).join('');

            logEvent('success', 'Presentation verified successfully');
        } else {
            icon.className = 'result-icon error';
            icon.innerHTML = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>';
            title.textContent = 'Verification Failed';
            claimsEl.innerHTML = '';
            logEvent('error', 'Presentation verification failed');
        }
    }

    // --- Copy link ---
    document.getElementById('btn-copy-link').addEventListener('click', () => {
        const input = document.getElementById('qr-link-input');
        navigator.clipboard.writeText(input.value).then(() => {
            logEvent('info', 'Link copied to clipboard');
        });
    });

    // --- DC API ---
    const dcapiSupport = document.getElementById('dcapi-support');
    if (navigator.credentials && 'get' in navigator.credentials) {
        dcapiSupport.textContent = 'Digital Credentials API is supported in this browser.';
        dcapiSupport.style.color = 'var(--success)';
    } else {
        dcapiSupport.textContent = 'Digital Credentials API is not supported in this browser.';
        dcapiSupport.style.color = 'var(--warning)';
    }

    document.getElementById('btn-dcapi-request').addEventListener('click', async () => {
        logEvent('info', 'Starting DC API request...');

        const queryText = document.getElementById('dcapi-query').value;
        const protocol = document.getElementById('dcapi-protocol').value;

        try {
            const query = JSON.parse(queryText);
            logEvent('info', `Protocol: ${protocol}`);
            logEvent('info', `Query: ${JSON.stringify(query).substring(0, 100)}...`);

            // Show that the request would be made
            const resultDiv = document.getElementById('dcapi-result');
            resultDiv.classList.remove('hidden');
            document.getElementById('dcapi-response').textContent = JSON.stringify({
                note: 'DC API requires a secure context and browser support',
                protocol: protocol,
                query: query,
                status: 'demo_mode'
            }, null, 2);

            logEvent('info', 'DC API request completed (demo mode)');
        } catch (err) {
            logEvent('error', `Invalid DCQL query: ${err.message}`);
        }
    });

    // --- Event Log ---
    function logEvent(level, message) {
        const log = document.getElementById('event-log');
        const emptyEl = log.querySelector('.log-empty');
        if (emptyEl) emptyEl.remove();

        const entry = document.createElement('div');
        entry.className = 'log-entry';
        const time = new Date().toLocaleTimeString();
        entry.innerHTML = `
            <span class="log-time">${time}</span>
            <span class="log-level log-level--${level}">${level.toUpperCase()}</span>
            <span class="log-msg">${esc(message)}</span>
        `;
        log.appendChild(entry);
        log.scrollTop = log.scrollHeight;
    }

    document.getElementById('btn-clear-log').addEventListener('click', () => {
        document.getElementById('event-log').innerHTML = '<div class="log-empty">No events yet</div>';
    });

    function esc(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // Init log
    logEvent('info', 'Verifier initialized');
})();
