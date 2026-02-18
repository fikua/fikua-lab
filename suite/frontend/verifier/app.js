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

    // --- Request Presentation ---
    document.getElementById('btn-verify').addEventListener('click', () => {
        const config = getConfig();
        logEvent('info', `Starting OID4VP request: ${config.credType} via ${config.queryMode}`);
        logEvent('info', `Client scheme: ${config.clientScheme}, Response mode: ${config.responseMode}`);

        // Show QR section
        const qrSection = document.getElementById('qr-section');
        qrSection.classList.remove('hidden');
        document.getElementById('result-section').classList.add('hidden');

        // Generate demo URL
        const demoUrl = `openid4vp://?client_id=${config.clientId}&request_uri=${config.verifierUrl}/oid4vp/v1/request/demo-session`;
        document.getElementById('qr-link-input').value = demoUrl;
        document.getElementById('qr-code').textContent = 'QR Code placeholder';

        logEvent('info', `Presentation request created`);
        logEvent('info', `Waiting for wallet response...`);

        // Simulate verification after delay
        setTimeout(() => {
            showResult(true, config);
        }, 3000);
    });

    function showResult(success, config) {
        document.getElementById('qr-section').classList.add('hidden');
        const resultSection = document.getElementById('result-section');
        resultSection.classList.remove('hidden');

        const icon = document.getElementById('result-icon');
        const title = document.getElementById('result-title');
        const claims = document.getElementById('result-claims');

        if (success) {
            icon.className = 'result-icon success';
            icon.innerHTML = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>';
            title.textContent = 'Presentation Verified';

            const demoClaims = config.credType === 'pid' ? [
                ['given_name', 'Oriol'],
                ['family_name', 'Canadés'],
                ['birthdate', '1992-01-01'],
                ['nationality', 'ES'],
                ['format', 'sd_jwt_vc'],
                ['query', config.queryMode],
                ['client_id_scheme', config.clientScheme]
            ] : [
                ['role', 'Technical Product Manager'],
                ['organization', 'Fikua'],
                ['employee_id', 'FK-001'],
                ['format', 'sd_jwt_vc'],
                ['query', config.queryMode],
                ['client_id_scheme', config.clientScheme]
            ];

            claims.innerHTML = demoClaims.map(([k, v]) =>
                `<div class="claim-row"><span class="claim-label">${esc(k)}</span><span class="claim-value">${esc(v)}</span></div>`
            ).join('');

            logEvent('success', 'Presentation verified successfully');
        } else {
            icon.className = 'result-icon error';
            icon.innerHTML = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>';
            title.textContent = 'Verification Failed';
            claims.innerHTML = '';
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
