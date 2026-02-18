// Theme toggle
(() => {
    const toggle = document.getElementById('theme-toggle');
    const html = document.documentElement;
    const saved = localStorage.getItem('fikua-theme');
    if (saved) {
        html.setAttribute('data-theme', saved);
    } else if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
        html.setAttribute('data-theme', 'dark');
    }
    toggle.addEventListener('click', () => {
        const next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
        html.setAttribute('data-theme', next);
        localStorage.setItem('fikua-theme', next);
    });
})();

(() => {
    const params = new URLSearchParams(window.location.search);
    const returnUrl = params.get('return_url') || 'https://issuer.lab.fikua.com';

    const phases = {
        loading: document.getElementById('phase-loading'),
        select: document.getElementById('phase-select'),
        nocert: document.getElementById('phase-nocert'),
        success: document.getElementById('phase-success')
    };

    function showPhase(name) {
        Object.entries(phases).forEach(([key, el]) => {
            el.classList.toggle('hidden', key !== name);
        });
    }

    function parseDN(dn) {
        if (!dn || dn === '-' || dn === '(null)') return {};
        const parts = {};
        // Split on commas NOT preceded by a backslash
        dn.split(/(?<!\\),/).forEach(part => {
            const [key, ...vals] = part.trim().split('=');
            if (key && vals.length) parts[key.trim()] = vals.join('=').replace(/\\,/g, ',').trim();
        });
        return parts;
    }

    function fetchCertificate() {
        fetch('/cert-info')
            .then(res => {
                const verified = res.headers.get('X-Client-Verify') || '';
                const subjectRaw = res.headers.get('X-Client-Subject') || '';
                const issuerRaw = res.headers.get('X-Client-Issuer') || '';
                const serial = res.headers.get('X-Client-Serial') || '-';
                const fingerprint = res.headers.get('X-Client-Fingerprint') || '-';
                const validFrom = res.headers.get('X-Client-Valid-From') || '-';
                const validTo = res.headers.get('X-Client-Valid-To') || '-';

                if (verified === 'NONE' || !subjectRaw) {
                    showPhase('nocert');
                    return;
                }

                const subject = parseDN(subjectRaw);
                const issuerDN = parseDN(issuerRaw);

                const cert = {
                    cn: subject.CN || subjectRaw,
                    issuer: issuerDN.CN || issuerDN.O || issuerRaw,
                    serial: serial,
                    fingerprint: fingerprint,
                    valid_from: validFrom,
                    valid_to: validTo,
                    verified: verified
                };

                renderCert(cert);
                showPhase('select');
            })
            .catch(() => {
                showPhase('nocert');
            });
    }

    function renderCert(cert) {
        const list = document.getElementById('cert-list');
        list.innerHTML = `
            <label class="cert-option selected">
                <input type="radio" name="cert" checked>
                <div class="cert-details">
                    <span class="cert-name">${esc(cert.cn)}</span>
                    <span class="cert-meta">
                        Issuer: ${esc(cert.issuer)}<br>
                        Serial: ${esc(cert.serial)}<br>
                        Valid: ${esc(cert.valid_from)} — ${esc(cert.valid_to)}
                    </span>
                </div>
            </label>
        `;

        document.getElementById('btn-accept').disabled = false;

        // Store for accept handler
        list._cert = cert;
    }

    // Accept button
    document.getElementById('btn-accept').addEventListener('click', () => {
        const cert = document.getElementById('cert-list')._cert;
        if (!cert) return;

        showPhase('success');

        setTimeout(() => {
            const certData = btoa(JSON.stringify({
                subject: cert.cn,
                issuer: cert.issuer,
                serial: cert.serial,
                fingerprint: cert.fingerprint
            }));
            const separator = returnUrl.includes('?') ? '&' : '?';
            window.location.href = `${returnUrl}${separator}cert=${certData}`;
        }, 2000);
    });

    // Cancel button
    document.getElementById('btn-cancel').addEventListener('click', () => {
        window.location.href = returnUrl;
    });

    // Retry button
    document.getElementById('btn-retry').addEventListener('click', () => {
        showPhase('loading');
        fetchCertificate();
    });

    // Back button
    document.getElementById('btn-back').addEventListener('click', () => {
        window.location.href = returnUrl;
    });

    function esc(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // Init
    fetchCertificate();
})();
