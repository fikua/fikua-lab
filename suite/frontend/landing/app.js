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
        const current = html.getAttribute('data-theme');
        const next = current === 'dark' ? 'light' : 'dark';
        html.setAttribute('data-theme', next);
        localStorage.setItem('fikua-theme', next);
    });

    document.querySelectorAll('a[href^="#"]').forEach(link => {
        link.addEventListener('click', e => {
            const target = document.querySelector(link.getAttribute('href'));
            if (target) {
                e.preventDefault();
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        });
    });
})();
