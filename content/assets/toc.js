// Table of Contents generator
(function () {
    const article = document.querySelector('article');
    if (!article) return;

    const headings = article.querySelectorAll('h2, h3');
    if (headings.length === 0) return;

    const tocNav = document.createElement('nav');
    tocNav.setAttribute('aria-label', 'Table of Contents');

    headings.forEach(heading => {
        if (!heading.id) {
            heading.id = heading.textContent
                .toLowerCase()
                .replace(/[^a-z0-9]+/g, '-')
                .replace(/^-|-$/g, '');
        }

        const link = document.createElement('a');
        link.href = `#${heading.id}`;
        link.textContent = heading.textContent;
        link.className = `toc-${heading.tagName.toLowerCase()}`;

        tocNav.appendChild(link);
    });

    const tocSidebar = document.createElement('aside');
    tocSidebar.className = 'toc-sidebar';
    tocSidebar.appendChild(tocNav);

    const main = document.querySelector('main');
    main.insertBefore(tocSidebar, main.firstChild);

    // Highlight active section on scroll
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            const id = entry.target.getAttribute('id');
            const link = tocNav.querySelector(`a[href="#${id}"]`);

            if (entry.isIntersecting) {
                tocNav.querySelectorAll('a').forEach(a => a.classList.remove('active'));
                if (link) link.classList.add('active');
            }
        });
    }, {
        rootMargin: '-100px 0px -66%',
        threshold: 0
    });

    headings.forEach(heading => observer.observe(heading));
})();
