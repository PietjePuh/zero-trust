document.addEventListener('DOMContentLoaded', () => {
    if (document.querySelector('.back-to-top')) return;

    const btn = document.createElement('button');
    btn.className = 'back-to-top';
    btn.innerHTML = '↑';
    btn.setAttribute('aria-label', 'Back to top');
    document.body.appendChild(btn);

    const toggleVisible = () => {
        if (window.scrollY > 300) {
            btn.classList.add('visible');
        } else {
            btn.classList.remove('visible');
        }
    };

    window.addEventListener('scroll', toggleVisible);
    toggleVisible(); // Check initial state
    btn.addEventListener('click', () => {
        window.scrollTo({ top: 0, behavior: 'smooth' });
    });

    // Global copy button injection for code blocks
    document.querySelectorAll('.tool-flags').forEach(flagsContainer => {
        // Only run if not already processed by a page-specific script
        if (flagsContainer.querySelector('.command-wrapper')) return;

        const fragment = document.createDocumentFragment();

        flagsContainer.childNodes.forEach(node => {
            if (node.nodeType === Node.TEXT_NODE && node.textContent.trim()) {
                const commandText = node.textContent.trim();

                const wrapper = document.createElement('div');
                wrapper.className = 'command-wrapper';

                const code = document.createElement('code');
                code.className = 'command-code';
                code.textContent = commandText;

                const btn = document.createElement('button');
                btn.className = 'copy-btn';
                btn.ariaLabel = 'Copy command';
                btn.innerHTML = '📋';
                btn.title = 'Copy to clipboard';

                btn.onclick = () => {
                    navigator.clipboard.writeText(commandText).then(() => {
                        btn.innerHTML = '✅';
                        setTimeout(() => btn.innerHTML = '📋', 2000);
                    }).catch(err => {
                        console.error('Failed to copy: ', err);
                        btn.innerHTML = '❌';
                        setTimeout(() => btn.innerHTML = '📋', 2000);
                    });
                };

                wrapper.appendChild(code);
                wrapper.appendChild(btn);
                fragment.appendChild(wrapper);
            } else {
                if (node.nodeType === Node.ELEMENT_NODE) {
                    fragment.appendChild(node.cloneNode(true));
                }
            }
        });

        flagsContainer.innerHTML = '';
        flagsContainer.appendChild(fragment);
    });
});
