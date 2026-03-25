/**
 * Service Worker Registration and Update Handling
 */
function registerServiceWorker() {
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('sw.js').then(reg => {
            reg.addEventListener('updatefound', () => {
                const newWorker = reg.installing;
                newWorker.addEventListener('statechange', () => {
                    if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
                        showUpdateBanner();
                    }
                });
            });
        }).catch(err => {
            console.error('SW registration failed:', err);
        });

        // Ensure we refresh when the new SW takes control
        let refreshing = false;
        navigator.serviceWorker.addEventListener('controllerchange', () => {
            if (!refreshing) {
                window.location.reload();
                refreshing = true;
            }
        });
    }
}

function showUpdateBanner() {
    if (document.getElementById('sw-update-banner')) return;

    const banner = document.createElement('div');
    banner.id = 'sw-update-banner';
    banner.className = 'update-banner';
    banner.setAttribute('role', 'alert');
    banner.setAttribute('aria-live', 'assertive');

    const content = document.createElement('div');
    content.className = 'update-banner-content';
    content.innerHTML = '<p>A new version of the Knowledge Base is available!</p>';

    const actions = document.createElement('div');
    actions.className = 'update-banner-actions';

    const updateBtn = document.createElement('button');
    updateBtn.className = 'button button-update';
    updateBtn.textContent = 'Update Now';
    updateBtn.onclick = () => {
        navigator.serviceWorker.ready.then(reg => {
            if (reg.waiting) {
                reg.waiting.postMessage({ type: 'SKIP_WAITING' });
            }
        });
    };

    const dismissBtn = document.createElement('button');
    dismissBtn.className = 'button button-secondary button-dismiss';
    dismissBtn.textContent = 'Later';
    dismissBtn.onclick = () => {
        banner.classList.add('hidden');
    };

    actions.appendChild(updateBtn);
    actions.appendChild(dismissBtn);
    content.appendChild(actions);
    banner.appendChild(content);
    document.body.appendChild(banner);

    // Focus management for accessibility
    updateBtn.focus();
}

document.addEventListener('DOMContentLoaded', () => {
    // Register SW
    registerServiceWorker();

    if (document.querySelector('.back-to-top')) return;

    const btn = document.createElement('button');
    btn.className = 'back-to-top';
    btn.innerHTML = '↑';
    btn.setAttribute('aria-label', 'Back to top');
    btn.setAttribute('title', 'Back to top');
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
});
