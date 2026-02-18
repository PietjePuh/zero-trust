/**
 * Theme toggle (dark/light mode) with localStorage persistence.
 * Default: dark theme.
 */
(function () {
    'use strict';

    const STORAGE_KEY = 'zt-theme';

    function getPreferred() {
        const stored = localStorage.getItem(STORAGE_KEY);
        if (stored === 'light' || stored === 'dark') return stored;
        return 'dark'; // default to dark
    }

    function applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem(STORAGE_KEY, theme);

        // Update toggle button icon if present
        const btn = document.getElementById('themeToggle');
        if (btn) {
            btn.textContent = theme === 'dark' ? '\u263E' : '\u2600'; // moon / sun
            btn.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
        }
    }

    // Apply immediately to prevent flash
    applyTheme(getPreferred());

    document.addEventListener('DOMContentLoaded', function () {
        var btn = document.getElementById('themeToggle');
        if (!btn) return;

        // Re-apply to make sure icon is correct after DOM load
        applyTheme(getPreferred());

        btn.addEventListener('click', function () {
            var current = document.documentElement.getAttribute('data-theme') || 'dark';
            applyTheme(current === 'dark' ? 'light' : 'dark');
        });
    });
})();
