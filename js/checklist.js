(function () {
    'use strict';

    document.addEventListener('DOMContentLoaded', () => {
        var STORAGE_KEY = 'zt-checklist';
        var checkboxes = document.querySelectorAll('.checklist-item input[type="checkbox"]');
        var domains = document.querySelectorAll('.checklist-domain');
        var overallText = document.getElementById('overallText');
        var overallBar = document.getElementById('overallBar');
        var resetBtn = document.getElementById('resetBtn');

        // Load saved state
        function loadState() {
            var saved = {};
            try {
                saved = JSON.parse(localStorage.getItem(STORAGE_KEY)) || {};
            } catch (e) {
                saved = {};
            }
            checkboxes.forEach(function (cb) {
                cb.checked = saved[cb.id] === true;
                updateItemStyle(cb);
            });
        }

        // Save state
        function saveState() {
            var state = {};
            checkboxes.forEach(function (cb) {
                if (cb.checked) state[cb.id] = true;
            });
            localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
        }

        // Update visual style for a checkbox's parent
        function updateItemStyle(cb) {
            var item = cb.closest('.checklist-item');
            if (cb.checked) {
                item.classList.add('completed');
            } else {
                item.classList.remove('completed');
            }
        }

        // Update progress bars
        function updateProgress() {
            var totalChecked = 0;
            var totalCount = checkboxes.length;

            domains.forEach(function (domain) {
                var cbs = domain.querySelectorAll('input[type="checkbox"]');
                var checked = domain.querySelectorAll('input[type="checkbox"]:checked').length;
                var total = cbs.length;
                var pct = total > 0 ? Math.round((checked / total) * 100) : 0;

                var bar = domain.querySelector('.domain-bar');
                var text = domain.querySelector('.domain-progress-text');
                if (bar) {
                    bar.style.width = pct + '%';
                    bar.parentElement.setAttribute('aria-valuenow', pct);
                }
                if (text) text.textContent = checked + ' / ' + total;

                totalChecked += checked;
            });

            var overallPct = totalCount > 0 ? Math.round((totalChecked / totalCount) * 100) : 0;
            overallBar.style.width = overallPct + '%';
            overallBar.parentElement.setAttribute('aria-valuenow', overallPct);
            overallText.textContent = totalChecked + ' of ' + totalCount + ' items completed (' + overallPct + '%)';
        }

        // Event listeners
        checkboxes.forEach(function (cb) {
            cb.addEventListener('change', function () {
                updateItemStyle(cb);
                saveState();
                updateProgress();
            });
        });

        resetBtn.addEventListener('click', function () {
            if (!confirm('Are you sure you want to reset all checklist progress?')) return;
            checkboxes.forEach(function (cb) {
                cb.checked = false;
                updateItemStyle(cb);
            });
            saveState();
            updateProgress();
        });

        // Initialize
        loadState();
        updateProgress();
    });
})();
