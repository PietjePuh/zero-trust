(function () {
    'use strict';

    document.addEventListener('DOMContentLoaded', () => {
        // Sortable table columns
        var tables = document.querySelectorAll('.comparison-table');

        tables.forEach(function (table) {
            var headers = table.querySelectorAll('thead th');
            var tbody = table.querySelector('tbody');

            headers.forEach(function (header, colIndex) {
                var sortDir = 0; // 0 = unsorted, 1 = asc, -1 = desc

                // UX Enhancement: Accessibility attributes and keyboard support
                header.setAttribute('tabindex', '0');
                header.setAttribute('role', 'button');
                header.setAttribute('aria-label', 'Sort by ' + header.textContent.trim());

                function handleSort() {
                    // Reset all other headers in this table
                    headers.forEach(function (h, i) {
                        if (i !== colIndex) {
                            h.querySelector('.sort-indicator').textContent = '';
                            h.querySelector('.sort-indicator').classList.remove('active');
                            h.removeAttribute('aria-sort');
                        }
                    });

                    // Toggle sort direction
                    sortDir = sortDir === 1 ? -1 : 1;

                    header.setAttribute('aria-sort', sortDir === 1 ? 'ascending' : 'descending');

                    var indicator = header.querySelector('.sort-indicator');
                    indicator.textContent = sortDir === 1 ? ' \u25B2' : ' \u25BC';
                    indicator.classList.add('active');

                    // Get rows and sort
                    var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr'));
                    rows.sort(function (a, b) {
                        var aText = a.cells[colIndex].textContent.trim().toLowerCase();
                        var bText = b.cells[colIndex].textContent.trim().toLowerCase();
                        if (aText < bText) return -1 * sortDir;
                        if (aText > bText) return 1 * sortDir;
                        return 0;
                    });

                    // Re-append in sorted order
                    rows.forEach(function (row) {
                        tbody.appendChild(row);
                    });
                }

                header.addEventListener('click', handleSort);

                header.addEventListener('keydown', function (e) {
                    if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        handleSort();
                    }
                });
            });
        });
    });
})();
