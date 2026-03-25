document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('resourceSearch');
    const clearBtn = document.getElementById('clearSearch');
    const noResults = document.getElementById('noResults');
    const searchAnnouncement = document.getElementById('searchAnnouncement');
    const resourceCategories = document.querySelectorAll('.resource-category');
    const filterChips = document.querySelectorAll('.filter-chip');
    let currentCat = 'all';

    function updateURL() {
        const url = new URL(window.location);
        if (currentCat && currentCat !== 'all') {
            url.searchParams.set('category', currentCat);
        } else {
            url.searchParams.delete('category');
        }

        if (searchInput.value) {
            url.searchParams.set('q', searchInput.value);
        } else {
            url.searchParams.delete('q');
        }
        window.history.replaceState({}, '', url);
    }

    function applyFilters() {
        updateURL();
        var searchTerm = searchInput.value.toLowerCase();
        var totalVisible = 0;

        // Clear previous highlights
        resourceCategories.forEach(function (cat) { SearchHighlight.clear(cat); });

        // Filter by category first
        resourceCategories.forEach(function (category) {
            var catMatch = currentCat === 'all' || category.getAttribute('data-category') === currentCat;
            if (!catMatch) {
                category.classList.add('hidden');
                return;
            }
            category.classList.remove('hidden');

            // Filter individual items within visible categories
            var items = category.querySelectorAll('.resource-item');
            var catVisible = 0;
            items.forEach(function (item) {
                var title = item.querySelector('.resource-title').textContent.toLowerCase();
                var domain = item.querySelector('.resource-domain').textContent.toLowerCase();

                if (!searchTerm || title.includes(searchTerm) || domain.includes(searchTerm)) {
                    item.classList.remove('hidden');
                    catVisible++;
                    totalVisible++;
                } else {
                    item.classList.add('hidden');
                }
            });

            if (catVisible === 0) {
                category.classList.add('hidden');
            }
        });

        // Apply search highlighting
        if (searchTerm.length >= 2) {
            resourceCategories.forEach(function (category) {
                if (category.classList.contains('hidden')) return;
                var items = category.querySelectorAll('.resource-item:not(.hidden)');
                items.forEach(function (item) {
                    var titleEl = item.querySelector('.resource-title');
                    if (titleEl) SearchHighlight.apply(titleEl, searchTerm);
                });
            });
        }

        // Toggle No Results
        if (totalVisible > 0) {
            noResults.classList.add('hidden');
        } else {
            noResults.classList.remove('hidden');
        }

        // Toggle Clear Button
        if (searchTerm) {
            clearBtn.classList.remove('hidden');
        } else {
            clearBtn.classList.add('hidden');
        }

        // Announce results
        searchAnnouncement.textContent = totalVisible > 0 ? totalVisible + " resources found." : "No resources found.";
    }

    // Category filter chips
    filterChips.forEach(function (chip) {
        chip.addEventListener('click', function () {
            filterChips.forEach(function (c) {
                c.classList.remove('active');
                c.setAttribute('aria-pressed', 'false');
            });
            chip.classList.add('active');
            chip.setAttribute('aria-pressed', 'true');
            currentCat = chip.getAttribute('data-cat');
            applyFilters();
        });
    });

    searchInput.addEventListener('input', function () {
        applyFilters();
    });

    clearBtn.addEventListener('click', function () {
        searchInput.value = '';
        applyFilters();
        searchInput.focus();
    });

    // Check for query parameter
    var urlParams = new URLSearchParams(window.location.search);
    var query = urlParams.get('q');
    var categoryParam = urlParams.get('category');

    if (categoryParam) {
        currentCat = categoryParam;
        // Update active chip
        filterChips.forEach(function (c) {
            if (c.getAttribute('data-cat') === currentCat) {
                c.classList.add('active');
                c.setAttribute('aria-pressed', 'true');
            } else {
                c.classList.remove('active');
                c.setAttribute('aria-pressed', 'false');
            }
        });
    }

    if (query) {
        searchInput.value = query;
    }

    if (query || categoryParam) {
        applyFilters();
    }

    // Keyboard shortcut for search
    document.addEventListener('keydown', function (e) {
        var activeTag = document.activeElement.tagName;
        if (e.key === '/' && activeTag !== 'INPUT' && activeTag !== 'TEXTAREA') {
            e.preventDefault();
            searchInput.focus();
        }
    });
});
