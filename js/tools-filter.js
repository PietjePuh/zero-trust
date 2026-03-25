document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('searchInput');
    const toolCards = document.querySelectorAll('.tool-card');
    const clearBtn = document.getElementById('clearSearch');
    const noResults = document.getElementById('noResults');
    const filterBtns = document.querySelectorAll('.filter-btn');
    const toolsGrid = document.getElementById('toolsGrid');
    const searchAnnouncement = document.getElementById('searchAnnouncement');
    let currentCategory = 'all';

    function updateURL() {
        const url = new URL(window.location);
        if (currentCategory && currentCategory !== 'all') {
            url.searchParams.set('category', currentCategory);
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

    function filterTools(searchTerm) {
        updateURL();
        searchTerm = searchTerm.toLowerCase();
        let hasResults = false;
        let resultCount = 0;

        // Clear previous highlights
        SearchHighlight.clear(toolsGrid);

        toolCards.forEach(card => {
            const title = card.querySelector('.tool-title').textContent.toLowerCase();
            const keywords = card.getAttribute('data-keywords') ? card.getAttribute('data-keywords').toLowerCase() : '';
            const desc = card.querySelector('.tool-desc').textContent.toLowerCase();
            const flags = card.querySelector('.tool-flags') ? card.querySelector('.tool-flags').textContent.toLowerCase() : '';

            // Check Category
            const categoryMatch = currentCategory === 'all' || card.querySelector('.cat-' + currentCategory);
            // Check Search
            const searchMatch = title.includes(searchTerm) || keywords.includes(searchTerm) || desc.includes(searchTerm) || flags.includes(searchTerm);

            if (categoryMatch && searchMatch) {
                card.classList.remove('hidden');
                hasResults = true;
                resultCount++;
            } else {
                card.classList.add('hidden');
            }
        });

        // Apply search highlighting to visible cards
        if (searchTerm.length >= 2) {
            toolCards.forEach(card => {
                if (!card.classList.contains('hidden')) {
                    var titleEl = card.querySelector('.tool-title');
                    var descEl = card.querySelector('.tool-desc');
                    if (titleEl) SearchHighlight.apply(titleEl, searchTerm);
                    if (descEl) SearchHighlight.apply(descEl, searchTerm);
                }
            });
        }

        // Toggle No Results
        if (hasResults) {
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
        searchAnnouncement.textContent = hasResults ? resultCount + " tools found." : "No tools found.";
    }

    function setCategory(cat) {
        currentCategory = cat;

        // Update Buttons
        filterBtns.forEach(btn => {
            if (btn.getAttribute('data-cat') === cat) {
                btn.classList.remove('button-secondary');
                btn.classList.add('button');
                btn.setAttribute('aria-pressed', 'true');
            } else {
                btn.classList.add('button-secondary');
                btn.classList.remove('button');
                btn.setAttribute('aria-pressed', 'false');
            }
        });

        filterTools(searchInput.value);
    }

    // Event Listeners for Filters
    filterBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            setCategory(btn.getAttribute('data-cat'));
        });
    });

    // Check for query parameters
    const urlParams = new URLSearchParams(window.location.search);
    const query = urlParams.get('q');
    const categoryParam = urlParams.get('category');

    if (categoryParam) {
        setCategory(categoryParam);
    }

    if (query) {
        searchInput.value = query;
        filterTools(query);
    }

    searchInput.addEventListener('input', (e) => {
        filterTools(e.target.value);
    });

    clearBtn.addEventListener('click', () => {
        searchInput.value = '';
        filterTools('');
        searchInput.focus();
    });

    // Keyboard shortcut for search
    document.addEventListener('keydown', (e) => {
        if (e.key === '/' && document.activeElement !== searchInput) {
            e.preventDefault();
            searchInput.focus();
        }
    });

    // Add Copy Buttons to Flags
    document.querySelectorAll('.tool-flags').forEach(flagsContainer => {
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
                        // Fallback?
                        btn.innerHTML = '❌';
                        setTimeout(() => btn.innerHTML = '📋', 2000);
                    });
                };

                wrapper.appendChild(code);
                wrapper.appendChild(btn);
                fragment.appendChild(wrapper);
            } else {
                // Keep element nodes (e.g. strong tags)
                if (node.nodeType === Node.ELEMENT_NODE) {
                    fragment.appendChild(node.cloneNode(true));
                }
            }
        });

        flagsContainer.innerHTML = '';
        flagsContainer.appendChild(fragment);
    });
});
