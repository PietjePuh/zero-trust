document.addEventListener('DOMContentLoaded', () => {
    const searchInputs = document.querySelectorAll('.search-input');
    
    searchInputs.forEach(input => {
        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                const query = e.target.value.toLowerCase();
                performSearch(query);
            }
        });
    });

    function performSearch(query) {
        if (!query) return;
        
        const results = searchIndex.filter(page => {
            return page.title.toLowerCase().includes(query) || 
                   page.content.toLowerCase().includes(query);
        });

        if (results.length > 0) {
            // If there's a strong match, go to the first result
            window.location.href = results[0].url;
        } else {
            // Show "no results" message instead of leaking queries to Google
            const searchContainer = document.querySelector('.search-container') || document.body;
            let noResults = document.getElementById('no-results-msg');
            if (!noResults) {
                noResults = document.createElement('div');
                noResults.id = 'no-results-msg';
                noResults.style.cssText = 'padding: 1rem; margin-top: 1rem; text-align: center; color: var(--text-secondary, #aaa); border: 1px solid var(--border-color, #333); border-radius: 8px;';
                searchContainer.appendChild(noResults);
            }
            noResults.textContent = `No results found for "${query}". Try a different search term.`;
            noResults.style.display = 'block';
        }
    }
});
