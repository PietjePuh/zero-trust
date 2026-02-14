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
            // Fallback to Google Search for the site if no internal match
            window.location.href = `https://www.google.com/search?q=site:zero-trust.pw+${encodeURIComponent(query)}`;
        }
    }
});
