document.addEventListener('DOMContentLoaded', () => {
    const searchInputs = document.querySelectorAll('.search-input');
    
    searchInputs.forEach(input => {
        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                const query = e.target.value.toLowerCase().trim();
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

        const noResults = document.getElementById('noResults');

        if (results.length > 0) {
            // Hide "No Results" message if it exists
            if (noResults) {
                noResults.classList.add('hidden');
            }

            // If there's an exact title match, go directly to it
            const exactMatch = results.find(page => page.title.toLowerCase() === query);
            if (exactMatch) {
                if (!window.location.pathname.endsWith(exactMatch.url)) {
                    window.location.href = exactMatch.url;
                }
                return;
            }

            // If there's only one result, go to it
            if (results.length === 1) {
                if (!window.location.pathname.endsWith(results[0].url)) {
                    window.location.href = results[0].url;
                }
                return;
            }

            // Multiple results: show suggestions in the "No Results" container if it exists
            if (noResults) {
                noResults.innerHTML = ''; // Safe to clear

                const message = document.createElement('p');
                message.textContent = `Found ${results.length} related pages:`;
                noResults.appendChild(message);

                const ul = document.createElement('ul');
                ul.style.listStyle = 'none';
                ul.style.padding = '1rem 0';
                ul.style.textAlign = 'center';

                results.slice(0, 5).forEach(page => {
                    const li = document.createElement('li');
                    li.style.margin = '0.5rem 0';

                    const a = document.createElement('a');
                    a.href = page.url;
                    a.style.color = 'var(--accent-color)';
                    a.style.textDecoration = 'none';
                    a.style.fontWeight = '600';

                    const icon = document.createElement('span');
                    icon.textContent = '📂 ';

                    const text = document.createElement('span');
                    text.textContent = page.title;

                    a.appendChild(icon);
                    a.appendChild(text);
                    li.appendChild(a);
                    ul.appendChild(li);
                });

                noResults.appendChild(ul);
                noResults.classList.remove('hidden');
            } else {
                // If no suggestion container, default to first result for UX
                window.location.href = results[0].url;
            }
        } else {
            // No internal match - show feedback instead of leaking to Google
            if (noResults) {
                noResults.innerHTML = ''; // Safe to clear

                const p = document.createElement('p');
                p.textContent = 'No results found for "';

                const strong = document.createElement('strong');
                strong.textContent = query;

                p.appendChild(strong);
                p.appendChild(document.createTextNode('". Try different keywords.'));

                noResults.appendChild(p);
                noResults.classList.remove('hidden');
            } else {
                alert(`No results found for "${query}".`);
            }
        }
    }
});
