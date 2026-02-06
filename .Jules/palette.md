## 2024-05-23 - Static Site Search Patterns
**Learning:** Static sites with client-side filtering often miss "empty states" (no results found), leaving users confused when a search yields nothing. They also frequently lack proper form labels.
**Action:** Always check for and implement "No results" feedback and explicit labels (visible or sr-only) when enhancing static list filters.

## 2024-05-24 - Reusable Search Components
**Learning:** The search component pattern (input + clear button + no results) defined in `css/style.css` is reusable across different pages (`tools.html`, `resources.html`).
**Action:** When adding search to other list pages (e.g. `index.html` or labs), reuse the `.search-container`, `.search-wrapper` and `.no-results` classes to maintain consistency and reduce code duplication.
