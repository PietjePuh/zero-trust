## 2024-05-23 - Static Site Search Patterns
**Learning:** Static sites with client-side filtering often miss "empty states" (no results found), leaving users confused when a search yields nothing. They also frequently lack proper form labels.
**Action:** Always check for and implement "No results" feedback and explicit labels (visible or sr-only) when enhancing static list filters.

## 2026-02-09 - Handling Empty Category Headers in Search
**Learning:** When filtering categorized lists (like in `resources.html`), simply hiding non-matching items leaves empty category headers visible, cluttering the UI.
**Action:** Implement logic to count visible items per category and hide the parent container/header if the count is zero.
