## 2024-05-23 - Static Site Search Patterns
**Learning:** Static sites with client-side filtering often miss "empty states" (no results found), leaving users confused when a search yields nothing. They also frequently lack proper form labels.
**Action:** Always check for and implement "No results" feedback and explicit labels (visible or sr-only) when enhancing static list filters.

## 2024-05-24 - Categorized List Filtering
**Learning:** When filtering categorized lists (like Resources or Tools), users get confused if empty category headers remain visible after filtering.
**Action:** Always implement logic to hide category headers when all their child items are filtered out.
