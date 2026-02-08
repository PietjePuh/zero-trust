## 2024-05-23 - Static Site Search Patterns
**Learning:** Static sites with client-side filtering often miss "empty states" (no results found), leaving users confused when a search yields nothing. They also frequently lack proper form labels.
**Action:** Always check for and implement "No results" feedback and explicit labels (visible or sr-only) when enhancing static list filters.

## 2024-05-24 - Filtered List Category Management
**Learning:** When filtering categorized lists (like resources or tools), keeping empty category headers visible creates visual noise and requires unnecessary scrolling.
**Action:** Implement logic to hide parent containers/headers when all their child items are filtered out.
