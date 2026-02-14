## 2024-05-23 - Static Site Search Patterns
**Learning:** Static sites with client-side filtering often miss "empty states" (no results found), leaving users confused when a search yields nothing. They also frequently lack proper form labels.
**Action:** Always check for and implement "No results" feedback and explicit labels (visible or sr-only) when enhancing static list filters.

## 2024-05-24 - Dynamic Category Management in Search
**Learning:** When filtering categorized lists (like on `resources.html`), hiding items without hiding their parent category headers leaves "ghost" headers that clutter the UI.
**Action:** Always implement logic to check if a category is empty after filtering and hide the category header accordingly.

## 2026-02-14 - Keyboard Shortcut Discoverability
**Learning:** Adding keyboard shortcuts (like '/' for search) significantly improves power-user experience, but they are useless if invisible. Updating the placeholder text to include the shortcut (e.g., "Press '/'") is a simple, zero-layout-shift way to boost discoverability.
**Action:** Always pair keyboard shortcuts with a visual indicator, such as a tooltip or placeholder text, to ensure users know they exist.
