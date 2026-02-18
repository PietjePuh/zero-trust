## 2024-05-23 - Static Site Search Patterns
**Learning:** Static sites with client-side filtering often miss "empty states" (no results found), leaving users confused when a search yields nothing. They also frequently lack proper form labels.
**Action:** Always check for and implement "No results" feedback and explicit labels (visible or sr-only) when enhancing static list filters.

## 2024-05-24 - Dynamic Category Management in Search
**Learning:** When filtering categorized lists (like on `resources.html`), hiding items without hiding their parent category headers leaves "ghost" headers that clutter the UI.
**Action:** Always implement logic to check if a category is empty after filtering and hide the category header accordingly.

## 2026-02-14 - Keyboard Shortcut Discoverability
**Learning:** Adding keyboard shortcuts (like '/' for search) significantly improves power-user experience, but they are useless if invisible. Updating the placeholder text to include the shortcut (e.g., "Press '/'") is a simple, zero-layout-shift way to boost discoverability.
**Action:** Always pair keyboard shortcuts with a visual indicator, such as a tooltip or placeholder text, to ensure users know they exist.

## 2026-02-14 - Retrofitting Copy Interactions
**Learning:** Static documentation often contains command snippets that users manually select and copy. Adding a dedicated 'Copy' button significantly reduces friction for technical users.
**Action:** Identify repetitive patterns in documentation (like code blocks) and enhance them with client-side DOM manipulation to add utility controls.

## 2024-05-24 - Global Keyboard Shortcuts Safety
**Learning:** When implementing global hotkeys (like '/' for search), naive implementations can break typing in other input fields if they don't explicitly check document.activeElement.tagName.
**Action:** Always wrap global keydown listeners with a check: if (activeTag !== 'INPUT' && activeTag !== 'TEXTAREA').

## 2026-02-18 - Navigation on Long Static Pages
**Learning:** On long static pages (like tools lists), users lose context of navigation. A simple, persistent 'Back to Top' button restores this context and is a high-value micro-UX improvement.
**Action:** When designing or enhancing long content pages, always include a mechanism to quickly return to the top navigation.
