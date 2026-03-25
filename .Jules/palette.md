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

## 2026-02-14 - Invisible Navigation Aids
**Learning:** Users on long content pages often struggle to return to the top navigation without excessive scrolling, causing friction.
**Action:** Implement unobtrusive "Back to Top" buttons that only appear after scrolling, maintaining a clean UI until the functionality is needed.

## 2026-02-14 - Styling Consistency in Mixed Static Sites
**Learning:** Static sites may mix inline styles (for performance on landing pages like `index.html`) with external stylesheets (for other content pages). When adding global UI components, verify both contexts to avoid unstyled content.
**Action:** Ensure global styles are either duplicated in the inline block or the external sheet is universally linked, testing both scenarios.

## 2026-02-14 - Semantic Progress Bars
**Learning:** Visual progress bars implemented with `div` widths are invisible to screen readers, who only hear the static text (e.g., "0 / 6").
**Action:** Always add `role="progressbar"`, `aria-valuemin`, `aria-valuemax`, and dynamically update `aria-valuenow` via JavaScript to ensure state changes are announced.
## 2026-02-27 - Toggle Button State Management
**Learning:** Interactive filter chips that function as toggle buttons often lack `aria-pressed` attributes, leaving screen reader users unaware of the current selection state.
**Action:** When using buttons for filtering, always manage `aria-pressed` state (true/false) in the click handler to explicitly communicate activation status.

## 2026-03-01 - Accessible Custom Radio Button Groups
**Learning:** When using custom `div` elements to create radio button groups (e.g., interactive quizzes like `maturity.html`), simply adding click events is not enough for accessibility or keyboard users.
**Action:** Always add `role="radiogroup"` to the container (linked via `aria-labelledby`), `role="radio"` and `aria-checked` to items, and implement a roving `tabindex` with Arrow key, Space, and Enter event listeners to ensure full keyboard navigation and screen reader support.
## 2026-02-27 - Custom Radio Group Accessibility
**Learning:** When using `div` elements to create custom radio button groups (e.g., in quizzes or assessments), they lack native keyboard support and semantic meaning, breaking navigation for keyboard and screen reader users.
**Action:** Always add `role="radiogroup"` to the container, `role="radio"` and `aria-checked` to options, and implement roving `tabindex` along with Space/Enter and Arrow key navigation in JavaScript.

## 2026-03-07 - Accessible Table Sort Headers
**Learning:** Interactive table headers that allow sorting are often implemented as clickable `<th>` elements but lack semantic meaning as buttons. Without keyboard support and ARIA roles, these controls are invisible to screen reader users and inaccessible to keyboard users.
**Action:** When implementing sortable table headers, always add `tabindex="0"`, `role="button"`, an explicit `aria-label`, and dynamic management of the `aria-sort` attribute (setting to `ascending`, `descending`, or removing it). Ensure `Enter` and `Space` keys trigger the sort action.

## 2026-03-08 - Focus Management for Dynamic Content
**Learning:** When dynamically replacing interactive content (like showing a result after a button click, or replacing form buttons with a success message), keyboard and screen reader focus is lost because the active element disappears. This leaves users disoriented at the top of the page.
**Action:** When replacing content and hiding the currently focused element, explicitly shift focus to the new container or message by adding `tabindex="-1"` and calling `.focus()` via JavaScript.

## 2026-03-09 - Accessible Tooltips for Icon-only Buttons
**Learning:** Adding `aria-label` to icon-only buttons (like theme toggles or clear search buttons) makes them accessible to screen readers, but mouse users may still be confused about their function.
**Action:** Always pair `aria-label` with the native `title` attribute on icon-only buttons to ensure a native browser tooltip appears on hover, improving discoverability for visual users.

## 2026-03-10 - Dynamic Search Announcements
**Learning:** Client-side list filtering happens instantly visually, but screen reader users get no feedback about the number of results, leaving them unsure if their search worked or how many items to tab through.
**Action:** For client-side list filtering (like search inputs), use an `aria-live="polite"` element (visually hidden) to dynamically announce the number of visible results after the filtering logic executes.

## 2024-03-24 - Sticky Header Anchor Offset
**Learning:** When using sticky headers, native anchor links (`<a href="#section">`) cause the target element to scroll underneath the header, hiding content and disorienting users.
**Action:** Always pair `position: sticky` headers with `scroll-padding-top` on the `html` element to offset the scroll position, and add `scroll-behavior: smooth` for better context.

## 2026-03-20 - Invisible Skip Navigation Links
**Learning:** Users relying on keyboard navigation face significant friction when forced to tab through long, repetitive navigation menus on every page load before reaching the main content. This is a common accessibility issue on static sites without built-in routing.
**Action:** Always implement a "Skip to main content" link as the first focusable element inside the body. Visually hide it by default, but make it appear on focus. Ensure the target `<main>` element has `id="main-content"` and `tabindex="-1"` so it can programmatically receive focus without breaking tab order.
