## 2024-05-23 - Static Site Search Patterns
**Learning:** Static sites with client-side filtering often miss "empty states" (no results found), leaving users confused when a search yields nothing. They also frequently lack proper form labels.
**Action:** Always check for and implement "No results" feedback and explicit labels (visible or sr-only) when enhancing static list filters.

## 2024-05-24 - Deep Linking Filters
**Learning:** Static site filters (like categories) often fail to support deep linking via URL parameters, breaking navigation flows from other pages.
**Action:** Always implement URL parameter handling (e.g., `?category=web`) when building client-side filters to support bookmarking and external links.
