# AGENTS.md

Coding guidelines for AI agents (Jules, Claude, Copilot, Gemini) working on this repository.

## Project Overview

Zero Trust Knowledge Base — a static security wiki for red, white, and gray hats. Pure HTML/CSS/JS, no build process. Hosted on GitHub Pages at `zero-trust.pw`.

## Build & Development

No build tools required. This is a static site.

```bash
# Local development
python -m http.server 8000
# or
npx serve .
```

## Architecture

```
zero-trust/
├── index.html          # Landing page
├── tools.html          # Security tools encyclopedia
├── resources.html      # Curated external resources
├── checklist.html      # Interactive checklist (localStorage)
├── comparison.html     # Tool comparison matrix
├── compliance.html     # Compliance frameworks
├── policy.html         # Policy as Code
├── processes.html      # Security processes
├── maturity.html       # Maturity assessment
├── resets.html         # Account recovery links
├── privacy.html        # Privacy policy
├── sw.js               # Service worker (cache-first)
├── css/style.css       # Global styles (dark/light themes)
├── js/
│   ├── theme.js        # Dark/light toggle (localStorage)
│   ├── highlight.js    # Search highlighting
│   ├── search.js       # Global search
│   └── search-data.js  # Search index
└── Sec-labs/           # Lab documentation
```

## Code Style & Conventions

- **HTML:** Semantic HTML5, all pages share common nav/footer structure
- **CSS:** Custom properties for theming in `:root` and `[data-theme="light"]`
- **JS:** Vanilla JavaScript only, no frameworks or libraries
- **Naming:** kebab-case for files, camelCase for JS variables
- **No inline styles** in new code (use `css/style.css`)

## Key Patterns

- CSS custom properties for dark/light theming
- `data-keywords` attributes on tool cards for client-side search
- `localStorage` for user preferences (`zt-theme`, `zt-checklist`)
- Category color coding via `.cat-*` classes
- URL query params for pre-filtered views (e.g., `tools.html?q=nmap`)

## Content Guidelines

- Security tools include command examples in `<div class="tool-flags">` blocks
- All pages include theme toggle button in nav
- New pages **must** be added to:
  1. `sw.js` — `URLS_TO_CACHE` array
  2. `js/search-data.js` — search index
  3. Navigation menu in relevant pages
- External links must point to reputable security sources

## Security Rules

- Never commit secrets, API keys, or PII
- No inline `<script>` tags (CSP compliance)
- No third-party CDN dependencies without SRI hashes
- No external data leaks (no Google fallback, no analytics that leak user data)
- Follow zero-trust principles in all code decisions

## Testing

No test framework currently. Manual testing:
1. Open each HTML page in browser
2. Verify dark/light theme toggle works
3. Test search functionality
4. Check responsive layout on mobile viewport
5. Validate service worker caching with DevTools

## Pull Request Guidelines

- One issue per PR
- Reference the issue number in commit messages (`Fixes #XX`)
- Labels: `security`, `enhancement`, `ux`, `auto-merge`, `jules`
- Small safe changes get `auto-merge` label
- Multi-file or architectural changes need manual review
