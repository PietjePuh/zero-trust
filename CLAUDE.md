# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Zero Trust Knowledge Base is a static security wiki for red, white, and gray hats. It provides tool references, cheat sheets, threat intel resources, and hands-on lab walkthroughs. Designed for decentralized hosting (`.brave` / `.pw` domains) and GitHub Pages.

## Architecture

**Static site with no build process** - pure HTML, CSS, and vanilla JavaScript.

```text
zero-trust/
├── index.html          # Landing page with learning paths and wiki sections
├── tools.html          # Security tools encyclopedia with client-side search
├── resources.html      # Curated external security resources with category filters
├── checklist.html      # Interactive implementation checklist (localStorage)
├── comparison.html     # Sortable tool comparison matrix
├── compliance.html     # International compliance frameworks
├── policy.html         # Policy as Code (OPA/Rego)
├── processes.html      # Security processes & lifecycle
├── maturity.html       # Maturity assessment quiz
├── resets.html         # Account recovery links
├── privacy.html        # Privacy policy
├── sw.js               # Service worker (offline cache-first)
├── css/style.css       # Global styles (dark/light themes, print styles)
├── js/
│   ├── theme.js        # Dark/light mode toggle with localStorage
│   ├── highlight.js    # Search result text highlighting (<mark>)
│   ├── search.js       # Global search navigation
│   └── search-data.js  # Search index data
└── Sec-labs/           # Hands-on lab documentation (MkDocs-style markdown)
    └── docs/
        └── tcm/practical-ethical-hacking/  # TCM Academy course notes
```

## Development

No build tools required. Open HTML files directly in browser or use any static file server:

```bash
# Python
python -m http.server 8000

# Node
npx serve .
```

## Key Patterns

- **CSS custom properties** for dark/light theming in `:root` and `[data-theme="light"]` (`css/style.css`)
- **Theme toggle** via `js/theme.js` -- persists preference in localStorage, defaults to dark
- **Client-side search** using `data-keywords` attributes on tool cards (`tools.html`)
- **Search highlighting** via `js/highlight.js` -- wraps matches in `<mark class="search-highlight">`
- **Category filters** -- filter chips on resources page, filter buttons on tools page
- **Category color coding** via `.cat-*` classes (net, web, exp, for, osint)
- **URL query params** for pre-filtered searches (e.g., `tools.html?q=nmap`)
- **localStorage persistence** for checklist progress (`zt-checklist`) and theme (`zt-theme`)
- **Service worker** (`sw.js`) with cache-first strategy for offline access
- **Print styles** via `@media print` in `css/style.css`

## Content Guidelines

- Security tools include command examples in `<div class="tool-flags">` blocks
- Lab walkthroughs follow TCM Academy curriculum structure
- External resources link to reputable security platforms (TryHackMe, HackTheBox, VirusTotal, etc.)
- All pages include the theme toggle button in the nav bar
- New pages must be added to `sw.js` URLS_TO_CACHE and `js/search-data.js`

## Contributing

This is a public repository. Contributions welcome via pull requests.
