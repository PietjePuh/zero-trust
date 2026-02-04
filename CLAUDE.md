# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Zero Trust Knowledge Base is a static security wiki for red, white, and gray hats. It provides tool references, cheat sheets, threat intel resources, and hands-on lab walkthroughs. Designed for decentralized hosting (`.brave` / `.pw` domains) and GitHub Pages.

## Architecture

**Static site with no build process** - pure HTML, CSS, and vanilla JavaScript.

```
zero-trust/
├── index.html          # Landing page with learning paths and wiki sections
├── tools.html          # Security tools encyclopedia with client-side search
├── resources.html      # Curated external security resources
├── css/style.css       # Global styles (dark theme, GitHub-inspired)
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

- **CSS variables** for theming in `:root` (`css/style.css:1-14`)
- **Client-side search** using `data-keywords` attributes on tool cards (`tools.html:303-333`)
- **Category color coding** via `.cat-*` classes (net, web, exp, for, osint)
- **URL query params** for pre-filtered searches (e.g., `tools.html?q=nmap`)

## Content Guidelines

- Security tools include command examples in `<div class="tool-flags">` blocks
- Lab walkthroughs follow TCM Academy curriculum structure
- External resources link to reputable security platforms (TryHackMe, HackTheBox, VirusTotal, etc.)

## Contributing

This is a public repository. Contributions welcome via pull requests.
