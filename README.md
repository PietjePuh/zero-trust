# Zero Trust Knowledge Base

A comprehensive, static security wiki for red, white, and gray hats. Provides tool references, cheat sheets, threat intelligence resources, compliance frameworks, and hands-on lab walkthroughs -- all with zero dependencies and offline support.

> Live at [zero-trust.brave](http://zero-trust.brave) | Hosted on GitHub Pages

![Screenshot placeholder](https://via.placeholder.com/800x400?text=Zero+Trust+Knowledge+Base)

## Features

- **Security Tools Index** -- Curated encyclopedia of offensive and defensive security tools with command examples and copy-to-clipboard
- **Resource Directory** -- 80+ links to search engines, threat intel platforms, learning sites, and news sources with category filters
- **Compliance Frameworks** -- EU (GDPR/NIS2), China (MLPS 2.0/PIPL), and US (EO 14028/CISA) zero-trust requirements
- **Policy as Code** -- OPA/Rego examples for zero-trust policy enforcement
- **Maturity Assessment** -- Interactive quiz benchmarking against the CISA Zero Trust Maturity Model
- **Implementation Checklist** -- Interactive 30-item checklist across 5 domains (Identity, Devices, Network, Applications, Data) with progress tracking saved to localStorage
- **Tool Comparison Matrix** -- Sortable tables comparing identity platforms, network solutions, and EDR vendors
- **Dark/Light Mode** -- Theme toggle with preference saved to localStorage (defaults to dark)
- **Search with Highlighting** -- Client-side search across tools and resources with `<mark>` highlighting of matches
- **Offline Support** -- Service worker with cache-first strategy for full offline access
- **Print-Friendly** -- Clean `@media print` styles for printing cheat sheets
- **Sec Labs** -- Hands-on lab walkthroughs (Kerberoasting, Buffer Overflow, EternalBlue)

## Project Structure

```text
zero-trust/
├── index.html            # Landing page
├── tools.html            # Security tools encyclopedia
├── resources.html        # Curated external resources
├── checklist.html        # Implementation checklist (localStorage)
├── comparison.html       # Tool comparison matrix (sortable)
├── compliance.html       # International compliance frameworks
├── policy.html           # Policy as Code (OPA/Rego)
├── processes.html        # Security processes & lifecycle
├── maturity.html         # Maturity assessment quiz
├── resets.html           # Account recovery links
├── privacy.html          # Privacy policy
├── sw.js                 # Service worker (offline support)
├── css/
│   └── style.css         # Global styles (dark/light themes, print)
├── js/
│   ├── theme.js          # Dark/light mode toggle
│   ├── highlight.js      # Search result highlighting
│   ├── search.js         # Global search navigation
│   └── search-data.js    # Search index data
├── Sec-labs/             # Hands-on lab documentation
│   └── docs/
│       ├── attacks/      # Attack technique labs
│       └── tcm/          # TCM Academy course notes
└── .github/
    └── workflows/
        ├── deploy.yml    # GitHub Pages deployment
        └── ci.yml        # HTML validation
```

## Getting Started

No build tools required. Open HTML files directly in a browser or use any static file server:

```bash
# Python
python -m http.server 8000

# Node
npx serve .

# Then open http://localhost:8000
```

## Contributing

Contributions are welcome! Here is how to get involved:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feat/my-enhancement`)
3. **Make** your changes -- keep it vanilla HTML/CSS/JS, no frameworks
4. **Test** by opening the pages in a browser
5. **Commit** using conventional commits (`feat:`, `fix:`, `docs:`)
6. **Push** and open a Pull Request

### Content Guidelines

- Security tools should include command examples in `<div class="tool-flags">` blocks
- External resources should link to reputable platforms with `target="_blank" rel="noopener noreferrer"`
- Use `data-keywords` attributes on tool cards for search discoverability
- Follow the existing category color coding (`.cat-net`, `.cat-web`, `.cat-exp`, `.cat-for`, `.cat-osint`)

## License

This project is open source. See the repository for license details.
