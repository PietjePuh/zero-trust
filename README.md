# Zero Trust Knowledge Base

A decentralized security knowledge platform for ethical hacking, blue teaming, and security research.

**Live Site**: [https://zero-trust.pw](https://zero-trust.pw) | [https://zero-trust.brave](https://zero-trust.brave)

## Features

- **Security Tools Encyclopedia** - Comprehensive index of penetration testing and SOC tools with command examples
- **Curated Resources** - Directory of threat intelligence platforms, CTF sites, and learning resources
- **Hands-on Labs** - Step-by-step walkthroughs for security techniques (EternalBlue, etc.)
- **Learning Paths** - Structured courses for different security domains

## Project Structure

```
zero-trust/
├── index.html          # Main landing page / knowledge base hub
├── tools.html          # Security tools index with search
├── resources.html      # External resources directory
├── 404.html            # Error page
├── css/
│   └── style.css       # Main stylesheet
├── Sec-labs/           # Lab documentation
│   └── docs/
│       └── tcm/
│           └── practical-ethical-hacking/
│               └── eternalblue-lab.md
├── robots.txt          # Search engine directives
├── sitemap.xml         # Sitemap for SEO
└── CNAME               # Custom domain config
```

## Local Development

1. Clone the repository:
   ```bash
   git clone https://github.com/PietjePuh/zero-trust.git
   cd zero-trust
   ```

2. Serve locally (any static server works):
   ```bash
   # Using Python
   python -m http.server 8000

   # Using Node.js
   npx serve
   ```

3. Open `http://localhost:8000` in your browser

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-tool`)
3. Commit your changes (`git commit -m 'Add new tool documentation'`)
4. Push to the branch (`git push origin feature/new-tool`)
5. Open a Pull Request

### Adding New Tools

Edit `tools.html` and add a new tool card:

```html
<div class="tool-card" id="tool-name" data-keywords="keyword1 keyword2">
    <div class="tool-header">
        <h3 class="tool-title">Tool Name</h3>
        <span class="tool-category cat-net">Category</span>
    </div>
    <div class="tool-desc">Tool description here.</div>
    <div class="tool-flags">
<strong># Command Example</strong>
tool-command --flags
    </div>
</div>
```

Categories: `cat-net` (Networking), `cat-web` (Web), `cat-exp` (Exploitation), `cat-for` (Forensics), `cat-osint` (OSINT)

## License

Open source. Use responsibly for authorized security testing and education only.
