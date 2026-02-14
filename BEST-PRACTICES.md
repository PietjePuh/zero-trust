# Security Best Practices Guide

This document outlines the core security practices for interacting with the Zero Trust Knowledge Base and maintaining a secure security-research environment.

## 1. Zero Trust Principles
Always apply the three core pillars of Zero Trust:
- **Verify Explicitly:** Never assume a tool or script is safe just because it is listed here. Verify checksums/hashes before execution.
- **Use Least Privilege:** Run security tools in isolated environments (VMs, Docker containers) with the minimum permissions required. Avoid running everything as `root` or `Administrator`.
- **Assume Breach:** Treat your host machine as potentially compromised. Use dedicated "lab" machines for testing exploits or analyzing malware.

## 2. Repo Maintenance & Contributions
- **Secrets Management:** Use `.env` files for local configurations and ensure they are never committed (verified by our `.gitignore`).
- **Content Integrity:** When adding tools, always use HTTPS links and link to official repositories or documentation.
- **Dependency Security:** If this project grows to include dependencies (Node.js/Python), use tools like `npm audit` or `safety` to check for known vulnerabilities.

## 3. Personal Security Hygiene
- **Hardware Keys:** Use FIDO2/WebAuthn (e.g., Yubikey) for GitHub and all email accounts linked to this project.
- **Encrypted Comms:** Use Signal or ProtonMail for sensitive security discussions.
- **Browsing:** Use a hardened browser (Brave, Librewolf) with extensions like uBlock Origin when researching security tools.

## 4. Lab Safety
- **Isolation:** Never run "Live Labs" on your primary production network. Use a host-only or NAT-isolated network in your virtualization software.
- **Snapshots:** Take snapshots of your lab VMs before running any tools so you can revert to a clean state instantly.
- **Data Disposal:** Securely wipe any memory dumps (`.dmp`) or packet captures (`.pcap`) once analysis is complete to prevent data leakage.
