/* global process */
/* global process */
(function() {
  'use strict';

  // Use global definitions
  const SNIPPETS = window.SNIPPETS;
  const KILL_CHAIN = window.KILL_CHAIN;
  const ATTACK_TACTICS = window.ATTACK_TACTICS;
  const PYRAMID_LEVELS = window.PYRAMID_LEVELS;
  const OWASP_TOP10 = window.OWASP_TOP10;


  // ═══════════════════════════════════════════════════════════
  //  OS TAGGING — maps snippet id → target OS
  // ═══════════════════════════════════════════════════════════

  const OS_MAP = {
    // Linux-only commands (run ON Linux target or Linux-specific tools)
    'bash-rev': 'linux', 'nc-rev': 'linux', 'python-rev': 'linux',
    'tty-upgrade': 'linux', 'linpeas': 'linux', 'sudo-l': 'linux',
    'find-suid': 'linux', 'persist-cron': 'linux', 'persist-service': 'linux',
    'download-http': 'linux', 'exfil-nc': 'linux', 'exfil-base64': 'linux',
    'netstat-linux': 'linux', 'find-creds': 'linux',
    'ir-collect-linux': 'linux', 'virustotal-hash': 'linux', 'remnux-analysis': 'linux',
    'blue-fw-rules': 'linux', 'blue-fail2ban': 'linux', 'blue-auth-logs': 'linux',
    'blue-process-audit': 'linux', 'blue-cron-audit': 'linux', 'blue-svc-audit': 'linux',
    'blue-network-connections': 'linux', 'blue-dns-monitor': 'linux',
    'blue-hash-check': 'linux', 'blue-user-audit': 'linux',
    'listener-rlwrap': 'linux', 'ldapsearch': 'linux',
    // Receivers (mostly cross-platform, some Linux)
    'dns-listener': 'linux', 'smtp-receiver': 'linux',
    'responder-http': 'linux',
    // Wireless (Linux — needs monitor mode)
    'airmon-start': 'linux', 'airodump': 'linux', 'aireplay-deauth': 'linux',
    'bettercap-wifi': 'linux', 'wifite': 'linux', 'eaphammer': 'linux',
    // Windows-only commands (run ON Windows target or Windows-specific)
    'powershell-rev': 'windows', 'winpeas': 'windows',
    'persist-schtask': 'windows', 'upload-certutil': 'windows',
    'upload-powershell': 'windows', 'netstat-windows': 'windows',
    'ir-collect-windows': 'windows', 'mimikatz-logonpasswords': 'windows',
    'blue-schtask-audit': 'windows', 'blue-windows-events': 'windows',
    // Windows post-exploitation
    'win-sysinfo': 'windows', 'win-powerview': 'windows', 'win-rubeus': 'windows',
    'win-sharphound': 'windows', 'win-token-impersonate': 'windows',
    'win-sam-dump': 'windows', 'win-dpapi': 'windows',
    'win-amsi-bypass': 'windows', 'win-uac-bypass': 'windows',
    // Mobile (mostly cross-platform tools, ADB = Linux/Mac primary)
    'adb-devices': 'linux', 'adb-shell': 'linux',
    // New privesc (Linux)
    'linux-capabilities': 'linux', 'writable-path': 'linux', 'pspy': 'linux', 'gtfobins-check': 'linux',
    // New privesc (Windows)
    'win-token-priv': 'windows', 'unquoted-svc': 'windows', 'always-install-elevated': 'windows', 'dll-hijack-search': 'windows',
    // New persist (Linux)
    'persist-ssh-key': 'linux', 'persist-bashrc': 'linux',
    // New persist (Windows)
    'persist-run-key': 'windows', 'persist-winlogon': 'windows', 'persist-startup-folder': 'windows',
    // New shells (Linux)
    'php-rev': 'linux', 'ruby-rev': 'linux', 'perl-rev': 'linux', 'php-webshell': 'linux', 'socat-encrypted': 'linux',
    // New enum (Linux)
    'world-writable': 'linux', 'recent-files': 'linux', 'docker-enum': 'linux',
    // New forensics (Linux)
    'disk-image-mount': 'linux', 'log2timeline': 'linux',
    // New forensics (Windows)
    'prefetch-parser': 'windows', 'chainsaw-evtx': 'windows',
    // New IR (Linux)
    'ir-containment': 'linux', 'ir-timeline-linux': 'linux',
    // New IR (Windows)
    'ir-timeline-windows': 'windows',
    // New detect (Windows)
    'blue-sysmon-config': 'windows',
    // New detect (Linux)
    'blue-auditd-config': 'linux',
    // New hardening (Linux)
    'blue-lynis': 'linux', 'blue-fail2ban-hardening': 'linux',
    // Social (Linux tools)
    'wifi-evil-twin': 'linux', 'responder-ntlm': 'linux',
    // Post-exploitation (Linux)
    'post-pivot-scan': 'linux',
    // Passwords (Linux tools)
    'cewl-wordlist': 'linux',
    // Wireless defense (Linux)
    'blue-wireless-scan': 'linux', 'blue-wireless-ids': 'linux',
    // Evasion (OS-specific)
    'ev-etw-patch': 'windows', 'ev-process-inject': 'linux',
    // Detect (Linux tools)
    'blue-honeypot': 'linux', 'blue-zeek-monitor': 'linux', 'blue-crowdsec': 'linux',
    // Database (Linux-specific)
    'redis-exploit': 'linux',
    // Docker (Linux-specific)
    'docker-cap-audit': 'linux', 'docker-secrets-extract': 'linux',
    // Setup (Linux/Kali)
    'kali-gui-xrdp': 'linux', 'kali-tools-meta': 'linux', 'kali-full-install': 'linux',
    'kali-pimp-script': 'linux', 'kali-ad-toolkit': 'linux', 'pentest-env-verify': 'linux',
    // Setup (Windows-specific)
    'kali-wsl2-install': 'windows',
    // Network analysis (Linux)
    'tcpdump-capture': 'linux', 'tcpdump-flags': 'linux',
    // C2 (Linux)
    'empire-setup': 'linux', 'empire-post-exploit': 'linux',
    'sliver-c2': 'linux', 'metasploit-handler': 'linux',
    // Tunneling (Linux)
    'ssh-local-forward': 'linux', 'ssh-dynamic-socks': 'linux',
    'ssh-reverse-tunnel': 'linux', 'ssh-jump-bastion': 'linux',
    'ligolo-pivot': 'linux', 'rpivot-socks': 'linux',
    // Stego (Linux)
    'steghide-ops': 'linux', 'binwalk-extract': 'linux',
    // PowerShell (Windows)
    'ps-recon': 'windows', 'ps-download-cradle': 'windows',
    'ps-amsi-bypass': 'windows', 'ps-scriptblock-logging': 'windows',
    // SIEM (mixed — Splunk/ELK are cross-platform, syslog is Linux)
    'syslog-analysis': 'linux',
    'windows-eventids': 'windows',
    // Encoding (encoding-cli and hash-operations have multi-OS commands objects)
    'xor-analysis': 'linux',
    // Phishing (gophish + infra Linux, payloads mostly Windows)
    'gophish-campaign': 'linux', 'phishing-infra': 'linux',
    'phishing-payloads': 'windows',
    // Binary exploitation (Linux-focused)
    'bof-basics': 'linux', 'pwntools-template': 'linux',
    'gdb-peda': 'linux', 'checksec-protections': 'linux',
    'format-string': 'linux',
    // Reverse engineering (Linux-focused)
    'radare2-basics': 'linux', 're-strings-analysis': 'linux',
    're-dynamic-analysis': 'linux', 're-patching': 'linux',
    // Lateral movement (Windows-focused, some have multi-OS commands)
    'lateral-pth': 'windows', 'lateral-rdp': 'windows',
    'lateral-detection': 'windows',
    // Windows forensics
    'volatility-memdump': 'linux', 'registry-forensics': 'windows',
    'memory-acquisition': 'windows', 'prefetch-timeline': 'windows',
    // Reporting (cross-platform)
    'evidence-collection': 'linux',
    // Network attacks (Linux tools)
    'arp-spoof': 'linux', 'dns-attacks': 'linux', 'vlan-hopping': 'linux',
    'responder-relay': 'linux', 'network-sniff': 'linux',
    // AD attacks (mixed — kerberoast/asrep/bloodhound have multi-OS)
    'dcsync': 'windows', 'golden-silver-ticket': 'windows',
    // WAF bypass (cross-platform)
    'waf-detect': 'linux',
    // Automation (bash-oneliners, python-pentest, expect = Linux; cron has multi-OS)
    'bash-oneliners': 'linux', 'python-pentest': 'linux',
    'expect-automation': 'linux', 'regex-security': 'linux',
    // OSINT (cross-platform except opsec tools)
    'osint-opsec': 'linux',
    // Pivoting
    'pivot-ssh-advanced': 'linux', 'pivot-chisel': 'linux',
    'pivot-windows': 'windows', 'pivot-detection': 'linux',
    // ICS/SCADA (mostly Linux recon tools, assessment is cross-platform)
    'ics-recon': 'linux', 'ics-exploit': 'linux',
    'ics-defense': 'linux', 'ics-honeypot': 'linux',
    // Browser exploitation (BeEF Linux, creds/forensics have multi-OS)
    'beef-xss': 'linux',
    // Playbooks (mostly cross-platform; insider has Windows audit commands)
    'playbook-ransomware': 'linux', 'playbook-phishing': 'linux',
    'evidence-collection-playbook': 'linux',
    // Metasploit (Linux attack platform)
    'msf-basics': 'linux', 'msf-handler': 'linux',
    'msf-scanning': 'linux', 'msf-post': 'linux',
    // Azure (auth attacks = Windows; rest = cross-platform)
    'azure-auth-attack': 'windows', 'azure-post-exploit': 'windows',
    // Windows Events (Sysmon/Security = Windows; Splunk/hunting = Linux)
    'winevents-security': 'windows', 'winevents-sysmon': 'windows',
    'winevents-splunk': 'linux', 'winevents-powershell': 'windows',
    'winevents-hunting': 'linux',
    // OPSEC (infra = Linux; detection-evasion = Windows)
    'opsec-infra': 'linux', 'opsec-detection-evasion': 'windows',
    // Sliver C2 (Linux-focused server)
    'sliver-basics': 'linux', 'sliver-post': 'linux',
    // Supply chain (attack tooling Linux; scan is multi-OS)
    'supply-chain-attack': 'linux',
    // Fuzzing (Linux-focused tooling)
    'fuzz-web': 'linux', 'fuzz-binary': 'linux', 'fuzz-api': 'linux',
    // Zero Trust (network segmentation = Linux iptables focused)
    'zt-network': 'linux',
  };

  SNIPPETS.forEach(s => { s.os = OS_MAP[s.id] || 'all'; });

  // ═══════════════════════════════════════════════════════════
  //  TOOL REGISTRY — canonical tool list with install hints
  // ═══════════════════════════════════════════════════════════

  const TOOL_REGISTRY = [
    // Recon
    { id: 'nmap',           label: 'Nmap',              cat: 'recon',     install: 'apt install nmap / choco install nmap / brew install nmap' },
    { id: 'whatweb',        label: 'WhatWeb',            cat: 'recon',     install: 'apt install whatweb / gem install whatweb' },
    { id: 'amass',          label: 'Amass',              cat: 'recon',     install: 'go install github.com/owasp-amass/amass/v4/...@master' },
    { id: 'subfinder',      label: 'Subfinder',          cat: 'recon',     install: 'go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest' },
    { id: 'theharvester',   label: 'theHarvester',       cat: 'recon',     install: 'pip install theHarvester' },
    { id: 'shodan',         label: 'Shodan CLI',         cat: 'recon',     install: 'pip install shodan' },
    { id: 'nuclei',         label: 'Nuclei',             cat: 'recon',     install: 'go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest' },
    // Web
    { id: 'ffuf',           label: 'ffuf',               cat: 'web',       install: 'go install github.com/ffuf/ffuf/v2@latest' },
    { id: 'gobuster',       label: 'Gobuster',           cat: 'web',       install: 'go install github.com/OJ/gobuster/v3@latest' },
    { id: 'feroxbuster',    label: 'Feroxbuster',        cat: 'web',       install: 'apt install feroxbuster / cargo install feroxbuster' },
    { id: 'nikto',          label: 'Nikto',              cat: 'web',       install: 'apt install nikto' },
    { id: 'sqlmap',         label: 'SQLMap',             cat: 'web',       install: 'apt install sqlmap / pip install sqlmap' },
    { id: 'wfuzz',          label: 'Wfuzz',              cat: 'web',       install: 'pip install wfuzz' },
    { id: 'wpscan',         label: 'WPScan',             cat: 'web',       install: 'gem install wpscan' },
    // Passwords
    { id: 'hydra',          label: 'Hydra',              cat: 'passwords', install: 'apt install hydra' },
    { id: 'hashcat',        label: 'Hashcat',            cat: 'passwords', install: 'apt install hashcat / choco install hashcat' },
    { id: 'john',           label: 'John the Ripper',    cat: 'passwords', install: 'apt install john' },
    { id: 'crackmapexec',   label: 'CrackMapExec',       cat: 'passwords', install: 'pip install crackmapexec' },
    // AD / Lateral
    { id: 'bloodhound',     label: 'BloodHound',         cat: 'ad',        install: 'pip install bloodhound' },
    { id: 'impacket',       label: 'Impacket',           cat: 'ad',        install: 'pip install impacket' },
    { id: 'evil-winrm',     label: 'Evil-WinRM',         cat: 'ad',        install: 'gem install evil-winrm' },
    { id: 'kerbrute',       label: 'Kerbrute',           cat: 'ad',        install: 'go install github.com/ropnop/kerbrute@latest' },
    { id: 'enum4linux',     label: 'Enum4Linux-ng',      cat: 'ad',        install: 'pip install enum4linux-ng' },
    { id: 'responder',      label: 'Responder',          cat: 'ad',        install: 'apt install responder / pip install Responder' },
    { id: 'mimikatz',       label: 'Mimikatz',           cat: 'ad',        install: 'Download from github.com/gentilkiwi/mimikatz' },
    // Tunneling
    { id: 'chisel',         label: 'Chisel',             cat: 'tunnel',    install: 'go install github.com/jpillora/chisel@latest' },
    { id: 'socat',          label: 'Socat',              cat: 'tunnel',    install: 'apt install socat' },
    { id: 'ligolo',         label: 'Ligolo-ng',          cat: 'tunnel',    install: 'go install github.com/nicocha30/ligolo-ng@latest' },
    // Payloads
    { id: 'msfvenom',       label: 'Msfvenom',           cat: 'payloads',  install: 'apt install metasploit-framework' },
    { id: 'metasploit',     label: 'Metasploit',         cat: 'payloads',  install: 'apt install metasploit-framework' },
    // Forensics / Blue
    { id: 'volatility',     label: 'Volatility 3',       cat: 'forensics', install: 'pip install volatility3' },
    { id: 'autopsy',        label: 'Autopsy / TSK',      cat: 'forensics', install: 'apt install sleuthkit' },
    { id: 'yara',           label: 'YARA',               cat: 'malware',   install: 'apt install yara / pip install yara-python' },
    { id: 'cuckoo',         label: 'Cuckoo Sandbox',     cat: 'malware',   install: 'pip install cuckoo' },
    // OSINT
    { id: 'recon-ng',       label: 'Recon-ng',           cat: 'osint',     install: 'pip install recon-ng' },
    { id: 'spiderfoot',     label: 'SpiderFoot',         cat: 'osint',     install: 'pip install spiderfoot' },
    { id: 'maltego',        label: 'Maltego CE',         cat: 'osint',     install: 'Download from maltego.com' },
    { id: 'dnsenum',        label: 'DNSenum',            cat: 'osint',     install: 'apt install dnsenum' },
    // Hardening / DAST
    { id: 'semgrep',        label: 'Semgrep',            cat: 'hardening', install: 'pip install semgrep' },
    { id: 'trivy',          label: 'Trivy',              cat: 'hardening', install: 'apt install trivy / brew install trivy' },
    { id: 'zap',            label: 'OWASP ZAP',          cat: 'hardening', install: 'Download from zaproxy.org / docker pull zaproxy/zap-stable' },
    { id: 'dependency-check', label: 'Dep-Check',        cat: 'hardening', install: 'Download from owasp.org/dependency-check' },
    // Cloud
    { id: 'aws',            label: 'AWS CLI',            cat: 'cloud',     install: 'pip install awscli / brew install awscli' },
    { id: 'prowler',        label: 'Prowler',            cat: 'cloud',     install: 'pip install prowler' },
    { id: 'scoutsuite',     label: 'ScoutSuite',         cat: 'cloud',     install: 'pip install scoutsuite' },
    { id: 'pacu',           label: 'Pacu (AWS exploit)', cat: 'cloud',     install: 'pip install pacu' },
    // Wireless
    { id: 'aircrack-ng',    label: 'Aircrack-ng Suite',  cat: 'wireless',  install: 'apt install aircrack-ng' },
    { id: 'bettercap',      label: 'Bettercap',          cat: 'wireless',  install: 'apt install bettercap / brew install bettercap' },
    { id: 'wifite',         label: 'Wifite',             cat: 'wireless',  install: 'apt install wifite' },
    { id: 'eaphammer',      label: 'EAPHammer',          cat: 'wireless',  install: 'github.com/s0lst1c3/eaphammer' },
    // Social Engineering
    { id: 'gophish',        label: 'GoPhish',            cat: 'social',    install: 'github.com/gophish/gophish/releases' },
    { id: 'setoolkit',      label: 'SET Toolkit',        cat: 'social',    install: 'apt install set' },
    { id: 'evilginx',       label: 'Evilginx2',         cat: 'social',    install: 'go install github.com/kgretzky/evilginx2@latest' },
    { id: 'swaks',          label: 'Swaks',              cat: 'social',    install: 'apt install swaks' },
    // Windows Post-Exploit
    { id: 'rubeus',         label: 'Rubeus',             cat: 'winpost',   install: 'github.com/GhostPack/Rubeus (compile)' },
    { id: 'sharphound',     label: 'SharpHound',         cat: 'winpost',   install: 'github.com/BloodHoundAD/SharpHound' },
    { id: 'powerview',      label: 'PowerView',          cat: 'winpost',   install: 'IEX(IWR .../PowerView.ps1)' },
    // Receivers
    { id: 'updog',          label: 'Updog',              cat: 'receivers', install: 'pip install updog' },
    { id: 'interactsh',     label: 'Interactsh',         cat: 'receivers', install: 'go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest' },
    { id: 'ngrok',          label: 'Ngrok',              cat: 'receivers', install: 'Download from ngrok.com / snap install ngrok' },
    { id: 'webdav',         label: 'WsgiDAV',            cat: 'receivers', install: 'pip install wsgidav cheroot' },
    { id: 'dnscat2',        label: 'dnscat2',            cat: 'receivers', install: 'gem install dnscat2 / github.com/iagox86/dnscat2' },
    // Mobile
    { id: 'adb',            label: 'ADB',                cat: 'mobile',    install: 'apt install adb / brew install android-platform-tools' },
    { id: 'apktool',        label: 'Apktool',            cat: 'mobile',    install: 'apt install apktool / brew install apktool' },
    { id: 'jadx',           label: 'JADX',               cat: 'mobile',    install: 'github.com/skylot/jadx/releases' },
    { id: 'frida',          label: 'Frida',              cat: 'mobile',    install: 'pip install frida-tools' },
    { id: 'objection',      label: 'Objection',          cat: 'mobile',    install: 'pip install objection' },
    { id: 'mobsf',          label: 'MobSF',              cat: 'mobile',    install: 'docker pull opensecurity/mobile-security-framework-mobsf' },
    // Container Defense
    { id: 'grype',          label: 'Grype',              cat: 'container', install: 'curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh' },
    { id: 'falco',          label: 'Falco',              cat: 'container', install: 'docker pull falcosecurity/falco' },
    { id: 'kubescape',      label: 'Kubescape',          cat: 'container', install: 'curl -s https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh | bash' },
    { id: 'cosign',         label: 'Cosign',             cat: 'container', install: 'go install github.com/sigstore/cosign/v2/cmd/cosign@latest' },
    // Common utils
    { id: 'nc',             label: 'Netcat',             cat: 'util',      install: 'apt install netcat / ncat (from nmap)' },
    { id: 'rlwrap',         label: 'rlwrap',             cat: 'util',      install: 'apt install rlwrap' },
    { id: 'fail2ban',       label: 'Fail2ban',           cat: 'defense',   install: 'apt install fail2ban' },
    { id: 'thehive',        label: 'TheHive',            cat: 'ir',        install: 'https://docs.strangebee.com' },
    { id: 'ssh',            label: 'SSH',                cat: 'util',      install: 'Built-in (OpenSSH)' },
    { id: 'curl',           label: 'cURL',               cat: 'util',      install: 'apt install curl / built-in (macOS, most Linux)' },
    // New tools from expansions
    { id: 'pspy',           label: 'pspy',               cat: 'privesc',   install: 'github.com/DominicBreuker/pspy/releases' },
    { id: 'smbclient',      label: 'smbclient',          cat: 'enum',      install: 'apt install smbclient' },
    { id: 'snmpwalk',       label: 'snmpwalk',           cat: 'enum',      install: 'apt install snmp' },
    { id: 'sherlock',        label: 'Sherlock',           cat: 'osint',     install: 'pip install sherlock-project' },
    { id: 'censys',         label: 'Censys CLI',         cat: 'osint',     install: 'pip install censys' },
    { id: 'ghidra',         label: 'Ghidra',             cat: 'malware',   install: 'Download from ghidra-sre.org' },
    { id: 'olevba',         label: 'OleVBA',             cat: 'malware',   install: 'pip install oletools' },
    { id: 'floss',          label: 'FLOSS',              cat: 'malware',   install: 'pip install flare-floss' },
    { id: 'capa',           label: 'capa',               cat: 'malware',   install: 'pip install flare-capa' },
    { id: 'chainsaw',       label: 'Chainsaw',           cat: 'forensics', install: 'github.com/WithSecureLabs/chainsaw/releases' },
    { id: 'plaso',          label: 'Plaso/log2timeline', cat: 'forensics', install: 'pip install plaso' },
    { id: 'velociraptor',   label: 'Velociraptor',       cat: 'ir',        install: 'github.com/Velocidex/velociraptor/releases' },
    { id: 'lynis',          label: 'Lynis',              cat: 'hardening', install: 'apt install lynis' },
    { id: 'ssh-audit',      label: 'SSH-Audit',          cat: 'hardening', install: 'pip install ssh-audit' },
    { id: 'sysmon',         label: 'Sysmon',             cat: 'detect',    install: 'Download from docs.microsoft.com/sysinternals/sysmon' },
    { id: 'sigma',          label: 'Sigma',              cat: 'detect',    install: 'pip install sigma-cli' },
    { id: 'wazuh',          label: 'Wazuh',              cat: 'detect',    install: 'apt install wazuh-agent / docker (manager)' },
    { id: 'suricata',       label: 'Suricata',           cat: 'detect',    install: 'apt install suricata' },
    { id: 'beef',           label: 'BeEF',               cat: 'social',    install: 'apt install beef-xss' },
    { id: 'httrack',        label: 'HTTrack',            cat: 'social',    install: 'apt install httrack' },
    { id: 'wifiphisher',    label: 'Wifiphisher',        cat: 'social',    install: 'pip install wifiphisher' },
    { id: 'oscap',          label: 'OpenSCAP',           cat: 'hardening', install: 'apt install libopenscap8' },
    // New tools — passwords (kerbrute already in 'ad' above)
    { id: 'cewl',            label: 'CeWL',               cat: 'passwords', install: 'gem install cewl' },
    { id: 'ntlmrelayx',      label: 'NTLMRelayx',         cat: 'passwords', install: 'pip install impacket' },
    { id: 'secretsdump',     label: 'Secretsdump',        cat: 'passwords', install: 'pip install impacket' },
    { id: 'lazagne',         label: 'LaZagne',            cat: 'post',      install: 'github.com/AlessandroZ/LaZagne/releases' },
    // Threat intel
    { id: 'misp',            label: 'MISP',               cat: 'threatintel', install: 'docker pull coolacid/misp-docker' },
    { id: 'opencti',         label: 'OpenCTI',            cat: 'threatintel', install: 'docker-compose from github.com/OpenCTI-Platform/docker' },
    { id: 'stix2',           label: 'python-stix2',       cat: 'threatintel', install: 'pip install stix2' },
    // Wireless defense
    { id: 'kismet',          label: 'Kismet',             cat: 'wireless',  install: 'apt install kismet' },
    // Evasion
    { id: 'donut',           label: 'Donut',              cat: 'evasion',   install: 'pip install donut-shellcode' },
    { id: 'upx',             label: 'UPX',                cat: 'evasion',   install: 'apt install upx / brew install upx' },
    { id: 'iodine',          label: 'Iodine',             cat: 'evasion',   install: 'apt install iodine' },
    // Detect
    { id: 'tpot',            label: 'T-Pot',              cat: 'detect',    install: 'github.com/telekom-security/tpotce' },
    { id: 'osquery',         label: 'OSQuery',            cat: 'detect',    install: 'apt install osquery / brew install osquery' },
    { id: 'zeek',            label: 'Zeek (Bro)',         cat: 'detect',    install: 'apt install zeek' },
    { id: 'crowdsec',        label: 'CrowdSec',           cat: 'detect',    install: 'apt install crowdsec' },
    // Crypto
    { id: 'openssl',         label: 'OpenSSL',            cat: 'crypto',    install: 'Built-in (most systems)' },
    { id: 'gpg',             label: 'GPG',                cat: 'crypto',    install: 'apt install gnupg / brew install gnupg' },
    { id: 'testssl',         label: 'testssl.sh',         cat: 'crypto',    install: 'apt install testssl.sh / github.com/drwetter/testssl.sh' },
    { id: 'hashid',          label: 'hashid',             cat: 'crypto',    install: 'pip install hashid' },
    // Cloud
    { id: 'gcloud',          label: 'Google Cloud CLI',   cat: 'cloud',     install: 'apt install google-cloud-cli / brew install google-cloud-sdk' },
    // Database
    { id: 'psql',            label: 'PostgreSQL Client',  cat: 'database',  install: 'apt install postgresql-client / brew install libpq / choco install postgresql' },
    { id: 'pg_dump',         label: 'pg_dump',            cat: 'database',  install: 'Included with postgresql-client' },
    { id: 'redis-cli',       label: 'Redis CLI',          cat: 'database',  install: 'apt install redis-tools / brew install redis' },
    { id: 'supabase',        label: 'Supabase CLI',       cat: 'database',  install: 'npm install -g supabase / brew install supabase/tap/supabase' },
    { id: 'testssl-db',      label: 'testssl.sh (DB)',    cat: 'database',  install: 'apt install testssl.sh / github.com/drwetter/testssl.sh' },
    // Docker
    { id: 'docker',          label: 'Docker Engine',      cat: 'docker',    install: 'apt install docker.io / brew install docker / choco install docker-desktop' },
    { id: 'docker-compose',  label: 'Docker Compose',     cat: 'docker',    install: 'apt install docker-compose / pip install docker-compose' },
    { id: 'capsh',           label: 'capsh (libcap)',     cat: 'docker',    install: 'apt install libcap2-bin' },
    // Setup / Environment
    { id: 'wsl',             label: 'WSL2',               cat: 'setup',     install: 'wsl --install (PowerShell Admin)' },
    { id: 'kali',            label: 'Kali Linux',         cat: 'setup',     install: 'wsl --install -d kali-linux / docker pull kalilinux/kali-rolling' },
    { id: 'xrdp',            label: 'xRDP',               cat: 'setup',     install: 'apt install xrdp' },
    { id: 'pimpmykali',      label: 'Pimp My Kali',       cat: 'setup',     install: 'github.com/Dewalt-arch/pimpmykali' },
    { id: 'neo4j',           label: 'Neo4j',              cat: 'setup',     install: 'apt install neo4j / brew install neo4j' },
    // Network Analysis
    { id: 'tcpdump',         label: 'tcpdump',            cat: 'netanalysis', install: 'apt install tcpdump / brew install tcpdump' },
    { id: 'wireshark',       label: 'Wireshark',          cat: 'netanalysis', install: 'apt install wireshark / brew install wireshark / choco install wireshark' },
    { id: 'tshark',          label: 'TShark',             cat: 'netanalysis', install: 'Included with Wireshark' },
    // C2
    { id: 'empire',          label: 'PowerShell Empire',  cat: 'c2',        install: 'apt install powershell-empire / docker pull bcsecurity/empire' },
    { id: 'sliver',          label: 'Sliver',             cat: 'c2',        install: 'github.com/BishopFox/sliver/releases' },
    // Tunneling
    { id: 'proxychains',     label: 'Proxychains',        cat: 'tunnel',    install: 'apt install proxychains4' },
    { id: 'autossh',         label: 'autossh',            cat: 'tunnel',    install: 'apt install autossh' },
    { id: 'rpivot',          label: 'rpivot',             cat: 'tunnel',    install: 'github.com/klsecservices/rpivot' },
    // Vulnerability scanning
    { id: 'nessus',          label: 'Nessus',             cat: 'vulnscan',  install: 'docker run -d -p 8834:8834 tenable/nessus' },
    { id: 'openvas',         label: 'OpenVAS/Greenbone',  cat: 'vulnscan',  install: 'docker run -d -p 443:443 immauss/openvas' },
    // Web Proxy
    { id: 'burpsuite',       label: 'Burp Suite',         cat: 'web',       install: 'Download from portswigger.net / apt install burpsuite' },
    { id: 'mitmproxy',       label: 'mitmproxy',          cat: 'web',       install: 'pip install mitmproxy / brew install mitmproxy' },
    { id: 'dalfox',          label: 'Dalfox',             cat: 'web',       install: 'go install github.com/hahwul/dalfox/v2@latest' },
    // Steganography
    { id: 'steghide',        label: 'steghide',           cat: 'stego',     install: 'apt install steghide' },
    { id: 'binwalk',         label: 'binwalk',            cat: 'stego',     install: 'apt install binwalk / pip install binwalk' },
    { id: 'exiftool',        label: 'ExifTool',           cat: 'stego',     install: 'apt install libimage-exiftool-perl / brew install exiftool' },
    { id: 'zsteg',           label: 'zsteg',              cat: 'stego',     install: 'gem install zsteg' },
    // SIEM & Log Analysis (sigma already in 'detect' above)
    { id: 'splunk',          label: 'Splunk',             cat: 'siem',      install: 'https://www.splunk.com/en_us/download.html (free tier available)' },
    { id: 'elk',             label: 'ELK Stack',          cat: 'siem',      install: 'docker-compose (Elasticsearch + Logstash + Kibana)' },
    { id: 'syslog-ng',       label: 'syslog-ng',          cat: 'siem',      install: 'apt install syslog-ng' },
    // Encoding & CyberChef
    { id: 'cyberchef',       label: 'CyberChef',          cat: 'encoding',  install: 'https://gchq.github.io/CyberChef/ (browser) / docker pull ghcr.io/gchq/cyberchef' },
    { id: 'xxd',             label: 'xxd',                cat: 'encoding',  install: 'apt install xxd / part of vim' },
    // Phishing & Email Security (gophish, evilginx already in 'social'; olevba in 'malware')
    { id: 'mxtoolbox',       label: 'MXToolbox',          cat: 'phishing',  install: 'https://mxtoolbox.com/ (online)' },
    // Binary Exploitation (ghidra already in 'malware' above)
    { id: 'pwntools',        label: 'pwntools',           cat: 'binexp',    install: 'pip install pwntools' },
    { id: 'gdb',             label: 'GDB',                cat: 'binexp',    install: 'apt install gdb' },
    { id: 'peda',            label: 'PEDA/GEF',           cat: 'binexp',    install: 'git clone https://github.com/longld/peda.git ~/peda' },
    { id: 'ropgadget',       label: 'ROPgadget',          cat: 'binexp',    install: 'pip install ROPgadget' },
    { id: 'checksec-tool',   label: 'checksec',           cat: 'binexp',    install: 'apt install checksec / pip install checksec.py' },
    // Reverse Engineering (ghidra already in 'malware' above)
    { id: 'radare2',         label: 'radare2',            cat: 'reveng',    install: 'apt install radare2 / brew install radare2' },
    { id: 'rabin2',          label: 'rabin2',             cat: 'reveng',    install: 'part of radare2' },
    { id: 'pefile',          label: 'pefile (Python)',     cat: 'reveng',    install: 'pip install pefile' },
    { id: 'readelf',         label: 'readelf',            cat: 'reveng',    install: 'apt install binutils (included)' },
    { id: 'strace',          label: 'strace',             cat: 'reveng',    install: 'apt install strace' },
    { id: 'ltrace',          label: 'ltrace',             cat: 'reveng',    install: 'apt install ltrace' },
    // Lateral Movement (evil-winrm in 'ad', chisel in 'tunnel', impacket/crackmapexec above)
    { id: 'psexec',          label: 'PsExec',             cat: 'lateral',   install: 'Sysinternals / impacket-psexec' },
    { id: 'sharprdp',        label: 'SharpRDP',           cat: 'lateral',   install: 'https://github.com/0xthirteen/SharpRDP' },
    // Windows Forensics (volatility already in malware tools conceptually)
    { id: 'volatility3',     label: 'Volatility 3',       cat: 'winforensics', install: 'pip install volatility3' },
    { id: 'ftk-imager',      label: 'FTK Imager',         cat: 'winforensics', install: 'https://www.exterro.com/ftk-imager' },
    { id: 'kape',            label: 'KAPE',               cat: 'winforensics', install: 'https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape' },
    { id: 'pecmd',           label: 'PECmd',              cat: 'winforensics', install: 'Eric Zimmerman tools: https://ericzimmerman.github.io' },
    { id: 'regripper',       label: 'RegRipper',          cat: 'winforensics', install: 'https://github.com/keydet89/RegRipper3.0' },
    { id: 'log2timeline',    label: 'Plaso/log2timeline', cat: 'winforensics', install: 'pip install plaso' },
    // Reporting
    { id: 'cvss-calc',       label: 'CVSS Calculator',    cat: 'reporting', install: 'https://www.first.org/cvss/calculator/3.1 (online)' },
    { id: 'flameshot',       label: 'Flameshot',          cat: 'reporting', install: 'apt install flameshot / choco install flameshot' },
    { id: 'greenshot',       label: 'Greenshot',          cat: 'reporting', install: 'choco install greenshot (Windows)' },
    // Network Attacks (bettercap in 'wireless', responder in 'receivers', iodine in 'evasion', dnscat2 in 'receivers')
    { id: 'ettercap',        label: 'Ettercap',           cat: 'netattack', install: 'apt install ettercap-text-only' },
    { id: 'yersinia',        label: 'Yersinia',           cat: 'netattack', install: 'apt install yersinia' },
    { id: 'dnschef',         label: 'DNSChef',            cat: 'netattack', install: 'pip install dnschef' },
    { id: 'arpwatch',        label: 'arpwatch',           cat: 'netattack', install: 'apt install arpwatch' },
    // AD Attacks (rubeus in 'winpost', bloodhound in 'ad')
    { id: 'bloodhound-py',   label: 'bloodhound-python',  cat: 'adattack',  install: 'pip install bloodhound' },
    // WAF Bypass
    { id: 'wafw00f',         label: 'wafw00f',            cat: 'waf',       install: 'pip install wafw00f' },
    { id: 'xsstrike',        label: 'XSStrike',           cat: 'waf',       install: 'git clone https://github.com/s0md3v/XSStrike.git' },
    // Kubernetes Security (trivy in 'hardening', falco in 'container')
    { id: 'kubectl',         label: 'kubectl',            cat: 'k8s',       install: 'apt install kubectl / brew install kubectl' },
    { id: 'kube-bench',      label: 'kube-bench',         cat: 'k8s',       install: 'go install github.com/aquasecurity/kube-bench@latest' },
    { id: 'kube-hunter',     label: 'kube-hunter',        cat: 'k8s',       install: 'pip install kube-hunter' },
    { id: 'kubeaudit',       label: 'kubeaudit',          cat: 'k8s',       install: 'go install github.com/Shopify/kubeaudit@latest' },
    // Automation & Scripting (lynis, oscap already in 'hardening')
    { id: 'sshpass',         label: 'sshpass',            cat: 'automation', install: 'apt install sshpass' },
    { id: 'paramiko',        label: 'Paramiko',           cat: 'automation', install: 'pip install paramiko' },
    // OSINT expansion (sherlock, shodan already above)
    { id: 'maigret',         label: 'Maigret',            cat: 'osint',     install: 'pip install maigret' },
    { id: 'holehe',          label: 'holehe',             cat: 'osint',     install: 'pip install holehe' },
    { id: 'instaloader',     label: 'Instaloader',        cat: 'osint',     install: 'pip install instaloader' },
    { id: 'waybackurls',     label: 'waybackurls',        cat: 'osint',     install: 'go install github.com/tomnomnom/waybackurls@latest' },
    { id: 'crosslinked',     label: 'CrossLinked',        cat: 'osint',     install: 'pip install crosslinked' },
    { id: 'trufflehog',      label: 'TruffleHog',        cat: 'osint',     install: 'pip install trufflehog / brew install trufflehog' },
    { id: 'gitleaks',        label: 'Gitleaks',           cat: 'osint',     install: 'go install github.com/gitleaks/gitleaks/v8@latest' },
    // Pivoting (chisel in 'lateral', proxychains in 'tunnel')
    { id: 'sshuttle',        label: 'SSHuttle',           cat: 'pivot',     install: 'apt install sshuttle / pip install sshuttle' },
    { id: 'plink',           label: 'Plink',              cat: 'pivot',     install: 'PuTTY suite: https://www.chiark.greenend.org.uk/~sgtatham/putty/' },
    // ICS/SCADA Security
    { id: 'pymodbus',        label: 'pymodbus',           cat: 'ics',       install: 'pip install pymodbus' },
    { id: 'conpot',          label: 'Conpot',             cat: 'ics',       install: 'pip install conpot / docker pull honeynet/conpot' },
    // Threat Modeling (scoutsuite, prowler already in 'cloud')
    { id: 'threat-dragon',   label: 'OWASP Threat Dragon', cat: 'threatmodel', install: 'npm install -g owasp-threat-dragon / https://www.threatdragon.com/' },
    { id: 'cartography',     label: 'Cartography',        cat: 'threatmodel', install: 'pip install cartography' },
    // Browser Exploitation (beef already in 'social')
    { id: 'sharpchrome',     label: 'SharpChrome',        cat: 'browser',   install: 'https://github.com/GhostPack/SharpDPAPI' },
    { id: 'pyhindsight',     label: 'Hindsight',          cat: 'browser',   install: 'pip install pyhindsight' },
    // Incident Playbooks (no dedicated tools — uses existing forensic/IR tools)
    // Metasploit
    { id: 'msfconsole',      label: 'Metasploit Framework', cat: 'metasploit', install: 'apt install metasploit-framework / docker pull metasploitframework/metasploit-framework' },
    { id: 'msfvenom',        label: 'msfvenom',            cat: 'metasploit', install: 'Included with metasploit-framework' },
    // Burp Suite (burpsuite already in 'web' registry)
    { id: 'autorize',        label: 'Autorize',            cat: 'burp',       install: 'Burp BApp Store (extension)' },
    { id: 'jwt-editor',      label: 'JWT Editor',          cat: 'burp',       install: 'Burp BApp Store (extension)' },
    { id: 'param-miner',     label: 'Param Miner',         cat: 'burp',       install: 'Burp BApp Store (extension)' },
    // Azure
    { id: 'msolspray',       label: 'MSOLSpray',           cat: 'azure',      install: 'github.com/dafthack/MSOLSpray (PowerShell)' },
    { id: 'azurehound',      label: 'AzureHound',          cat: 'azure',      install: 'github.com/BloodHoundAD/AzureHound/releases' },
    { id: 'roadtools',       label: 'ROADtools',           cat: 'azure',      install: 'pip install roadtools roadrecon roadtx' },
    { id: 'aadinternals',    label: 'AADInternals',        cat: 'azure',      install: 'Install-Module AADInternals (PowerShell Gallery)' },
    { id: 'powerzure',       label: 'PowerZure',           cat: 'azure',      install: 'github.com/hausec/PowerZure (PowerShell)' },
    { id: 'monkey365',       label: 'Monkey365',           cat: 'azure',      install: 'Install-Module monkey365 / github.com/silverhack/monkey365' },
    // Windows Events
    { id: 'sysmon',          label: 'Sysmon',              cat: 'winevents',  install: 'https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon' },
    // Supply Chain / DevSecOps
    { id: 'snyk',            label: 'Snyk',                cat: 'supplychain', install: 'npm install -g snyk / brew install snyk' },
    { id: 'sonarqube',       label: 'SonarQube',           cat: 'devsecops',  install: 'docker pull sonarqube:community / apt (sonarqube)' },
    // Fuzzing
    { id: 'schemathesis',    label: 'Schemathesis',        cat: 'fuzzing',    install: 'pip install schemathesis' },
    { id: 'boofuzz',         label: 'boofuzz',             cat: 'fuzzing',    install: 'pip install boofuzz' },
    { id: 'afl-fuzz',        label: 'AFL++',               cat: 'fuzzing',    install: 'apt install afl++ / docker pull aflplusplus/aflplusplus' },
    // Threat Hunting
    { id: 'rita',            label: 'RITA',                cat: 'threathunt', install: 'github.com/activecm/rita / docker pull activecm/rita' },
    // Malware Defense
    { id: 'yargen',          label: 'yarGen',              cat: 'maldef',     install: 'pip install yargen / github.com/Neo23x0/yarGen' },
    { id: 'pestudio',        label: 'PEStudio',            cat: 'maldef',     install: 'https://www.winitor.com/ (Windows freeware)' },
    { id: 'any-run',         label: 'ANY.RUN',             cat: 'maldef',     install: 'https://any.run/ (cloud sandbox, free tier)' },
    // API Security
    { id: 'postman',         label: 'Postman',             cat: 'apisec',     install: 'https://www.postman.com/downloads/ / snap install postman' },
    { id: 'kiterunner',      label: 'Kiterunner',          cat: 'apisec',     install: 'go install github.com/assetnote/kiterunner/cmd/kr@latest' },
  ];

  // Build a lookup: tool id → registry entry
  const TOOL_LOOKUP = Object.fromEntries(TOOL_REGISTRY.map(t => [t.id, t]));

  // Map each snippet to its primary tool (first tag that matches the registry)
  function snippetPrimaryTool(snippet) {
    for (const tag of snippet.tags) {
      const norm = tag.toLowerCase().replace(/[^a-z0-9-]/g, '');
      if (TOOL_LOOKUP[norm]) return norm;
    }
    return null;
  }

  // Notion-synced snippets loaded from storage
  let notionSnippets = [];

  function getAllSnippets() {
    return [...SNIPPETS, ...notionSnippets];
  }

  // ═══════════════════════════════════════════════════════════
  //  STATE
  // ═══════════════════════════════════════════════════════════

  const state = {
    search: '', category: 'all', team: 'all',
    os: 'all',              // 'all' | 'linux' | 'windows' | 'macos'
    installedTools: new Set(), // tool IDs the user has checked
    filterByTools: false,   // when true, dim/hide snippets needing unavailable tools
    favorites: new Set(),   // snippet IDs the user has starred
    target: '', lhost: '10.10.14.7', lport: '4444',
    domain: '', user: '', pass: '',
    activeKcPhase: null, activeAttackTactic: null,
    activePyramidLevel: null, activeOwaspCategory: null,
  };

  // ═══════════════════════════════════════════════════════════
  //  HELPERS
  // ═══════════════════════════════════════════════════════════

  function sanitize(v) { return String(v || '').replace(/[^\w.\-:/]/g, '').trim(); }
  const GENERIC_LINK_RE = /(https?:\/\/[^\s"'<>]+|github\.com\/[^\s"'<>]+)/gi;
  const GITHUB_LINK_RE = /(?:https?:\/\/)?github\.com\/[^\s"'<>]+/gi;

  function normalizeExternalLink(raw) {
    if (!raw) return null;
    let link = String(raw).trim().replace(/[),.;\]]+$/g, '');
    if (/^https?:\/\//i.test(link)) return link;
    if (!/^github\.com\//i.test(link)) return null;

    link = link
      .replace(/^github\.com\//i, '')
      .replace(/@.*$/, '')
      .replace(/\/\.\.\..*$/, '');
    const parts = link.split('/').filter(Boolean);
    if (parts.length < 2) return null;
    return `https://github.com/${parts[0]}/${parts[1]}`;
  }

  function extractExternalLink(text, githubOnly = false) {
    if (!text) return null;
    const regex = githubOnly ? GITHUB_LINK_RE : GENERIC_LINK_RE;
    const links = String(text).match(regex);
    if (!links || !links.length) return null;
    return normalizeExternalLink(links[0]) || links[0].replace(/[),.;\]]+$/g, '');
  }

  function openExternalLink(url) {
    if (!url) return;
    if (typeof chrome !== 'undefined' && chrome.tabs && typeof chrome.tabs.create === 'function') {
      chrome.tabs.create({ url });
      return;
    }
    window.open(url, '_blank', 'noopener');
  }

  // OS filter: 'all' shows everything; a specific OS shows 'all' + that OS + multi-OS
  function matchesOs(snippet) {
    if (state.os === 'all') return true;
    // Multi-OS snippets always match (they have a variant for the selected OS)
    if (snippet.commands && snippet.commands[state.os]) return true;
    const s = snippet.os || 'all';
    return s === 'all' || s === state.os;
  }

  // Tool filter: returns true if snippet's primary tool is installed (or no filter active)
  function matchesTools(snippet) {
    if (!state.filterByTools) return true;
    const tool = snippetPrimaryTool(snippet);
    if (!tool) return true; // no known tool → always show
    return state.installedTools.has(tool);
  }

  function renderCmd(cmd) {
    if (!cmd) return '';
    return cmd
      .replaceAll('LHOST', state.lhost || 'LHOST')
      .replaceAll('LPORT', state.lport || 'LPORT')
      .replaceAll('DOMAIN', state.domain || 'DOMAIN')
      .replaceAll('USER', state.user || 'USER')
      .replaceAll('PASS', state.pass || 'PASS')
      .replaceAll('NTHASH', 'NTHASH')
      .replaceAll('TARGET', state.target || 'TARGET');
  }

  // Resolve the best command for a snippet, preferring OS-variant if available
  function resolveCommand(item) {
    if (item.commands && state.os !== 'all' && item.commands[state.os]) {
      return item.commands[state.os];
    }
    return item.command;
  }

  function makeCard(item) {
    const card = document.createElement('article');
    card.className = 'card';
    const rendered = renderCmd(resolveCommand(item));
    const githubLink = extractExternalLink(rendered, true);

    // Dim if tool not installed and filter active
    const primaryTool = snippetPrimaryTool(item);
    const toolAvailable = !primaryTool || state.installedTools.has(primaryTool);
    if (state.filterByTools && !toolAvailable) card.classList.add('dimmed');

    // Favorite star
    const favBtn = document.createElement('button');
    favBtn.className = 'fav-btn' + (state.favorites.has(item.id) ? ' active' : '');
    favBtn.textContent = state.favorites.has(item.id) ? '\u2605' : '\u2606';
    favBtn.title = state.favorites.has(item.id) ? 'Remove from favorites' : 'Add to favorites';
    favBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      if (state.favorites.has(item.id)) {
        state.favorites.delete(item.id);
        favBtn.classList.remove('active');
        favBtn.textContent = '\u2606';
        favBtn.title = 'Add to favorites';
      } else {
        state.favorites.add(item.id);
        favBtn.classList.add('active');
        favBtn.textContent = '\u2605';
        favBtn.title = 'Remove from favorites';
      }
      saveFavorites();
      renderFavoritesStrip();
    });

    const head = document.createElement('div');
    head.className = 'card-head';
    const title = document.createElement('span');
    title.className = 'card-title';
    title.textContent = item.title;

    // OS badge — single OS or multi-OS indicator
    const hasVariants = item.commands && Object.keys(item.commands).length > 1;
    const itemOs = item.os || 'all';
    if (hasVariants) {
      const osBadge = document.createElement('span');
      osBadge.className = 'card-os-badge';
      osBadge.style.cssText = 'background:rgba(51,209,122,0.15);color:var(--co-green);';
      const activeOs = state.os !== 'all' ? state.os : 'multi';
      osBadge.textContent = activeOs === 'multi' ? 'Multi-OS' : (activeOs === 'linux' ? 'Linux' : activeOs === 'windows' ? 'Win' : 'macOS');
      title.appendChild(document.createTextNode(' '));
      title.appendChild(osBadge);
    } else if (itemOs !== 'all') {
      const osBadge = document.createElement('span');
      osBadge.className = 'card-os-badge ' + itemOs;
      osBadge.textContent = itemOs === 'linux' ? 'Linux' : itemOs === 'windows' ? 'Win' : 'macOS';
      title.appendChild(document.createTextNode(' '));
      title.appendChild(osBadge);
    }

    // Tool missing badge
    if (primaryTool && !toolAvailable) {
      const missingBadge = document.createElement('span');
      missingBadge.className = 'card-tool-missing';
      const reg = TOOL_LOOKUP[primaryTool];
      missingBadge.textContent = 'needs ' + (reg ? reg.label : primaryTool);
      missingBadge.title = reg ? 'Install: ' + reg.install : '';
      title.appendChild(document.createTextNode(' '));
      title.appendChild(missingBadge);
    }

    const cat = document.createElement('span');
    cat.className = 'card-cat ' + item.team;
    cat.textContent = (item.team === 'red' ? 'RED' : 'BLUE') + ' / ' + item.category;
    head.appendChild(favBtn);
    head.appendChild(title);
    head.appendChild(cat);

    const desc = document.createElement('div');
    desc.className = 'card-desc';
    desc.textContent = item.description;

    const cmd = document.createElement('pre');
    cmd.className = 'card-cmd';
    cmd.textContent = rendered;

    const actions = document.createElement('div');
    actions.className = 'card-actions';
    const tags = document.createElement('span');
    tags.className = 'card-tags';
    const tagParts = [...item.tags];
    if (item.owasp && item.owasp.length) tagParts.push(...item.owasp);
    tags.textContent = tagParts.join(', ');
    const actionBtns = document.createElement('div');
    actionBtns.className = 'card-btns';
    const copyBtn = document.createElement('button');
    copyBtn.className = 'copy-btn';
    copyBtn.textContent = 'Copy';
    copyBtn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(rendered);
        copyBtn.textContent = 'Copied';
        copyBtn.classList.add('ok');
        setTimeout(() => { copyBtn.textContent = 'Copy'; copyBtn.classList.remove('ok'); }, 1200);
      } catch { copyBtn.textContent = 'Failed'; }
    });
    const mutateBtn = document.createElement('button');
    mutateBtn.className = 'copy-btn';
    mutateBtn.textContent = 'Mutate';
    mutateBtn.title = 'Send to AI Red Team Mutation Lab';
    mutateBtn.addEventListener('click', () => {
      // Open AI Red Team with mutation tab and pre-filled command
      const url = chrome.runtime.getURL('ai-hub/ai-redteam.html') + '#mutation';
      chrome.storage.local.set({ aiRedTeamPrefill: rendered }, () => {
        window.open(url, '_blank');
      });
    });

    let githubBtn = null;
    if (githubLink) {
      githubBtn = document.createElement('button');
      githubBtn.className = 'copy-btn';
      githubBtn.textContent = 'GitHub';
      githubBtn.title = 'Open related GitHub page';
      githubBtn.addEventListener('click', () => openExternalLink(githubLink));
    }

    const saveBtn = window.ObsidianSave ? window.ObsidianSave.button({
      tool: 'cyberops',
      size: 'sm',
      label: 'Save',
      className: 'copy-btn',
      getContent: () => ({
        title: item.title,
        content: `## ${item.title}\n\n**Category:** ${item.category}\n**Team:** ${item.team}\n**Description:** ${item.description}\n\n### Command\n\`\`\`bash\n${rendered}\n\`\`\`\n\n*Generated by Toolbelt CyberOps*`,
        tags: ['cyberops', item.team, item.category, ...(item.tags || [])]
      })
    }) : null;

    actions.appendChild(tags);
    actionBtns.appendChild(copyBtn);
    actionBtns.appendChild(mutateBtn);
    if (githubBtn) actionBtns.appendChild(githubBtn);
    if (saveBtn) actionBtns.appendChild(saveBtn);
    actions.appendChild(actionBtns);

    card.appendChild(head);
    card.appendChild(desc);
    card.appendChild(cmd);
    card.appendChild(actions);
    return card;
  }

  // ═══════════════════════════════════════════════════════════
  //  GLOBAL VARIABLE BAR — wired to all views
  // ═══════════════════════════════════════════════════════════

  function initVarBar() {
    const varInputs = {
      target: document.getElementById('globalTarget'),
      lhost: document.getElementById('globalLhost'),
      lport: document.getElementById('globalLport'),
      domain: document.getElementById('globalDomain'),
      user: document.getElementById('globalUser'),
      pass: document.getElementById('globalPass'),
    };

    // Load saved vars from storage
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.get(['cyberOpsVars'], (result) => {
        const saved = result.cyberOpsVars || {};
        if (saved.target) { state.target = saved.target; varInputs.target.value = saved.target; }
        if (saved.lhost) { state.lhost = saved.lhost; varInputs.lhost.value = saved.lhost; }
        if (saved.lport) { state.lport = saved.lport; varInputs.lport.value = saved.lport; }
        if (saved.domain) { state.domain = saved.domain; varInputs.domain.value = saved.domain; }
        if (saved.user) { state.user = saved.user; varInputs.user.value = saved.user; }
        if (saved.pass) { state.pass = saved.pass; varInputs.pass.value = saved.pass; }
        refreshAllViews();
      });
    }

    function saveVars() {
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.set({ cyberOpsVars: {
          target: state.target, lhost: state.lhost, lport: state.lport,
          domain: state.domain, user: state.user, pass: state.pass,
        }});
      }
    }

    function bindVar(el, key) {
      el.addEventListener('input', () => {
        state[key] = key === 'target' ? sanitize(el.value) || '' : el.value.trim();
        saveVars();
        refreshAllViews();
      });
    }

    bindVar(varInputs.target, 'target');
    bindVar(varInputs.lhost, 'lhost');
    bindVar(varInputs.lport, 'lport');
    bindVar(varInputs.domain, 'domain');
    bindVar(varInputs.user, 'user');
    bindVar(varInputs.pass, 'pass');
  }

  // ═══════════════════════════════════════════════════════════
  //  OS SELECTOR — wired to refresh all views
  // ═══════════════════════════════════════════════════════════

  function initOsSelector() {
    const group = document.getElementById('osGroup');
    if (!group) return;

    // Load saved OS
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.get(['cyberOpsOs'], (result) => {
        if (result.cyberOpsOs) {
          state.os = result.cyberOpsOs;
          group.querySelectorAll('.os-btn').forEach(b => {
            b.classList.toggle('active', b.dataset.os === state.os);
          });
          refreshAllViews();
        }
      });
    }

    group.querySelectorAll('.os-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        state.os = btn.dataset.os;
        group.querySelectorAll('.os-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        if (typeof chrome !== 'undefined' && chrome.storage) {
          chrome.storage.local.set({ cyberOpsOs: state.os });
        }
        // Reinit frameworks so counts update
        initKillChain();
        initAttackMatrix();
        initPyramid();
        initOwasp();
        renderSnippets();
      });
    });
  }

  // ═══════════════════════════════════════════════════════════
  //  TOOL INVENTORY — checkable list, stored in chrome.storage
  // ═══════════════════════════════════════════════════════════

  function initToolInventory() {
    const toggleBtn = document.getElementById('toolsToggleBtn');
    const panel = document.getElementById('toolsPanel');
    const grid = document.getElementById('toolsGrid');
    const selectAllBtn = document.getElementById('toolsSelectAll');
    const selectNoneBtn = document.getElementById('toolsSelectNone');
    const filterToggle = document.getElementById('toolsFilterToggle');
    if (!toggleBtn || !panel || !grid) return;

    // Toggle panel
    toggleBtn.addEventListener('click', () => {
      panel.classList.toggle('open');
      toggleBtn.textContent = panel.classList.contains('open') ? 'Hide Tools' : 'Tools';
    });

    // Build grid of checkboxes
    function renderToolGrid() {
      grid.innerHTML = '';
      // Group by category
      const cats = [...new Set(TOOL_REGISTRY.map(t => t.cat))];
      cats.forEach(cat => {
        const tools = TOOL_REGISTRY.filter(t => t.cat === cat);
        tools.forEach(tool => {
          const item = document.createElement('label');
          item.className = 'tool-item' + (state.installedTools.has(tool.id) ? ' checked' : '');
          item.title = tool.install;

          const cb = document.createElement('input');
          cb.type = 'checkbox';
          cb.checked = state.installedTools.has(tool.id);
          cb.addEventListener('change', () => {
            if (cb.checked) state.installedTools.add(tool.id);
            else state.installedTools.delete(tool.id);
            item.classList.toggle('checked', cb.checked);
            saveToolInventory();
            refreshAllViews();
          });

          const label = document.createElement('span');
          label.textContent = tool.label;

          const catLabel = document.createElement('span');
          catLabel.className = 'tool-cat';
          catLabel.textContent = cat;

          const toolLink = extractExternalLink(tool.install, false);
          const linkBtn = toolLink ? document.createElement('button') : null;
          if (linkBtn) {
            linkBtn.type = 'button';
            linkBtn.className = 'tool-link-btn';
            linkBtn.textContent = /github\.com/i.test(toolLink) ? 'GitHub' : 'Docs';
            linkBtn.title = 'Open install page';
            linkBtn.addEventListener('click', (e) => {
              e.preventDefault();
              e.stopPropagation();
              openExternalLink(toolLink);
            });
          }

          item.appendChild(cb);
          item.appendChild(label);
          item.appendChild(catLabel);
          if (linkBtn) item.appendChild(linkBtn);
          grid.appendChild(item);
        });
      });
    }

    // Select all / none
    selectAllBtn.addEventListener('click', () => {
      state.installedTools = new Set(TOOL_REGISTRY.map(t => t.id));
      saveToolInventory();
      renderToolGrid();
      refreshAllViews();
    });

    selectNoneBtn.addEventListener('click', () => {
      state.installedTools = new Set();
      saveToolInventory();
      renderToolGrid();
      refreshAllViews();
    });

    // Filter toggle
    filterToggle.addEventListener('click', () => {
      state.filterByTools = !state.filterByTools;
      filterToggle.classList.toggle('active', state.filterByTools);
      filterToggle.textContent = state.filterByTools ? 'Show All' : 'Hide Unavailable';
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.set({ cyberOpsFilterByTools: state.filterByTools });
      }
      refreshAllViews();
    });

    // Load saved inventory
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.get(['cyberOpsInstalledTools', 'cyberOpsFilterByTools'], (result) => {
        if (result.cyberOpsInstalledTools && Array.isArray(result.cyberOpsInstalledTools)) {
          state.installedTools = new Set(result.cyberOpsInstalledTools);
        }
        if (result.cyberOpsFilterByTools) {
          state.filterByTools = true;
          filterToggle.classList.add('active');
          filterToggle.textContent = 'Show All';
        }
        renderToolGrid();
        refreshAllViews();
      });
    } else {
      renderToolGrid();
    }
  }

  function saveToolInventory() {
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.set({ cyberOpsInstalledTools: [...state.installedTools] });
    }
  }

  function refreshAllViews() {
    // Refresh whichever detail panel is currently visible
    if (state.activeKcPhase) {
      const phase = KILL_CHAIN.find(p => p.id === state.activeKcPhase);
      if (phase) renderKcDetail(phase);
    }
    if (state.activeAttackTactic) {
      const tactic = ATTACK_TACTICS.find(t => t.id === state.activeAttackTactic);
      if (tactic) renderAttackDetail(tactic);
    }
    if (state.activePyramidLevel) {
      const level = PYRAMID_LEVELS.find(l => l.id === state.activePyramidLevel);
      if (level) renderPyramidDetail(level);
    }
    if (state.activeOwaspCategory) {
      const cat = OWASP_TOP10.find(c => c.id === state.activeOwaspCategory);
      if (cat) renderOwaspDetail(cat);
    }
    renderSnippets();
    renderFavoritesStrip();
    updateStatsBar();
  }

  // ═══════════════════════════════════════════════════════════
  //  FRAMEWORK TABS
  // ═══════════════════════════════════════════════════════════

  document.querySelectorAll('.fw-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.fw-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.fw-panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      document.querySelector(`.fw-panel[data-fw="${tab.dataset.fw}"]`).classList.add('active');
    });
  });

  // ═══════════════════════════════════════════════════════════
  //  KILL CHAIN
  // ═══════════════════════════════════════════════════════════

  function initKillChain() {
    const container = document.getElementById('kcChain');
    container.innerHTML = '';

    KILL_CHAIN.forEach(phase => {
      const all = getAllSnippets();
      const items = all.filter(s => s.killchain === phase.id && matchesOs(s));

      const el = document.createElement('div');
      el.className = 'kc-phase';
      el.dataset.phase = phase.id;

      const head = document.createElement('div');
      head.className = 'kc-phase-head';
      head.innerHTML = `${phase.label}<span class="kc-phase-count">${items.length} tools</span>`;

      const body = document.createElement('div');
      body.className = 'kc-phase-body';

      items.slice(0, 6).forEach(item => {
        const tag = document.createElement('span');
        tag.className = 'kc-mini-tag ' + item.team;
        tag.textContent = item.title.length > 18 ? item.title.substring(0, 16) + '..' : item.title;
        tag.title = item.title;
        body.appendChild(tag);
      });

      if (items.length > 6) {
        const more = document.createElement('span');
        more.className = 'kc-mini-tag';
        more.textContent = `+${items.length - 6} more`;
        body.appendChild(more);
      }

      el.appendChild(head);
      el.appendChild(body);
      container.appendChild(el);

      el.addEventListener('click', () => {
        state.activeKcPhase = phase.id;
        document.querySelectorAll('.kc-phase').forEach(p => p.classList.remove('active'));
        el.classList.add('active');
        renderKcDetail(phase);
      });
    });

    const firstPhase = container.querySelector('.kc-phase');
    if (firstPhase) firstPhase.click();
  }

  function renderKcDetail(phase) {
    const container = document.getElementById('kcDetail');
    const all = getAllSnippets();
    const items = all.filter(s => s.killchain === phase.id && matchesOs(s));
    const redItems = items.filter(s => s.team === 'red');
    const blueItems = items.filter(s => s.team === 'blue');

    container.innerHTML = '';

    const header = document.createElement('div');
    header.className = 'phase-detail-header';
    header.style.padding = '16px 24px 0';
    header.innerHTML = `
      <h2>${phase.label}</h2>
      <span class="team-label red">${redItems.length} Red</span>
      <span class="team-label blue">${blueItems.length} Blue</span>
      <span style="color:var(--co-text-muted);font-size:13px;margin-left:8px;">${phase.desc}</span>`;
    container.appendChild(header);

    const grid = document.createElement('div');
    grid.className = 'snippet-grid';
    [...redItems, ...blueItems].forEach(item => grid.appendChild(makeCard(item)));
    container.appendChild(grid);

    if (items.length === 0) {
      container.innerHTML += '<div class="empty">No tools mapped to this phase yet.</div>';
    }
  }

  // ═══════════════════════════════════════════════════════════
  //  MITRE ATT&CK
  // ═══════════════════════════════════════════════════════════

  function initAttackMatrix() {
    const container = document.getElementById('attackMatrix');
    container.innerHTML = '';

    const grid = document.createElement('div');
    grid.className = 'attack-grid';

    ATTACK_TACTICS.forEach(tactic => {
      const all = getAllSnippets();
      const items = all.filter(s => s.attack.includes(tactic.id) && matchesOs(s));

      const col = document.createElement('div');

      const header = document.createElement('div');
      header.className = 'attack-tactic';
      header.dataset.tactic = tactic.id;
      header.innerHTML = `<span class="attack-count">${items.length}</span>${tactic.label}`;
      header.addEventListener('click', () => {
        state.activeAttackTactic = tactic.id;
        document.querySelectorAll('.attack-tactic').forEach(t => t.classList.remove('active'));
        header.classList.add('active');
        renderAttackDetail(tactic);
      });

      const techniques = document.createElement('div');
      techniques.className = 'attack-techniques';
      items.slice(0, 5).forEach(item => {
        const el = document.createElement('div');
        el.className = 'attack-tech-item ' + item.team;
        el.textContent = item.title;
        el.title = item.description;
        techniques.appendChild(el);
      });
      if (items.length > 5) {
        const more = document.createElement('div');
        more.className = 'attack-tech-item';
        more.textContent = `+${items.length - 5} more`;
        more.style.fontStyle = 'italic';
        techniques.appendChild(more);
      }

      col.appendChild(header);
      col.appendChild(techniques);
      grid.appendChild(col);
    });

    container.appendChild(grid);
  }

  function renderAttackDetail(tactic) {
    const container = document.getElementById('attackDetail');
    const all = getAllSnippets();
    const items = all.filter(s => s.attack.includes(tactic.id) && matchesOs(s));

    container.innerHTML = '';
    const header = document.createElement('div');
    header.className = 'phase-detail-header';
    header.style.padding = '16px 24px 0';
    header.innerHTML = `<h2>${tactic.label}</h2><span class="badge">${tactic.code}</span><span style="margin-left:8px;color:var(--co-text-muted);font-size:13px;">${items.length} techniques mapped</span>`;
    container.appendChild(header);

    const grid = document.createElement('div');
    grid.className = 'snippet-grid';
    items.forEach(item => grid.appendChild(makeCard(item)));
    container.appendChild(grid);
  }

  // ═══════════════════════════════════════════════════════════
  //  PYRAMID OF PAIN
  // ═══════════════════════════════════════════════════════════

  function initPyramid() {
    const container = document.getElementById('pyramidWrap');
    container.innerHTML = '';

    PYRAMID_LEVELS.forEach(level => {
      const all = getAllSnippets();
      const items = all.filter(s => s.pyramid === level.id && matchesOs(s));

      const el = document.createElement('div');
      el.className = 'pyramid-level';
      el.dataset.level = level.id;

      const pain = document.createElement('span');
      pain.className = 'pyramid-pain ' + level.painClass;
      pain.textContent = level.pain;

      const label = document.createElement('span');
      label.className = 'pyramid-label';
      label.textContent = level.label;

      const count = document.createElement('span');
      count.className = 'badge';
      count.textContent = `${items.length} tools`;

      el.appendChild(pain);
      el.appendChild(label);
      el.appendChild(count);
      container.appendChild(el);

      el.addEventListener('click', () => {
        state.activePyramidLevel = level.id;
        document.querySelectorAll('.pyramid-level').forEach(l => l.classList.remove('active'));
        el.classList.add('active');
        renderPyramidDetail(level);
      });
    });
  }

  function renderPyramidDetail(level) {
    const container = document.getElementById('pyramidDetail');
    const all = getAllSnippets();
    const items = all.filter(s => s.pyramid === level.id && matchesOs(s));

    container.innerHTML = '';

    const info = document.createElement('div');
    info.className = 'fw-info';
    info.innerHTML = `<strong>${level.label}</strong> — ${level.desc}`;
    container.appendChild(info);

    const grid = document.createElement('div');
    grid.className = 'snippet-grid';
    items.forEach(item => grid.appendChild(makeCard(item)));
    container.appendChild(grid);

    if (items.length === 0) {
      container.innerHTML += '<div class="empty">No tools mapped to this level yet.</div>';
    }
  }

  // ═══════════════════════════════════════════════════════════
  //  OWASP TOP 10
  // ═══════════════════════════════════════════════════════════

  function initOwasp() {
    const container = document.getElementById('owaspGrid');
    container.innerHTML = '';

    OWASP_TOP10.forEach(cat => {
      const all = getAllSnippets();
      const items = all.filter(s => s.owasp && s.owasp.includes(cat.id) && matchesOs(s));

      const card = document.createElement('div');
      card.className = 'owasp-card';
      card.dataset.owasp = cat.id;

      card.innerHTML = `
        <div class="owasp-code">${cat.code}</div>
        <div class="owasp-name">${cat.label}</div>
        <div class="owasp-count">${items.length} tools mapped</div>`;

      card.addEventListener('click', () => {
        state.activeOwaspCategory = cat.id;
        document.querySelectorAll('.owasp-card').forEach(c => c.classList.remove('active'));
        card.classList.add('active');
        renderOwaspDetail(cat);
      });

      container.appendChild(card);
    });
  }

  function renderOwaspDetail(cat) {
    const container = document.getElementById('owaspDetail');
    const all = getAllSnippets();
    const items = all.filter(s => s.owasp && s.owasp.includes(cat.id) && matchesOs(s));
    const redItems = items.filter(s => s.team === 'red');
    const blueItems = items.filter(s => s.team === 'blue');

    container.innerHTML = '';

    const header = document.createElement('div');
    header.className = 'phase-detail-header';
    header.style.padding = '16px 24px 0';
    header.innerHTML = `
      <h2>${cat.code}: ${cat.label}</h2>
      <span class="team-label red">${redItems.length} Exploit</span>
      <span class="team-label blue">${blueItems.length} Mitigate</span>`;
    container.appendChild(header);

    const info = document.createElement('div');
    info.className = 'fw-info';
    info.textContent = cat.desc;
    container.appendChild(info);

    const grid = document.createElement('div');
    grid.className = 'snippet-grid';
    [...redItems, ...blueItems].forEach(item => grid.appendChild(makeCard(item)));
    container.appendChild(grid);

    if (items.length === 0) {
      container.innerHTML += '<div class="empty">No tools mapped to this OWASP category yet.</div>';
    }
  }

  // ═══════════════════════════════════════════════════════════
  //  ALL SNIPPETS (searchable)
  // ═══════════════════════════════════════════════════════════

  function initSnippets() {
    const all = getAllSnippets();
    const categories = [...new Set(all.map(s => s.category))].sort();
    const sel = document.getElementById('categorySelect');
    // Clear old options except "All"
    while (sel.options.length > 1) sel.remove(1);
    categories.forEach(cat => {
      const opt = document.createElement('option');
      opt.value = cat;
      opt.textContent = cat.charAt(0).toUpperCase() + cat.slice(1);
      sel.appendChild(opt);
    });

    const inputs = {
      search: document.getElementById('searchInput'),
      category: document.getElementById('categorySelect'),
      team: document.getElementById('teamSelect'),
    };

    inputs.search.addEventListener('input', () => { state.search = inputs.search.value.trim().toLowerCase(); renderSnippets(); });
    inputs.category.addEventListener('change', () => { state.category = inputs.category.value; renderSnippets(); });
    inputs.team.addEventListener('change', () => { state.team = inputs.team.value; renderSnippets(); });

    renderSnippets();
  }

  function renderSnippets() {
    const all = getAllSnippets();
    const items = all.filter(item => {
      if (state.category !== 'all' && item.category !== state.category) return false;
      if (state.team !== 'all' && item.team !== state.team) return false;
      if (!matchesOs(item)) return false;
      if (state.search) {
        const haystack = [item.title, item.description, item.command, item.category, item.team, ...item.tags, ...(item.owasp || [])].join(' ').toLowerCase();
        if (!haystack.includes(state.search)) return false;
      }
      return true;
    });

    document.getElementById('resultBadge').textContent = `${items.length} snippet${items.length === 1 ? '' : 's'}`;

    const grid = document.getElementById('snippetGrid');
    grid.innerHTML = '';
    items.forEach(item => grid.appendChild(makeCard(item)));

    document.getElementById('emptyState').style.display = items.length === 0 ? 'block' : 'none';
  }

  // ═══════════════════════════════════════════════════════════
  //  NOTION SYNC — Pull tools from Security Tools DB
  // ═══════════════════════════════════════════════════════════

  const NOTION_SECURITY_TOOLS_DB = process.env.NOTION_SECURITY_TOOLS_DB || null;
  const NOTION_COMMAND_LIBRARY_DB = process.env.NOTION_COMMAND_LIBRARY_DB || null;

  async function notionSync() {
    const syncBtn = document.getElementById('notionSyncBtn');
    const syncStatus = document.getElementById('syncStatus');
    syncBtn.disabled = true;
    syncStatus.style.display = 'inline-flex';
    syncStatus.textContent = 'Syncing...';

    try {
      // Request Notion data via service worker
      const response = await chrome.runtime.sendMessage({
        action: 'cyberOpsNotionSync',
        databases: [NOTION_SECURITY_TOOLS_DB, NOTION_COMMAND_LIBRARY_DB],
      });

      if (response && response.error) {
        syncStatus.textContent = response.error;
        setTimeout(() => { syncStatus.style.display = 'none'; }, 3000);
        return;
      }

      if (response && response.snippets) {
        notionSnippets = response.snippets;
        // Cache in storage
        await chrome.storage.local.set({ cyberOpsNotionSnippets: notionSnippets });
        syncStatus.textContent = `${notionSnippets.length} synced`;

        // Reinitialize all views with new data
        initKillChain();
        initAttackMatrix();
        initPyramid();
        initOwasp();
        initSnippets();

        setTimeout(() => { syncStatus.style.display = 'none'; }, 3000);
      }
    } catch (err) {
      syncStatus.textContent = 'Sync failed';
      console.error('Notion sync error:', err);
      setTimeout(() => { syncStatus.style.display = 'none'; }, 3000);
    } finally {
      syncBtn.disabled = false;
    }
  }

  function loadCachedNotionSnippets() {
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.get(['cyberOpsNotionSnippets'], (result) => {
        if (result.cyberOpsNotionSnippets && result.cyberOpsNotionSnippets.length) {
          notionSnippets = result.cyberOpsNotionSnippets;
          // Refresh views
          initKillChain();
          initAttackMatrix();
          initPyramid();
          initOwasp();
          initSnippets();
        }
      });
    }
  }

  // ═══════════════════════════════════════════════════════════
  //  FAVORITES — star snippets for quick access
  // ═══════════════════════════════════════════════════════════

  function saveFavorites() {
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.set({ cyberOpsFavorites: [...state.favorites] });
    }
  }

  function loadFavorites(cb) {
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.local.get(['cyberOpsFavorites'], (result) => {
        if (result.cyberOpsFavorites && Array.isArray(result.cyberOpsFavorites)) {
          state.favorites = new Set(result.cyberOpsFavorites);
        }
        if (cb) cb();
      });
    } else if (cb) cb();
  }

  function renderFavoritesStrip() {
    const strip = document.getElementById('favoritesStrip');
    const scroll = document.getElementById('favoritesScroll');
    const countEl = document.getElementById('favCount');
    if (!strip || !scroll) return;

    const all = getAllSnippets();
    const favItems = all.filter(s => state.favorites.has(s.id));

    strip.classList.toggle('has-favs', favItems.length > 0);
    countEl.textContent = favItems.length;
    scroll.innerHTML = '';

    favItems.forEach(item => {
      const chip = document.createElement('div');
      chip.className = 'fav-chip';
      chip.title = renderCmd(resolveCommand(item));

      const dot = document.createElement('span');
      dot.className = 'fav-chip-team ' + item.team;

      const label = document.createElement('span');
      label.textContent = item.title;

      const copyHint = document.createElement('span');
      copyHint.className = 'fav-chip-copy';
      copyHint.textContent = 'click=copy';

      chip.appendChild(dot);
      chip.appendChild(label);
      chip.appendChild(copyHint);

      chip.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(renderCmd(resolveCommand(item)));
          copyHint.textContent = 'copied!';
          setTimeout(() => { copyHint.textContent = 'click=copy'; }, 1200);
        } catch { copyHint.textContent = 'failed'; }
      });

      scroll.appendChild(chip);
    });
  }

  // ═══════════════════════════════════════════════════════════
  //  STATS BAR — snippet counts
  // ═══════════════════════════════════════════════════════════

  function updateStatsBar() {
    const all = getAllSnippets();
    const osFiltered = all.filter(s => matchesOs(s));

    const statTotal = document.getElementById('statTotal');
    const statRed = document.getElementById('statRed');
    const statBlue = document.getElementById('statBlue');
    const statOs = document.getElementById('statOs');
    const statOsLabel = document.getElementById('statOsLabel');
    const statCats = document.getElementById('statCats');
    const statTools = document.getElementById('statTools');

    if (statTotal) statTotal.textContent = all.length;
    if (statRed) statRed.textContent = all.filter(s => s.team === 'red').length;
    if (statBlue) statBlue.textContent = all.filter(s => s.team === 'blue').length;
    if (statOs) statOs.textContent = osFiltered.length;
    if (statOsLabel) {
      const labels = { all: 'visible (all OS)', linux: 'for Linux', windows: 'for Windows', macos: 'for macOS' };
      statOsLabel.textContent = labels[state.os] || 'visible';
    }
    if (statCats) statCats.textContent = new Set(all.map(s => s.category)).size;
    if (statTools) statTools.textContent = TOOL_REGISTRY.length;
  }

  // ═══════════════════════════════════════════════════════════
  //  KEYBOARD SHORTCUTS
  // ═══════════════════════════════════════════════════════════

  function initKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
      // Cheat-sheet overlay toggle (? key or Escape to close)
      const overlay = document.getElementById('cheatsheetOverlay');
      if (e.key === 'Escape' && overlay && overlay.classList.contains('open')) {
        overlay.classList.remove('open');
        return;
      }

      // Skip if typing in an input/textarea
      const tag = document.activeElement.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') {
        // Escape blurs the input
        if (e.key === 'Escape') document.activeElement.blur();
        return;
      }

      // ? → toggle cheat-sheet
      if (e.key === '?') {
        if (overlay) overlay.classList.toggle('open');
        return;
      }

      // Ctrl+K or / → focus search
      if (e.key === '/' || (e.ctrlKey && e.key === 'k')) {
        e.preventDefault();
        // Switch to All Snippets tab first
        const snippetsTab = document.querySelector('.fw-tab[data-fw="snippets"]');
        if (snippetsTab && !snippetsTab.classList.contains('active')) snippetsTab.click();
        const searchInput = document.getElementById('searchInput');
        if (searchInput) searchInput.focus();
        return;
      }

      // Ctrl+E → export
      if (e.ctrlKey && e.key === 'e') {
        e.preventDefault();
        exportConfig();
        return;
      }

      // 1-4 → OS switch (when not in input)
      const osKeys = { '1': 'all', '2': 'linux', '3': 'windows', '4': 'macos' };
      if (osKeys[e.key]) {
        e.preventDefault();
        const btn = document.querySelector(`.os-btn[data-os="${osKeys[e.key]}"]`);
        if (btn) btn.click();
        return;
      }

      // Ctrl+1-5 → switch framework tabs
      if (e.ctrlKey && e.key >= '1' && e.key <= '5') {
        e.preventDefault();
        const tabs = document.querySelectorAll('.fw-tab');
        const idx = parseInt(e.key) - 1;
        if (tabs[idx]) tabs[idx].click();
        return;
      }
    });
  }

  // ═══════════════════════════════════════════════════════════
  //  EXPORT / IMPORT — settings, favorites, tools as JSON
  // ═══════════════════════════════════════════════════════════

  function exportConfig() {
    const config = {
      version: 1,
      exportDate: new Date().toISOString(),
      os: state.os,
      vars: {
        target: state.target, lhost: state.lhost, lport: state.lport,
        domain: state.domain, user: state.user, pass: state.pass,
      },
      favorites: [...state.favorites],
      installedTools: [...state.installedTools],
      filterByTools: state.filterByTools,
    };

    const blob = new Blob([JSON.stringify(config, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cyber-ops-config-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function importConfig(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const config = JSON.parse(e.target.result);
        if (!config.version) throw new Error('Invalid config file');

        // Restore state
        if (config.os) {
          state.os = config.os;
          const osGroup = document.getElementById('osGroup');
          if (osGroup) {
            osGroup.querySelectorAll('.os-btn').forEach(b => {
              b.classList.toggle('active', b.dataset.os === state.os);
            });
          }
        }

        if (config.vars) {
          Object.keys(config.vars).forEach(key => {
            state[key] = config.vars[key];
            const input = document.getElementById('global' + key.charAt(0).toUpperCase() + key.slice(1));
            if (input) input.value = config.vars[key];
          });
        }

        if (config.favorites) {
          state.favorites = new Set(config.favorites);
          saveFavorites();
        }

        if (config.installedTools) {
          state.installedTools = new Set(config.installedTools);
          saveToolInventory();
        }

        if (typeof config.filterByTools === 'boolean') {
          state.filterByTools = config.filterByTools;
        }

        // Save everything
        if (typeof chrome !== 'undefined' && chrome.storage) {
          chrome.storage.local.set({
            cyberOpsOs: state.os,
            cyberOpsVars: config.vars || {},
            cyberOpsFilterByTools: state.filterByTools,
          });
        }

        // Full refresh
        initKillChain();
        initAttackMatrix();
        initPyramid();
        initOwasp();
        initSnippets();
        renderFavoritesStrip();
        updateStatsBar();

        // Reinit tool inventory grid
        const grid = document.getElementById('toolsGrid');
        if (grid) {
          grid.querySelectorAll('input[type="checkbox"]').forEach(cb => {
            const toolId = cb.closest('.tool-item').querySelector('.tool-cat')
              ? cb.closest('.tool-item').querySelector('span:not(.tool-cat)').textContent
              : '';
            // Re-render tool grid by re-calling init
          });
        }

        // Flash success on import button
        const importBtn = document.getElementById('importBtn');
        if (importBtn) {
          const orig = importBtn.textContent;
          importBtn.textContent = 'Imported!';
          importBtn.style.color = 'var(--co-green)';
          importBtn.style.borderColor = 'var(--co-green)';
          setTimeout(() => {
            importBtn.textContent = orig;
            importBtn.style.color = '';
            importBtn.style.borderColor = '';
          }, 2000);
        }
      } catch (err) {
        console.error('Import error:', err);
        const importBtn = document.getElementById('importBtn');
        if (importBtn) {
          importBtn.textContent = 'Invalid file';
          importBtn.style.color = 'var(--co-red)';
          setTimeout(() => { importBtn.textContent = 'Import'; importBtn.style.color = ''; }, 2000);
        }
      }
    };
    reader.readAsText(file);
  }

  function initExportImport() {
    const exportBtn = document.getElementById('exportBtn');
    const importBtn = document.getElementById('importBtn');
    const importFile = document.getElementById('importFile');

    if (exportBtn) exportBtn.addEventListener('click', exportConfig);
    if (importBtn) importBtn.addEventListener('click', () => importFile.click());
    if (importFile) importFile.addEventListener('change', (e) => {
      if (e.target.files[0]) importConfig(e.target.files[0]);
      e.target.value = ''; // Reset so same file can be re-imported
    });
  }

  // ═══════════════════════════════════════════════════════════
  //  CHEAT-SHEET OVERLAY
  // ═══════════════════════════════════════════════════════════

  function initCheatSheet() {
    const overlay = document.getElementById('cheatsheetOverlay');
    const closeBtn = document.getElementById('cheatsheetClose');
    if (!overlay) return;
    // Close button
    if (closeBtn) closeBtn.addEventListener('click', () => overlay.classList.remove('open'));
    // Click outside to close
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) overlay.classList.remove('open');
    });
  }

  // ═══════════════════════════════════════════════════════════
  //  INTERACTIVE TOOL LAUNCHERS
  // ═══════════════════════════════════════════════════════════

  function openTool(page, tab) {
    const url = chrome.runtime.getURL(page) + (tab ? `#${tab}` : '');
    chrome.tabs.create({ url });
  }

  document.getElementById('launchRepeater').addEventListener('click', () => openTool('security-hub/security-toolkit.html', 'repeater'));
  document.getElementById('launchScanner').addEventListener('click', () => openTool('security-hub/security-toolkit.html', 'scanner'));
  document.getElementById('launchFuzzer').addEventListener('click', () => openTool('security-hub/security-toolkit.html', 'fuzzer'));
  document.getElementById('launchEncoder').addEventListener('click', () => openTool('security-hub/security-toolkit.html', 'encoder'));
  document.getElementById('launchHashes').addEventListener('click', () => openTool('security-hub/security-toolkit.html', 'hashes'));
  document.getElementById('notionSyncBtn').addEventListener('click', notionSync);

  // ═══════════════════════════════════════════════════════════
  //  INIT
  // ═══════════════════════════════════════════════════════════

  loadFavorites(() => {
    initVarBar();
    initOsSelector();
    initToolInventory();
    initKillChain();
    initAttackMatrix();
    initPyramid();
    initOwasp();
    initSnippets();
    initKeyboardShortcuts();
    initExportImport();
    initCheatSheet();
    renderFavoritesStrip();
    updateStatsBar();
    loadCachedNotionSnippets();
  });
})();
