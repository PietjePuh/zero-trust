// Cyber Ops Framework Definitions
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
  { id: 'A04', code: 'A04:2021', label: 'Insecure Design',           desc: 'Focus on risks related to design flaws' },
  { id: 'A05', code: 'A05:2021', label: 'Security Misconfiguration', desc: 'Insecure default configurations, incomplete configurations, open S3 buckets' },
  { id: 'A06', code: 'A06:2021', label: 'Vulnerable & Outdated Components', desc: 'Using software that is unsupported, out of date, or vulnerable' },
  { id: 'A07', code: 'A07:2021', label: 'Identification & Authentication Failures', desc: 'Confirmation of the users identity, authentication, and session management' },
  { id: 'A08', code: 'A08:2021', label: 'Software & Data Integrity Failures', desc: 'Focus on making assumptions related to software updates, critical data, and CI/CD pipelines' },
  { id: 'A09', code: 'A09:2021', label: 'Security Logging & Monitoring Failures', desc: 'Failures to detect, escalate, and respond to active breaches' },
  { id: 'A10', code: 'A10:2021', label: 'Server-Side Request Forgery (SSRF)', desc: 'Web applications that fetch a remote resource without validating the user-supplied URL' },
];
