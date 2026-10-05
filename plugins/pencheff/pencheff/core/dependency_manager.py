"""Check and optionally install missing dependencies."""

from __future__ import annotations

import importlib
from typing import Any

from pencheff.core.tool_runner import tool_available

REQUIRED_PYTHON = {
    "httpx": "httpx",
    "pydantic": "pydantic",
    "pyjwt": "jwt",
    "cryptography": "cryptography",
    "jinja2": "jinja2",
    "dnspython": "dns.resolver",
    "beautifulsoup4": "bs4",
    "lxml": "lxml",
    "boto3": "boto3",
    "paramiko": "paramiko",
    "websockets": "websockets",
    "h2": "h2",
    "playwright": "playwright",   # browser crawl, DOM XSS, login macro
}

OPTIONAL_PYTHON: dict = {}

SYSTEM_TOOLS = {
    # ══════════════════════════════════════════════════════════════
    # NETWORK SCANNING TOOLS (10)
    # ══════════════════════════════════════════════════════════════
    "ipscan": "Angry IP Scanner — fast IP address and port scanning with host info",
    "fping": "Fast ICMP ping to multiple hosts simultaneously for network diagnosis",
    "unicornscan": "Asynchronous TCP/UDP scanner for large networks",
    "netcat": "Network utility — port scanning, file transfer, reverse shells, banner grabbing",
    "masscan": "Ultra-fast port scanning (100K+ ports/sec) — Internet-scale scanning",
    "naabu": "Fast port scanner (ProjectDiscovery) — SYN/CONNECT scanning",
    "nessus": "Tenable vulnerability scanner — comprehensive network security assessment",
    "hping3": "Packet crafting and analysis — firewall testing, idle scanning, traceroute",

    # ══════════════════════════════════════════════════════════════
    # VULNERABILITY SCANNING TOOLS (7)
    # ══════════════════════════════════════════════════════════════
    "openvas": "Open Vulnerability Assessment Scanner — comprehensive security assessments",
    "gvm-cli": "Greenbone Vulnerability Management CLI",
    "nessus": "Tenable Nessus — network vulnerability scanning with detailed reports",
    "skipfish": "Web app security recon — generates interactive sitemap with security checks",
    "vega": "Web vulnerability scanner — SQLi, XSS, sensitive data exposure",

    # ══════════════════════════════════════════════════════════════
    # PASSWORD CRACKING TOOLS (9)
    # ══════════════════════════════════════════════════════════════
    "john": "John the Ripper — password cracker supporting 100s of hash types",
    "hashcat": "GPU-accelerated password recovery — 300+ hash types, world's fastest cracker",
    "rcrack": "RainbowCrack — hash cracker using precomputed rainbow tables",
    "aircrack-ng": "WiFi security suite — WEP/WPA/WPA2 cracking, packet capture, monitoring",
    "hydra": "Network login brute-forcer — 50+ protocols (HTTP, SSH, FTP, MySQL, etc.)",
    "medusa": "Parallel network login brute-forcer — fast credential testing",
    "l0phtcrack": "Password auditing — dictionary, brute-force, rainbow table attacks",
    "cowpatty": "WPA2-PSK brute-force cracking — weak passphrase detection",
    "ophcrack": "Windows password cracker using rainbow tables",

    # ══════════════════════════════════════════════════════════════
    # EXPLOITATION TOOLS (10)
    # ══════════════════════════════════════════════════════════════
    "msfconsole": "Metasploit Framework — exploit development, post-exploitation, pivoting",
    "msfvenom": "Metasploit payload generator — shellcode, executables, scripts",
    "msfdb": "Metasploit database management",
    "setoolkit": "Social-Engineer Toolkit — phishing, credential harvesting, SMS spoofing",
    "beef-xss": "Browser Exploitation Framework — XSS attacks targeting browser sessions",
    "armitage": "Graphical Metasploit frontend — target visualization, exploit recommendations",
    "zap-cli": "OWASP ZAP CLI — automated web security scanning and testing",
    "zaproxy": "OWASP Zed Attack Proxy — web app security scanner with add-ons",
    "commix": "Command injection exploiter — automated OS command injection",

    # ══════════════════════════════════════════════════════════════
    # PACKET SNIFFING & SPOOFING TOOLS (9)
    # ══════════════════════════════════════════════════════════════
    "tshark": "Wireshark CLI — deep packet inspection of 100s of protocols",
    "tcpdump": "Command-line packet analyzer — capture and filter network traffic",
    "ettercap": "Man-in-the-middle attack suite — ARP spoofing, DNS spoofing, sniffing",
    "bettercap": "Network attack Swiss Army knife — WiFi, BLE, Ethernet MitM attacks",
    "snort": "Intrusion detection/prevention system — rule-based packet analysis",
    "ngrep": "Network grep — pattern-matching packet analyzer across protocols",
    "nemesis": "Packet crafting and injection — custom protocol packets, Layer 2 injection",
    "scapy": "Interactive packet manipulation — craft, send, sniff, dissect packets",
    "dsniff": "Password sniffer — network auditing and penetration testing",

    # ══════════════════════════════════════════════════════════════
    # WIRELESS HACKING TOOLS (7)
    # ══════════════════════════════════════════════════════════════
    "wifite": "Automated wireless auditing — WEP/WPA/WPS attacks",
    "kismet": "Wireless detector, sniffer, IDS — WiFi, Bluetooth, Zigbee, RF",
    "reaver": "WPS brute-force attack — recover WPA/WPA2 passphrases",
    "bully": "WPS brute-force (C-based) — improved performance over Reaver",
    "wifiphisher": "Rogue AP framework — WiFi phishing, credential capture",
    "hostapd-wpe": "Rogue RADIUS server for WPA2-Enterprise attacks",
    "mdk4": "WiFi testing — beacon flooding, deauth, WDS confusion",

    # ══════════════════════════════════════════════════════════════
    # DIRECTORY / PATH BRUTE FORCE (6)
    # ══════════════════════════════════════════════════════════════
    "ffuf": "Fast web fuzzer — directory brute force, parameter fuzzing, vhost discovery",
    "gobuster": "Directory/DNS/vhost brute-force scanner — fast, Go-based",
    "dirb": "Web content scanner — recursive directory brute force",
    "wfuzz": "Web fuzzer — headers, POST data, URLs, authentication testing",
    "feroxbuster": "Recursive content discovery — fast, smart wordlists, auto-filtering",
    "dirsearch": "Web path brute-forcer with recursive scanning and extension support",

    # ══════════════════════════════════════════════════════════════
    # WEB APPLICATION HACKING TOOLS (5)
    # ══════════════════════════════════════════════════════════════
    "whatweb": "Web technology fingerprinting — CMS, frameworks, servers, plugins",
    "wafw00f": "WAF fingerprinting and detection — identifies 100+ WAF products",
    "wpscan": "WordPress vulnerability scanner — plugins, themes, users, passwords",
    "dalfox": "XSS scanner with DOM analysis — parameter mining and payload optimization",
    "xsstrike": "Advanced XSS detection — fuzzing, crawling, context analysis",

    # ══════════════════════════════════════════════════════════════
    # SUBDOMAIN ENUMERATION (7)
    # ══════════════════════════════════════════════════════════════
    "subfinder": "Passive subdomain discovery (ProjectDiscovery) — 30+ sources",
    "amass": "OWASP attack surface mapping — active/passive subdomain enumeration",
    "fierce": "DNS reconnaissance — subdomain brute-forcing and zone discovery",
    "dnsrecon": "DNS enumeration — zone transfers, brute force, cache snooping",
    "sublist3r": "Subdomain enumeration using search engines and public sources",
    "knockpy": "Subdomain scanner with DNS resolution and takeover detection",
    "dnsenum": "DNS enumeration — subdomains, MX, NS, zone transfer attempts",

    # ══════════════════════════════════════════════════════════════
    # DNS TOOLS (3)
    # ══════════════════════════════════════════════════════════════
    "dig": "DNS lookups — query DNS records with full control",
    "whois": "Domain registration info — registrar, nameservers, dates",
    "host": "Simple DNS lookup utility — forward and reverse lookups",

    # ══════════════════════════════════════════════════════════════
    # SSL/TLS TESTING (4)
    # ══════════════════════════════════════════════════════════════
    "sslscan": "SSL/TLS scanner — cipher suites, protocols, certificate analysis",
    "testssl": "Comprehensive SSL/TLS testing (testssl.sh) — BEAST, POODLE, Heartbleed",
    "sslyze": "Fast SSL/TLS scanner — certificate validation, protocol support",
    "openssl": "SSL/TLS cryptography toolkit — certificate management, testing",

    # ══════════════════════════════════════════════════════════════
    # OSINT / SOCIAL ENGINEERING TOOLS (9)
    # ══════════════════════════════════════════════════════════════
    "theHarvester": "OSINT — emails, subdomains, IPs from public sources",
    "maltego": "OSINT and link analysis — data correlation across 100s of sources",
    "recon-ng": "Web reconnaissance framework — modular OSINT collection",
    "sherlock": "Username enumeration across 400+ social networks",
    "spiderfoot": "Automated OSINT collection — 200+ data sources",
    "gophish": "Phishing campaign toolkit — email phishing simulation",
    "king-phisher": "Phishing simulation — credential harvesting, website cloning",
    "evilginx2": "MitM framework — session cookie theft, 2FA bypass via reverse proxy",
    "social-engineer-toolkit": "SET alias — social engineering attack framework",

    # ══════════════════════════════════════════════════════════════
    # FORENSIC TOOLS (8)
    # ══════════════════════════════════════════════════════════════
    "autopsy": "Digital forensics platform — disk image analysis",
    "foremost": "File recovery/carving for forensic analysis — headers/footers",
    "scalpel": "Fast file carver — improved version of Foremost",
    "fls": "The Sleuth Kit — list files and directories in disk images",
    "mmls": "The Sleuth Kit — display partition layout of volume systems",
    "icat": "The Sleuth Kit — extract file content from disk images",
    "volatility": "Memory forensics framework — RAM analysis, process dumping",
    "binwalk": "Firmware analysis — extract embedded files and code",

    # ══════════════════════════════════════════════════════════════
    # POST-EXPLOITATION / CREDENTIAL TOOLS (10)
    # ══════════════════════════════════════════════════════════════
    "mimikatz": "Windows credential extraction — pass-the-hash, pass-the-ticket",
    "crackmapexec": "Post-exploitation — SMB, LDAP, WinRM, MSSQL credential testing",
    "impacket-secretsdump": "Impacket — dump NTLM hashes, Kerberos tickets from DC",
    "impacket-psexec": "Impacket — remote command execution via SMB",
    "impacket-smbexec": "Impacket — SMB-based remote execution",
    "impacket-wmiexec": "Impacket — WMI-based remote execution",
    "responder": "LLMNR/NBT-NS/MDNS poisoner — credential capture on LAN",
    "enum4linux": "SMB/Windows enumeration — shares, users, groups, policies",
    "smbclient": "SMB client — connect to file shares, list/download files",
    "pcredz": "Credential extraction from PCAP files — 20+ protocols",

    # ══════════════════════════════════════════════════════════════
    # WEB PROXY / API TESTING (3)
    # ══════════════════════════════════════════════════════════════
    "curl": "HTTP requests — full protocol control, auth, proxies",
    "wget": "HTTP downloader — recursive website mirroring",
    "httpx-toolkit": "HTTP probing (ProjectDiscovery) — tech detection, status codes",

    # ══════════════════════════════════════════════════════════════
    # STATIC ANALYSIS / SECRET SCANNING (4)
    # ══════════════════════════════════════════════════════════════
    "semgrep": "Static analysis — 5000+ rules across 30+ languages",
    "bandit": "Python security analysis — find common security issues",
    "trufflehog": "Secret scanning — git repos, S3 buckets, filesystem",
    "git-dumper": "Extract git repositories from misconfigured web servers",

    # ══════════════════════════════════════════════════════════════
    # MISCELLANEOUS (5)
    # ══════════════════════════════════════════════════════════════
    "interactsh-client": "OAST out-of-band callback detection — blind SSRF/SQLi/XSS (ProjectDiscovery)",
    "gau": "URL discovery from web archives — AlienVault, Wayback, CommonCrawl",
    "waybackurls": "Fetch URLs from Wayback Machine",
    "commix": "Automated command injection exploiter",
    "xsser": "Cross-site scripting framework — automated XSS exploitation",
}


def check_python_package(import_name: str) -> bool:
    try:
        importlib.import_module(import_name)
        return True
    except ImportError:
        return False


def check_all_dependencies() -> dict[str, Any]:
    """Check all dependencies and return a status report."""
    python_required = {}
    for pkg, imp in REQUIRED_PYTHON.items():
        python_required[pkg] = {
            "available": check_python_package(imp),
            "required": True,
        }

    python_optional = {}
    for pkg, imp in OPTIONAL_PYTHON.items():
        python_optional[pkg] = {
            "available": check_python_package(imp),
            "required": False,
        }

    system = {}
    for tool, desc in SYSTEM_TOOLS.items():
        system[tool] = {
            "available": tool_available(tool),
            "description": desc,
        }

    missing_required = [p for p, s in python_required.items() if not s["available"]]
    missing_optional = [p for p, s in python_optional.items() if not s["available"]]
    missing_system = [t for t, s in system.items() if not s["available"]]

    # Build capability summary based on available tools
    available_system = [t for t, s in system.items() if s["available"]]
    capabilities = []
    cap_map = {
        "hydra": "Network brute-force attacks (50+ protocols)",
        "ffuf": "Directory/parameter fuzzing",
        "gobuster": "Directory brute-force scanning",
        "subfinder": "Passive subdomain enumeration",
        "amass": "Attack surface mapping",
        "sslscan": "SSL/TLS configuration testing",
        "wafw00f": "WAF detection and fingerprinting",
        "whatweb": "Technology fingerprinting",
        "dalfox": "Advanced XSS detection",
        "masscan": "Ultra-fast port scanning",
        "john": "Password hash cracking",
        "hashcat": "GPU-accelerated password cracking",
        "msfconsole": "Metasploit exploitation framework",
        "wpscan": "WordPress vulnerability scanning",
        "testssl": "Comprehensive SSL/TLS testing",
        "feroxbuster": "Recursive content discovery",
        "interactsh-client": "Blind SSRF/injection/XSS via OOB callbacks",
    }
    for tool_name in available_system:
        if tool_name in cap_map:
            capabilities.append(f"✓ {cap_map[tool_name]} (via {tool_name})")

    capabilities.append("✓ Browser crawl + DOM XSS + login macro (via playwright)")

    return {
        "python_required": python_required,
        "python_optional": python_optional,
        "system_tools": system,
        "missing_required": missing_required,
        "missing_optional": missing_optional,
        "missing_system": missing_system,
        "available_system_tools": available_system,
        "capabilities": capabilities,
        "ready": len(missing_required) == 0,
        "next_steps": [
            "Use Pencheff map, sqli, webscan, and pulse for core coverage; use run_security_tool only for auxiliary tools.",
            f"{len(available_system)} external tools available, {len(missing_system)} not installed.",
            "PRIORITIZE: Pencheff map/recon_active for host discovery, Pencheff webscan/scan_infrastructure for web exposure, Pencheff sqli/scan_injection for SQLi, scan_pulse for template detection, and hydra only for authorized brute-force checks.",
        ],
    }
