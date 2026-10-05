"""Centralized registry for new security-tool integrations.

Phase-2 expansion: rather than editing the 4000+ line MCP server allowlist
inline, this registry owns the metadata (binary name, install hint, domain)
for the tools added in the orchestrator era. ``ALLOWED_TOOLS`` is unioned
into ``server.run_security_tool`` so both the orchestrator and existing
LLM-driven sessions can reach the new tools.

Each entry cites the tool's own homepage / docs in the ``install`` hint. No
code is copied from any third-party orchestrator.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolEntry:
    name: str
    domain: str          # network | web | ad | cloud | binary | osint | forensics | wireless | mobile | ctf | crypto
    purpose: str
    install: str         # short installation hint shown in check_dependencies


# ─── New tools added in Phase 2 ────────────────────────────────────────
_NEW_TOOLS: list[ToolEntry] = [
    # Network / recon
    ToolEntry("rustscan",     "network",   "Ultra-fast port scanner",                    "cargo install rustscan"),
    ToolEntry("autorecon",    "network",   "Service-aware enumeration orchestrator",     "pipx install autorecon"),
    ToolEntry("httpx",        "web",       "Fast HTTP probing (ProjectDiscovery)",       "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    ToolEntry("katana",       "web",       "JS-aware crawler (ProjectDiscovery)",        "go install github.com/projectdiscovery/katana/cmd/katana@latest"),
    ToolEntry("hakrawler",    "web",       "Web crawler",                                "go install github.com/hakluke/hakrawler@latest"),
    ToolEntry("aquatone",     "web",       "Visual recon — screenshots",                 "go install github.com/michenriksen/aquatone@latest"),
    ToolEntry("kiterunner",   "web",       "API path brute-forcer",                      "go install github.com/assetnote/kiterunner/cmd/kr@latest"),
    ToolEntry("assetfinder",  "network",   "Subdomain discovery",                        "go install github.com/tomnomnom/assetfinder@latest"),
    ToolEntry("nuclei",       "web",       "Template-based vulnerability scanner",       "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),

    # Web fuzz / discovery
    ToolEntry("paramspider",  "web",       "Param discovery from wayback URLs",          "pipx install paramspider"),
    ToolEntry("arjun",        "web",       "HTTP parameter discovery",                   "pipx install arjun"),
    ToolEntry("x8",           "web",       "Hidden parameter brute-forcer",              "cargo install x8"),
    ToolEntry("jaeles",       "web",       "Web vuln scanner with signature DSL",        "go install github.com/jaeles-project/jaeles@latest"),
    ToolEntry("ghauri",       "web",       "Advanced SQL injection automator",           "pipx install ghauri"),
    ToolEntry("commix",       "web",       "Command injection exploiter",                "pipx install commix"),
    ToolEntry("tplmap",       "web",       "Server-side template injection scanner",     "git clone github.com/epinna/tplmap"),

    # Pipeline utilities
    ToolEntry("anew",         "web",       "Dedupe-stream helper",                       "go install github.com/tomnomnom/anew@latest"),
    ToolEntry("qsreplace",    "web",       "Query string replacer",                      "go install github.com/tomnomnom/qsreplace@latest"),
    ToolEntry("uro",          "web",       "URL deduplicator",                           "pipx install uro"),

    # Active Directory
    ToolEntry("netexec",      "ad",        "AD/SMB/WinRM/MSSQL credential spray (nxc)",  "pipx install netexec"),
    ToolEntry("nxc",          "ad",        "alias for netexec",                          "pipx install netexec"),
    ToolEntry("evil-winrm",   "ad",        "WinRM shell over Kerberos/NTLM",             "gem install evil-winrm"),
    ToolEntry("certipy",      "ad",        "ADCS abuse — ESC1..ESC8",                    "pipx install certipy-ad"),
    ToolEntry("impacket-getuserspns",   "ad", "Kerberoast SPN ticket request",           "pipx install impacket"),
    ToolEntry("impacket-getnpusers",    "ad", "AS-REP roasting",                         "pipx install impacket"),
    ToolEntry("impacket-secretsdump",   "ad", "Domain credential dump",                  "pipx install impacket"),
    ToolEntry("impacket-psexec",        "ad", "PSExec via impacket",                     "pipx install impacket"),
    ToolEntry("impacket-wmiexec",       "ad", "WMIExec via impacket",                    "pipx install impacket"),
    ToolEntry("impacket-smbexec",       "ad", "SMBExec via impacket",                    "pipx install impacket"),
    ToolEntry("bloodhound-python",      "ad", "BloodHound ingestor (Python)",            "pipx install bloodhound"),
    ToolEntry("kerbrute",     "ad",        "Pre-auth user brute-forcer",                  "go install github.com/ropnop/kerbrute@latest"),

    # Cloud / Kubernetes
    ToolEntry("prowler",      "cloud",     "AWS / Azure / GCP best-practice auditor",    "pipx install prowler"),
    ToolEntry("scout-suite",  "cloud",     "Multi-cloud security auditor",               "pipx install scoutsuite"),
    ToolEntry("scoutsuite",   "cloud",     "alias for scout-suite",                      "pipx install scoutsuite"),
    ToolEntry("pacu",         "cloud",     "AWS exploitation framework",                  "pipx install pacu"),
    ToolEntry("cloudsploit",  "cloud",     "Cloud scanner",                              "npm install -g cloudsploit"),
    ToolEntry("cloudfox",     "cloud",     "Offensive AWS recon",                        "go install github.com/BishopFox/cloudfox@latest"),
    ToolEntry("kube-hunter",  "cloud",     "Kubernetes pen-tester",                      "pipx install kube-hunter"),
    ToolEntry("kube-bench",   "cloud",     "K8s CIS benchmark scanner",                  "go install github.com/aquasecurity/kube-bench@latest"),
    ToolEntry("kubectl",      "cloud",     "Kubernetes CLI",                             "brew install kubectl"),
    ToolEntry("aws",          "cloud",     "AWS CLI",                                    "pipx install awscli"),
    ToolEntry("gcloud",       "cloud",     "Google Cloud SDK",                           "https://cloud.google.com/sdk/docs/install"),
    ToolEntry("az",           "cloud",     "Azure CLI",                                  "https://learn.microsoft.com/cli/azure/install-azure-cli"),

    # Binary / RE
    ToolEntry("radare2",      "binary",    "Reverse engineering framework",              "brew install radare2"),
    ToolEntry("r2",           "binary",    "alias for radare2",                          "brew install radare2"),
    ToolEntry("ghidra-headless", "binary", "Ghidra headless analyzer",                   "https://ghidra-sre.org"),
    ToolEntry("analyzeHeadless", "binary", "Ghidra headless launcher script",            "https://ghidra-sre.org"),
    ToolEntry("ROPgadget",    "binary",    "ROP gadget extractor",                       "pipx install ROPGadget"),
    ToolEntry("ropgadget",    "binary",    "alias for ROPgadget",                        "pipx install ROPGadget"),
    ToolEntry("ropper",       "binary",    "ROP / JOP gadget finder",                    "pipx install ropper"),
    ToolEntry("one-gadget",   "binary",    "libc one-shot gadget finder",                "gem install one_gadget"),
    ToolEntry("pwninit",      "binary",    "CTF binary helper",                          "cargo install pwninit"),
    ToolEntry("checksec",     "binary",    "ELF security feature checker",               "brew install checksec"),
    ToolEntry("file",         "binary",    "Magic-byte type detection",                  "preinstalled on most unixes"),
    ToolEntry("strings",      "binary",    "Printable-string extractor",                 "preinstalled (binutils)"),
    ToolEntry("objdump",      "binary",    "Binary disassembler",                        "preinstalled (binutils)"),
    ToolEntry("readelf",      "binary",    "ELF inspector",                              "preinstalled (binutils)"),
    ToolEntry("nm",           "binary",    "Symbol-table inspector",                     "preinstalled (binutils)"),
    ToolEntry("xxd",          "binary",    "Hexdump utility",                            "preinstalled (vim package)"),

    # Forensics
    ToolEntry("photorec",     "forensics", "File carver (TestDisk suite)",               "brew install testdisk"),
    ToolEntry("bulk_extractor", "forensics", "Forensic feature extractor",               "brew install bulk_extractor"),
    ToolEntry("exiftool",     "forensics", "Metadata reader/writer",                     "brew install exiftool"),
    ToolEntry("plaso",        "forensics", "Timeline tool",                              "pipx install plaso"),

    # OSINT
    ToolEntry("social-analyzer", "osint",  "Profile analyzer across social networks",    "npm install -g social-analyzer"),
    ToolEntry("amass-intel",  "osint",     "Amass intel mode",                           "see amass install hint"),

    # Stego (for CTF and incident triage)
    ToolEntry("stegseek",     "ctf",       "Faster steghide cracker",                    "brew install stegseek"),
    ToolEntry("steghide",     "ctf",       "JPEG/BMP stego",                             "brew install steghide"),
    ToolEntry("zsteg",        "ctf",       "PNG/BMP stego inspector",                    "gem install zsteg"),
    ToolEntry("stegsolve",    "ctf",       "Manual stego viewer (Java)",                 "https://github.com/zardus/ctf-tools"),

    # Cryptography helpers used by ctf module wrappers
    ToolEntry("john",         "crypto",    "John the Ripper",                            "brew install john"),
    ToolEntry("hashid",       "crypto",    "Hash type identifier",                        "pipx install hashid"),
    ToolEntry("hash-identifier", "crypto", "Hash type identifier (Python)",              "pipx install hash-identifier"),

    # Wireless extras
    ToolEntry("hcxdumptool",  "wireless",  "WPA/WPA2 capture",                           "brew install hcxdumptool"),
    ToolEntry("hcxtools",     "wireless",  "WPA/WPA2 conversion suite",                  "brew install hcxtools"),
]


_TOOL_INDEX: dict[str, ToolEntry] = {entry.name: entry for entry in _NEW_TOOLS}


ALLOWED_TOOLS: frozenset[str] = frozenset(_TOOL_INDEX.keys())


def all_tools() -> list[ToolEntry]:
    return list(_NEW_TOOLS)


def by_domain(domain: str) -> list[ToolEntry]:
    return [t for t in _NEW_TOOLS if t.domain == domain]


def install_hint(name: str) -> str:
    entry = _TOOL_INDEX.get(name)
    return entry.install if entry else ""


def is_known(name: str) -> bool:
    return name in _TOOL_INDEX
