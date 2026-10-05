# Third-Party Notices

Pencheff invokes a number of external security tools via subprocess. None
of these tools are bundled, statically linked, or modified — they are
called as black-box CLIs through `pencheff/core/tool_runner.py`. Their
licences therefore do **not** propagate to pencheff.

This file documents every wrapped binary, its licence, and the upstream
location where authoritative documentation lives.

## Phase-1 / pre-existing wrappers

(See `pencheff/server.py` `ALLOWED_TOOLS` set for the complete inventory.)

## Phase-2 expansion (added in this branch)

The orchestrator era added the wrappers below. All sources below are the
upstream project — pencheff does **not** vendor any of their code.

### Network & recon

| Tool        | Licence       | Upstream                                                  |
|-------------|---------------|-----------------------------------------------------------|
| rustscan    | GPL-3.0       | https://github.com/RustScan/RustScan                       |
| autorecon   | GPL-3.0       | https://github.com/Tib3rius/AutoRecon                      |
| naabu       | MIT           | https://github.com/projectdiscovery/naabu                  |
| httpx       | MIT           | https://github.com/projectdiscovery/httpx                  |
| katana      | MIT           | https://github.com/projectdiscovery/katana                 |
| hakrawler   | MIT           | https://github.com/hakluke/hakrawler                       |
| aquatone    | MIT           | https://github.com/michenriksen/aquatone                   |
| kiterunner  | Apache-2.0    | https://github.com/assetnote/kiterunner                    |
| assetfinder | MIT           | https://github.com/tomnomnom/assetfinder                   |
| nuclei      | MIT           | https://github.com/projectdiscovery/nuclei                 |

### Web fuzz / discovery

| Tool        | Licence       | Upstream                                                  |
|-------------|---------------|-----------------------------------------------------------|
| paramspider | MIT           | https://github.com/devanshbatham/paramspider                |
| arjun       | GPL-3.0       | https://github.com/s0md3v/Arjun                            |
| x8          | MIT           | https://github.com/Sh1Yo/x8                                |
| jaeles      | Apache-2.0    | https://github.com/jaeles-project/jaeles                   |
| ghauri      | MIT           | https://github.com/r0oth3x49/ghauri                        |
| commix      | GPL-3.0       | https://github.com/commixproject/commix                    |
| tplmap      | GPL-3.0       | https://github.com/epinna/tplmap                           |
| dalfox      | MIT           | https://github.com/hahwul/dalfox                           |
| xsstrike    | GPL-3.0       | https://github.com/s0md3v/XSStrike                         |
| feroxbuster | MIT           | https://github.com/epi052/feroxbuster                      |
| dirsearch   | GPL-2.0       | https://github.com/maurosoria/dirsearch                    |

### Pipeline utilities

| Tool        | Licence       | Upstream                                                  |
|-------------|---------------|-----------------------------------------------------------|
| anew        | MIT           | https://github.com/tomnomnom/anew                          |
| qsreplace   | MIT           | https://github.com/tomnomnom/qsreplace                     |
| uro         | MIT           | https://github.com/s0md3v/uro                              |

### Active Directory

| Tool                    | Licence       | Upstream                                          |
|-------------------------|---------------|---------------------------------------------------|
| netexec / nxc           | BSD-2         | https://github.com/Pennyw0rth/NetExec              |
| evil-winrm              | LGPL-3.0      | https://github.com/Hackplayers/evil-winrm          |
| certipy                 | MIT           | https://github.com/ly4k/Certipy                    |
| impacket-*              | BSD-3         | https://github.com/fortra/impacket                 |
| bloodhound-python       | MIT           | https://github.com/dirkjanm/BloodHound.py          |
| kerbrute                | Apache-2.0    | https://github.com/ropnop/kerbrute                 |

### Cloud / Kubernetes

| Tool         | Licence    | Upstream                                                |
|--------------|------------|---------------------------------------------------------|
| prowler      | Apache-2.0 | https://github.com/prowler-cloud/prowler                 |
| scoutsuite   | GPL-2.0    | https://github.com/nccgroup/ScoutSuite                   |
| pacu         | BSD-3      | https://github.com/RhinoSecurityLabs/pacu                |
| cloudsploit  | GPL-3.0    | https://github.com/aquasecurity/cloudsploit              |
| cloudfox     | MIT        | https://github.com/BishopFox/cloudfox                    |
| kube-hunter  | Apache-2.0 | https://github.com/aquasecurity/kube-hunter              |
| kube-bench   | Apache-2.0 | https://github.com/aquasecurity/kube-bench               |

### Binary / RE

| Tool         | Licence    | Upstream                                                |
|--------------|------------|---------------------------------------------------------|
| radare2 / r2 | LGPL-3.0   | https://github.com/radareorg/radare2                     |
| ghidra       | Apache-2.0 | https://github.com/NationalSecurityAgency/ghidra         |
| ROPgadget    | BSD-3      | https://github.com/JonathanSalwan/ROPgadget              |
| ropper       | BSD-3      | https://github.com/sashs/Ropper                          |
| one-gadget   | MIT        | https://github.com/david942j/one_gadget                  |
| pwninit      | MIT        | https://github.com/io12/pwninit                          |
| checksec     | BSD-3      | https://github.com/slimm609/checksec.sh                  |

### Forensics

| Tool          | Licence       | Upstream                                              |
|---------------|---------------|-------------------------------------------------------|
| photorec      | GPL-2.0       | https://www.cgsecurity.org/wiki/PhotoRec               |
| bulk_extractor| public-domain | https://github.com/simsong/bulk_extractor              |
| exiftool      | Artistic / GPL| https://exiftool.org/                                  |

### OSINT

| Tool             | Licence    | Upstream                                          |
|------------------|------------|---------------------------------------------------|
| sherlock         | MIT        | https://github.com/sherlock-project/sherlock      |
| spiderfoot       | MIT        | https://github.com/smicallef/spiderfoot           |
| trufflehog       | AGPL-3.0   | https://github.com/trufflesecurity/trufflehog     |
| social-analyzer  | AGPL-3.0   | https://github.com/qeeqbox/social-analyzer        |

### Stego / CTF

| Tool       | Licence    | Upstream                                              |
|------------|------------|-------------------------------------------------------|
| stegseek   | MIT        | https://github.com/RickdeJager/stegseek                |
| steghide   | GPL-2.0    | http://steghide.sourceforge.net/                       |
| zsteg      | MIT        | https://github.com/zed-0xff/zsteg                       |

### Wireless

| Tool         | Licence    | Upstream                                              |
|--------------|------------|-------------------------------------------------------|
| hcxdumptool  | MIT        | https://github.com/ZerBea/hcxdumptool                 |
| hcxtools     | MIT        | https://github.com/ZerBea/hcxtools                    |

---

## Python dependencies

Pencheff also imports the following Python libraries directly. Their
licences propagate normally.

- `mcp` — MIT
- `httpx` — BSD-3
- `pydantic` — MIT
- `pyjwt` — MIT
- `cryptography` — Apache-2.0 / BSD-3
- `pyyaml` — MIT
- `dnspython` — ISC
- `python-docx` — MIT
- `websockets` — BSD-3
- `playwright` — Apache-2.0
- `defusedxml` — Python License
- `mitmproxy` — MIT (optional)
- `impacket` — BSD-3 (optional, for AD modules)
- `pycryptodome` — BSD-2 + Public Domain (used by `modules/ctf/crypto/rsa`)
- `gmpy2` — LGPL-3.0 (optional, accelerates `modules/ctf/crypto/rsa`)
- `lief` — Apache-2.0 (optional, used by `modules/binary_analysis/elf_pe`)
- `Pillow` — HPND (optional, used by `modules/ctf/stego/lsb`)
