# Forensics Methodology (Defensive)

## Acquisition (chain of custody)
- Hash before/after: `sha256sum image.dd`
- Use write-blockers; document timezone, time skew, examiner

## Memory
- `volatility3 -f mem.raw windows.info`
- Pslist / pstree / cmdline / netstat / handles / dlllist
- Malfind, ldrmodules for hidden modules
- LSASS dump → mimikatz offline

## Disk
- `mmls`, `fls`, `icat` (Sleuth Kit)
- Autopsy for GUI triage
- MFT parsing: `mftparser`, `analyzeMFT`

## Timeline
- `log2timeline.py` / `psteal.py`
- Plaso `pinfo` + `psort -o l2tcsv`
- Filter on user, hostname, hour-of-day

## Network
- pcap triage: tshark, zeek, suricata
- Indicators: rare DNS, beacon intervals, TLS JA3 anomalies

## Reporting
- Document hashes, timestamps, examiner, tools, version, command line
- Include MITRE technique mappings for each observed action
