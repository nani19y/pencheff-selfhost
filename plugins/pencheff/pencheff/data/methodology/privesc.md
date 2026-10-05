# Privilege Escalation Methodology

## Linux
- Enumerate: `linpeas.sh`, `linux-smart-enumeration`, `linenum.sh`
- SUID/SGID hunt: `find / -perm -4000 -type f 2>/dev/null` cross-ref `gtfobins.github.io`
- sudo -l → cross-ref GTFOBins
- Cron jobs / systemd timers writable by current user
- Capabilities: `getcap -r / 2>/dev/null`
- Kernel CVE: `uname -a` → exploit-db
- Misconfig: writable /etc/passwd, NFS no_root_squash

## Windows
- Enumerate: `winPEAS.exe`, `Seatbelt.exe`, `PowerUp.ps1`
- Token privileges: `whoami /priv` → SeImpersonate (Juicy/Rogue/Potato)
- Unquoted service paths
- Service binPath modification (BUILTIN\Users with SERVICE_CHANGE_CONFIG)
- DLL hijacking via PATH/AppData
- AlwaysInstallElevated
- Stored creds: `cmdkey /list`, `runas /savecred`, browser saved
- LAPS: extract via `nxc smb -M laps`

## Container / cloud
- Docker socket mount → host RCE
- Privileged container → mount host fs
- `kubectl auth can-i --list` → service account abuse
- Mount cloud metadata from inside the container
