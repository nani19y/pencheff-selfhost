# Web Application Methodology

## Reconnaissance
- Subdomain enumeration: `subfinder -d {domain}`, `amass enum -passive -d {domain}`
- Cert transparency: `crt.sh?q=%25.{domain}&output=json`
- Wayback URLs: `gau {domain}`, `waybackurls {domain}`
- Tech fingerprinting: `whatweb`, `wappalyzer`

## Discovery
- Directory brute-force: `ffuf -u https://{target}/FUZZ -w common.txt`
- Backup-file probes: `.git/`, `.env`, `.svn/`, `.DS_Store`, `*.bak`, `*.swp`
- Robots / sitemap parsing
- JS analysis: extract endpoints with `LinkFinder`, `subjs`

## Authentication
- Default creds: admin:admin, test:test, debug:debug
- Brute / spray: `hydra -L users -P passwords {target} http-post-form ...`
- JWT abuse: `alg=none`, kid traversal, weak HS256 secret crack
- OAuth: open redirect on `redirect_uri`, missing `state`, token leakage to Referer

## Authorization
- IDOR: enumerate sequential / UUID-keyed resources
- Function-level: admin endpoints accessible without role check
- Vertical: low-priv → admin
- Horizontal: user A → user B's data

## Injection
- SQLi: error/blind/time/UNION/stacked
- NoSQLi: `[$ne]`, `[$gt]`, `[$where]`
- Cmd injection: `; ` `|` ``  `$()`
- SSRF: `http://169.254.169.254/`, `file:///etc/passwd`, gopher to localhost
- SSTI: `{{7*7}}`, `${7*7}`, `<%=7*7%>`
- XXE: external entity, parameter entity, blind via OOB

## Client-side
- Reflected / stored / DOM XSS
- CSRF: missing token / SameSite / Origin check
- Clickjacking: missing X-Frame-Options / CSP frame-ancestors
- CORS: `Access-Control-Allow-Origin: *` with credentials
- DOM clobbering, prototype pollution

## Advanced
- HTTP request smuggling (CL.TE / TE.CL / TE.TE)
- Web cache poisoning (unkeyed inputs)
- Cache deception (path confusion)
- Deserialization (Java, .NET, PHP, Python pickle, Ruby Marshal)
- Prototype pollution → DOM XSS / RCE on Node

## Verification
- Reproduce every finding with `test_endpoint`
- Build PoCs that survive header/cookie variations
- Note WAF presence and bypass technique used
