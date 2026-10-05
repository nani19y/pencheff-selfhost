# Example: STIG output

`pencheff stig --asset webapp --id STIG-WEB-001`:

```
# STIG-WEB-001 — Web server must use TLS 1.2 or higher
- Severity: high
- Asset(s): webapp, webserver

## Description
All HTTPS endpoints must negotiate TLS 1.2 or 1.3. Older protocols are
deprecated and exploitable.

## Check
sslscan TARGET | grep -E 'SSLv|TLSv1\.0|TLSv1\.1'

## Fix
Disable SSLv2/3, TLSv1.0, TLSv1.1 in the web server configuration.
Configure only TLSv1.2 and TLSv1.3 cipher suites.
```
