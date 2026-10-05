# Mobile Methodology

## Android
- Decompile: `apktool d app.apk` → smali
- Java decomp: `jadx -d out app.apk`
- Manifest review: exported activities/services/receivers, permissions, taskAffinity
- Hard-coded secrets: `grep -RE 'api_key|secret|password' out/`
- Network security config: cleartext / pinning bypass
- WebView: `setJavaScriptEnabled(true)` + JS bridge → RCE
- Frida hooks for runtime instrumentation
- MobSF static + dynamic via REST API

## iOS
- IPA: `unzip app.ipa -d out`
- `class-dump`, `otool`, Hopper / Ghidra
- Plist + entitlements review
- Keychain dump (jailbroken or via objection)
- ATS exceptions, certificate pinning bypass

## Common
- Insecure local storage (SQLite, shared prefs, plist)
- Insecure deep links / URL schemes
- Tapjacking, screen overlay
- Backups expose data (Android `allowBackup=true`)
