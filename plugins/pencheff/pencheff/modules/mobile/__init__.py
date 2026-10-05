"""Mobile (Android / iOS) static & dynamic gap module.

Phase 1 — static analysis only:
  - AndroidManifestModule  (apktool + manifest XML parse)
  - MobileSecretsModule    (jadx decompile + regex/secret sweep)
  - MobileCryptoModule     (jadx decompile + insecure crypto detection)
  - IOSStaticModule        (IPA unzip + Info.plist + binary hardening)

Low-level wrappers used by the modules:
  - apktool.decompile      (APK -> smali + AndroidManifest.xml)
  - jadx.recover           (APK -> Java source)
  - mobsf.scan             (optional MobSF REST API enrichment)
  - ios.triage             (legacy iOS file triage; superseded by IOSStaticModule)

Dynamic instrumentation (Frida, Objection, Drozer) is Phase 2.
"""
