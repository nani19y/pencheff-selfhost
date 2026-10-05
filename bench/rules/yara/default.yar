/*
 * Pencheff default YARA rule bundle.
 *
 * Small, high-signal ruleset aimed at the kinds of malware/backdoors that
 * actually land in application source trees: web-shell skeletons,
 * obfuscated loaders, hard-coded miner endpoints, known typosquat payloads.
 *
 * These are intentionally conservative to keep false positives low in
 * normal application code. Users can add their own .yar files under
 * bench/rules/yara/ — the runner globs the directory.
 */

rule PHP_Webshell_Minimal
{
    meta:
        author = "pencheff"
        severity = "critical"
        description = "Minimal PHP web-shell — executes request parameter as shell command"
    strings:
        $a = /eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/
        $b = /system\s*\(\s*\$_(GET|POST|REQUEST)\s*\[/
        $c = /passthru\s*\(\s*\$_(GET|POST|REQUEST)\s*\[/
        $d = /shell_exec\s*\(\s*\$_(GET|POST|REQUEST)\s*\[/
    condition:
        any of them
}

rule JS_Obfuscated_Loader
{
    meta:
        author = "pencheff"
        severity = "high"
        description = "JavaScript loader style common in supply-chain backdoors (base64 → eval)"
    strings:
        $a = /eval\s*\(\s*atob\s*\(/
        $b = /Function\s*\(\s*atob\s*\(/
        $c = /new\s+Function\s*\(\s*decodeURIComponent\s*\(\s*escape\s*\(/
    condition:
        any of them
}

rule Crypto_Miner_Pool
{
    meta:
        author = "pencheff"
        severity = "high"
        description = "Hard-coded mining-pool endpoint (stratum://, pool.minexmr, xmrig config)"
    strings:
        $a = "stratum+tcp://"
        $b = "pool.minexmr"
        $c = "xmrig"
        $d = "coinhive.min.js"
    condition:
        any of them
}

rule Python_Pickle_RCE_Payload
{
    meta:
        author = "pencheff"
        severity = "high"
        description = "Hand-crafted pickle/reduce payload — the classic RCE gadget"
    strings:
        $a = /__reduce__\s*\(\s*self\s*\)\s*:\s*return\s*\(\s*os\.system/
        $b = /__reduce__\s*\(\s*self\s*\)\s*:\s*return\s*\(\s*subprocess\./
    condition:
        any of them
}

rule Reverse_Shell_Generic
{
    meta:
        author = "pencheff"
        severity = "critical"
        description = "Classic /dev/tcp or python reverse shell oneliner"
    strings:
        $a = "bash -i >& /dev/tcp/"
        $b = /socket\.socket\(socket\.AF_INET,socket\.SOCK_STREAM\).connect\(\(.+?,\s*\d+\)/
        $c = "nc -e /bin/sh"
        $d = "perl -e 'use Socket;"
    condition:
        any of them
}
