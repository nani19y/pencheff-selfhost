# Pencheff Benchmark Harness

A reproducible suite for comparing Pencheff against other web-vulnerability
scanners (OWASP ZAP, Astra, Burp, …) on the same set of
deliberately-vulnerable targets. Every run produces a normalised CSV of
findings and a score per target so you can publish a direct comparison.

## What gets measured

| Target | What it tests | Scoring | Auto-boot? |
|---|---|---|---|
| **OWASP Juice Shop** | 100+ modern web challenges (XSS, IDOR, JWT, SQLi, business logic, prototype pollution, …) with a built-in scoreboard | `solved / total × 100` | ✅ via `docker-compose.targets.yml` |
| **OWASP Benchmark** | ~2 740 TP / TN cases across CWE-22, 78, 79, 89, 327, 330, 501, 614 | Youden Index = TPR − FPR | ⚙️ one-off `targets/owasp-benchmark/setup.sh` |
| **WAVSEP** | 1 000+ XSS / SQLi / RFI / LFI / open-redirect cases with realistic FP traps | TPR, FPR, detection rate by class | ❌ bring your own — [setup options](targets/wavsep/README.md) |

## Layout

```
bench/
├── README.md                     this file
├── docker-compose.targets.yml    brings up juice-shop + wavsep on host ports
├── run_all.sh                    orchestrator: start targets → run each scanner → score
├── targets/
│   ├── juice-shop/README.md
│   ├── owasp-benchmark/
│   │   ├── README.md
│   │   └── setup.sh              clones + boots BenchmarkJava
│   └── wavsep/README.md
├── runners/
│   ├── common.sh                 shared env / output-dir / logging helpers
│   ├── pencheff.sh               commissions a scan via the Pencheff API
│   ├── zap.sh                    zaproxy/zap-stable baseline scan (Docker)
│   ├── astra.sh                  stub — Astra has no public API, manual export
│   └── burp.sh                   stub — Burp Enterprise REST API (commercial)
├── score/
│   ├── requirements.txt          pandas, requests
│   ├── normalize_findings.py     per-scanner JSON/XML → common CSV schema
│   ├── juice_shop_score.py       scrape /api/challenges → solved count
│   └── owasp_benchmark_score.py  match findings to expectedresults-*.csv
└── results/
    └── .gitkeep                  CSVs land here, one per (scanner, target, date)
```

## Quick start

```bash
# 0. Prerequisites
#    - Docker + Docker Compose
#    - Python 3.11+
#    - Java 17+ (only for OWASP Benchmark)
#    - Docker images for the baseline scanners

cd bench
python3 -m venv .venv && source .venv/bin/activate
pip install -r score/requirements.txt

# 1. Boot the targets
docker compose -f docker-compose.targets.yml up -d
# Juice Shop → http://localhost:3001
# (WAVSEP is opt-in — see targets/wavsep/README.md; no maintained
#  public Docker image exists, so the bench doesn't auto-boot it.)

# 2. (Optional) Boot OWASP Benchmark — heavier, JVM-based
./targets/owasp-benchmark/setup.sh      # clones + mvn package + starts Tomcat on :8443

# 3. Point scanners at the targets
export PENCHEFF_API_URL=http://localhost:8000
export PENCHEFF_API_TOKEN=<paste a Clerk session JWT from the browser>
#     (Browser → DevTools → Application → Cookies → __session, or run
#      `await window.Clerk.session.getToken()` in the console.)

./runners/pencheff.sh  http://host.docker.internal:3001  juice-shop
./runners/zap.sh       http://host.docker.internal:3001  juice-shop

# 4. Score the run
python3 score/juice_shop_score.py       # reads /api/challenges and writes results/*.csv

# 5. Look at results/<date>-summary.csv

# Or skip the individual commands and run everything:
./run_all.sh juice-shop
```

## Target URL conventions

Pencheff's worker runs inside Docker, so the target URL it scans must be
reachable from inside that network — use `host.docker.internal` on
Mac/Windows or the bridge gateway IP on Linux.

```
Scanner       │ Target URL to use
──────────────┼─────────────────────────────────────────
zap           │ http://host.docker.internal:3001 (it runs in Docker too)
pencheff      │ http://host.docker.internal:3001
astra, burp   │ http://<your-public-host>:3001  (their SaaS needs a public URL)
```

If your Pencheff is in the same compose network as Juice Shop and you
want to skip the public URL requirement for SaaS scanners, tunnel with
ngrok or Cloudflare Tunnel.

## Scoring methodology

Each scanner writes a `results/<scanner>-<target>-<YYYY-MM-DD>.csv` with
this schema:

```
scanner,target,severity,cwe,title,url,confidence,verified
```

The score scripts then:

1. **Juice Shop** — GET `/api/challenges` (built-in scoreboard). If the
   scanner's exploits popped a challenge, `solved=true`. Score is solved
   count divided by total challenges.
2. **OWASP Benchmark** — match each finding's CWE + URL against
   `expectedresults-1.2.csv` (shipped with BenchmarkJava). Compute TP, FP,
   FN, TN → Youden Index.
3. **WAVSEP** — each test case has a known-vulnerable path and a known
   clean variant; match findings to compute TPR / FPR per class.

The summary CSV:

```
scanner,target,tpr,fpr,youden,solved_ratio,time_seconds,findings_total,findings_verified
pencheff,juice-shop,,,,0.72,412,47,38
zap,juice-shop,,,,0.41,1820,113,?
pencheff,owasp-benchmark,0.61,0.12,0.49,,2117,,
zap,owasp-benchmark,0.47,0.23,0.24,,3640,,
```

## Adding a new scanner

1. Drop a `runners/<name>.sh` that takes `$TARGET_URL $TARGET_NAME` and
   writes `results/<name>-<target>-raw.*` and a normalised
   `results/<name>-<target>-<date>.csv`.
2. Add it to `run_all.sh`.
3. Re-run.

## Publishing

Commit the contents of `results/` after each run. The README at the repo
root links to the latest summary so anyone can cross-check.

> "Anyone can reproduce our benchmark" is the credibility play here. The
> harness is as important as the numbers.

## Limitations

- **Astra** and **Burp Pro** have no open pentest API, so the runners
  here are stubs that document manual steps.
- **OWASP Benchmark** is synthetic Java code — it measures *detection*
  of CWE patterns, not end-to-end exploitation. Juice Shop + WAVSEP are
  the real-world complement.
- **Juice Shop's scoreboard** only flips to `solved=true` for exploits
  the app recognises — some classes of finding (headers, CSP) never
  count, by design.
