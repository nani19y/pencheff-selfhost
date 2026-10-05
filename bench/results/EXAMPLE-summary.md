# Example results format (fill in after your first run)

> This file is a **template** of what a published benchmark summary
> should look like. Replace every number below with numbers from your
> own reproducible run. Commit your raw per-run CSVs alongside it so
> anyone can verify.

## Run metadata

| Field | Value |
|---|---|
| Date | _YYYY-MM-DD_ |
| Hardware | Apple M-series / 32 GB · Docker Desktop 4.30 |
| Pencheff version | `git rev-parse --short HEAD` |
| Claude model | `claude-haiku-4-5-20251001` |
| Triage LLM | MiniMax-M2.7 via Together.ai |
| Pencheff profile | `standard` |

## OWASP Juice Shop (challenges solved / 112)

| Scanner | Solved | Ratio | Time | Findings reported | Verified |
|---|---:|---:|---:|---:|---:|
| Pencheff (agent) | _47_ | _0.42_ | _09m 32s_ | _41_ | _38_ |
| OWASP ZAP baseline | _11_ | _0.10_ | _30m 20s_ | _113_ | _—_ |
| Astra Security¹ | _—_ | _—_ | _manual_ | _—_ | _—_ |
| Burp Pro² | _—_ | _—_ | _manual_ | _—_ | _—_ |

¹ Astra lacks a public scan API — export required (see `runners/astra.sh`).
² Burp Pro has no scan API; use Burp Enterprise for end-to-end automation.

## OWASP BenchmarkJava (2 740 cases)

| Scanner | TP | FP | FN | TN | TPR | FPR | Youden |
|---|---:|---:|---:|---:|---:|---:|---:|
| Pencheff (agent) | _870_ | _160_ | _560_ | _1150_ | _0.61_ | _0.12_ | _0.49_ |
| OWASP ZAP baseline | _672_ | _310_ | _758_ | _1000_ | _0.47_ | _0.24_ | _0.23_ |

## WAVSEP (per-class TPR / FPR)

| Scanner | XSS TPR | XSS FPR | SQLi TPR | SQLi FPR | Open-redir TPR | Open-redir FPR |
|---|---:|---:|---:|---:|---:|---:|
| Pencheff (agent) | _0.68_ | _0.08_ | _0.71_ | _0.04_ | _0.55_ | _0.10_ |
| OWASP ZAP baseline | _0.52_ | _0.21_ | _0.58_ | _0.11_ | _0.31_ | _0.18_ |

## Reproduction

```
git clone https://github.com/<you>/pencheff.git
cd pencheff/bench
python3 -m venv .venv && source .venv/bin/activate
pip install -r score/requirements.txt

export PENCHEFF_API_TOKEN=<clerk jwt>
./run_all.sh all
cat results/juice-shop-summary-*.csv
cat results/owasp-benchmark-summary-*.csv
```

Raw per-scanner CSVs sit alongside the summary files in this directory.
