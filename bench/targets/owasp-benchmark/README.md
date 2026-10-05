# OWASP Benchmark target

Purpose-built suite for measuring the **true-positive** and
**false-positive** rates of SAST/DAST tools. Contains ~2 740 test
cases, each annotated in `expectedresults-*.csv` as `TRUE` (the case
really is vulnerable) or `FALSE` (the case *looks* vulnerable — e.g.
`SELECT * FROM Users WHERE name = '` + sanitized + `'` — but
isn't).

Any scanner that flags the `FALSE` cases is a noise generator; the
`TRUE` cases show what it can actually detect.

## Setup

```bash
./setup.sh
```

What it does:

1. Clones https://github.com/OWASP-Benchmark/BenchmarkJava into
   `bench/targets/owasp-benchmark/BenchmarkJava/` if it isn't there.
2. Builds with `mvn package` (JDK 17).
3. Starts Tomcat on `https://localhost:8443/benchmark/` via
   `./runCrawler.sh`.

The Benchmark ships self-signed certs. Configure each scanner to
ignore TLS errors for that host.

## Scoring

`expectedresults-1.2.csv` sits next to `BenchmarkJava/` after clone:

```
# test name, real vulnerability, CWE, category
BenchmarkTest00001,FALSE,22,pathtraver
BenchmarkTest00002,TRUE,89,sqli
...
```

`score/owasp_benchmark_score.py` maps each scanner finding's
`(url, cwe)` → test name, then:

- **TP** = finding that matches a TRUE entry
- **FP** = finding that matches a FALSE entry
- **FN** = TRUE entry with no matching finding
- **TN** = FALSE entry with no matching finding
- **TPR** = TP / (TP + FN)
- **FPR** = FP / (FP + TN)
- **Youden** = TPR − FPR

## Known limitations

- Java-only patterns: doesn't exercise JS sinks, framework-specific
  flaws (Rails/Django ORM injection), etc.
- Synthetic endpoints: some scanners that rely on behaviour
  (timing-based SQLi confirmation) under-perform vs. pattern-based
  tools. This biases the Benchmark toward SAST — document it in
  your publication.

The honest thing to do is publish Benchmark scores alongside the
Juice Shop solve ratio (dynamic, exploit-driven) and WAVSEP numbers
(broader, less Java-skewed).
