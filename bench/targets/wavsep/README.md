# WAVSEP target

The Web Application Vulnerability Scanner Evaluation Project — ~1 000
test cases designed specifically for **scanner comparison**. Every
case ships with a known-good "clean" variant alongside, so scanners
that pattern-match rather than probe get penalised via false
positives.

## Why it's not in `docker-compose.targets.yml`

The historically-popular `citizenstig/wavsep` image has been removed
from Docker Hub and there is no single widely-maintained replacement.
The bench stays opinionated about what it boots automatically, so
WAVSEP is opt-in.

## Option 1 — community Dockerfile (fastest, unmaintained)

There are community Dockerfiles around (mostly forks of the
`citizenstig` one). They're all unofficial, so audit the Dockerfile
before trusting it on a dev machine:

```bash
git clone https://github.com/sectooladdict/wavsep.git wavsep-src
cd wavsep-src
# Look for any Dockerfile contributed by the community; if there is one,
# docker build -t wavsep-local .
# docker run --rm -d --name bench-wavsep -p 8888:8080 wavsep-local
```

If the repo has no Dockerfile, use **Option 2**.

## Option 2 — manual Tomcat + MySQL (reproducible)

WAVSEP is a Java web-app that needs Tomcat 7/8 and MySQL 5.7+. The
canonical install instructions live in the WAVSEP README. A minimal
local-dev path:

```bash
# 1. Grab Tomcat 8 and a matching JDK.
docker run --rm -d --name bench-tomcat \
  -p 8888:8080 tomcat:8-jdk8

# 2. Clone WAVSEP's .war release.
git clone https://github.com/sectooladdict/wavsep.git
# The built WAR lives at wavsep/wavsep.war (check the repo's Releases tab
# for a pre-built version; the Maven build also works).

# 3. Drop the WAR into Tomcat's webapps and start a MySQL instance
#    alongside it (see wavsep/wavsep-install-db/*.sql for seed data).
docker cp wavsep/wavsep.war bench-tomcat:/usr/local/tomcat/webapps/
docker run --rm -d --name bench-mysql \
  -e MYSQL_ROOT_PASSWORD=root -p 3306:3306 mysql:5.7
# Apply the SQL seed from the WAVSEP install-db/ directory.
```

Then point the bench at it:

```bash
TARGET_URL_WAVSEP=http://host.docker.internal:8888/wavsep/ \
  ./run_all.sh wavsep
```

## Option 3 — skip WAVSEP, use Juice Shop + OWASP Benchmark

The Juice Shop scoreboard (dynamic, exploit-driven) and the OWASP
Benchmark (TP/FP/Youden) together cover the same ground WAVSEP does:
broad coverage of injection/XSS classes **with** a noise floor that
penalises scanners for false positives. Publishing Juice Shop and
Benchmark numbers alone is perfectly defensible — it's what
independent scanner reviews have increasingly moved toward since
WAVSEP stopped getting regular updates circa 2017.

## Reachability (once it's up)

`docker-compose.targets.yml` *does not* start WAVSEP, so the bench
defaults to `http://localhost:8888/wavsep/`. Override with
`TARGET_URL_WAVSEP=http://…` if you put it somewhere else.

## Test surface

WAVSEP organises cases under these roots:

```
/wavsep/active/                   active-probe test cases
  RFI-Detection-Evaluation/
  LFI-Detection-Evaluation/
  RedirectDetection/
  RXSS-Detection-Evaluation/      reflected XSS
  SQLi-Detection-Evaluation/
  SInjection-Detection/           generic injection
/wavsep/passive/                  passive / informational
/wavsep/false/                    deliberate false-positive bait
```

## Scoring

Each case has a stable URL pattern. `score/wavsep_score.py` (to be
written — PRs welcome) classifies each finding as TP (reported on
`/active/<class>/<id>/*?…`) or FP (reported on `/false/…`), then
reports TPR / FPR per vulnerability class.
