#!/usr/bin/env bash
set -euo pipefail
#
# Clone, build, and launch OWASP BenchmarkJava locally.
# Requires: git, mvn, JDK 17.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$HERE/BenchmarkJava"
REPO_URL="https://github.com/OWASP-Benchmark/BenchmarkJava.git"
REF="${BENCHMARK_REF:-main}"

if [[ ! -d "$REPO_DIR/.git" ]]; then
  echo "→ cloning $REPO_URL → $REPO_DIR"
  git clone --depth=1 --branch "$REF" "$REPO_URL" "$REPO_DIR"
else
  echo "→ reusing existing clone at $REPO_DIR"
fi

cd "$REPO_DIR"

echo "→ building (mvn package)"
mvn -q -DskipTests package

echo "→ starting Tomcat on https://localhost:8443/benchmark/"
# runCrawler.sh blocks until Tomcat is ready and then runs the supplied
# crawler; we just want the app up, so start it detached.
nohup ./runLocalBenchmark.sh > "$HERE/benchmark.log" 2>&1 &
echo $! > "$HERE/benchmark.pid"

echo
echo "Benchmark is coming up in the background (pid $(cat "$HERE/benchmark.pid"))."
echo "  URL : https://localhost:8443/benchmark/"
echo "  log : $HERE/benchmark.log"
echo "  stop: kill \$(cat $HERE/benchmark.pid)"
echo
echo "Expected-results CSV: $REPO_DIR/expectedresults-*.csv"
