#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Runs the binaries mayhem/build.sh produced under mayhem/build/ (never compiles):
#  1. upstream's embedded self-test (hashmap.c `#ifdef HASHMAP_TEST`): thousands of asserted
#     set/get/delete/scan/iter/clear checks; it prints "PASSED" only after all of them.
#  2. a known-answer probe: SipHash-2-4 reference vectors, fixed murmur/xxhash3 values and
#     map results for a fixed set/delete sequence, compared value by value here.
OUT="$SRC/mayhem/build"
passed=0; failed=0
for b in hashmap_selftest hashmap_kat; do
  [ -x "$OUT/$b" ] || { echo "FAIL: $OUT/$b missing (build.sh bug)" >&2; emit_ctrf "hashmap-selftest+kat" 0 1; exit 1; }
done

# 1) upstream self-test, fixed seed so the run is reproducible
st_out="$(SEED=1 N=2000 "$OUT/hashmap_selftest" 2>&1)"; st_rc=$?
if [ "$st_rc" -eq 0 ] && printf '%s\n' "$st_out" | grep -qx 'PASSED' \
   && printf '%s\n' "$st_out" | grep -qx 'seed=1, count=2000, item_size=4'; then
  passed=$((passed+1)); echo "ok   selftest"
else
  failed=$((failed+1)); echo "FAIL selftest (rc=$st_rc)"; printf '%s\n' "$st_out" | tail -5
fi

# 2) known answers
kat_out="$("$OUT/hashmap_kat" 2>&1)"
expect() {  # expect <name> <value>
  local got
  got="$(printf '%s\n' "$kat_out" | awk -v k="$1" '$1==k {print $2}')"
  if [ "$got" = "$2" ]; then passed=$((passed+1)); echo "ok   $1 = $2"
  else failed=$((failed+1)); echo "FAIL $1: expected $2, got '${got}'"; fi
}
expect sip0       726fdb47dd0e0e31   # SipHash-2-4 reference vector, len 0
expect sip15      a129ca6149be45e5   # reference vector, len 15
expect sip63      958a324ceb064572   # reference vector, len 63
expect murmur     b65cc60cbadcdfc9
expect xxh3_short 70c98554505069d6
expect xxh3_long  3ce5bdf7575926c0
expect count      500
expect get500     500
expect get501     missing
expect sum        250500

emit_ctrf "hashmap-selftest+kat" "$passed" "$failed"
