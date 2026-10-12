#!/usr/bin/env bash
# tools/fast-gate.test.sh — the fast gate's own suite.
#
# Why this file exists: the fast gate is the thing that decides whether a green result means anything. A
# selector that silently selects nothing is a false-green generator, so the selector gets tests — including
# the fail-loud case (a changed code file that maps to NO suite). Run it directly:
#
#   bash tools/fast-gate.test.sh
#
# Self-contained: no network, no git state, no real test runner. It runs the gate against a throwaway copy of
# itself with `FAST_GATE_RUNNER` stubbed, and asserts on what the gate PRINTED and on its EXIT CODE — both,
# because the printed markers are what `~/fleet/remote/check-coverage.py` parses into the cached verdict.
#
# The stub repo carries `main.ts` and `templates/index.ts` because this repo's suite-map.tsv names them; the
# other fixtures (src/greet.ts, an integration suite) keep the cases that rewrite or hide the map meaningful.
set -uo pipefail
HERE=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
PASS=0; FAIL=0; FAILED=()
ok()  { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); FAILED+=("$1"); printf '  FAIL %s\n      %s\n' "$1" "${2:-}"; }
has()   { grep -qF -- "$2" <<<"$1" && ok "$3" || bad "$3" "expected to find: $2"; }
hasnt() { grep -qF -- "$2" <<<"$1" && bad "$3" "expected NOT to find: $2" || ok "$3"; }

ROOT=$(mktemp -d); trap 'rm -rf "$ROOT"' EXIT
# A throwaway repo whose tools/ is a copy of this one, so a case can damage the map without touching the
# real one. ROOT is derived from the script's path, which is why the copy works.
mkdir -p "$ROOT/repo"
cp -r "$HERE" "$ROOT/repo/tools"
GATE="$ROOT/repo/tools/fast-gate.sh"
mkdir -p "$ROOT/repo/tests/unit" "$ROOT/repo/tests/integration"
: > "$ROOT/repo/tests/unit/greet.test.ts"
: > "$ROOT/repo/tests/unit/other.test.ts"
: > "$ROOT/repo/tests/unit/feed.test.ts"
: > "$ROOT/repo/tests/unit/content.test.ts"
: > "$ROOT/repo/tests/unit/index_template.test.ts"
: > "$ROOT/repo/tests/integration/greet.integration.test.ts"
mkdir -p "$ROOT/repo/src" "$ROOT/repo/templates"
: > "$ROOT/repo/src/greet.ts"; : > "$ROOT/repo/main.ts"; : > "$ROOT/repo/templates/index.ts"
# Stub runner: records every suite it was asked to run, exits 0 (or 1 when STUB_FAIL=1).
cat > "$ROOT/runner" <<'STUB'
#!/usr/bin/env bash
echo "$1" >> "$RUN_LOG"
[ "${STUB_FAIL:-0}" = 1 ] && exit 1
exit 0
STUB
chmod +x "$ROOT/runner"
export FAST_GATE_RUNNER="$ROOT/runner" RUN_LOG="$ROOT/run.log"

run() { ( cd "$ROOT/repo" && FAST_GATE_RUNNER="$FAST_GATE_RUNNER" RUN_LOG="$RUN_LOG" STUB_FAIL="${STUB_FAIL:-0}" bash "$GATE" "$@" 2>&1 ); }
run_rc() { ( cd "$ROOT/repo" && FAST_GATE_RUNNER="$FAST_GATE_RUNNER" RUN_LOG="$RUN_LOG" STUB_FAIL="${STUB_FAIL:-0}" bash "$GATE" "$@" >/dev/null 2>&1 ); echo $?; }

echo "fast-gate: selection and fail-loud behaviour"

# 1. a mapped source file selects EVERY suite the map names for it, and runs them.
#    main.ts is the whole application today and its row names two suites, so this is the real shape.
rm -f "$RUN_LOG"
out=$(run --changed main.ts)
rc=$(run_rc --changed main.ts)
has "$out" "fast-gate: running: tests/unit/feed.test.ts" "1a mapped source selects its first suite"
has "$out" "fast-gate: running: tests/unit/content.test.ts" "1b ... and every other suite the row names"
has "$out" "fast-gate: passed: tests/unit/feed.test.ts" "1c a passing suite is reported with the positive marker"
[ "$rc" = 0 ] && ok "1d exit 0 when every selected suite passes" || bad "1d expected exit 0" "got $rc"

# 1e. a second module's row selects its own suite — the map is per-module, not per-directory.
out=$(run --changed templates/index.ts)
has "$out" "fast-gate: running: tests/unit/index_template.test.ts" "1e templates/index.ts selects its template suite"
hasnt "$out" "tests/unit/feed.test.ts" "1f ... and not an unrelated module's suite"

# 2. the fail-loud case: a changed CODE file that maps to nothing. This is the whole point of the gate.
out=$(run --changed src/newmodule.ts)
rc=$(run_rc --changed src/newmodule.ts)
has "$out" "fast-gate: unmapped: src/newmodule.ts" "2a unmapped changed file is named in the record's vocabulary"
[ "$rc" != 0 ] && ok "2b an unmapped changed file exits non-zero (fail loud, not fail silent)" || bad "2b expected non-zero exit" "got $rc"
hasnt "$out" "fast-gate: passed:" "2c nothing is reported as passing when the map is incomplete"

# 3. a changed suite maps to itself (docs/speed.md R14 names this case as a measured defect).
out=$(run --changed tests/unit/other.test.ts)
has "$out" "fast-gate: running: tests/unit/other.test.ts" "3a a changed test file maps to itself"

# 4. an explicitly exempt path is not an unmapped path, and runs nothing.
out=$(run --changed README.md)
rc=$(run_rc --changed README.md)
has "$out" "fast-gate: no suites affected" "4a an exempt path selects nothing"
[ "$rc" = 0 ] && ok "4b an exempt path exits 0" || bad "4b expected exit 0" "got $rc"
hasnt "$out" "fast-gate: unmapped:" "4c an exempt path is NOT reported unmapped"
# ... but an unlisted file of the same extension is still unmapped: the exemption is the pattern, not the type.
out=$(run --changed NOTES.txt)
has "$out" "fast-gate: unmapped: NOTES.txt" "4d an unlisted file is still unmapped (exemption is per pattern)"

# 5. --list prints the selection and runs nothing.
rm -f "$RUN_LOG"
out=$(run --list --changed main.ts)
has "$out" "tests/unit/feed.test.ts" "5a --list prints the selected suite"
[ ! -s "$RUN_LOG" ] && ok "5b --list runs no suite" || bad "5b --list ran something" "$(cat "$RUN_LOG")"

# 6. a failing suite fails the gate and is not counted as executed.
STUB_FAIL=1
out=$(run --changed main.ts)
rc=$(run_rc --changed main.ts)
has "$out" "fast-gate: failed: tests/unit/feed.test.ts" "6a a failing suite is reported as failed"
hasnt "$out" "fast-gate: passed: tests/unit/feed.test.ts" "6b a failing suite is not also reported as passed"
[ "$rc" != 0 ] && ok "6c a failing suite exits non-zero" || bad "6c expected non-zero exit" "got $rc"
STUB_FAIL=0

# 7. a map that names a suite which does not exist fails loudly instead of reading as green.
cp "$ROOT/repo/tools/suite-map.tsv" "$ROOT/map.bak"
printf 'src/*.ts\ttests/unit/gone.test.ts\n' > "$ROOT/repo/tools/suite-map.tsv"
out=$(run --changed src/greet.ts)
rc=$(run_rc --changed src/greet.ts)
has "$out" "fast-gate: missing: tests/unit/gone.test.ts" "7a a stale map entry is named"
[ "$rc" != 0 ] && ok "7b a stale map entry exits non-zero" || bad "7b expected non-zero exit" "got $rc"
cp "$ROOT/map.bak" "$ROOT/repo/tools/suite-map.tsv"

# 8. no map at all is a refusal, not an empty selection.
mv "$ROOT/repo/tools/suite-map.tsv" "$ROOT/map.hidden"
out=$(run --changed src/greet.ts)
rc=$(run_rc --changed src/greet.ts)
has "$out" "the map IS the gate" "8a a missing map refuses to guess"
[ "$rc" != 0 ] && ok "8b a missing map exits non-zero" || bad "8b expected non-zero exit" "got $rc"
mv "$ROOT/map.hidden" "$ROOT/repo/tools/suite-map.tsv"

echo
# --- the FULL gate wrapper ----------------------------------------------------------------------------
# tools/full-gate.sh is what the merger and CI run, so its two steps are exercised here with stub commands.
# The *_CMD overrides are captured before tools/gate.conf is sourced, precisely so a probe can do this.
FULL="$ROOT/repo/tools/full-gate.sh"
full_run() { ( cd "$ROOT/repo" && STATIC_CMD="$1" FULL_TIER_CMD="$2" bash "$FULL" 2>&1 ); }
full_rc() { ( cd "$ROOT/repo" && STATIC_CMD="$1" FULL_TIER_CMD="$2" bash "$FULL" >/dev/null 2>&1 ); echo $?; }

echo "full-gate: step wiring"
out=$(full_run "echo static-ok" "echo tests-ok"); rc=$(full_rc "echo static-ok" "echo tests-ok")
has "$out" "static-ok" "9a the full gate runs the static step"
has "$out" "tests-ok" "9b ... and the test tier"
has "$out" "full gate: PASS" "9c the full gate reports PASS when both steps pass"
[ "$rc" = 0 ] && ok "9d ... and exits 0" || bad "9d expected exit 0" "got $rc"

out=$(full_run "exit 1" "echo tests-still-ran"); rc=$(full_rc "exit 1" "echo tests-still-ran")
has "$out" "tests-still-ran" "9e a failing static step does not skip the test tier"
has "$out" "full gate: FAIL" "9f ... and the gate reports FAIL"
[ "$rc" != 0 ] && ok "9g ... and exits non-zero" || bad "9g expected non-zero exit" "got $rc"

out=$(full_run "echo static-ok" "exit 1"); rc=$(full_rc "echo static-ok" "exit 1")
has "$out" "full gate: FAIL" "9h a failing test tier fails the gate"
[ "$rc" != 0 ] && ok "9i ... and exits non-zero" || bad "9i expected non-zero exit" "got $rc"

echo
# --- 10. STAGED changes count as changes (the selector's own false-green bug, measured 2026-10-12) ------
# The bare `git diff --name-only` compares the worktree against the INDEX, so a change that has been
# `git add`-ed is invisible to it AND to `$MB..HEAD` — the gate then printed "no suites affected by 0
# changed file(s)" and exited 0 with a real change sitting in the tree. This stub repo is turned into a git
# repo with a `main` branch so the no-`--changed` path is exercised end to end.
git -C "$ROOT/repo" init -q -b main
git -C "$ROOT/repo" -c user.email=t@example.com -c user.name=t add -A
git -C "$ROOT/repo" -c user.email=t@example.com -c user.name=t commit -qm base
echo "// staged edit" >> "$ROOT/repo/main.ts"
git -C "$ROOT/repo" add main.ts
out=$( cd "$ROOT/repo" && FAST_GATE_RUNNER="$FAST_GATE_RUNNER" RUN_LOG="$RUN_LOG" STUB_FAIL=0 bash "$GATE" 2>&1 )
rc=$( cd "$ROOT/repo" && FAST_GATE_RUNNER="$FAST_GATE_RUNNER" RUN_LOG="$RUN_LOG" STUB_FAIL=0 bash "$GATE" >/dev/null 2>&1; echo $? )
has "$out" "fast-gate: running: tests/unit/feed.test.ts" "10a a staged change still selects its suites"
hasnt "$out" "fast-gate: no suites affected" "10b a staged change is not reported as nothing affected"
[ "$rc" = 0 ] && ok "10c the staged-change run exits 0" || bad "10c expected exit 0" "got $rc"

echo
if [ "$FAIL" -eq 0 ]; then
  echo "fast-gate tests: $PASS passed, 0 failed"
  exit 0
fi
echo "fast-gate tests: $PASS passed, $FAIL FAILED"
for t in "${FAILED[@]}"; do echo "  FAILED: $t"; done
exit 1
