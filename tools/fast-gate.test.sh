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
MAP="$HERE/suite-map.tsv"

# The fixture FOLLOWS this repo's map instead of hardcoding its rows. A map edit - a module split, a new
# module - must not make the gate red for whoever makes it; that is the pathology docs/speed.md names, and
# it is what full-rss-514 was (full-rss-11b rewrote main.ts's row and this fixture still asserted the old
# one, which nobody saw because the gate was not running this suite at all - full-rss-q9q).
row_suites() { awk -F'\t' -v k="$1" '$1 == k { print $2 }' "$MAP" | tr ' ' '\n' | grep -v '^$'; }
# Every path the map names, on both sides, becomes a real file: then `--changed <key>` works for any key and
# the "missing suite" check cannot be tripped by a suite this fixture forgot to invent.
{
  awk -F'\t' '!/^#/ && $1 !~ /^!/ { print $1 }' "$MAP"
  awk -F'\t' '!/^#/ && $1 !~ /^!/ { print $2 }' "$MAP" | tr ' ' '\n' | grep -v '^$'
} | sort -u | while IFS= read -r path; do
  # Never truncate a file that is already there: the map's own keys include tools/fast-gate.sh, gate.conf and
  # full-gate.sh, which the fixture copied a moment ago and cases 7-9 exercise.
  [ -e "$ROOT/repo/$path" ] && continue
  mkdir -p "$ROOT/repo/$(dirname "$path")"
  : > "$ROOT/repo/$path"
done
# Paths the cases below create themselves, plus a stub for the gate's own suite: this fixture is inside the
# repo it tests, so a .sh suite that now really runs must not be the real one (it would recurse).
# `tests/unit/other.test.ts` is deliberately NOT in the map: case 3 uses it to prove that a changed suite maps
# to itself without a row. src/ has to be made here: the loop above creates the directories of the paths the
# MAP names, and src/newmodule.ts is deliberately not one of them (full-rss-4ce - writing to a missing
# directory failed with "No such file or directory" on stderr while the suite still passed).
mkdir -p "$ROOT/repo/src"
: > "$ROOT/repo/src/newmodule.ts"; : > "$ROOT/repo/NOTES.txt"; : > "$ROOT/repo/tests/unit/other.test.ts"
for p in src/newmodule.ts NOTES.txt tests/unit/other.test.ts; do
  [ -e "$ROOT/repo/$p" ] || { echo "fixture: $p was not created - the cases below would test nothing" >&2; exit 1; }
done
cat > "$ROOT/repo/tools/fast-gate.test.sh" <<'STUBGATE'
#!/usr/bin/env bash
echo "STUB-GATE-SUITE ran"
exit 0
STUBGATE
chmod +x "$ROOT/repo/tools/fast-gate.test.sh"
MAIN_SUITES=$(row_suites main.ts)
MAIN_FIRST=$(printf '%s\n' "$MAIN_SUITES" | head -1)
TEMPL_SUITES=$(row_suites templates/index.ts)
TEMPL_FIRST=$(printf '%s\n' "$TEMPL_SUITES" | head -1)
[ -n "$MAIN_FIRST" ] && [ -n "$TEMPL_FIRST" ] || {
  echo "fast-gate tests: the map no longer names main.ts and templates/index.ts; this suite needs both" >&2
  exit 1
}
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

# 1. a mapped source file selects EVERY suite the map names for it, and runs them. Both the selection and
#    the expectations are read from the map, so this case survives a map edit (see row_suites above).
rm -f "$RUN_LOG"
out=$(run --changed main.ts)
rc=$(run_rc --changed main.ts)
while IFS= read -r s; do
  has "$out" "fast-gate: running: $s" "1a main.ts selects $s"
  has "$out" "fast-gate: passed: $s" "1b $s is reported with the positive marker"
done <<< "$MAIN_SUITES"
[ "$rc" = 0 ] && ok "1c exit 0 when every selected suite passes" || bad "1c expected exit 0" "got $rc"

# 1d. and it does not select another module's suite: the map is per-module, not per-directory.
out=$(run --changed templates/index.ts)
has "$out" "fast-gate: running: $TEMPL_FIRST" "1d templates/index.ts selects $TEMPL_FIRST"
if [ "$TEMPL_FIRST" = "$MAIN_FIRST" ]; then
  bad "1e ... and not an unrelated module's suite" "the map names the same suite for both modules"
else
  hasnt "$out" "fast-gate: running: $MAIN_FIRST" "1e ... and not main.ts's suite"
fi

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
has "$out" "$MAIN_FIRST" "5a --list prints the selected suite"
[ ! -s "$RUN_LOG" ] && ok "5b --list runs no suite" || bad "5b --list ran something" "$(cat "$RUN_LOG")"

# 6. a failing suite fails the gate and is not counted as executed.
STUB_FAIL=1
out=$(run --changed main.ts)
rc=$(run_rc --changed main.ts)
has "$out" "fast-gate: failed: $MAIN_FIRST" "6a a failing suite is reported as failed"
hasnt "$out" "fast-gate: passed: $MAIN_FIRST" "6b a failing suite is not also reported as passed"
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
has "$out" "fast-gate: running: $MAIN_FIRST" "10a a staged change still selects its suites"
hasnt "$out" "fast-gate: no suites affected" "10b a staged change is not reported as nothing affected"
[ "$rc" = 0 ] && ok "10c the staged-change run exits 0" || bad "10c expected exit 0" "got $rc"

echo
# --- 11. a suite that is a SHELL SCRIPT is executed, with bash (full-rss-q9q) ----------------------------
# The gate handed every selected suite to FAST_GATE_RUNNER, which is `deno test`: deno is given a shell
# script, runs nothing, exits 0, and the gate printed "passed: tools/fast-gate.test.sh" for a suite it never
# executed. The suite this file belongs to was that suite. A stub .sh suite is added to the fixture's map.
printf 'src/shellsuite.sh\ttests/unit/shellsuite.test.sh\n' >> "$ROOT/repo/tools/suite-map.tsv"
: > "$ROOT/repo/src/shellsuite.sh"
cat > "$ROOT/repo/tests/unit/shellsuite.test.sh" <<'STUB'
#!/usr/bin/env bash
echo "SHELL-SUITE-MARKER"
[ -n "${SHELL_MARKER:-}" ] && echo ran >> "$SHELL_MARKER"
exit "${SHELL_SUITE_RC:-0}"
STUB
rm -f "$RUN_LOG" "$ROOT/shell.marker"
out=$(SHELL_MARKER="$ROOT/shell.marker" run --changed src/shellsuite.sh)
rc=$(SHELL_MARKER="$ROOT/shell.marker" run_rc --changed src/shellsuite.sh)
[ -s "$ROOT/shell.marker" ] && ok "11a a .sh suite is really executed (it wrote its own marker)" \
  || bad "11a a .sh suite is really executed" "the suite did not run"
hasnt "$(cat "$RUN_LOG" 2>/dev/null)" "tests/unit/shellsuite.test.sh" \
  "11b ... and it did NOT go to the test runner"
has "$out" "fast-gate: passed: tests/unit/shellsuite.test.sh" "11c a passing .sh suite is reported as passed"
[ "$rc" = 0 ] && ok "11d ... and the gate exits 0" || bad "11d expected exit 0" "got $rc"
out=$(SHELL_SUITE_RC=1 run --changed src/shellsuite.sh)
rc=$(SHELL_SUITE_RC=1 run_rc --changed src/shellsuite.sh)
has "$out" "fast-gate: failed: tests/unit/shellsuite.test.sh" "11e a failing .sh suite fails the gate"
has "$out" "SHELL-SUITE-MARKER" "11f ... and its log is shown"
[ "$rc" != 0 ] && ok "11g ... and the gate exits non-zero" || bad "11g expected non-zero exit" "got $rc"

echo
# --- 12. a suite that ran NO TESTS is a failure, not a pass (the general form of the bug in 11) ----------
# `deno test` exits 0 for a file with no test cases, so a suite could be added, mapped, executed, and prove
# nothing while the gate called it green. The guard reads the runner's own all-zero summary.
cat > "$ROOT/runner_zero" <<'STUB'
#!/usr/bin/env bash
echo "ok | 0 passed | 0 failed (0ms)"
exit 0
STUB
chmod +x "$ROOT/runner_zero"
: > "$ROOT/repo/tests/unit/zero.test.ts"
zero_run() { ( cd "$ROOT/repo" && FAST_GATE_RUNNER="$1" bash "$GATE" --changed tests/unit/zero.test.ts 2>&1 ); }
zero_rc() { ( cd "$ROOT/repo" && FAST_GATE_RUNNER="$1" bash "$GATE" --changed tests/unit/zero.test.ts >/dev/null 2>&1 ); echo $?; }
out=$(zero_run "$ROOT/runner_zero"); rc=$(zero_rc "$ROOT/runner_zero")
has "$out" "fast-gate: failed: tests/unit/zero.test.ts" "12a a suite that ran no tests fails the gate"
hasnt "$out" "fast-gate: passed: tests/unit/zero.test.ts" "12b ... and is not also reported as passed"
has "$out" "ran no tests" "12c ... and says why"
[ "$rc" != 0 ] && ok "12d ... and exits non-zero" || bad "12d expected non-zero exit" "got $rc"
# The guard is not a blanket failure: a runner reporting real counts is untouched by it.
cat > "$ROOT/runner_some" <<'STUB'
#!/usr/bin/env bash
echo "ok | 3 passed | 0 failed (5ms)"
exit 0
STUB
chmod +x "$ROOT/runner_some"
out=$(zero_run "$ROOT/runner_some")
has "$out" "fast-gate: passed: tests/unit/zero.test.ts" "12e a suite with tests still passes (the guard is not a blanket failure)"

echo
if [ "$FAIL" -eq 0 ]; then
  echo "fast-gate tests: $PASS passed, 0 failed"
  exit 0
fi
echo "fast-gate tests: $PASS passed, $FAIL FAILED"
for t in "${FAILED[@]}"; do echo "  FAILED: $t"; done
exit 1
