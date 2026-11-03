#!/usr/bin/env bash
# tools/live-drive.test.sh — the live parity drive's own suite (full-rss-u48).
#
# Why this file exists: tools/suite-map.tsv exempted tools/live-drive.sh because it needs the real network
# ("correctness is witnessed by running it, not by a suite"), and that exemption cost us: six defects in the
# tool were found by reviewers READING it - drivers written into the tree being driven (full-rss-ua2), a
# baseline snapshot whose sha marker lived somewhere else (also ua2), a run that exited 0 with zero article
# expansion (full-rss-cno), `cut` handed a sha as a filename (ua2), two runs interleaving one evidence
# directory (ua2), and `git archive` reading the caller's repo (full-rss-vek). Not one of those needed the
# network: the drive shells out to `deno run`, so a STUB deno on PATH exercises the whole script offline,
# and each defect above becomes a one-line assertion.
#
# The stub answers the two things the drive runs - the driver (an RSS document + STATUS:200 on stderr) and
# the index page (HTML) - and the run happens in a throwaway git tree so `git archive origin/main` is real.
#
# Self-contained: no network, no Deno, no state outside mktemp. Run it directly:
#
#   bash tools/live-drive.test.sh
set -uo pipefail
HERE=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
DRIVE="$HERE/live-drive.sh"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s\n      %s\n' "$1" "${2:-}"; }
# has/equal take the observed value first so a failure prints what was actually seen.
has()   { grep -qF -- "$2" <<<"$1" && ok "$3" || bad "$3" "expected to find [$2] in: $1"; }
hasnt() { grep -qF -- "$2" <<<"$1" && bad "$3" "expected NOT to find [$2] in: $1" || ok "$3"; }
is()    { [ "$1" = "$2" ] && ok "$3" || bad "$3" "expected [$2], got [$1]"; }

[ -f "$DRIVE" ] || { echo "no $DRIVE" >&2; exit 1; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
BIN="$TMP/bin"; mkdir -p "$BIN"

# The stub: EXPAND=1 makes the served document carry converted article text (what a working expansion
# produces), EXPAND=0 leaves content:encoded empty (a passthrough). STUB_SLEEP holds the run open for the
# TERM and concurrency tests.
cat >"$BIN/deno" <<'STUB'
#!/usr/bin/env bash
[ -n "${STUB_SLEEP:-}" ] && sleep "$STUB_SLEEP"
if [[ "$*" == *home.ts* ]]; then
  printf '<!doctype html><title>Full Feed RSS</title>'
  exit 0
fi
if [ "${EXPAND:-0}" = 1 ]; then body='<content:encoded>ARTICLE TEXT</content:encoded>'
else body='<content:encoded></content:encoded>'; fi
printf '<rss><item>%s</item><item><content:encoded></content:encoded></item></rss>' "$body"
echo "STATUS:200" >&2
STUB
chmod +x "$BIN/deno"

# A throwaway tree that looks drivable: the snapshot validation insists on server.ts/deno.json/deno.lock,
# and `git -C "$THIS_TREE" archive origin/main` needs a real repo with a real remote ref.
new_tree() { # dir [with-files]
  local d=$1
  mkdir -p "$d/tools"
  cp "$DRIVE" "$d/tools/live-drive.sh"
  if [ "${2:-yes}" = yes ]; then
    : >"$d/server.ts"; echo '{}' >"$d/deno.json"; echo '{}' >"$d/deno.lock"
  fi
  git -C "$d" init -q .
  git -C "$d" add -A
  git -C "$d" -c user.email=t@t -c user.name=t commit -qm base
  git -C "$d" update-ref refs/remotes/origin/main HEAD
}

# Run the drive with the stub on PATH, always from $TMP (a directory that is NOT the tree), because the
# caller's cwd is what used to decide which repository got archived.
drive() { # tree outdir [env...]
  local tree=$1 out=$2; shift 2
  # `env` applies the caller's VAR=VALUE arguments to the drive; without it bash would try to run
  # "EXPAND=1" as a command word.
  ( cd "$TMP" && PATH="$BIN:$PATH" FULL_RSS_LIVE_DRIVE_OUT="$out" \
      env "$@" bash "$tree/tools/live-drive.sh" 2>&1 )
}

printf '=== a working drive passes, and says what it proved\n'
A="$TMP/a"; new_tree "$A"
out=$(drive "$A" "$TMP/oa" EXPAND=1); rc=$?
is "$rc" "0" "an expanding drive exits 0"
has "$out" "PARITY: served documents identical" "it reports parity"
has "$out" "EXPANSION: content:encoded" "it reports the expansion it measured"
has "$out" "DONE" "it reaches DONE"

printf '=== zero article expansion FAILS the drive instead of passing as a passthrough\n'
out=$(drive "$A" "$TMP/ob" EXPAND=0); rc=$?
is "$rc" "1" "a drive with no expansion exits 1 (full-rss-cno)"
has "$out" "FAIL: no real article expansion" "it says the documents are a passthrough"

printf '=== the tool writes nothing into the tree it drives (full-rss-ua2)\n'
is "$(git -C "$A" status --porcelain | tr -d '\n')" "" "the driven tree is still clean afterwards"
is "$(ls "$A"/live-drive-*.ts 2>/dev/null | wc -l | tr -d ' ')" "0" "no driver script is left in the tree"
is "$(ls "$TMP"/oa/*.ts 2>/dev/null | wc -l | tr -d ' ')" "0" "no driver left in the output directory either"

printf '=== the tool writes nothing into the tree WHILE it runs (full-rss-ua2)\n'
# Asserted MID-RUN, not afterwards: the pre-fix tool created its driver inside the tree and removed it on
# the way out, so a check taken after a normal run passes on code that writes into the tree. Holding the
# stub open is what makes the window observable - and a SIGKILL in that window (the reaper's) is exactly
# how a file used to get stranded.
# The drive has TWO phases and only the second one drives THIS tree, so the sample has to land after the
# first phase's stub returns: STUB_SLEEP=3, sample at 4s.
# setsid gives the drive its own process GROUP, so ending it below ends the stub's sleep too - a bare
# `kill $pid` leaves that sleep orphaned and the runner waiting on the pipe it still holds.
setsid env STUB_SLEEP=3 PATH="$BIN:$PATH" FULL_RSS_LIVE_DRIVE_OUT="$TMP/oc" \
  bash "$A/tools/live-drive.sh" >/dev/null 2>&1 &
mid=$!
sleep 4
is "$(ls "$A"/live-drive-*.ts 2>/dev/null | wc -l | tr -d ' ')" "0" "no driver script exists in the tree mid-run"
is "$(git -C "$A" status --porcelain | tr -d '\n')" "" "the tree is untouched mid-run"
kill -TERM -"$mid" 2>/dev/null; wait "$mid" 2>/dev/null
is "$(ls "$TMP"/oc/*.ts 2>/dev/null | wc -l | tr -d ' ')" "0" "the trap removed the driver from OUT on TERM"

printf '=== two drives cannot interleave one evidence directory (full-rss-ua2)\n'
setsid env STUB_SLEEP=10 PATH="$BIN:$PATH" FULL_RSS_LIVE_DRIVE_OUT="$TMP/od" \
  bash -c "cd '$TMP' && bash '$A/tools/live-drive.sh'" >/dev/null 2>&1 &
holder=$!
sleep 1
out=$(STUB_SLEEP=1 drive "$A" "$TMP/od"); rc=$?
# End the holder rather than waiting out its stub holds: an assertion is not worth 20s of gate time.
kill -TERM -"$holder" 2>/dev/null; wait "$holder" 2>/dev/null || true
is "$rc" "2" "the second drive refuses while the first holds the lock"
has "$out" "another live drive is already running" "and says why"

printf '=== the baseline is snapshotted from THIS tree, not from the caller cwd, and refreshed when main moves\n'
out=$(drive "$A" "$TMP/oe" EXPAND=1); rc=$?
old_sha=$(git -C "$A" rev-parse --short=12 origin/main)
has "$out" "baseline: origin/main $old_sha" "the evidence names the sha it snapshotted"
git -C "$A" -c user.email=t@t -c user.name=t commit -q --allow-empty -m moved
git -C "$A" update-ref refs/remotes/origin/main HEAD
new_sha=$(git -C "$A" rev-parse --short=12 origin/main)
out=$(drive "$A" "$TMP/oe" EXPAND=1); rc=$?
is "$rc" "0" "the drive still passes after origin/main moves"
has "$out" "baseline: origin/main $new_sha" "a moved origin/main forces a fresh snapshot (no stale baseline)"
hasnt "$out" "baseline: origin/main $old_sha" "the old sha is not reused"

printf '=== a snapshot that cannot drive fails loudly, at the snapshot, not 40 lines later\n'
B="$TMP/b"; new_tree "$B" no   # committed without server.ts/deno.json/deno.lock
out=$(drive "$B" "$TMP/of" EXPAND=1); rc=$?
is "$rc" "2" "a snapshot without the modules exits 2"
has "$out" "baseline snapshot of" "it names the snapshot as the problem"
has "$out" "has no server.ts" "and names the file that is missing"

printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
