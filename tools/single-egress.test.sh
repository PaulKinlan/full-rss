#!/usr/bin/env bash
# tools/single-egress.test.sh — the single-egress lint's own suite (full-rss-sc4).
#
# Why this file exists: a lint that cannot fail is not a lint. tools/single-egress.sh is the only thing
# standing between a stray `fetch(` and the egress policy in egress.ts, so its DETECTOR is tested against
# fixtures - one per spelling it claims to catch - and against the spellings it must not catch, so it cannot
# turn into a permanent red that everybody learns to ignore. It also runs the check against this repo: the
# invariant is asserted where it matters, not only in a fixture.
#
# Self-contained: no network, no git state, fixtures in a throwaway directory. Run it directly:
#
#   bash tools/single-egress.test.sh
set -uo pipefail
HERE=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s\n      %s\n' "$1" "${2:-}"; }
has()   { grep -qF -- "$2" <<<"$1" && ok "$3" || bad "$3" "expected to find: $2"; }
hasnt() { grep -qF -- "$2" <<<"$1" && bad "$3" "expected NOT to find: $2" || ok "$3"; }

CHECK="$HERE/single-egress.sh"
[ -f "$CHECK" ] || { echo "no $CHECK" >&2; exit 1; }

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

printf '=== the invariant holds in this repo\n'
out=$(bash "$CHECK" "${HERE%/tools}" 2>&1); rc=$?
[ "$rc" -eq 0 ] && ok "the checked-in tree has no platform fetch outside egress.ts" \
  || bad "the checked-in tree has no platform fetch outside egress.ts" "$out"
has "$out" "single-egress: ok" "it says so"

printf '=== every spelling it claims to catch, one fixture per spelling\n'
fixture="$TMP/violations"; mkdir -p "$fixture"
# Each line is a separate spelling from the script's header comment; all of them must be reported.
cat >"$fixture/calls.ts" <<'EOF'
const a = await fetch("https://example.com/a");
const b = fetch;
someClient(a, fetch);
const c = globalThis.fetch;
const d = self.fetch;
const e = window.fetch;
const f = globalThis["fetch"];
EOF
out=$(bash "$CHECK" "$fixture" 2>&1); rc=$?
[ "$rc" -eq 1 ] && ok "a file that reaches the platform fetch fails the check" \
  || bad "a file that reaches the platform fetch fails the check" "exit $rc: $out"
for needle in \
  'calls.ts:1:' 'calls.ts:2:' 'calls.ts:3:' 'calls.ts:4:' 'calls.ts:5:' 'calls.ts:6:' 'calls.ts:7:'; do
  has "$out" "$needle" "line ${needle#calls.ts:} is reported"
done
has "$out" "single-egress: FAIL" "the failure is named"

printf '=== the spellings it must NOT catch\n'
fixture="$TMP/clean"; mkdir -p "$fixture"
cat >"$fixture/clean.ts" <<'EOF'
// fetch( is what egress.ts uses; this module goes through guardedFetch instead.
/*
 * globalThis.fetch is deliberately not used here.
 */
const html = await guardedFetchContent(url);
const parsed = await parseFetchableUrl(url);
const prefetched = awaitingPrefetch(input);
const other = client.fetch.bind(client);
EOF
cat >"$fixture/egress.ts" <<'EOF'
export const fetchUrl = (url: URL) => fetch(url);
EOF
mkdir -p "$fixture/tests"
cat >"$fixture/tests/stub.test.ts" <<'EOF'
globalThis.fetch = ((_input: string) => Promise.resolve(new Response("x"))) as typeof globalThis.fetch;
EOF
out=$(bash "$CHECK" "$fixture" 2>&1); rc=$?
[ "$rc" -eq 0 ] && ok "comment lines, wrappers, other objects' .fetch, egress.ts and tests/ are exempt" \
  || bad "comment lines, wrappers, other objects' .fetch, egress.ts and tests/ are exempt" "exit $rc: $out"

printf '=== the exit code and the message are the contract\n'
out=$(bash "$CHECK" "$TMP/nonexistent" 2>&1); rc=$?
[ "$rc" -eq 1 ] && ok "a missing directory fails rather than passing vacuously" \
  || bad "a missing directory fails rather than passing vacuously" "exit $rc: $out"

printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
