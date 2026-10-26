#!/usr/bin/env bash
# tools/single-egress.sh — the single-egress invariant, enforced rather than described (full-rss-sc4).
#
# egress.ts is the ONLY place this service may reach the network (full-rss-apm): it is what applies the
# private/reserved-target policy, the per-hop redirect re-validation and the byte caps. A stray `fetch(` in
# server.ts or feed.ts would bypass all of it, and no test would necessarily notice, because a stubbed
# globalThis.fetch in a suite makes the bypass look like working code. So the invariant gets a check:
# outside egress.ts, reaching the network is a build failure.
#
# WHAT "REACHING THE NETWORK" MEANS, and why it is not one pattern. Deno exposes several outbound entry
# points, and a detector that knew only one spelling was the bug this file's header used to have
# (full-rss-bm0: Deno.connect and a destructured `const { fetch: f } = globalThis` both passed). Three rules,
# all of them cheap and all in the fail-loud direction:
#
#   1. THE PLATFORM FETCH, spelled the ways TypeScript can reach it: `fetch(` as a call, fetch passed as a
#      value (`= fetch`, `(fetch)`, `[fetch`, `fn(fetch)`), the indirect `globalThis.fetch` / `self.fetch` /
#      `window.fetch` / `globalThis["fetch"]`, and a DESTRUCTURING or rename of it
#      (`const { fetch: f } = globalThis`), which is the spelling a rename slips through.
#   2. THE OTHER OUTBOUND APIs: `Deno.connect`/`connectTls` (raw TCP/TLS), `Deno.createHttpClient`,
#      `new WebSocket(`/`new EventSource(`/`new XMLHttpRequest(`, and `node:http(s)`/`net`/`tls`/`dgram`/`http2`
#      imports. These are few, stable, and every one of them bypasses egress.ts exactly as a stray fetch does.
#      `Deno.resolveDns` is on the list too: it is not a request, but it is the DNS half of the policy and the
#      only legitimate caller is egress.ts.
#   3. INBOUND LISTENERS, `Deno.serve`/`Deno.listen`, are allowed in server.ts and nowhere else: a second
#      listener is a second service, and it would not be going through the request path either.
#
# SCOPE. Every `*.ts` file in the tree except two, where a reference is legitimate:
#   * egress.ts itself, the one implementation;
#   * tests/**, which replace globalThis.fetch with a stub on purpose (that is how the suites stay offline).
# A `.ts` file under tools/ is checked too - the rule is cheap to satisfy and there is no reason to carve out
# a second allowlist that could quietly grow to hide the thing it exists to catch.
#
# TWO DELIBERATE LIMITS, both in the "fail loudly" direction:
#   * whole-line comments are skipped, so documentation may discuss the fetch it forbids - but a TRAILING
#     comment that spells `fetch(` still fails its line. Rewording such a comment is cheaper than a checker
#     clever enough to parse TypeScript.
#   * a string literal containing `fetch(` fails too. No such string should exist in this service.
#   * it is a grep, not a type-checker: an identifier assembled at runtime (`globalThis["fet" + "ch"]`) or
#     reached through a variable assigned elsewhere is out of reach. The claim this file makes is therefore
#     "these spellings fail", not "no other network path can exist" - THREAT_MODEL.md says the same
#     (full-rss-bm0).
#
# Usage: bash tools/single-egress.sh [root]        exit 0 = invariant holds, 1 = a reference was found
set -uo pipefail

HERE=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
ROOT=${1:-$(cd "$HERE/.." && pwd)}
EGRESS="$ROOT/egress.ts"

[ -d "$ROOT" ] || { echo "single-egress: no such directory: $ROOT" >&2; exit 1; }

# The platform fetch, spelled the ways TypeScript can reach it. Kept as one pattern so tools/single-egress.test.sh
# can prove each alternative fires - a lint nobody exercised is a lint that fails open.
PATTERN='(^|[^A-Za-z0-9_$.])fetch\(|(self|window|globalThis)[[:space:]]*(\.[[:space:]]*fetch|\[[[:space:]]*["'\'']fetch["'\''])|=[[:space:]]*fetch[[:space:]]*[;,)]|[(,][[:space:]]*fetch[[:space:]]*[),]|\{[^{}]*\bfetch\b[^{}]*\}[[:space:]]*=[^=]'

# The other ways out, and the DNS half of the policy. `node:` imports are matched on the specifier so
# `import("node:http")` and `new (await import("node:net"))` both count.
NETWORK_PATTERN='Deno\.(connect|connectTls|createHttpClient|resolveDns)[[:space:]]*\(|new[[:space:]]+(WebSocket|EventSource|XMLHttpRequest)[[:space:]]*\(|(^|[^A-Za-z0-9_$.])(WebSocket|EventSource)\(|["'\'']node:(http|https|http2|net|tls|dgram)["'\'']'

# Inbound listeners: legitimate in server.ts and nowhere else.
INBOUND_PATTERN='Deno\.(serve|listen)(Tls)?[[:space:]]*\('
INBOUND_ALLOWED="$ROOT/server.ts"

violations=0
report() { # $1 = file, $2 = line text, $3 = message
  echo "single-egress: ${1#"$ROOT"/}:$2" >&2
  [ -n "$3" ] && echo "single-egress:   $3" >&2
  violations=$((violations + 1))
}

while IFS= read -r -d '' file; do
  [ "$file" = "$EGRESS" ] && continue
  while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    report "$file" "$hit" "the platform fetch lives in egress.ts"
  done < <(
    grep -nvE '^[[:space:]]*(//|/\*|\*)' "$file" 2>/dev/null |
      grep -E "$PATTERN" |
      sed 's|^\([0-9]*\):|\1:|'
  )
  while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    report "$file" "$hit" "route it through egress.ts (guardedFetch/parseFetchableUrl)"
  done < <(
    grep -nvE '^[[:space:]]*(//|/\*|\*)' "$file" 2>/dev/null |
      grep -E "$NETWORK_PATTERN" |
      sed 's|^\([0-9]*\):|\1:|'
  )
  if [ "$file" != "$INBOUND_ALLOWED" ]; then
    while IFS= read -r hit; do
      [ -z "$hit" ] && continue
      report "$file" "$hit" "listeners belong in server.ts"
    done < <(
      grep -nvE '^[[:space:]]*(//|/\*|\*)' "$file" 2>/dev/null |
        grep -E "$INBOUND_PATTERN" |
        sed 's|^\([0-9]*\):|\1:|'
    )
  fi
done < <(
  find "$ROOT" -name '*.ts' -type f \
    -not -path '*/.git/*' -not -path '*/node_modules/*' -not -path "$ROOT/tests/*" \
    -print0 | sort -z
)

if [ "$violations" -ne 0 ]; then
  echo "single-egress: FAIL — $violations network reference(s) outside egress.ts;" >&2
  echo "single-egress: route the request through guardedFetch/parseFetchableUrl instead (full-rss-apm)." >&2
  exit 1
fi
echo "single-egress: ok — no platform fetch or other network entry point outside egress.ts"
