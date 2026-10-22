#!/usr/bin/env bash
# tools/single-egress.sh — the single-egress invariant, enforced rather than described (full-rss-sc4).
#
# egress.ts is the ONLY place this service may reach the network (full-rss-apm): it is what applies the
# private/reserved-target policy, the per-hop redirect re-validation and the byte caps. A stray `fetch(` in
# server.ts or feed.ts would bypass all of it, and no test would necessarily notice, because a stubbed
# globalThis.fetch in a suite makes the bypass look like working code. So the invariant gets a check:
# outside egress.ts, a reference to the platform fetch is a build failure.
#
# SCOPE. Every `*.ts` file in the tree except two, where a fetch reference is legitimate:
#   * egress.ts itself, the one implementation;
#   * tests/**, which replace globalThis.fetch with a stub on purpose (that is how the suites stay offline).
# A `.ts` file under tools/ is checked too - the rule is cheap to satisfy and there is no reason to carve out
# a second allowlist that could quietly grow to hide the thing it exists to catch.
#
# WHAT COUNTS AS A REFERENCE. `fetch(` as a call, fetch passed as a value (`= fetch`, `(fetch)`, `[fetch`, a
# `fn(fetch)` argument), and the indirect spellings `globalThis.fetch`, `self.fetch`, `window.fetch` and
# `globalThis["fetch"]`. `guardedFetch(`, `fetchContent(` and `parseFetchableUrl(` are different identifiers
# and do not match; `.fetch(` on any other object is somebody else's method, not the platform's.
#
# TWO DELIBERATE LIMITS, both in the "fail loudly" direction:
#   * whole-line comments are skipped, so documentation may discuss the fetch it forbids - but a TRAILING
#     comment that spells `fetch(` still fails its line. Rewording such a comment is cheaper than a checker
#     clever enough to parse TypeScript.
#   * a string literal containing `fetch(` fails too. No such string should exist in this service.
#
# Usage: bash tools/single-egress.sh [root]        exit 0 = invariant holds, 1 = a reference was found
set -uo pipefail

HERE=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
ROOT=${1:-$(cd "$HERE/.." && pwd)}
EGRESS="$ROOT/egress.ts"

[ -d "$ROOT" ] || { echo "single-egress: no such directory: $ROOT" >&2; exit 1; }

# The platform fetch, spelled the ways TypeScript can reach it. Kept as one pattern so tools/single-egress.test.sh
# can prove each alternative fires - a lint nobody exercised is a lint that fails open.
PATTERN='(^|[^A-Za-z0-9_$.])fetch\(|(self|window|globalThis)[[:space:]]*(\.[[:space:]]*fetch|\[[[:space:]]*["'\'']fetch["'\''])|=[[:space:]]*fetch[[:space:]]*[;,)]|[(,][[:space:]]*fetch[[:space:]]*[),]'

violations=0
while IFS= read -r -d '' file; do
  [ "$file" = "$EGRESS" ] && continue
  while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    echo "single-egress: ${hit#"$ROOT"/}" >&2
    violations=$((violations + 1))
  done < <(
    grep -nvE '^[[:space:]]*(//|/\*|\*)' "$file" 2>/dev/null |
      grep -E "$PATTERN" |
      sed "s|^|$file:|"
  )
done < <(
  find "$ROOT" -name '*.ts' -type f \
    -not -path '*/.git/*' -not -path '*/node_modules/*' -not -path "$ROOT/tests/*" \
    -print0 | sort -z
)

if [ "$violations" -ne 0 ]; then
  echo "single-egress: FAIL — $violations platform-fetch reference(s) outside egress.ts;" >&2
  echo "single-egress: route the request through guardedFetch/parseFetchableUrl instead (full-rss-apm)." >&2
  exit 1
fi
echo "single-egress: ok — no platform fetch outside egress.ts"
