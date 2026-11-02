#!/usr/bin/env bash
# live-drive.sh — drive the REAL request path with REAL network for one public upstream feed, in two
# trees, and diff the served documents: the canonical checkout (origin/main, pre-refresh) against this
# tree. Written for the dependency refresh (full-rss-vek) so every future refresh can rerun it.
#
# The driver imports `handleRequest` — the boundary the integration suite already treats as the HTTP
# contract — rather than binding a socket: Deno.serve's default port (:8000) is fleet/vmui's on this VM,
# and the socket layer is Deno core, which a lockfile change cannot alter. Everything a dependency can
# change (feed parse, egress-guarded article expansion, sanitize, export, serialization) runs for real,
# with the process's own fetch, no stubs.
#
# Neither tree is written to: each gets a temp driver file, removed on exit; caches and KV go to DENO_DIR.
set -uo pipefail

THIS_TREE="$(cd "$(dirname "$0")/.." && pwd)"
# The baseline tree is a THROWAWAY snapshot of origin/main in /tmp (full-rss-ryg): never the canonical
# checkout ~/full-rss - no lane writes there, not even a temp file - and never a worktree (that would
# write worktree metadata into the shared .git). git archive reads objects only.
BASELINE=/tmp/full-rss-live-drive/baseline
FEED_URL="https://cdn.jsdelivr.net/gh/PaulKinlan/full-rss@8f51a8c62a1b50dc9c08a09d5b714bae93f862fd/tests/fixtures/live-drive-feed.xml" # this repo's fixture at the pinned sha, via jsDelivr: byte-stable, 2 items, 1 expansion
OUT=/tmp/full-rss-live-drive
mkdir -p "$OUT"

# Cleanup is a trap, not the happy path (full-rss-ryg): a bound that kills the drive mid-run (or any
# crash) must not leave the driver scripts behind in the trees it used. Only THIS_TREE can hold one
# after the baseline move - the baseline is /tmp and disposable either way - but the rm is cheap and
# unconditional. INT/TERM run it too: bash does not run the EXIT handler on a signal by itself.
trap 'rm -f "$THIS_TREE/live-drive-driver.ts" "$THIS_TREE/live-drive-home.ts"' INT TERM EXIT

if [ ! -d "$BASELINE" ]; then
  mkdir -p "$BASELINE"
  # git -C THIS_TREE: the script is launched from the caller's cwd (a detached gate's is not the repo),
  # and a failed archive into the pipe silently left an EMPTY baseline behind - the drive then died on
  # a missing server.ts (full-rss-vek). archive reads objects only, so -C does not touch any tree.
  git -C "$THIS_TREE" archive origin/main | tar -x -C "$BASELINE" \
    || { echo "FAIL: the baseline snapshot failed"; exit 2; }
fi

# The self-expansion refusal needs the service to know its own origins (full-rss-7mo): unset, the
# service fail-closes rather than guess its identity from the client-chosen Host header. Both trees
# get the same value - it only identifies the service, no request in this drive targets it.
export FULL_RSS_SELF_HOSTS="localhost"

# The driver: real handleRequest, real fetch, no stubs. The service logs its progress on the console
# (server.ts console.log), and this driver's stdout must carry ONLY the document for the parity diff,
# so every console channel is routed to stderr first. Untracked in whichever tree runs it.
make_driver() { # tree
  cat > "$1/live-drive-driver.ts" <<'EOF'
import { handleRequest } from "./server.ts";
const toStderr = (...args: unknown[]) => {
  Deno.stderr.writeSync(new TextEncoder().encode(args.map(String).join(" ") + "\n"));
};
console.log = toStderr;
console.info = toStderr;
console.warn = toStderr;
console.error = toStderr;
const feedUrl = Deno.args[0];
const res = await handleRequest(
  new Request(`http://localhost/?url=${encodeURIComponent(feedUrl)}`),
);
Deno.stderr.writeSync(new TextEncoder().encode(`STATUS:${res.status}\n`));
Deno.stdout.write(new Uint8Array(await res.arrayBuffer()));
EOF
}

drive() { # tree outfile
  make_driver "$1" || return 1
  (
    cd "$1" || exit 1
    deno run --allow-net --allow-env --unstable-kv live-drive-driver.ts "$FEED_URL" \
      > "$2" 2> "$2.err"
  )
  local rc=$?
  rm -f "$1/live-drive-driver.ts"
  if [ $rc -ne 0 ]; then
    echo "FAIL: drive of $1 exited $rc:"; tail -5 "$2.err"
    return 1
  fi
  grep -q "^STATUS:200$" "$2.err" || { echo "FAIL: $1 answered $(head -1 "$2.err" | head -c 120)"; return 1; }
  return 0
}

echo "== driving the PRE-refresh baseline (origin/main snapshot) from $BASELINE"
drive "$BASELINE" "$OUT/old-feed.xml" || exit 2
echo "== driving the REFRESHED tree (this branch) from $THIS_TREE"
drive "$THIS_TREE" "$OUT/new-feed.xml" || exit 2

echo "== index page (refreshed tree)"
cat > "$THIS_TREE/live-drive-home.ts" <<'EOF'
import { handleRequest } from "./server.ts";
const res = await handleRequest(new Request("http://localhost/"));
Deno.stdout.write(new Uint8Array(await res.arrayBuffer()));
EOF
(
  cd "$THIS_TREE"
  deno run --allow-net --allow-env live-drive-home.ts > "$OUT/new-home.html" 2> "$OUT/new-home.err"
)
rm -f "$THIS_TREE/live-drive-driver.ts" "$THIS_TREE/live-drive-home.ts"
if [ ! -s "$OUT/new-home.html" ]; then
  echo "FAIL: index page empty:"; tail -3 "$OUT/new-home.err"; exit 1
fi

echo "== evidence"
old_items=$(grep -c '<item>' "$OUT/old-feed.xml" || true)
new_items=$(grep -c '<item>' "$OUT/new-feed.xml" || true)
# Expansion evidence = a content:encoded element that actually carries converted article text (the
# builder emits the element for every item, empty when expansion never ran).
old_enc=$(grep -cE '<content:encoded[^>]*>[^<]' "$OUT/old-feed.xml" || true)
new_enc=$(grep -cE '<content:encoded[^>]*>[^<]' "$OUT/new-feed.xml" || true)
echo "old: $old_items items, $old_enc expanded, $(wc -c < "$OUT/old-feed.xml") bytes"
echo "new: $new_items items, $new_enc expanded, $(wc -c < "$OUT/new-feed.xml") bytes"
echo "new index page: $(wc -c < "$OUT/new-home.html") bytes, title: $(grep -o '<title>[^<]*</title>' "$OUT/new-home.html" | head -1)"

# Known output deltas are normalized before the diff, each announced: lastBuildDate and the item
# pubDate fallback are request-time (the fixture's items carry no dates); <language> and <generator>
# are library defaults that @feed/feed 1.3.0 changed (en -> en-US, new generator string); the root
# element's xmlns layout went multi-line with an added xmlns:media. Everything else must be identical.
normalize() {
  sed -z -E 's#<rss[^>]*>#<rss/>#g; s#<lastBuildDate>[^<]*</lastBuildDate>#<lastBuildDate/>#g; s#<pubDate>[^<]*</pubDate>#<pubDate/>#g; s#<language>[^<]*</language>#<language/>#g; s#<generator>[^<]*</generator>#<generator/>#g' "$1" | tr -d '\000'
}
if diff <(normalize "$OUT/old-feed.xml") <(normalize "$OUT/new-feed.xml") > "$OUT/feed.diff"; then
  echo "PARITY: served documents identical (modulo lastBuildDate)"
else
  echo "DIFF (first 60 lines):"
  head -60 "$OUT/feed.diff"
  exit 1
fi

# Expansion actually happened on BOTH trees (a real article fetch + conversion, not a passthrough).
# Zero expansions used to print a WARN and exit 0 - a false green (full-rss-vek, coord 2026-11-02):
# parity of a passthrough document proves nothing about the parse -> egress -> sanitize -> convert ->
# export path this drive exists to witness, so a drive without expansion evidence FAILS loudly and
# the operator picks a fixture with an expandable item.
if [ "${old_enc:-0}" -ge 1 ] && [ "${new_enc:-0}" -ge 1 ]; then
  echo "EXPANSION: content:encoded present on both trees"
else
  echo "FAIL: no real article expansion (old=${old_enc:-0}, new=${new_enc:-0}) - a passthrough-only parity witnesses nothing"
  exit 1
fi
echo "DONE"
