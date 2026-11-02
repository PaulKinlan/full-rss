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
# NEITHER tree is written to at all (full-rss-ua2): the baseline is a /tmp snapshot, and both drivers are
# generated under /tmp too and import server.ts by ABSOLUTE path. Only DENO_DIR (module cache, KV) is touched,
# and that is not inside any checkout. A trap alone would not be enough: it removes the file on the paths that
# emit a signal, but a SIGKILL (the reaper's) runs no handler, and any file left behind is an untracked
# root-level .ts in a checkout - which the fast gate rejects as unmapped and fleet-handoff rejects as dirty.
set -uo pipefail

THIS_TREE="$(cd "$(dirname "$0")/.." && pwd)"
# The baseline tree is a THROWAWAY snapshot of origin/main in /tmp (full-rss-ryg): never the canonical
# checkout ~/full-rss - no lane writes there, not even a temp file - and never a worktree (that would
# write worktree metadata into the shared .git). git archive reads objects only.
BASELINE=/tmp/full-rss-live-drive/baseline
FEED_URL="https://cdn.jsdelivr.net/gh/PaulKinlan/full-rss@8f51a8c62a1b50dc9c08a09d5b714bae93f862fd/tests/fixtures/live-drive-feed.xml" # this repo's fixture at the pinned sha, via jsDelivr: byte-stable, 2 items, 1 expansion
OUT=${FULL_RSS_LIVE_DRIVE_OUT:-/tmp/full-rss-live-drive}  # overridable so the drive can be exercised with a stub deno, no network
mkdir -p "$OUT"

# Cleanup is a trap, not the happy path: the EXIT handler covers the normal path, and INT/TERM EXIT via
# `exit 143` rather than a bare handler - bash RESUMES after a trapped signal once the handler returns, so a
# handler that only rm's lets a killed drive carry on into the next phase and write a fresh driver behind it.
cleanup() { rm -f "$OUT/driver.ts" "$OUT/home.ts"; }
trap cleanup EXIT
trap 'exit 143' INT TERM

# `git -C THIS_TREE`: the script is launched from the caller's cwd, which a detached gate does not set to the
# repo, and a failed archive into the pipe silently left an EMPTY baseline behind (full-rss-vek).
# The archived sha is recorded and re-snapshotted when origin/main moves: a stale /tmp snapshot would
# otherwise pass a parity check as "current origin/main" long after main had moved on (full-rss-ua2).
BASE_SHA=$(git -C "$THIS_TREE" rev-parse origin/main 2>/dev/null) \
  || { echo "FAIL: $THIS_TREE has no origin/main to snapshot from" >&2; exit 2; }
if [ ! -d "$BASELINE" ] || [ "$(cat "$OUT/baseline-sha" 2>/dev/null)" != "$BASE_SHA" ]; then
  rm -rf "$BASELINE"; mkdir -p "$BASELINE"
  git -C "$THIS_TREE" archive origin/main | tar -x -C "$BASELINE" \
    || { echo "FAIL: the baseline snapshot failed"; exit 2; }
  printf '%s' "$BASE_SHA" > "$OUT/baseline-sha"
fi
echo "baseline: origin/main $(cut -c1-12 "$OUT/baseline-sha") snapshotted at $BASELINE"

# The self-expansion refusal needs the service to know its own origins (full-rss-7mo): unset, the
# service fail-closes rather than guess its identity from the client-chosen Host header. Both trees
# get the same value - it only identifies the service, no request in this drive targets it.
export FULL_RSS_SELF_HOSTS="localhost"

# The driver: real handleRequest, real fetch, no stubs. The service logs its progress on the console
# (server.ts console.log), and this driver's stdout must carry ONLY the document for the parity diff,
# so every console channel is routed to stderr first. It lives in /tmp and imports the tree's server.ts by
# ABSOLUTE path, because the one thing this tool may never do is write into the tree it drives (full-rss-ua2).
# The placeholder is substituted rather than interpolated: the inlined script contains ${...} itself.
make_driver() { # tree
  cat > "$OUT/driver.ts" <<'EOF'
import { handleRequest } from "__TREE__/server.ts";
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
  sed -i "s|__TREE__|$1|" "$OUT/driver.ts"   # '|' because a path may contain '/', and '#' may appear in one
}

drive() { # tree outfile
  make_driver "$1" || return 1
  # One announced retry: this drive's only dependency outside the repo is a public CDN (jsDelivr) for the
  # fixture, and a single egress timeout there makes the run "unknown" rather than "the change broke it".
  # Loud, so a flake can never be mistaken for a pass it did not get.
  local attempt rc
  for attempt in 1 2; do
    # --config/--frozen-lockfile: the entrypoint is in /tmp, so without them the tree's import map (cheerio,
    # marked, @feed/feed) would not resolve and Deno would resolve against no lockfile at all.
    deno run --config "$1/deno.json" --frozen-lockfile \
      --allow-net --allow-env --unstable-kv "$OUT/driver.ts" "$FEED_URL" \
      > "$2" 2> "$2.err"
    rc=$?
    [ $rc -eq 0 ] && grep -q "^STATUS:200$" "$2.err" && return 0
    [ $attempt -eq 1 ] && echo "WARN: attempt 1 against $1 failed ($(drive_detail "$2.err")); retrying once" >&2
  done
  if [ $rc -ne 0 ]; then
    echo "FAIL: drive of $1 exited $rc:"; tail -5 "$2.err"
    return 1
  fi
  echo "FAIL: $1 answered $(drive_detail "$2.err")"
  return 1
}

# The useful line of a failed drive is the STATUS the driver printed last, not the first console line it
# logged: the app logs "Fetching feed from ..." before anything can go wrong (full-rss-ua2).
drive_detail() { # errfile
  local line
  line=$(grep -m1 '^STATUS:' "$1" 2>/dev/null) || line=""
  [ -n "$line" ] || line=$(grep -E '^(Failed|Error)' "$1" 2>/dev/null | tail -1)
  [ -n "$line" ] || line=$(tail -1 "$1" 2>/dev/null)
  printf '%s' "${line:0:200}"
}

echo "== driving the PRE-refresh baseline (origin/main snapshot) from $BASELINE"
drive "$BASELINE" "$OUT/old-feed.xml" || exit 2
echo "== driving the REFRESHED tree (this branch) from $THIS_TREE"
drive "$THIS_TREE" "$OUT/new-feed.xml" || exit 2

echo "== index page (refreshed tree)"
cat > "$OUT/home.ts" <<'EOF'
import { handleRequest } from "__TREE__/server.ts";
const res = await handleRequest(new Request("http://localhost/"));
Deno.stdout.write(new Uint8Array(await res.arrayBuffer()));
EOF
sed -i "s|__TREE__|$THIS_TREE|" "$OUT/home.ts"
deno run --config "$THIS_TREE/deno.json" --frozen-lockfile --allow-net --allow-env "$OUT/home.ts" \
  > "$OUT/new-home.html" 2> "$OUT/new-home.err"
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
