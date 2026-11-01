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
set -u

THIS_TREE="$(cd "$(dirname "$0")/.." && pwd)"
OLD_TREE="/home/exedev/full-rss" # canonical checkout at origin/main (read-only use: run only)
FEED_URL="https://paul.kinlan.me/tags/ai/index.xml" # 8 light static items, fast host: 10s feed cap + 8 short expansions fit the 30s whole-request budget under load
OUT=/tmp/full-rss-live-drive
mkdir -p "$OUT"

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

echo "== driving the PRE-refresh tree (origin/main) from $OLD_TREE"
drive "$OLD_TREE" "$OUT/old-feed.xml" || exit 2
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
  deno run --allow-net live-drive-home.ts > "$OUT/new-home.html" 2>/dev/null
)
rm -f "$THIS_TREE/live-drive-driver.ts" "$THIS_TREE/live-drive-home.ts"

echo "== evidence"
old_items=$(grep -c '<item>' "$OUT/old-feed.xml" || true)
new_items=$(grep -c '<item>' "$OUT/new-feed.xml" || true)
old_enc=$(grep -c '<content:encoded' "$OUT/old-feed.xml" || true)
new_enc=$(grep -c '<content:encoded' "$OUT/new-feed.xml" || true)
echo "old: $old_items items, $old_enc expanded, $(wc -c < "$OUT/old-feed.xml") bytes"
echo "new: $new_items items, $new_enc expanded, $(wc -c < "$OUT/new-feed.xml") bytes"
echo "new index page: $(wc -c < "$OUT/new-home.html") bytes, title: $(grep -o '<title>[^<]*</title>' "$OUT/new-home.html" | head -1)"

normalize() { sed -E 's#<lastBuildDate>[^<]*</lastBuildDate>#<lastBuildDate/>#g' "$1"; }
if diff <(normalize "$OUT/old-feed.xml") <(normalize "$OUT/new-feed.xml") > "$OUT/feed.diff"; then
  echo "PARITY: served documents identical (modulo lastBuildDate)"
else
  echo "DIFF (first 60 lines):"
  head -60 "$OUT/feed.diff"
  exit 1
fi

# Expansion actually happened on the refreshed tree (a real article fetch + conversion, not a passthrough).
if [ "${new_enc:-0}" -gt 0 ] && [ "$(wc -c < "$OUT/new-feed.xml")" -gt 20000 ]; then
  echo "EXPANSION: content:encoded present on the refreshed tree"
else
  echo "WARN: no expansion evidence on the refreshed tree (upstream may have had no expandable items)"
fi
echo "DONE"
