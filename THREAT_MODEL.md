# Threat Model — full-rss

full-rss is a Deno HTTP service that takes a requester's `?url=`, fetches that
RSS/Atom feed, fetches each article the feed links to, and returns a new RSS 2.0
document whose items carry the full article content. It runs on Deno Deploy with
`--allow-net --allow-env` and Deno KV for caching.

This document records what the service trusts, what it refuses, and which
residuals are accepted on purpose. The egress design lives in `egress.ts` and is
summarized here so an audit can check the code against an explicit contract
rather than guess it.

## Assets and trust boundaries

- **The host's network position.** The service can reach anything its runtime
  can reach. An attacker who chooses the fetched URLs must not be able to aim it
  at private networks, localhost, link-local or cloud metadata addresses.
- **Requester privacy.** Feed and article URLs can carry API keys in query
  strings or userinfo. Logs must not leak them.
- **Memory and time.** An upstream may answer with an unbounded body, a slow
  stream, or a redirect loop; none may pin the service's memory or a request
  forever. One requester's expansion also may not become unbounded work: a feed
  or article that points back at this service must not make it expand itself.
- **Feed readers' trust in the output.** Everything in the returned document
  that came from the feed publisher — item bodies, summaries, titles, authors —
  is attacker-controlled markup or text. A feed reader renders item HTML; raw
  publisher HTML must not reach it unsanitized.
- **The KV cache.** Cached article content is keyed by URL hash and served back
  to later requesters of the same URL. It holds derived markdown (gzipped),
  never source HTML.

Untrusted inputs: the requester's `?url=`, every byte of every fetched feed and
article (including redirect targets and DNS answers), and feed item metadata.

## Egress architecture (`egress.ts`)

Every outbound fetch — the requester's feed URL and every article link inside a
fetched feed (the second-order SSRF surface) — goes through the same module.
There is no other `fetch` call in the application.

### `parseFetchableUrl` — what may be fetched

Refuses, with `BlockedUrlError` (so callers can answer 403 rather than 500):

- non-`http(s)` schemes;
- URLs carrying credentials (userinfo);
- empty hosts and IPv6 zone identifiers;
- **IP literals in blocked ranges.** `new URL()` canonicalizes the host before
  we see it (`0x7f000001`, `2130706433`, `127.1` all arrive as `127.0.0.1`), so
  only the canonical dotted-quad and IPv6 shapes need parsing. Blocked IPv4:
  `0.0.0.0/8`, `10/8`, `100.64/10`, `127/8`, `169.254/16` (cloud metadata),
  `172.16/12`, `192.0.0/24`, `192.0.2/24`, `192.88.99/24` (6to4 relay anycast),
  `192.168/16`, `198.18/15`, `198.51.100/24`, `203.0.113/24`, `224/4`, `240/4`.
  Blocked IPv6: `::`, `::1`, `100::/64`, `2001:2::/48` (benchmarking),
  `2001:db8::/32`, `fc00::/7`, `fe80::/10`, `fec0::/10` (deprecated site-local),
  `ff00::/8`, and any IPv4-embedded form (mapped `::ffff:0:0/96`, translated
  `::ffff:0:0:0/96`, compatible, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`, Teredo
  `2001::/32`) whose embedded address is blocked. A Teredo address carries the
  client IPv4 in bits 96..127 **inverted** (`2001:0:...:3fff:fdd2` tunnels to
  `192.0.2.45`), so the check complements those bits before classifying them;
  reading them literally would refuse every client below `240.0.0.0/4` (8.8.8.8
  is stored `f7f7:f7f7`) instead of the private ones.
- **names meaning "here"** — `localhost`, `*.localhost`, `local`, `internal` —
  before DNS is consulted;
- **URLs on this service's own host, and on its own addresses.** The caller
  passes `selfOrigins` — the hosts this service answers on — and
  `selfAddresses`, the addresses they resolve to, and any URL matching either is
  refused (`<host>` is this service's own address). This is the
  recursive-amplification guard (full-rss-qxz): a feed whose items link back at
  the expander would turn one request into a tree of them, ten items per level,
  and the target is a public address, so no range check would ever see it.
  **Both come from configuration (`FULL_RSS_SELF_HOSTS`), never from the
  request** — `req.url` is built from the client's `Host` header (an
  absolute-form request line overrides it too), so a client sending
  `Host: attacker.example` made the guard compare against the attacker's host
  while the items pointed at the real one (full-rss-647). The request origin is
  used only as a development fallback when nothing is configured, and the
  service says so in the log once at startup-level clarity, because in that mode
  the client chooses what "this service" means. `host` rather than `origin` is
  compared deliberately — an `http://` reference to the same host reaches the
  same service through the platform's own https redirect. Both sides are
  normalised first: lower-cased, default port dropped, and **terminal dots
  removed**, because `service.test.` is the root-anchored spelling of the same
  DNS host while `new URL()` preserves the dot — comparing the raw `host` let
  one appended character through (full-rss-pbz). Addresses are compared **by
  value**, so the same service spelled as its own IP literal is refused too
  (full-rss-647). A target's resolved ADDRESSES are deliberately not compared
  against ours: behind a shared CDN or reverse proxy (Cloudflare, a Deno Deploy
  edge, Vercel) thousands of unrelated sites share our address, so that
  comparison refused every ordinary feed on the same front - a worse failure
  than the hole it closed (full-rss-og0). An alias hostname pointing at this
  service is therefore not detected, and is recorded as a residual. The guard
  also covers the requester's `?url=` and every redirect hop, because
  `guardedFetch` re-runs this function per hop.

### DNS validation

A public-looking name can resolve somewhere private, so names are resolved and
**every** A and AAAA answer must be fetchable; a single private answer blocks
the fetch, as does an empty answer set. Fail-closed everywhere:

- with net permission and no DNS API available, the URL is refused rather than
  fetched unchecked;
- a resolver error refuses the URL (the earlier fail-open behavior allowed
  unvalidated hostnames; that was closed deliberately);
- without net permission the DNS layer is skipped, because the process cannot
  fetch anyway — this also keeps the offline unit suites network-free.

### `guardedFetch` — fetching safely

- Follows redirects **manually** and re-runs full `parseFetchableUrl` validation
  on every hop: a public URL that 302s to `http://169.254.169.254/` is refused
  exactly like a direct request.
- Per-hop 10-second timeout (`AbortSignal.timeout`, combined with the caller's
  signal), so a slow upstream cannot pin a request.
- Redirect hop budget (5) stops loops.
- A redirect with an unparseable `Location` is a `BlockedUrlError`; a redirect
  without `Location` is returned as the final response (mirrors `fetch`-follow).
- `guardedFetch` re-validates even a `URL` object it is handed — a `URL` is not
  proof of prior validation.

### `readCappedStream` / `readCappedText` — memory bound

Response bodies are read with a byte cap measured by what is actually consumed
(2 MB feeds, 5 MB articles), not by a claimed `Content-Length`; exceeding the
cap cancels the reader and throws. `readCappedStream` takes the stream so the
same budget bounds a **decompressed** body: the KV cache holds gzip, and a few
kilobytes of it can expand to gigabytes (a decompression bomb), so `content.ts`
pipes its `DecompressionStream` through the same 5 MB cap rather than calling
`.text()` on it.

### `sanitizeForLog`

Attacker-controlled URLs and error strings are stripped of control characters
(forged log lines, ANSI), have userinfo masked, have query/fragment redacted,
and are **bounded in length**: a log value is cut to `MAX_LOG_CHARS` (1024)
characters and the cut is announced with a `...[truncated N chars]` marker
(full-rss-d2m). A URL is the content of these lines, and a feed may link to a
megabyte-long path, so without a bound a single item becomes a megabyte of log
write per request. Truncation happens **last**, after the redactions, so the
surviving prefix is already sanitized; the cut never splits a surrogate pair.
Redacting a prefix first is not an option even though it looks cheaper: a
userinfo whose `@` sits past the cut would be logged verbatim, which is why the
redactions run over a **window** of `MAX_LOG_SCAN` (4096) characters instead and
the cut is applied to their output (full-rss-al9). The window is the CPU bound -
every pass is a single forward scan with no backtracking, so the cost of a log
line is constant rather than growing with the value; the pattern this replaced
backtracked from every start position and cost ~100 ms of CPU for one
~920-character request line (full-rss-9ey). An authority that runs past the
window is masked **fail-closed**: nothing is emitted from text whose end could
not be seen.

## Content pipeline

- `content.ts` converts fetched article HTML to markdown (cheerio + turndown,
  dropping `script`/`style`/`iframe`/`nav`/`header`/`footer`/`img`/banner and
  navigation roles, unwrapping links), renders it back with `marked`, and runs
  it through `sanitize-html` defaults before it enters the feed. The KV cache
  stores the gzipped markdown, never the source HTML. Only a **2xx** response is
  converted and cached: a 4xx/5xx body is an error page, and caching it for the
  TTL would serve an error to every later requester of that URL as if it were
  the article (full-rss-qxz). A non-2xx expansion therefore fails, and the item
  keeps the feed's own summary like any other expansion failure.
- `feed.ts` sanitizes **feed-supplied** item markup (`content:encoded` and
  `description`) with the same `sanitize-html` defaults at the single export
  boundary, so items whose expansion was skipped or fell back cannot carry
  publisher HTML (scripts, event handlers, `javascript:` URLs, iframes) into a
  reader. Sanitization is idempotent under a fixed config, so expanded articles
  pass through unchanged.
- The same boundary decides which **links** a reader receives (full-rss-d2m).
  `<link>` (channel and item) is a navigation target, so only `http(s)` is
  re-emitted — anything else becomes an empty element, the shape an item with no
  link already had. `<guid>` is an _identifier_, not a link: Atom ids are
  routinely `urn:uuid:…` or `tag:…`, and dropping them would leave items with no
  id, so a **denylist** is dropped: exactly the schemes in `feed.ts`'s
  `ACTIVE_SCHEMES` (`javascript:`, `data:`, `vbscript:`, `blob:`, `file:`,
  `about:`, `view-source:`, the browser/extension schemes, and the OS handler
  schemes it lists). Detection goes through the URL parser, so `JaVaScRiPt:` and
  tab/newline-obfuscated spellings normalise before the comparison. **A denylist
  cannot be complete** (full-rss-sbu): an OS handler scheme that is not listed —
  `itms-services:`, `ms-word:`, `shell:` — survives into `<guid>` verbatim, and
  that is accepted because `<guid>` is an identifier a reader dedupes on, not a
  navigation target, and the item's `<link>` remains strict `http(s)`. Making
  the id safe would mean allowlisting identifier schemes and silently
  re-identifying every item of a feed that uses an unlisted one.
- Item author and category values are XML-escaped when written into the output
  document; the `@feed/feed` builder escapes everything else it emits.

## HTTP responses

Every rendered HTML page (home, errors, the 504 deadline retry page) is served
with `default-src 'none'` CSP (one inline style allowed), `nosniff`,
`frame-ancestors 'none'`/`X-Frame-Options: DENY`, and
`referrer-policy:
no-referrer`. The feed itself is served as
`application/rss+xml` with `default-src 'none'; frame-ancestors 'none'`,
`nosniff`, `X-Frame-Options: DENY` and `referrer-policy: no-referrer`, so a
browser that opens the feed directly cannot sniff or frame it either. A
whole-request 30-second deadline bounds the full feed+articles pipeline and
renders the retry page on expiry.

## Accepted residuals

Known limits that are accepted deliberately:

1. **DNS rebinding (TOCTOU).** Validation resolves the name, then `fetch`
   resolves it again; a hostile DNS server can answer the second query
   differently. Closing this needs pinning the connection to the checked IP,
   which the runtime's `fetch` cannot express.
2. **The article cache is shared and unauthenticated.** Anyone who can get the
   service to fetch a URL can read the cached conversion of that URL for its
   60-second TTL. Keys are SHA-256 of the URL; there are no per-requester
   partitions. Accepted because the service only fetches public URLs.
3. **Caching is keyed on the URL, not the content.** A publisher that changes an
   article serves stale content for up to the TTL. Availability concern, not
   integrity, because nothing is ever _served_ from the cache without being
   sanitized: the cache holds the gzipped **turndown output** (markdown
   converted from the publisher's HTML) and `sanitize-html` runs on the read
   path, after decompression, so a poisoned or stale entry still passes the same
   allowlist before it reaches a reader (full-rss-sbu). The cache is therefore
   inside the trust boundary for availability and outside it for content policy.
4. **`sanitize-html` defaults are the policy.** Content that needs tags outside
   the default allowlist (e.g. images) is dropped rather than carried. This is
   consistent between the expanded-article path and the fallback path.
5. **No rate limiting per requester.** A requester can make the service fetch up
   to 11 targets per request (the feed and 10 articles), and **each target may
   take up to 5 redirect hops**, every hop re-validated and re-fetched — so up
   to 66 outbound requests, plus a DNS lookup per hop, bounded in time and size
   individually and by the request deadline overall (full-rss-sbu). Global
   platform limits (Deno Deploy) are the backstop.
6. **Timeouts are best-effort bounds.** `AbortSignal` only cancels work that
   observes it; the 30-second request race in `server.ts` bounds even
   non-cancellable work (DNS, KV, parsing) for the response, though the losing
   work may still finish in the background.
7. **The self-reference guard is per-host, per-address, not per-deployment.** It
   refuses the hosts and addresses in `FULL_RSS_SELF_HOSTS`. A second deployment
   of this same service on a different hostname and different addresses (a
   preview URL, another operator's instance) is an ordinary public host to the
   guard, so a feed linking to _that_ copy is not detected. Closing it would
   need a registry of deployment hostnames, which the service does not have; the
   per-request 30-second deadline and the 10-article cap remain the bound. Two
   related residuals, both deliberate: if `FULL_RSS_SELF_HOSTS` is unset the
   service falls back to the request's own origin, which the client chooses, and
   logs that once; and if this service's own addresses cannot be resolved only
   the host (and literal-address) comparison applies. Neither is silent in the
   code, and both are worse than configuration, not equal to it. A misconfigured
   entry cannot silently become a different host either: `parseSelfHosts`
   rejects a userinfo, path, query or fragment, so
   `https://service@attacker.example` fails the boot with an error instead of
   configuring the attacker's host (full-rss-56w). An **alias hostname** for
   this same service (a name that resolves to our addresses) is likewise not
   detected, for the shared-CDN reason above: an address match cannot establish
   that a distinct Host routes here (full-rss-og0). The literal spelling of our
   own address IS refused, because that is a statement about the target's
   spelling rather than about who else lives at that address. A depth counter is
   **not** used, and should not be added: the loop crosses independent HTTP
   requests, so any "depth" would have to arrive in the request — the same
   client-controlled input that made the Host header unusable. Identity of the
   service is the property that can be trusted.

## Change discipline

A change that adds a new outbound fetch, a new place feed-supplied text enters
the output, or a new logged value must update this document in the same change,
and `egress.ts` remains the only egress point: new fetches go through
`guardedFetch`, never `fetch` directly. That last rule is not a convention any
more — `tools/single-egress.sh` fails the build when any `*.ts` file outside
`egress.ts` (and outside `tests/`, which stubs `globalThis.fetch` on purpose)
reaches the network, and it runs in both gate tiers. It catches the platform
fetch in its spellings (called, passed as a value, `globalThis.fetch`,
`self.fetch`, `window.fetch`, `globalThis["fetch"]`, and a rename through
destructuring), the other outbound entry points (`Deno.connect`, `connectTls`,
`createHttpClient`, `resolveDns`, `WebSocket`, `EventSource`, `XMLHttpRequest`,
`node:http(s)`/`net`/`tls`/`dgram`/`http2`), and a listener anywhere but
`server.ts` (full-rss-bm0). It is a grep, so its claim is bounded and stated
plainly: **these spellings fail the build**, not "no other network path can
exist" — an identifier assembled at runtime (`globalThis["fet" + "ch"]`) or
imported from a dependency is outside what a text check can see.
