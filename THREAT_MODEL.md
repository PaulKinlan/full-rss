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
  forever.
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
  `172.16/12`, `192.0.0/24`, `192.0.2/24`, `192.168/16`, `198.18/15`,
  `198.51.100/24`, `203.0.113/24`, `224/4`, `240/4`. Blocked IPv6: `::`, `::1`,
  `100::/64`, `2001:db8::/32`, `fc00::/7`, `fe80::/10`, `ff00::/8`, and any
  IPv4-embedded form (mapped, compatible, NAT64 `64:ff9b::/96`, 6to4
  `2002::/16`) whose embedded address is blocked;
- **names meaning "here"** — `localhost`, `*.localhost`, `local`, `internal` —
  before DNS is consulted.

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

### `readCappedText` — memory bound

Response bodies are read with a byte cap measured by what is actually consumed
(2 MB feeds, 5 MB articles), not by a claimed `Content-Length`; exceeding the
cap cancels the reader and throws.

### `sanitizeForLog`

Attacker-controlled URLs and error strings are stripped of control characters
(forged log lines, ANSI), have userinfo masked, and have query/fragment redacted
before logging.

## Content pipeline

- `content.ts` converts fetched article HTML to markdown (cheerio + turndown,
  dropping `script`/`style`/`iframe`/`nav`/`header`/`footer`/`img`/banner and
  navigation roles, unwrapping links), renders it back with `marked`, and runs
  it through `sanitize-html` defaults before it enters the feed. The KV cache
  stores the gzipped markdown, never the source HTML.
- `feed.ts` sanitizes **feed-supplied** item markup (`content:encoded` and
  `description`) with the same `sanitize-html` defaults at the single export
  boundary, so items whose expansion was skipped or fell back cannot carry
  publisher HTML (scripts, event handlers, `javascript:` URLs, iframes) into a
  reader. Sanitization is idempotent under a fixed config, so expanded articles
  pass through unchanged.
- Item author and category values are XML-escaped when written into the output
  document; the `@feed/feed` builder escapes everything else it emits.

## HTTP responses

Every rendered HTML page (home, errors, the 504 deadline retry page) is served
with `default-src 'none'` CSP (one inline style allowed), `nosniff`,
`frame-ancestors 'none'`/`X-Frame-Options: DENY`, and
`referrer-policy:
no-referrer`. The feed itself is served as
`application/rss+xml`. A whole-request 30-second deadline bounds the full
feed+articles pipeline and renders the retry page on expiry.

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
   integrity: the cached bytes were sanitized when produced.
4. **`sanitize-html` defaults are the policy.** Content that needs tags outside
   the default allowlist (e.g. images) is dropped rather than carried. This is
   consistent between the expanded-article path and the fallback path.
5. **No rate limiting per requester.** A requester can make the service fetch up
   to 11 URLs (feed + 10 articles) per request, each bounded in time and size.
   Global platform limits (Deno Deploy) are the backstop.
6. **Timeouts are best-effort bounds.** `AbortSignal` only cancels work that
   observes it; the 30-second request race in `server.ts` bounds even
   non-cancellable work (DNS, KV, parsing) for the response, though the losing
   work may still finish in the background.

## Change discipline

A change that adds a new outbound fetch, a new place feed-supplied text enters
the output, or a new logged value must update this document in the same change,
and `egress.ts` remains the only egress point: new fetches go through
`guardedFetch`, never `fetch` directly.
