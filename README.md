# Full RSS

## Description

Full RSS is a Deno-based application that takes an RSS feed and returns the full
content of each article in the same RSS feed. It uses KV storage for caching the
full content of each article.

## Features

- Fetches and processes RSS feeds to include full article content.
- Converts HTML content to Markdown.
- Caches article content to improve performance.
- Supports Atom and RSS feed formats.

## Installation

1. Install [Deno](https://deno.land/).
2. Clone this repository.

## Usage

To start the server, run the following command:

```sh
deno run --unstable-kv --allow-net --allow-env main.ts
```

`--unstable-kv` is required: `Deno.openKv` is still an unstable API in the
pinned toolchain (Deno 2.9.7), and without the flag the process exits at boot
with `TypeError: Deno.openKv is not a function`.

Each remaining flag is measured, not habitual (full-rss-apm):

- `--allow-env` is whole-read, deliberately: importing the application pulls in
  npm CJS dependencies (undici, via cheerio and `@mikaelporttila/rss`) whose
  module-init code probes `process.env` (`NODE_V8_COVERAGE`, `UNDICI_NO_FG`), so
  a variable whitelist breaks on the next dependency bump with a `NotCapable`
  error far from the change that caused it. No code here writes to the
  environment.
- `--allow-read` and `--allow-write` are gone: boot plus a KV set/get round trip
  succeeds without them, because the default KV database lives under `DENO_DIR`
  and is not reached through the permission-gated filesystem APIs.
- `--allow-net` stays broad because fetching arbitrary public feeds and articles
  is the product. The egress filter is therefore the application layer, not the
  runtime: every outbound URL (the requester's `?url=` and every article link
  inside a fetched feed) goes through `egress.ts`, which refuses non-http(s)
  schemes, credentials, and private, local, link-local or reserved targets
  (including a name that resolves to one), re-validates every redirect hop,
  bounds each request with a 10-second timeout, and caps how much of a response
  is buffered.

## Tests and gates

```sh
bash tools/fast-gate.sh   # changed/affected suites only — the gate for a single change
bash tools/full-gate.sh   # type-check plus every suite — the gate for a landing
```

Both are driven from one place, `tools/gate.conf`, and both run under
`deno test`; neither downloads anything. The fast gate selects suites from
`tools/suite-map.tsv` and **fails loudly** when a changed file maps to no suite,
so a new module needs a row there (the file's header explains the rules).
`fleet-check`/`fleet-check --fast` on the project VM run exactly these two
commands (`tools/check.conf`).

The landing gate also runs the static half: `deno check` on every module,
`deno
lint` over the tree and `deno fmt --check` (`tools/gate.conf`'s
`STATIC_CMD`). Each of the three was added in the change that made it pass - the
tree was formatted in one whitespace-only commit (11 of 13 files) before the
format check joined, and lint went green first - so none of them is a red the
reader learns to ignore.

Unit suites live in `tests/unit/` and boundary (routing) suites in
`tests/integration/` (`deno test --allow-env tests`). Nothing binds a port or
opens KV at import time — `serve()` opens the KV handle and `main.ts` only calls
it under `import.meta.main` — so every domain function is importable from a
test. The application is split so that a change to one concern cannot collide
with another:

| file                 | what it owns                                                              |
| -------------------- | ------------------------------------------------------------------------- |
| `main.ts`            | the entrypoint Deno Deploy runs; boot only                                |
| `server.ts`          | HTTP routing, status codes and the socket (`serve()`)                     |
| `egress.ts`          | every outbound fetch: target validation, redirects, caps (`guardedFetch`) |
| `feed.ts`            | a parsed feed to the RSS 2.0 document (`exportFeed`, `processFeed`)       |
| `content.ts`         | article fetch, HTML to markdown, gzipped KV cache (`fetchContent`)        |
| `templates/index.ts` | the HTML landing/error page                                               |

## Endpoints

- `GET /?url=<URL>`: Fetches the full content of each article in the RSS feed at
  the specified URL.

```sh
curl "http://localhost:8000/?url=https://example.com/rss"
```
