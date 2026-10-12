# Full RSS

## Description

Full RSS is a Deno-based application that takes an RSS feed and returns the full content of each article in the same RSS feed. It uses KV storage for caching the full content of each article.

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
deno run --unstable-kv --allow-net --allow-read --allow-write --allow-env main.ts
```

`--unstable-kv` is required: `Deno.openKv` is still an unstable API in the pinned toolchain (Deno 2.9.7),
and without the flag the process exits at boot with `TypeError: Deno.openKv is not a function`.

## Tests and gates

```sh
bash tools/fast-gate.sh   # changed/affected suites only — the gate for a single change
bash tools/full-gate.sh   # type-check plus every suite — the gate for a landing
```

Both are driven from one place, `tools/gate.conf`, and both run under `deno test`; neither downloads
anything. The fast gate selects suites from `tools/suite-map.tsv` and **fails loudly** when a changed file
maps to no suite, so a new module needs a row there (the file's header explains the rules).
`fleet-check`/`fleet-check --fast` on the project VM run exactly these two commands (`tools/check.conf`).

Unit suites live in `tests/unit/` and boundary (routing) suites in `tests/integration/`
(`deno test --allow-env tests`). Nothing binds a port or opens KV at import time — `serve()` opens the KV
handle and `main.ts` only calls it under `import.meta.main` — so every domain function is importable from a
test. The application is split so that a change to one concern cannot collide with another:

| file | what it owns |
|---|---|
| `main.ts` | the entrypoint Deno Deploy runs; boot only |
| `server.ts` | HTTP routing, status codes and the socket (`serve()`) |
| `feed.ts` | a parsed feed to the RSS 2.0 document (`exportFeed`, `processFeed`) |
| `content.ts` | article fetch, HTML to markdown, gzipped KV cache (`fetchContent`) |
| `templates/index.ts` | the HTML landing/error page |

## Endpoints

- `GET /?url=<URL>`: Fetches the full content of each article in the RSS feed at the specified URL.

```sh
curl "http://localhost:8000/?url=https://example.com/rss"
```
