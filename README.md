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
deno run --allow-net --allow-read --allow-write --allow-env main.ts
```

## Endpoints

- `GET /?url=<URL>`: Fetches the full content of each article in the RSS feed at the specified URL.

```sh
curl "http://localhost:8000/?url=https://example.com/rss"
```
