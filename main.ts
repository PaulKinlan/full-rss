/*
  full-rss - takes an RSS feed and returns the full content of each article in the same RSS feed.

  Hosted using Deno.
  + KV storage for caching of the full content of each article.

  This file is only the entrypoint Deno Deploy runs: the application lives in three domain modules, so a
  change to one of them cannot collide with a change to another (full-rss-11b, the ADR full-rss-7d0):

    server.ts   HTTP routing and the socket (serve())
    feed.ts     parsed feed -> the RSS 2.0 document the reader receives
    content.ts  article fetch, HTML -> markdown, gzipped KV cache

  `import.meta.main` keeps the server out of every import of these modules, so tests can import the domain
  functions without binding a port or opening KV.
*/

import { serve } from "./server.ts";

if (import.meta.main) await serve();
