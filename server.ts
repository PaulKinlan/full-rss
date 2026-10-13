/*
  server.ts - the HTTP side: validate ?url=, fetch the feed document, parse it, hand the parsed feed to
  feed.ts, and turn every outcome into a response. `serve()` owns the socket and opens the KV handle, so
  importing this module binds nothing; main.ts is the thin file Deno Deploy runs (full-rss-11b).

  We never cache the feed, we want any RSS reader to always get the latest feed. (TODO: maybe introduce some
  basic caching for the feed itself)
*/

import { parseFeed } from "@mikaelporttila/rss";
import { index } from "./templates/index.ts";
import { openKv } from "./content.ts";
import { exportFeed, processFeed } from "./feed.ts";
import {
  BlockedUrlError,
  guardedFetch,
  parseFetchableUrl,
  readCappedText,
  sanitizeForLog,
} from "./egress.ts";

// The most feed document we will read, decompressed. A feed that arrives larger than this is refused
// rather than buffered and parsed (full-rss-apm).
const MAX_FEED_BYTES = 2 * 1024 * 1024;

export const handleRequest = async (req: Request): Promise<Response> => {
  if (req.method !== "GET") {
    return new Response("Method not allowed", { status: 405 });
  }

  const { searchParams } = new URL(req.url);
  const url = searchParams.get("url");

  if (!url) {
    return new Response(await index(undefined), {
      status: 200,
      headers: { "content-type": "text/html" },
    });
  }

  // What we may fetch is egress.ts's decision: a typo keeps the historical 400, a target this service must
  // not fetch (private network, localhost, credentials, non-http) gets its own 403 (full-rss-apm).
  let target: URL;
  try {
    target = await parseFetchableUrl(url);
  } catch (e) {
    if (e instanceof BlockedUrlError) {
      return new Response(
        await index(
          "This URL cannot be fetched: only public http(s) addresses are supported, not private, local or reserved networks.",
        ),
        { status: 403 },
      );
    }
    return new Response(
      await index(
        "Invalid URL parameter. Please enter a valid URL e.g, https://paul.kinlan.me/index.xml",
      ),
      { status: 400 },
    );
  }

  console.log(sanitizeForLog(`Fetching feed from ${url}`));

  // guardedFetch re-validates every redirect hop and bounds each request in time; readCappedText bounds
  // the document in memory. A timeout, an unreachable host or an oversized feed all land in the catch.
  let feedXml: string;
  try {
    const feedResponse = await guardedFetch(target);
    if (!feedResponse.ok) {
      return new Response(
        await index(
          "There was an error fetching the feed. Please check the URL",
        ),
        {
          status: 500,
        },
      );
    }
    feedXml = await readCappedText(feedResponse, MAX_FEED_BYTES);
  } catch (e) {
    if (e instanceof BlockedUrlError) {
      // The feed redirected somewhere this service must not follow.
      return new Response(
        await index(
          "This feed redirected to a URL that cannot be fetched (a private, local or reserved network address).",
        ),
        { status: 403 },
      );
    }
    console.error(sanitizeForLog(`Failed to fetch the feed: ${e}`));
    return new Response(
      await index("There was an error fetching the feed. Please check the URL"),
      {
        status: 500,
      },
    );
  }

  try {
    const feed = await parseFeed(feedXml);
    const fullFeed = await processFeed(feed);

    return new Response(exportFeed(fullFeed), {
      headers: { "content-type": "application/rss+xml" },
    });
  } catch (e) {
    console.error(e);
    return new Response(
      await index(
        "There was an error parsing the feed or an item in the feed. Please check the URL is a valid feed",
      ),
      {
        status: 500,
      },
    );
  }
};

export const serve = async (): Promise<void> => {
  // Open the KV handle at boot and only at boot: an unavailable KV must fail here, loudly, instead of
  // failing per article inside processFeed's error handling (which would silently degrade every feed to
  // summaries only).
  await openKv();
  Deno.serve(handleRequest);
};
