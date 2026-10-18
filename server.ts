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
// The full feed, including DNS, redirects, body reads and up to ten sequential article expansions,
// has one budget in addition to each outbound fetch's per-hop timeout.
const REQUEST_TIMEOUT_MS = 30_000;

// Every rendered page (including errors and the deadline retry page) uses the same policy. The index has
// one inline style and no scripts; allow that style without allowing any script or external resource.
const HTML_HEADERS = {
  "content-type": "text/html; charset=utf-8",
  "content-security-policy":
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
};

const htmlResponse = async (
  message: string | undefined,
  status = 200,
): Promise<Response> =>
  new Response(await index(message), { status, headers: HTML_HEADERS });

const handleFeedRequest = async (
  req: Request,
  signal: AbortSignal,
): Promise<Response> => {
  if (req.method !== "GET") {
    return new Response("Method not allowed", { status: 405 });
  }

  const { searchParams } = new URL(req.url);
  const url = searchParams.get("url");

  if (!url) {
    return htmlResponse(undefined);
  }

  // What we may fetch is egress.ts's decision: a typo keeps the historical 400, a target this service must
  // not fetch (private network, localhost, credentials, non-http) gets its own 403 (full-rss-apm).
  let target: URL;
  try {
    target = await parseFetchableUrl(url);
  } catch (e) {
    if (e instanceof BlockedUrlError) {
      return htmlResponse(
        "This URL cannot be fetched: only public http(s) addresses are supported, not private, local or reserved networks.",
        403,
      );
    }
    return htmlResponse(
      "Invalid URL parameter. Please enter a valid URL e.g, https://paul.kinlan.me/index.xml",
      400,
    );
  }

  console.log(sanitizeForLog(`Fetching feed from ${url}`));

  // guardedFetch re-validates every redirect hop and bounds each request in time; readCappedText bounds
  // the document in memory. A timeout, an unreachable host or an oversized feed all land in the catch.
  let feedXml: string;
  try {
    signal.throwIfAborted();
    const feedResponse = await guardedFetch(target, { signal });
    if (!feedResponse.ok) {
      return htmlResponse(
        "There was an error fetching the feed. Please check the URL",
        500,
      );
    }
    feedXml = await readCappedText(feedResponse, MAX_FEED_BYTES);
  } catch (e) {
    if (e instanceof BlockedUrlError) {
      // The feed redirected somewhere this service must not follow.
      return htmlResponse(
        "This feed redirected to a URL that cannot be fetched (a private, local or reserved network address).",
        403,
      );
    }
    console.error(sanitizeForLog(`Failed to fetch the feed: ${e}`));
    return htmlResponse(
      "There was an error fetching the feed. Please check the URL",
      500,
    );
  }

  try {
    const feed = await parseFeed(feedXml);
    signal.throwIfAborted();
    const fullFeed = await processFeed(feed, signal);
    signal.throwIfAborted();

    return new Response(exportFeed(fullFeed), {
      headers: { "content-type": "application/rss+xml" },
    });
  } catch (e) {
    console.error(sanitizeForLog(`Failed to parse feed or item: ${e}`));
    return htmlResponse(
      "There was an error parsing the feed or an item in the feed. Please check the URL is a valid feed",
      500,
    );
  }
};

export const handleRequest = async (
  req: Request,
  requestTimeoutMs = REQUEST_TIMEOUT_MS,
): Promise<Response> => {
  // The home page and method rejection do no upstream work; only expansion needs a deadline.
  if (req.method !== "GET" || !new URL(req.url).searchParams.get("url")) {
    return handleFeedRequest(req, new AbortController().signal);
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), requestTimeoutMs);
  let onAbort: (() => void) | undefined;
  const expired = new Promise<Response>((resolve, reject) => {
    onAbort = () => {
      htmlResponse("This feed took too long to process. Please try again.", 504)
        .then(resolve, reject);
    };
    controller.signal.addEventListener("abort", onAbort, { once: true });
  });
  try {
    // Racing bounds even non-cancellable work (DNS, KV, parsing). The losing promise remains observed,
    // so a late failure cannot become an unhandled rejection.
    return await Promise.race([
      handleFeedRequest(req, controller.signal),
      expired,
    ]);
  } finally {
    clearTimeout(timer);
    controller.signal.removeEventListener("abort", onAbort!);
  }
};

export const serve = async (): Promise<void> => {
  // Open the KV handle at boot and only at boot: an unavailable KV must fail here, loudly, instead of
  // failing per article inside processFeed's error handling (which would silently degrade every feed to
  // summaries only).
  await openKv();
  Deno.serve((req) => handleRequest(req));
};
