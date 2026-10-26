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
  parseSelfHosts,
  readCappedText,
  resolveSelfAddresses,
  sanitizeForLog,
} from "./egress.ts";

// The most feed document we will read, decompressed. A feed that arrives larger than this is refused
// rather than buffered and parsed (full-rss-apm).
const MAX_FEED_BYTES = 2 * 1024 * 1024;
// The full feed, including DNS, redirects, body reads and up to ten sequential article expansions,
// has one budget in addition to each outbound fetch's per-hop timeout.
const REQUEST_TIMEOUT_MS = 30_000;

// Where this service names ITSELF. `req.url` cannot do it: it is built from the client's `Host` header (and an
// absolute-form request line overrides it), so a client sending `Host: attacker.example` made the
// self-expansion guard compare against the attacker's host and the amplification loop reopened (full-rss-647).
// Comma/whitespace-separated `host`, `host:port` or origin; every deployment that expands feeds should set it.
const SELF_HOSTS_ENV = "FULL_RSS_SELF_HOSTS";
// How long this service's own resolved addresses are reused. They change only on a redeploy, and one lookup
// per request would put a DNS round trip on the path of every expansion.
const SELF_ADDRESS_TTL_MS = 5 * 60_000;
// A failed lookup is retried soon rather than cached as "this service has no addresses".
const SELF_ADDRESS_RETRY_MS = 30_000;

let configuredRaw: string | null | undefined;
let configuredOrigins: string[] = [];

/** The configured self hosts, re-parsed only when the environment value changes (so a suite can set it). */
const selfOriginsFromEnv = (): string[] => {
  const raw = Deno.env.get(SELF_HOSTS_ENV) ?? null;
  if (raw !== configuredRaw) {
    configuredRaw = raw;
    configuredOrigins = parseSelfHosts(raw ?? undefined);
  }
  return configuredOrigins;
};

/**
 * Parse the configured self hosts now, and throw if they are malformed. `serve()` calls this BEFORE the
 * socket is bound, so a typo stops the process from starting: the alternative is a deployment that looks
 * healthy, answers the home page, and then fails every feed expansion with a 500 on the first request
 * (full-rss-7mo). The per-request path parses defensively too, which is what the suites exercise.
 */
export const validateSelfHostsConfig = (): string[] => selfOriginsFromEnv();

let warnedUnconfigured = false;

/**
 * The hosts this service answers on. Configuration wins; the origin the request arrived on is only a
 * development fallback when nothing is configured, and it says so in the log once, because in that mode a
 * client-chosen `Host` decides what "this service" means (full-rss-647).
 */
const selfOriginsFor = (req: Request): string[] => {
  const configured = selfOriginsFromEnv();
  if (configured.length > 0) return configured;
  if (!warnedUnconfigured) {
    warnedUnconfigured = true;
    console.warn(
      `${SELF_HOSTS_ENV} is not set: this service is identifying itself by the request's own Host header, which the client chooses. Set it to this service's public host(s) in any deployment.`,
    );
  }
  return [new URL(req.url).origin];
};

let selfAddressCache:
  | { key: string; addresses: string[]; expiresAt: number }
  | undefined;

/** This service's own addresses, for the IP-literal and alias spellings of it (cached, best effort). */
const selfAddressesFor = async (
  origins: readonly string[],
): Promise<string[]> => {
  const key = origins.join(",");
  const now = Date.now();
  if (selfAddressCache?.key === key && now < selfAddressCache.expiresAt) {
    return selfAddressCache.addresses;
  }
  let addresses: string[] = [];
  try {
    addresses = await resolveSelfAddresses(origins);
  } catch (e) {
    console.error(
      sanitizeForLog(`Could not resolve this service's own addresses: ${e}`),
    );
  }
  selfAddressCache = {
    key,
    addresses,
    expiresAt: now +
      (addresses.length > 0 ? SELF_ADDRESS_TTL_MS : SELF_ADDRESS_RETRY_MS),
  };
  return addresses;
};

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

// The RSS document is served to feed readers, so it carries no HTML policy - but it still leaves this origin,
// and a browser that opens it directly must not sniff it into something executable or frame this service.
// Same reason as HTML_HEADERS: the factory's feed-response finding (full-rss-bxs).
const FEED_HEADERS = {
  "content-type": "application/rss+xml",
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
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

  // The hosts this service answers on, AND the addresses they resolve to, and nothing here may fetch either: a
  // feed or article URL that points back at us is this service expanding itself, ten items at a time
  // (full-rss-qxz). Both come from configuration, never from the request - see SELF_HOSTS_ENV (full-rss-647).
  const selfOrigins = selfOriginsFor(req);
  const selfAddresses = await selfAddressesFor(selfOrigins);
  const egressOptions = { selfOrigins, selfAddresses };

  // What we may fetch is egress.ts's decision: a typo keeps the historical 400, a target this service must
  // not fetch (private network, localhost, credentials, non-http) gets its own 403 (full-rss-apm).
  let target: URL;
  try {
    target = await parseFetchableUrl(url, egressOptions);
  } catch (e) {
    if (e instanceof BlockedUrlError) {
      return htmlResponse(
        "This URL cannot be fetched: only public http(s) addresses are supported, not private, local or reserved networks - and not this service itself.",
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
    const feedResponse = await guardedFetch(target, {
      signal,
      ...egressOptions,
    });
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
        "This feed redirected to a URL that cannot be fetched (a private, local or reserved network address, or this service itself).",
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
    const fullFeed = await processFeed(feed, signal, egressOptions);
    signal.throwIfAborted();

    return new Response(exportFeed(fullFeed), { headers: FEED_HEADERS });
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
  // Fail here, not on the first request: a malformed FULL_RSS_SELF_HOSTS is a deployment error, and a
  // process that starts and then refuses every expansion is worse than one that refuses to start
  // (full-rss-7mo).
  validateSelfHostsConfig();
  // Open the KV handle at boot and only at boot: an unavailable KV must fail here, loudly, instead of
  // failing per article inside processFeed's error handling (which would silently degrade every feed to
  // summaries only).
  await openKv();
  Deno.serve((req) => handleRequest(req));
};
