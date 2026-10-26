/*
  egress.ts - everything this service fetches from the outside goes through here (full-rss-apm).

  The factory's threat-model pass rated the fetches blind: article links out of an attacker-controlled feed
  (second-order SSRF) and the requester's ?url= (first-order) were both fetched with only a syntax check, so
  a feed could aim this service at localhost, a cloud metadata address or any private network. This module is
  the single egress point:

    parseFetchableUrl  decides what may be fetched (scheme, credentials, private/reserved targets)
    guardedFetch       fetches it, and re-decides at every redirect hop - a public URL that 302s to
                       http://169.254.169.254/ is refused exactly like a direct request would be
    readCappedText     bounds how much of a response may be read into memory
    sanitizeForLog     keeps attacker-controlled URLs and errors from forging log lines or leaking userinfo

  Importing this module needs no permission and touches no network: the DNS layer runs only when the process
  actually holds net permission (netPermissionGranted below), which is also what keeps the unit suites
  network-free under `deno test --allow-env`.
*/

/** Thrown when a URL is parseable but points somewhere this service must not fetch. */
export class BlockedUrlError extends Error {
  constructor(reason: string) {
    super(`Blocked URL: ${reason}`);
    this.name = "BlockedUrlError";
  }
}

/** A redirect status `fetch(redirect: "manual")` hands back instead of following. */
const REDIRECT_STATUSES: ReadonlySet<number> = new Set([
  301,
  302,
  303,
  307,
  308,
]);

/** One outbound request may take this long, per redirect hop. */
const FETCH_TIMEOUT_MS = 10_000;

/** A single URL may be redirected this many times before we give up. */
const MAX_REDIRECTS = 5;

// --- address classification (pure) -------------------------------------------------------------------
//
// `new URL()` has already canonicalised the host by the time we see it: "0x7f000001", "2130706433" and
// "127.1" all arrive as "127.0.0.1", and IPv6 hosts arrive bracketless. The parsers below therefore only
// need the canonical shapes, and anything that is not an IP literal is treated as a name.

/** "a.b.c.d" -> the 32-bit address as a Number, or null when the host is not a dotted quad. */
const parseIPv4 = (host: string): number | null => {
  const parts = host.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (/^\d{1,3}$/.test(part) === false || Number(part) > 255) return null;
    value = value * 256 + Number(part);
  }
  return value;
};

/** Private, reserved, benchmarking and documentation ranges: nothing here is a legitimate article host. */
const IPV4_BLOCKED_RANGES: readonly (readonly [bigint, bigint])[] = [
  [0x00000000n, 0x00ffffffn], // 0.0.0.0/8 "this network"
  [0x0a000000n, 0x0affffffn], // 10.0.0.0/8 private
  [0x64400000n, 0x647fffffn], // 100.64.0.0/10 carrier-grade NAT (through 100.127.255.255)
  [0x7f000000n, 0x7fffffffn], // 127.0.0.0/8 loopback
  [0xa9fe0000n, 0xa9feffffn], // 169.254.0.0/16 link-local (incl. cloud metadata)
  [0xac100000n, 0xac1fffffn], // 172.16.0.0/12 private
  [0xc0000000n, 0xc00000ffn], // 192.0.0.0/24 IETF protocol assignments
  [0xc0000200n, 0xc00002ffn], // 192.0.2.0/24 TEST-NET-1
  [0xc0586300n, 0xc05863ffn], // 192.88.99.0/24 6to4 relay anycast (deprecated)
  [0xc0a80000n, 0xc0a8ffffn], // 192.168.0.0/16 private
  [0xc6120000n, 0xc613ffffn], // 198.18.0.0/15 benchmarking
  [0xc6336400n, 0xc63364ffn], // 198.51.100.0/24 TEST-NET-2
  [0xcb007100n, 0xcb0071ffn], // 203.0.113.0/24 TEST-NET-3
  [0xe0000000n, 0xefffffffn], // 224.0.0.0/4 multicast
  [0xf0000000n, 0xffffffffn], // 240.0.0.0/4 reserved (incl. 255.255.255.255)
];

const isBlockedIPv4 = (address: bigint): boolean =>
  IPV4_BLOCKED_RANGES.some(([low, high]) => address >= low && address <= high);

/**
 * An IPv6 host -> its 8 groups, or null when it is not an IPv6 literal. Handles "::" compression and the
 * embedded-IPv4 tail ("::ffff:127.0.0.1"); a zone identifier ("%eth0") is refused by the caller before this
 * runs, because URL-percent-encoded zones are their own private-network signal.
 */
const parseIPv6 = (host: string): number[] | null => {
  const split = host.split("::");
  if (split.length > 2) return null; // "::" may appear once

  const parseGroups = (segment: string): number[] | null => {
    if (segment === "") return [];
    const parts = segment.split(":");
    const groups: number[] = [];
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      if (part.includes(".")) {
        // An embedded IPv4 tail is only legal as the last component, and expands to two groups.
        if (i !== parts.length - 1) return null;
        const v4 = parseIPv4(part);
        if (v4 == null) return null;
        groups.push(Math.floor(v4 / 65536), v4 % 65536);
        break;
      }
      if (/^[0-9a-fA-F]{1,4}$/.test(part) === false) return null;
      groups.push(Number.parseInt(part, 16));
    }
    return groups;
  };

  const head = parseGroups(split[0]);
  if (head == null) return null;
  const tail = split.length === 2 ? parseGroups(split[1]) : [];
  if (tail == null) return null;

  if (split.length === 1) return head.length === 8 ? head : null;
  const fill = 8 - head.length - tail.length;
  if (fill < 1) return null; // "::" must stand for at least one zero group
  return [...head, ...Array<number>(fill).fill(0), ...tail];
};

const ipv6ToV4 = (groups: number[]): bigint | null => {
  // The embedded IPv4 of a mapped (::ffff:0:0/96), translated (::ffff:0:0:0/96), compatible (::x.y.z.w,
  // deprecated but parsed), NAT64 (64:ff9b::/96), 6to4 (2002::/16) or Teredo (2001::/32) address, as one
  // 32-bit value.
  const tail = (groups[6] ?? 0) * 65536 + (groups[7] ?? 0);
  if (
    groups.slice(0, 5).every((group) => group === 0) && groups[5] === 0xffff
  ) {
    return BigInt(tail); // IPv4-mapped
  }
  if (
    groups.slice(0, 4).every((group) => group === 0) &&
    groups[4] === 0xffff && groups[5] === 0
  ) {
    // IPv4-translated (::ffff:0:0:0/96, RFC 2765): "[::ffff:0:127.0.0.1]" parses as ::ffff:0:7f00:1 and
    // reaches loopback just like the mapped form does.
    return BigInt(tail);
  }
  if (groups.slice(0, 6).every((group) => group === 0) && tail !== 0) {
    return BigInt(tail); // IPv4-compatible
  }
  if (groups[0] === 0x64 && groups[1] === 0xff9b) {
    return BigInt(tail); // NAT64
  }
  if (groups[0] === 0x2002) {
    return BigInt(groups[1] * 65536 + groups[2]); // 6to4
  }
  if (groups[0] === 0x2001 && groups[1] === 0) {
    // Teredo (2001::/32, RFC 4380): 2001:0000:<server IPv4>:<flags + port>:<client IPv4>. The client
    // address in bits 96..127 is stored as its bitwise COMPLEMENT, so the address the relay forwards to is
    // 0xffffffff - tail. Reading the stored bits instead would flag every client below 240.0.0.0/4 - 8.8.8.8
    // is stored as f7f7:f7f7 - and block a mechanism rather than a destination.
    return BigInt(0xffffffff - tail);
  }
  return null;
};

const isBlockedIPv6 = (groups: number[]): boolean => {
  if (groups.every((group) => group === 0)) return true; // :: unspecified
  if (groups.slice(0, 7).every((group) => group === 0) && groups[7] === 1) {
    return true; // ::1
  }
  if (
    groups[0] === 0x0100 && groups.slice(1, 4).every((group) => group === 0)
  ) return true; // 100::/64
  if (groups[0] === 0x2001 && groups[1] === 0x0db8) return true; // 2001:db8::/32 documentation
  if (
    groups[0] === 0x2001 && groups[1] === 0x0002 && groups[2] === 0
  ) return true; // 2001:2::/48 benchmarking
  if ((groups[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local
  if ((groups[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((groups[0] & 0xffc0) === 0xfec0) return true; // fec0::/10 deprecated site-local
  if ((groups[0] & 0xff00) === 0xff00) return true; // ff00::/8 multicast
  const embedded = ipv6ToV4(groups);
  if (embedded != null && isBlockedIPv4(embedded)) return true; // mapped/compatible/NAT64/6to4/Teredo
  return false;
};

// Names that mean "here" without spelling an address. A name under any of these is refused before DNS is
// consulted; other names are checked against their resolved addresses instead.
const BLOCKED_NAME_SUFFIXES = ["localhost", "local", "internal"];

const isBlockedName = (host: string): boolean =>
  BLOCKED_NAME_SUFFIXES.some((suffix) =>
    host === suffix || host.endsWith(`.${suffix}`)
  );

// --- the resolver layer --------------------------------------------------------------------------------
//
// The syntactic checks above catch every address an attacker can spell. They cannot catch a public-looking
// NAME that resolves somewhere private ("box.attacker.tld" -> 10.0.0.5), so for names we resolve first and
// require every answer to be fetchable. Two honest limits, by design:
//   * the resolve and the fetch are two lookups, so a server that answers the second query differently
//     (DNS rebinding) still gets a window - closing that needs pinning the connection to the checked IP,
//     which this runtime's fetch cannot express;
//   * without net permission the DNS layer is skipped (the process cannot fetch anyway); with net
//     permission a missing resolver fails closed rather than allowing unchecked hostnames.

export type ResolveDns = (hostname: string) => Promise<string[]>;

const netPermissionGranted = (): boolean => {
  try {
    return Deno.permissions.querySync({ name: "net" }).state === "granted";
  } catch {
    return true; // no permissions API in this runtime: assume egress is possible
  }
};

const resolveForValidation: ResolveDns = async (hostname) => {
  // Both record types, because a host may hold only one of them; an all-settled merge keeps an A-only host
  // fetchable when the AAAA lookup answers "no records".
  const [a, aaaa] = await Promise.allSettled([
    Deno.resolveDns(hostname, "A"),
    Deno.resolveDns(hostname, "AAAA"),
  ]);
  return [
    ...(a.status === "fulfilled" ? a.value : []),
    ...(aaaa.status === "fulfilled" ? aaaa.value : []),
  ];
};

// --- URL validation -------------------------------------------------------------------------------------

/**
 * Options for the suites and for the caller's egress policy: an explicit resolver is always consulted,
 * permission gate or not, `selfOrigins` names the hosts this service answers on so a URL pointing back at one
 * of them can be refused (full-rss-qxz), and `selfAddresses` names the same service by ADDRESS, which is what
 * an IP literal or an alias hostname is spelled with (full-rss-647).
 */
export type FetchUrlOptions = {
  resolveDns?: ResolveDns;
  signal?: AbortSignal;
  selfOrigins?: readonly string[];
  selfAddresses?: readonly string[];
};

/**
 * The host a URL names, normalised for comparison: lower-cased, terminal dots removed, and the port kept
 * only when it is not the scheme's default (WHATWG URL drops a default port, so two spellings of the same
 * service agree).
 *
 * The terminal dot is load-bearing. "service.test." is the root-anchored (FQDN) spelling of the very same
 * DNS host as "service.test", and `new URL()` preserves it - so comparing `host` directly let a feed or a
 * `?url=` reach this service by appending one character, which is the whole amplification loop again
 * (full-rss-pbz). The address and name checks below strip it for the same reason.
 */
const hostKey = (url: URL): string => {
  const hostname = url.hostname.toLowerCase().replace(/\.+$/, "");
  return url.port === "" ? hostname : `${hostname}:${url.port}`;
};

/**
 * True when `url` names a host this service answers on. Compared by host (which includes a non-default
 * port) rather than by origin, deliberately: an `http://` reference to the same host reaches the same
 * service through the platform's own https redirect, so the scheme must not open a way around the check.
 * An origin the caller handed us that does not parse cannot mean "this service", so it matches nothing.
 */
const isOwnHost = (url: URL, origin: string): boolean => {
  try {
    return hostKey(new URL(origin)) === hostKey(url);
  } catch {
    return false;
  }
};

/**
 * The configured hosts this service answers on, from a comma/whitespace-separated list: `host`, `host:port` or
 * a full origin. This exists because the request's own URL cannot be trusted to name the service: `req.url` is
 * built from the client's `Host` header (and an absolute-form request line overrides that), so `Host:
 * attacker.example` made the self-expansion guard compare against the wrong host and the amplification loop
 * reopened (full-rss-647). Configuration is the operator's statement of identity; the request is not.
 *
 * Entries are normalised through `new URL`, so a default port disappears and comparison stays by host:port. A
 * malformed entry throws rather than being dropped: silently ignoring it would disable the guard while looking
 * configured.
 */
export const parseSelfHosts = (raw: string | undefined): string[] => {
  const origins: string[] = [];
  for (const entry of (raw ?? "").split(/[\s,]+/)) {
    if (entry === "") continue;
    let url: URL;
    try {
      url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(entry) ? entry : `https://${entry}`);
    } catch {
      throw new Error(
        `${entry} is not a host, host:port or origin to name this service by`,
      );
    }
    if (url.hostname === "") {
      throw new Error(`${entry} names no host for this service`);
    }
    origins.push(url.origin);
  }
  return origins;
};

/**
 * A canonical key for an address literal, so two spellings of one address compare equal (and so an address can
 * never be confused with a name). Returns null for anything that is not an IP literal.
 */
const addressKey = (raw: string): string | null => {
  const v4 = parseIPv4(raw);
  if (v4 != null) return `v4:${v4}`;
  const v6 = parseIPv6(raw);
  return v6 == null ? null : `v6:${v6.join(":")}`;
};

/** The addresses this service answers on, as comparable keys. Empty when none are configured. */
const ownAddressKeys = (addresses: readonly string[] | undefined): Set<string> => {
  const keys = new Set<string>();
  for (const address of addresses ?? []) {
    const key = addressKey(address);
    if (key != null) keys.add(key);
  }
  return keys;
};

/**
 * Resolve this service's own configured hosts to addresses, for the spelling the host comparison cannot see: a
 * target that is our own public IP literal, or an alias hostname that resolves to it. Best effort by design -
 * a lookup that fails leaves the host comparison, which is still correct, in place (and the residual is
 * recorded in THREAT_MODEL.md).
 */
export const resolveSelfAddresses = async (
  origins: readonly string[],
  resolveDns?: ResolveDns,
): Promise<string[]> => {
  const resolver = resolveDns ??
    (netPermissionGranted() ? resolveForValidation : undefined);
  const addresses: string[] = [];
  for (const origin of origins) {
    let hostname: string;
    try {
      hostname = new URL(origin).hostname.replace(/^\[|\]$/g, "");
    } catch {
      continue;
    }
    if (hostname === "") continue;
    // A configured literal needs no lookup: it is its own address.
    if (addressKey(hostname) != null) {
      addresses.push(hostname);
      continue;
    }
    if (resolver == null) continue;
    try {
      addresses.push(...await resolver(hostname));
    } catch {
      // Unresolved: degrade to the host comparison rather than failing requests.
    }
  }
  return addresses;
};

/**
 * Parse a URL this service may fetch, or throw. An unparseable input throws `Error("Invalid URL ...")` -
 * the message fetchContent has always thrown - and everything refused by policy throws BlockedUrlError, so
 * callers can tell a typo from a blocked target apart (server.ts answers 400 and 403 respectively).
 */
export const parseFetchableUrl = async (
  raw: string,
  options?: FetchUrlOptions,
): Promise<URL> => {
  if (URL.canParse(raw) === false) {
    throw new Error(`Invalid URL ${raw}`);
  }
  const url = new URL(raw);

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new BlockedUrlError(`${url.protocol} is not an http(s) target`);
  }
  if (url.username !== "" || url.password !== "") {
    throw new BlockedUrlError(`${url.host} carries credentials`);
  }

  // A URL on this service's own host is not a feed or an article: fetching it is this service requesting
  // itself (full-rss-qxz). That is the amplification loop - one request expands up to ten items, each of
  // which could expand up to ten more - and it needs no private address, so none of the checks below see
  // it. Decided here rather than in feed.ts so it also covers the requester's `?url=`, and every redirect
  // hop for free (guardedFetch re-runs this function per hop).
  if ((options?.selfOrigins ?? []).some((origin) => isOwnHost(url, origin))) {
    throw new BlockedUrlError(`${url.host} is this service's own address`);
  }

  const host = url.hostname.toLowerCase().replace(/\.+$/, "");
  // IPv6 hosts arrive bracketed ("[::1]" - brackets are part of the WHATWG hostname serialisation), so
  // the checks below see the bracketless form; brackets are only legal around IPv6 literals.
  const address = host.startsWith("[") && host.endsWith("]")
    ? host.slice(1, -1)
    : host;
  if (address === "") {
    throw new BlockedUrlError("the URL names no host");
  }
  if (address.includes("%")) {
    // A zone identifier (fe80::1%25eth0): a link-local address with an interface name attached.
    throw new BlockedUrlError(`${address} carries a zone identifier`);
  }

  // The same service, spelled by address instead of by name: our own IP literal, or an alias that resolves to
  // it. The host comparison above cannot see either, and both reopen the loop the host check exists to close
  // (full-rss-647).
  const ownAddresses = ownAddressKeys(options?.selfAddresses);
  if (ownAddresses.size > 0) {
    const literal = addressKey(address);
    if (literal != null && ownAddresses.has(literal)) {
      throw new BlockedUrlError(`${url.host} is this service's own address`);
    }
  }

  const asIPv4 = parseIPv4(address);
  if (asIPv4 != null) {
    if (isBlockedIPv4(BigInt(asIPv4))) {
      throw new BlockedUrlError(
        `${address} is a private, reserved or local address`,
      );
    }
    return url;
  }

  const asIPv6 = address.includes(":") ? parseIPv6(address) : null;
  if (asIPv6 != null) {
    if (isBlockedIPv6(asIPv6)) {
      throw new BlockedUrlError(
        `${address} is a private, reserved or local address`,
      );
    }
    return url;
  }

  if (isBlockedName(address)) {
    throw new BlockedUrlError(`${address} is a local name`);
  }

  const resolveDns = options?.resolveDns;
  if (resolveDns != null) {
    let answers: string[];
    try {
      answers = await resolveDns(address);
    } catch (e) {
      throw new BlockedUrlError(
        `${address} could not be resolved (${
          e instanceof Error ? e.message : String(e)
        })`,
      );
    }
    assertAnswersFetchable(address, answers, ownAddresses);
    return url;
  }

  // No net permission means fetch itself is impossible (and keeps offline tests network-free). If egress
  // is available, a missing DNS API must not silently bypass the private-address check.
  if (!netPermissionGranted()) return url;
  if (typeof Deno.resolveDns !== "function") {
    throw new BlockedUrlError(`${address} cannot be validated without DNS`);
  }
  let answers: string[];
  try {
    answers = await resolveForValidation(address);
  } catch (e) {
    throw new BlockedUrlError(
      `${address} could not be resolved (${
        e instanceof Error ? e.message : String(e)
      })`,
    );
  }
  assertAnswersFetchable(address, answers, ownAddresses);
  return url;
};

const assertAnswersFetchable = (
  host: string,
  answers: string[],
  ownAddresses: Set<string>,
): void => {
  if (answers.length === 0) {
    throw new BlockedUrlError(`${host} resolves nowhere`);
  }
  for (const answer of answers) {
    const key = addressKey(answer);
    if (key != null && ownAddresses.has(key)) {
      // An alias hostname for this same service. Refused for the same reason as the literal spelling.
      throw new BlockedUrlError(
        `${host} resolves to this service's own address ${answer}`,
      );
    }
    const v4 = parseIPv4(answer);
    if (v4 != null) {
      if (isBlockedIPv4(BigInt(v4))) {
        throw new BlockedUrlError(
          `${host} resolves to the private address ${answer}`,
        );
      }
      continue;
    }
    const v6 = answer.includes(":") ? parseIPv6(answer) : null;
    if (v6 == null) {
      throw new BlockedUrlError(
        `${host} resolves to the unusable address ${answer}`,
      );
    }
    if (isBlockedIPv6(v6)) {
      throw new BlockedUrlError(
        `${host} resolves to the private address ${answer}`,
      );
    }
  }
};

// --- the fetch loop -------------------------------------------------------------------------------------

/**
 * Fetch a validated URL, following redirects MANUALLY so every hop is re-validated - the guard would be
 * hollow if https://public.example could 302 to the metadata address. Mirrors fetch-follow for the corner
 * cases: a redirect without a Location header is returned as the final response, and the hop budget stops
 * redirect loops. Each hop gets its own deadline (FETCH_TIMEOUT_MS), so a slow upstream can no longer pin a
 * request forever (the factory's no-timeout finding).
 */
export const guardedFetch = async (
  url: URL | string,
  options?: FetchUrlOptions,
): Promise<Response> => {
  // A caller may construct or mutate a URL itself; URL objects are not proof of prior validation.
  const target = await parseFetchableUrl(
    typeof url === "string" ? url : url.href,
    options,
  );

  let current = target;
  for (let hop = 0;; hop++) {
    options?.signal?.throwIfAborted();
    const signal = options?.signal == null
      ? AbortSignal.timeout(FETCH_TIMEOUT_MS)
      : AbortSignal.any([
        options.signal,
        AbortSignal.timeout(FETCH_TIMEOUT_MS),
      ]);
    const response = await fetch(current, {
      redirect: "manual",
      signal,
    });
    if (REDIRECT_STATUSES.has(response.status) === false) {
      return response;
    }
    const location = response.headers.get("location");
    if (location == null) {
      return response;
    }
    await response.body?.cancel();

    if (hop >= MAX_REDIRECTS) {
      throw new Error(`Too many redirects fetching ${target.href}`);
    }
    let next: URL;
    try {
      next = new URL(location, current);
    } catch {
      throw new BlockedUrlError(
        `redirected to an unusable target (${location})`,
      );
    }
    current = await parseFetchableUrl(next.href, options);
  }
};

/**
 * Read a byte stream as text, refusing to buffer more than maxBytes of it. The factory's unbounded-buffering
 * finding: an upstream could hand this service an arbitrarily large "article" and eat memory; now the read
 * is capped by what is actually consumed, not by what a Content-Length claims.
 *
 * Takes a stream rather than a Response because the same budget has to bound a DECOMPRESSED body too: a
 * small gzip blob can expand without limit, so content.ts pipes its DecompressionStream through here
 * (full-rss-sc4).
 */
export const readCappedStream = async (
  stream: ReadableStream<Uint8Array>,
  maxBytes: number,
): Promise<string> => {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new Error(
        `Response body exceeds the ${maxBytes}-byte budget`,
      );
    }
    chunks.push(value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(merged);
};

/** Read a response body as text under a byte budget. See readCappedStream. */
export const readCappedText = (
  response: Response,
  maxBytes: number,
): Promise<string> =>
  response.body == null
    ? response.text()
    : readCappedStream(response.body, maxBytes);

/**
 * No log line carries more than this many characters of attacker-controlled text. A URL is the content of
 * these lines and a feed may link to a megabyte-long path, so without a bound one item becomes a megabyte of
 * log write per request (full-rss-d2m). Truncation happens LAST, after the redactions below, so the surviving
 * prefix is already sanitized and the marker only counts what was dropped.
 */
export const MAX_LOG_CHARS = 1024;

/**
 * Most characters of attacker-controlled text a log line is ever redacted from: four times the emitted bound,
 * because redactions can only shorten what they touch, so the surviving prefix of a real line is well inside
 * it. The cut here is a CPU bound (full-rss-9ey); MAX_LOG_CHARS is the log-write bound. A value longer than
 * this is redacted as a window - with the userinfo of an authority that runs past the window masked fail
 * closed, so no secret is emitted from text whose end could not be seen (full-rss-al9).
 */
export const MAX_LOG_SCAN = 4 * MAX_LOG_CHARS;

/**
 * Where the authority of an absolute URL ends: at the first '/' or whitespace, exactly the set the regex this
 * replaced excluded (`[^@/\s]`). That set is deliberate and must not grow. An earlier version of this function
 * also stopped at `'`, `"`, `<`, `>` and `\\` on the theory that a URL authority cannot contain them - it can:
 * WHATWG retains all of those in userinfo (percent-encoded in `href`, unencoded in the raw string we are handed),
 * so stopping there meant `sanitizeForLog("http://user:sec'ret@host/x")` returned the password verbatim while
 * the regex had masked it (full-rss-96w). Over-masking is the safe direction (the docblock below says so);
 * under-masking is the bug. Nothing before a '/' can be told apart from userinfo reliably enough to stop early,
 * and text before the '/' is exactly where a password can sit - a '?' or '#' or quote inside it is masked
 * too, which costs nothing: a query or fragment is redacted wholesale a moment later.
 */
const endsAuthority = (value: string, index: number): boolean =>
  value[index] === "/" || value.charCodeAt(index) <= 0x20;

/**
 * Mask the userinfo of every absolute URL in `value` (`user:password@host` becomes `***@host`).
 *
 * One forward scan, and deliberately not a regular expression. The pattern that used to do this
 * (`([a-z][a-z0-9+.-]*:\/\/)([^/@\s:]+):?[^@/\s]*@`) has to find a literal '@' to match at all, so on a value
 * with no '@' in it it backtracked from every start position to the end of the string: O(n^2), measured at
 * 40-100 ms of CPU for ONE ~920-character request line (full-rss-9ey). Every cursor here only moves forward,
 * so the pass is linear in the value it is given.
 *
 * The mask runs over the value rather than a truncated prefix because the '@' can sit past the bound: a cut
 * applied first left `http://user:secretpasswordaaa...` in the log with the secrets intact (full-rss-al9).
 * Reading "absolute URL" liberally is intentional - masking one thing too many is safe, missing one is not.
 *
 * A password may itself contain an '@' (`http://user:p@ss@host/`), so the terminator is the LAST '@' before
 * the authority ends; masking to the first one would leave the rest of the password in the line.
 *
 * `windowed` says the caller already cut the value at MAX_LOG_SCAN, so an authority that runs to the end of
 * the value may be missing the '@' that terminates it. That case fails CLOSED: the whole visible authority
 * is masked, because the alternative is emitting a password prefix we could not see the end of.
 */
const maskUserinfo = (value: string, windowed: boolean): string => {
  // `copyFrom` is how much of the value is already in `masked`; `searchFrom` is where the next "://" search
  // starts. They differ whenever an authority is scanned and found clean: the scan moves past it, the copy
  // does not. Both only ever move forward.
  let masked = "";
  let copyFrom = 0;
  let searchFrom = 0;
  for (;;) {
    const schemeAt = value.indexOf("://", searchFrom);
    if (schemeAt < 0) break;
    const authorityStart = schemeAt + 3;
    let authorityEnd = authorityStart;
    while (authorityEnd < value.length && !endsAuthority(value, authorityEnd)) {
      authorityEnd++;
    }
    let terminator = -1;
    for (
      let at = value.indexOf("@", authorityStart);
      at >= 0 && at < authorityEnd;
      at = value.indexOf("@", at + 1)
    ) {
      terminator = at;
    }
    if (terminator >= 0) {
      masked += `${value.slice(copyFrom, authorityStart)}***@`;
      copyFrom = searchFrom = terminator + 1;
    } else if (windowed && authorityEnd === value.length) {
      masked += `${value.slice(copyFrom, authorityStart)}***@`;
      copyFrom = searchFrom = value.length;
    } else {
      searchFrom = authorityEnd;
    }
    if (searchFrom >= value.length) break;
  }
  return copyFrom === 0 ? value : masked + value.slice(copyFrom);
};

/**
 * Redact everything from the first '?' or '#' on. Incoming URLs are raw, decoded strings, so spaces inside a
 * query cannot be distinguished from the text after the URL: stopping at whitespace would leak later
 * parameters (full-rss-d2m). This also covers invalid URLs quoted in parse errors and fragments without a
 * query. `indexOf` is linear; the `.replace(/[?#].*$/s)` this replaces scanned the tail once per candidate.
 */
const redactQuery = (value: string): string => {
  const cut = value.search(/[?#]/);
  return cut < 0 ? value : `${value.slice(0, cut)}${value[cut]}[redacted]`;
};

/** Longest prefix of `value` that fits in `limit` characters without splitting a surrogate pair. */
const sliceChars = (value: string, limit: number): string => {
  let end = Math.min(limit, value.length);
  const code = value.charCodeAt(end - 1);
  // A high surrogate at the cut has lost its partner: drop it rather than emit half a character.
  if (code >= 0xd800 && code <= 0xdbff) end -= 1;
  return value.slice(0, end);
};

/**
 * One line of attacker-controlled text, safe for a log: control characters (forged log lines, ANSI) are
 * stripped, userinfo is masked, URL queries/fragments are redacted, and the result is bounded in length.
 * Feed and article URLs can carry API keys even when the hostname is public, including inside exception
 * messages from upstream libraries.
 *
 * The redactions run FIRST, each as a single forward pass over a bounded window, and the cut comes LAST - the
 * order every statement of this function's contract already claimed (THREAT_MODEL.md, the MAX_LOG_CHARS note
 * above), and the one that makes the guarantee unconditional: redacting a truncated prefix could miss a
 * delimiter that sits past the cut and log the secret in front of it (full-rss-al9).
 *
 * Cost is bounded by MAX_LOG_SCAN, not by the value: nothing backtracks (full-rss-9ey - the old pattern cost
 * ~100 ms of CPU for ONE ~920-character request line), and the window is far more than the emitted prefix can
 * use. Together with the fail-closed authority rule in maskUserinfo, the bound does not weaken the guarantee.
 */
export const sanitizeForLog = (value: string): string => {
  const windowed = value.length > MAX_LOG_SCAN;
  const scanned = windowed ? sliceChars(value, MAX_LOG_SCAN) : value;
  const cleaned = redactQuery(
    maskUserinfo(
      // \p{Cc} is the control-character class (C0, DEL and C1) - the lint-quiet spelling of the same set.
      scanned.replace(/[\p{Cc}]/gu, ""),
      windowed,
    ),
  );
  const bounded = sliceChars(cleaned, MAX_LOG_CHARS);
  if (bounded === cleaned && !windowed) return cleaned;
  const dropped = value.length - bounded.length;
  return `${bounded}...[truncated ${dropped} chars]`;
};
