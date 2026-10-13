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
  [0x64400000n, 0x657fffffn], // 100.64.0.0/10 carrier-grade NAT
  [0x7f000000n, 0x7fffffffn], // 127.0.0.0/8 loopback
  [0xa9fe0000n, 0xa9feffffn], // 169.254.0.0/16 link-local (incl. cloud metadata)
  [0xac100000n, 0xac1fffffn], // 172.16.0.0/12 private
  [0xc0000000n, 0xc00000ffn], // 192.0.0.0/24 IETF protocol assignments
  [0xc0000200n, 0xc00002ffn], // 192.0.2.0/24 TEST-NET-1
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
  // The embedded IPv4 of a mapped (::ffff:0:0/96), compatible (::x.y.z.w, deprecated but parsed), NAT64
  // (64:ff9b::/96) or 6to4 (2002::/16) address, as one 32-bit value.
  const tail = (groups[6] ?? 0) * 65536 + (groups[7] ?? 0);
  if (
    groups.slice(0, 5).every((group) => group === 0) && groups[5] === 0xffff
  ) {
    return BigInt(tail); // IPv4-mapped
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
  if ((groups[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local
  if ((groups[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((groups[0] & 0xff00) === 0xff00) return true; // ff00::/8 multicast
  const embedded = ipv6ToV4(groups);
  if (embedded != null && isBlockedIPv4(embedded)) return true; // mapped/compatible/NAT64/6to4
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
//   * when the API or the permission to resolve is missing, the layer is skipped rather than the service
//     bricked - the syntactic and redirect checks remain in force.

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

/** Options are for the suites: an explicit resolver is always consulted, permission gate or not. */
export type FetchUrlOptions = { resolveDns?: ResolveDns };

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

  const host = url.hostname.toLowerCase();
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
    assertAnswersFetchable(address, answers);
    return url;
  }

  // The default resolver: consulted only when this process can actually fetch (the unit suites run without
  // net permission, and there egress is impossible anyway). Missing API or missing answers elsewhere fail
  // closed - but a runtime without resolveDns skips the layer rather than refusing every feed.
  if (
    typeof Deno.resolveDns === "function" && netPermissionGranted()
  ) {
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
    assertAnswersFetchable(address, answers);
  }
  return url;
};

const assertAnswersFetchable = (host: string, answers: string[]): void => {
  if (answers.length === 0) {
    throw new BlockedUrlError(`${host} resolves nowhere`);
  }
  for (const answer of answers) {
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
  const target = typeof url === "string"
    ? await parseFetchableUrl(url, options)
    : url; // a URL object is one this module (or its caller via parseFetchableUrl) already validated

  let current = target;
  for (let hop = 0;; hop++) {
    const response = await fetch(current, {
      redirect: "manual",
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
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
 * Read a response body as text, refusing to buffer more than maxBytes of it. The factory's
 * unbounded-buffering finding: an upstream could hand this service an arbitrarily large "article" and eat
 * memory; now the read is capped by what is actually consumed, not by what a Content-Length claims.
 */
export const readCappedText = async (
  response: Response,
  maxBytes: number,
): Promise<string> => {
  if (response.body == null) {
    return response.text();
  }
  const reader = response.body.getReader();
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

/**
 * One line of attacker-controlled text, safe for a log: control characters (forged log lines, ANSI) are
 * stripped and any userinfo in a URL is masked - "https://user:pass@host/" is not something a log should
 * keep (the factory's log-injection findings at the three fetch call sites).
 */
export const sanitizeForLog = (value: string): string =>
  value
    // \p{Cc} is the control-character class (C0, DEL and C1) - the lint-quiet spelling of the same set.
    .replace(/[\p{Cc}]/gu, "")
    .replace(/([a-z][a-z0-9+.-]*:\/\/)([^/@\s:]+):?[^@/\s]*@/gi, "$1***@");
