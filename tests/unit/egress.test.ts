// tests/unit/egress.test.ts — what this service may fetch, and what happens when it fetches it.
//
// egress.ts is the single outbound-fetch point (full-rss-apm): parseFetchableUrl decides targets,
// guardedFetch re-decides at every redirect hop, readCappedText bounds bodies, sanitizeForLog keeps
// attacker-controlled text out of the logs. Everything here is offline:
//   * DNS is exercised through an explicit `resolveDns` stub (parseFetchableUrl's options exist for exactly
//     this — an explicit resolver is always consulted, permission gate or not);
//   * redirects are exercised through a stubbed globalThis.fetch, the same way server.test.ts stubs it;
//   * the DEFAULT resolver is never touched: without --allow-net its permission gate skips the DNS layer,
//     which is the behaviour the integration suites depend on, so one test pins it.
import {
  assert,
  assertEqual,
  assertExcludes,
  assertIncludes,
  assertRejects,
} from "../asserts.ts";
import {
  guardedFetch,
  MAX_LOG_CHARS,
  MAX_LOG_SCAN,
  parseFetchableUrl,
  parseSelfHosts,
  readCappedStream,
  readCappedText,
  type ResolveDns,
  resolveSelfAddresses,
  sanitizeForLog,
} from "../../egress.ts";

/** Replace `fetch` for the duration of `body`, handing the impl the requested URL and init. */
async function withStubbedFetch(
  impl: (url: string, init?: RequestInit) => Response,
  body: () => Promise<void>,
): Promise<void> {
  const original = globalThis.fetch;
  globalThis.fetch =
    ((input: string | URL | Request, init?: RequestInit) =>
      Promise.resolve(
        impl(
          typeof input === "string"
            ? input
            : input instanceof URL
            ? input.href
            : input.url,
          init,
        ),
      )) as typeof globalThis.fetch;
  try {
    await body();
  } finally {
    globalThis.fetch = original;
  }
}

const PUBLIC_A = ["93.184.216.34"];
const PUBLIC_AAAA = ["2606:4700:10::ac42:93f3"];
const resolver = (answers: string[]) => () => Promise.resolve(answers);

/**
 * Model a runtime WITH outbound networking and a chosen `Deno.resolveDns`, for the paths that only the
 * DEFAULT resolver reaches (an explicit `resolveDns` option bypasses it entirely). Used by the tests that
 * pin what a partial DNS failure does - nothing is fetched and no real lookup happens.
 */
async function withDefaultResolver(
  resolveDns: (hostname: string, type: "A" | "AAAA") => Promise<string[]>,
  body: () => Promise<void>,
): Promise<void> {
  const dns = Object.getOwnPropertyDescriptor(Deno, "resolveDns");
  const permission = Object.getOwnPropertyDescriptor(
    Deno.permissions,
    "querySync",
  );
  Object.defineProperty(Deno, "resolveDns", {
    configurable: true,
    value: resolveDns,
  });
  Object.defineProperty(Deno.permissions, "querySync", {
    configurable: true,
    value: () => ({ state: "granted" }),
  });
  try {
    await body();
  } finally {
    if (dns) Object.defineProperty(Deno, "resolveDns", dns);
    else Reflect.deleteProperty(Deno, "resolveDns");
    if (permission) {
      Object.defineProperty(Deno.permissions, "querySync", permission);
    } else Reflect.deleteProperty(Deno.permissions, "querySync");
  }
}

// --- parseFetchableUrl: what may be fetched ------------------------------------------------------------

Deno.test("a public http(s) URL with public answers parses", async () => {
  const url = await parseFetchableUrl("https://example.com/post/1?x=2", {
    resolveDns: resolver(PUBLIC_A),
  });
  assertEqual(url.hostname, "example.com", "hostname");
});

Deno.test("an unparseable URL keeps the historical Invalid URL error", async () => {
  await assertRejects(
    () => parseFetchableUrl("not a url"),
    "Invalid URL not a url",
    "parseFetchableUrl",
  );
});

Deno.test("non-http schemes are blocked", async () => {
  for (const scheme of ["file:///etc/passwd", "ftp://example.com/x"]) {
    await assertRejects(
      () => parseFetchableUrl(scheme),
      "Blocked URL",
      `the ${scheme.split(":")[0]} scheme`,
    );
  }
});

Deno.test("a URL carrying credentials is blocked", async () => {
  await assertRejects(
    () =>
      parseFetchableUrl("https://user:secret@example.com/feed", {
        resolveDns: resolver(PUBLIC_A),
      }),
    "credentials",
    "parseFetchableUrl",
  );
});

Deno.test("private and reserved IPv4 literals are blocked, public ones are not", async () => {
  const blocked = [
    "http://0.0.0.0/",
    "http://10.0.0.5/",
    "http://100.64.0.1/",
    "http://100.127.255.254/",
    "http://127.0.0.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://172.16.0.1/",
    "http://172.31.255.254/",
    "http://192.0.0.1/",
    "http://192.0.2.1/",
    "http://192.88.99.1/", // 6to4 relay anycast
    "http://192.168.1.1/",
    "http://198.18.0.1/",
    "http://198.51.100.1/",
    "http://203.0.113.1/",
    "http://224.0.0.1/",
    "http://240.0.0.1/",
    "http://255.255.255.255/",
    // Non-dotted spellings the URL parser canonicalises to loopback:
    "http://2130706433/",
    "http://0x7f000001/",
    "http://127.1/",
  ];
  for (const url of blocked) {
    await assertRejects(
      () => parseFetchableUrl(url, { resolveDns: resolver(PUBLIC_A) }),
      "Blocked URL",
      `${url} to be blocked`,
    );
  }
  // The neighbours of the private ranges must stay fetchable.
  assert(
    await parseFetchableUrl("http://172.32.0.1/", {
      resolveDns: resolver(PUBLIC_A),
    }) != null,
    "172.32.0.1 (just past 172.16/12) to be allowed",
  );
  assert(
    await parseFetchableUrl("http://100.63.255.255/", {
      resolveDns: resolver(PUBLIC_A),
    }) != null,
    "100.63.255.255 (just before 100.64/10) to be allowed",
  );
  assert(
    await parseFetchableUrl("http://100.128.0.1/", {
      resolveDns: resolver(PUBLIC_A),
    }) != null,
    "100.128.0.1 (just past 100.64/10) to be allowed",
  );
});

Deno.test("private and reserved IPv6 literals are blocked, public ones are not", async () => {
  // The explicit resolver makes a fall-through loud: a bracketed literal that somehow failed to parse as an
  // address would be treated as a name, resolved to a public answer, and allowed - failing this test.
  const blocked = [
    "http://[::]/",
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:10.0.0.1]/",
    // IPv4-translated (::ffff:0:0:0/96): "::ffff:0:127.0.0.1" parses as ::ffff:0:7f00:1, which is the
    // same loopback address reached through the RFC 2765 form.
    "http://[::ffff:0:127.0.0.1]/",
    "http://[::ffff:0:7f00:1]/",
    "http://[::ffff:0:169.254.169.254]/",
    "http://[fe80::1]/",
    "http://[fec0::1]/", // deprecated site-local
    "http://[fec0:1::1]/",
    "http://[fc00::1]/",
    "http://[fd12:3456:789a::1]/",
    "http://[2001:db8::1]/",
    "http://[2001:2::1]/", // benchmarking
    "http://[2001:2:0:1::1]/",
    "http://[ff02::1]/",
    "http://[64:ff9b::127.0.0.1]/",
    "http://[2002:0a00:0001::1]/", // 6to4 of 10.0.0.1
  ];
  for (const url of blocked) {
    await assertRejects(
      () => parseFetchableUrl(url, { resolveDns: resolver(PUBLIC_A) }),
      "Blocked URL",
      `${url} to be blocked`,
    );
  }
  // A zone identifier ("[fe80::1%25eth0]") never parses as a URL in this toolchain at all, so it is
  // refused with the historical Invalid URL error rather than the blocked-target one. Either way it is
  // not fetchable; egress.ts keeps its own % check for hosts that might arrive by other roads.
  await assertRejects(
    () => parseFetchableUrl("http://[fe80::1%25eth0]/"),
    "Invalid URL",
    "a zoned IPv6 literal",
  );
  assert(
    await parseFetchableUrl("http://[2606:4700:10::ac42:93f3]/", {
      resolveDns: resolver(PUBLIC_A),
    }) != null,
    "a global unicast IPv6 address to be allowed",
  );
  // The neighbours of the newly reserved ranges must stay fetchable.
  for (
    const url of [
      "http://192.88.98.1/",
      "http://192.88.100.1/",
      "http://[2001:3::1]/",
      "http://[::ffff:0:8.8.8.8]/",
    ]
  ) {
    assert(
      await parseFetchableUrl(url, { resolveDns: resolver(PUBLIC_A) }) != null,
      `${url} to be allowed`,
    );
  }
});

Deno.test("Teredo addresses are judged by the client IPv4 they carry, which is stored inverted", async () => {
  // 2001:0000:<server IPv4>:<flags + port>:<client IPv4, bitwise NOT> (RFC 4380). The last 32 bits are the
  // complement of the client address, so a checker that read the stored bits literally would block every
  // client below 240.0.0.0/4 instead of the private ones (full-rss-sc4).
  for (
    const [url, why] of [
      // RFC 4380's own example: stored 3fff:fdd2 is client 192.0.2.45, TEST-NET-1.
      ["http://[2001:0:4136:e378:8000:63bf:3fff:fdd2]/", "documentation range"],
      // Stored f5ff:fffa is client 10.0.0.5.
      ["http://[2001:0:4136:e378:8000:63bf:f5ff:fffa]/", "private range"],
      // Stored ff00:0001 is client 0.0.255.254, "this network".
      ["http://[2001:0:4136:e378:8000:63bf:ff00:0001]/", "this-network range"],
    ] as const
  ) {
    await assertRejects(
      () => parseFetchableUrl(url, { resolveDns: resolver(PUBLIC_A) }),
      "Blocked URL",
      `a Teredo address whose client IPv4 is in the ${why} to be blocked`,
    );
  }
  // Stored f7f7:f7f7 is client 8.8.8.8. It is also inside 240.0.0.0/4 as stored, which is exactly why the
  // stored bits must not be tested: doing so would refuse a public Teredo tunnel to a public address.
  assert(
    await parseFetchableUrl("http://[2001:0:4136:e378:8000:63bf:f7f7:f7f7]/", {
      resolveDns: resolver(PUBLIC_A),
    }) != null,
    "a Teredo address tunnelling to a public IPv4 to be allowed",
  );
  // The prefix check must stay narrow: 2001:2::/48 benchmarking and 2001:db8::/32 documentation are not
  // Teredo, and neither are the global unicast addresses just past it.
  assert(
    await parseFetchableUrl("http://[2001:1::1]/", {
      resolveDns: resolver(PUBLIC_A),
    }) != null,
    "2001:1::/32 (past the Teredo prefix) to be allowed",
  );
});

Deno.test("local names are blocked before any DNS lookup", async () => {
  let resolved = false;
  const spy = () => {
    resolved = true;
    return Promise.resolve(PUBLIC_A);
  };
  for (
    const host of [
      "localhost",
      "box.localhost",
      "nas.local",
      "api.internal",
      "localhost.",
      "box.localhost.",
      "nas.local.",
      "api.internal..",
    ]
  ) {
    await assertRejects(
      () => parseFetchableUrl(`https://${host}/`, { resolveDns: spy }),
      "local name",
      `${host} to be blocked`,
    );
  }
  assert(
    resolved === false,
    "no DNS lookup for syntactically local names, including trailing dots",
  );
});

Deno.test("a name resolving to a private address is blocked, mixed answers included", async () => {
  await assertRejects(
    () =>
      parseFetchableUrl("https://box.attacker.tld/", {
        resolveDns: resolver(["10.0.0.5"]),
      }),
    "resolves to the private address",
    "a wholly private answer set",
  );
  await assertRejects(
    () =>
      parseFetchableUrl("https://box.attacker.tld/", {
        resolveDns: resolver([...PUBLIC_A, "192.168.1.1"]),
      }),
    "resolves to the private address",
    "a mixed answer set (one private record is enough to refuse)",
  );
  await assertRejects(
    () =>
      parseFetchableUrl("https://box.attacker.tld/", {
        resolveDns: resolver(["fd00::1"]),
      }),
    "resolves to the private address",
    "a private IPv6 answer",
  );
});

Deno.test("a failing or empty resolver blocks the name (fail closed)", async () => {
  await assertRejects(
    () =>
      parseFetchableUrl("https://gone.example/", {
        resolveDns: () => Promise.reject(new Error("NXDOMAIN")),
      }),
    "could not be resolved",
    "a rejecting resolver",
  );
  await assertRejects(
    () =>
      parseFetchableUrl("https://gone.example/", { resolveDns: resolver([]) }),
    "resolves nowhere",
    "an empty answer set",
  );
});

Deno.test("a rejected A lookup refuses the URL instead of validating only the AAAA answers (full-rss-2h8)", async () => {
  // The attack: make the A query fail (SERVFAIL, a timeout, a rate limit) and answer AAAA with something
  // public. The old all-settled merge dropped the rejection, so the URL was accepted with no IPv4 answer
  // ever checked, and getaddrinfo at fetch time could still return the private A record.
  await withDefaultResolver(
    (_hostname, type) =>
      type === "A"
        ? Promise.reject(new Error("proto error: SERVFAIL"))
        : Promise.resolve(PUBLIC_AAAA),
    async () => {
      await assertRejects(
        () => parseFetchableUrl("https://half-answers.example/feed"),
        "A lookup failed",
        "a rejected A query with a public AAAA answer",
      );
    },
  );
});

Deno.test("a rejected AAAA lookup refuses the URL the same way", async () => {
  await withDefaultResolver(
    (_hostname, type) =>
      type === "AAAA"
        ? Promise.reject(new Error("proto error: timeout"))
        : Promise.resolve(PUBLIC_A),
    async () => {
      await assertRejects(
        () => parseFetchableUrl("https://half-answers.example/feed"),
        "AAAA lookup failed",
        "a rejected AAAA query with a public A answer",
      );
    },
  );
});

Deno.test("a host with only one address family stays fetchable (NODATA is not a failure)", async () => {
  // Deno reports "no records of that type" as a NotFound rejection, not an empty array (measured:
  // ipv4.google.com has no AAAA, ipv6.google.com has no A). Failing closed on that would refuse every
  // v4-only and v6-only host, so the distinction is the fix, not a tolerance.
  const noRecords = () =>
    Promise.reject(new Deno.errors.NotFound("proto error: no records found"));
  await withDefaultResolver(
    (_hostname, type) => type === "A" ? Promise.resolve(PUBLIC_A) : noRecords(),
    async () => {
      assertEqual(
        (await parseFetchableUrl("https://v4-only.example/feed")).hostname,
        "v4-only.example",
        "an A-only host is still fetchable",
      );
    },
  );
  await withDefaultResolver(
    (_hostname, type) =>
      type === "AAAA" ? Promise.resolve(PUBLIC_AAAA) : noRecords(),
    async () => {
      assertEqual(
        (await parseFetchableUrl("https://v6-only.example/feed")).hostname,
        "v6-only.example",
        "an AAAA-only host is still fetchable",
      );
    },
  );
  await withDefaultResolver(
    () => noRecords(),
    async () => {
      await assertRejects(
        () => parseFetchableUrl("https://no-addresses.example/feed"),
        "resolves nowhere",
        "a host with no records of either family",
      );
    },
  );
});

Deno.test("a private answer in the surviving family still blocks", async () => {
  // The merge is not the only guard: when one family is NODATA the other family's answers are classified
  // exactly as before, so the 2h8 fix cannot be read as "A-only hosts skip the check".
  await withDefaultResolver(
    (_hostname, type) =>
      type === "A" ? Promise.resolve(["10.0.0.5"]) : Promise.reject(
        new Deno.errors.NotFound("proto error: no records found"),
      ),
    async () => {
      await assertRejects(
        () => parseFetchableUrl("https://v4-private.example/feed"),
        "resolves to the private address",
        "a private IPv4 answer on an A-only host",
      );
    },
  );
});

Deno.test("a missing DNS API fails closed when outbound networking is available", async () => {
  // Model a runtime without resolveDns but with net permission; no actual lookup or fetch is performed.
  const dns = Object.getOwnPropertyDescriptor(Deno, "resolveDns");
  const permission = Object.getOwnPropertyDescriptor(
    Deno.permissions,
    "querySync",
  );
  Object.defineProperty(Deno, "resolveDns", {
    configurable: true,
    value: undefined,
  });
  Object.defineProperty(Deno.permissions, "querySync", {
    configurable: true,
    value: () => ({ state: "granted" }),
  });
  try {
    await assertRejects(
      () => parseFetchableUrl("https://public-looking.example/feed"),
      "cannot be validated without DNS",
      "a public-looking name without DNS validation",
    );
    // Literal addresses still go through their own classification without needing DNS.
    assertEqual(
      (await parseFetchableUrl("https://93.184.216.34/feed")).hostname,
      "93.184.216.34",
      "a public literal remains fetchable",
    );
  } finally {
    if (dns) Object.defineProperty(Deno, "resolveDns", dns);
    else Reflect.deleteProperty(Deno, "resolveDns");
    if (permission) {
      Object.defineProperty(Deno.permissions, "querySync", permission);
    } else Reflect.deleteProperty(Deno.permissions, "querySync");
  }
});

Deno.test("the default resolver's DNS layer is skipped without net permission", async () => {
  // The unit and integration suites run under `deno test --allow-env`: no net permission, so egress is
  // impossible and the default resolver's permission gate must skip the DNS layer rather than fail every
  // hostname. This is the behaviour the server suite's stubbed-fetch tests rely on.
  const url = await parseFetchableUrl("https://example.com/feed.xml");
  assertEqual(url.hostname, "example.com", "hostname");
});

Deno.test("a short log value is unchanged by the length bound", () => {
  assertEqual(
    sanitizeForLog("Failed to fetch the feed: boom"),
    "Failed to fetch the feed: boom",
    "a line under the bound is untouched (no marker, no truncation)",
  );
});

Deno.test("an oversized attacker-controlled log value is truncated with a count", () => {
  // A feed may link to a megabyte-long path, and the URL is the log line: unbounded, one item is a
  // megabyte of log write per request (full-rss-d2m).
  const line = sanitizeForLog("https://evil.example/" + "a".repeat(100_000));
  assertIncludes(line, "https://evil.example/", "the useful prefix survives");
  assertIncludes(line, "...[truncated ", "the marker says it was cut");
  assertIncludes(line, "chars]", "the marker says how much");
  assert(
    line.length <= MAX_LOG_CHARS + 40,
    `the log line stays near the bound, got ${line.length} chars`,
  );
});

Deno.test("truncation keeps the redactions: a secret tail is still not logged", () => {
  // The redaction happens before the cut, so the query is already gone; what survives the cut is the prefix
  // of the path, which holds no secret. (A short value loses nothing: see the test above.)
  const long = "https://evil.example/" + "a".repeat(100_000) +
    "?token=secret-123";
  const line = sanitizeForLog(long);
  assertExcludes(line, "secret-123", "query redaction survives truncation");
  assertExcludes(line, "?token", "the query is redacted, not just cut");
  assertIncludes(line, "...[truncated ", "the cut is announced");
});

Deno.test("truncation never splits a surrogate pair", () => {
  // One leading char shifts the cut into the middle of an emoji, which would otherwise emit half a code
  // point (a lone surrogate) into the log.
  const line = sanitizeForLog("a" + "😀".repeat(2000));
  const prefix = line.slice(0, line.indexOf("...[truncated"));
  for (let i = 0; i < prefix.length; i++) {
    const code = prefix.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = prefix.charCodeAt(i + 1);
      assert(
        next >= 0xdc00 && next <= 0xdfff,
        `no lone high surrogate at index ${i}`,
      );
      i++;
    } else {
      assert(
        code < 0xdc00 || code > 0xdfff,
        `no lone low surrogate at index ${i}`,
      );
    }
  }
});

Deno.test("a long log value costs bounded time, not quadratic", () => {
  // The redactions are single forward passes over at most MAX_LOG_SCAN characters, so the cost of a log value
  // does not grow with the value at all (full-rss-9ey). The regression this guards: the userinfo pattern had
  // to find a literal '@', so on an '@'-free value it backtracked from every start position to the end -
  // measured at 40-100 ms of CPU for ONE ~920-character request line, and 161 SECONDS at 100k characters, on
  // the path every request takes before it fetches anything. Both sizes below measure ~0.01 ms, so the budget
  // does not fail on a slow machine; a return to the old order or the old pattern misses it by 10^4-10^6.
  const budget = 200;
  for (const size of [100_000, 5_000_000]) {
    const value = "https://evil.example/" + "a".repeat(size);
    sanitizeForLog(value); // warm up: JIT and the first use of each pattern
    const started = performance.now();
    sanitizeForLog(value);
    const elapsed = performance.now() - started;
    assert(
      elapsed < budget,
      `one ${size}-char log value to sanitize in under ${budget}ms, took ${
        Math.round(elapsed)
      }ms`,
    );
  }
});

// --- self-reference: this service may not fetch itself ------------------------------------------------
//
// A feed can link back at the service that is expanding it, and one expansion is up to ten more: that is an
// amplification loop, and no private address is involved, so none of the address checks above catch it. The
// caller passes the hosts it answers on (`selfOrigins`) and their addresses (`selfAddresses`), both from
// CONFIGURATION rather than from the request, which is client-controlled (full-rss-647); anything on either is
// refused (full-rss-qxz).

Deno.test("a URL on this service's own host is refused, whatever its scheme, path or spelling", async () => {
  for (
    const url of [
      "https://service.test/?url=https%3A%2F%2Fevil.test%2Ffeed.xml",
      "http://service.test/feed.xml",
      "https://SERVICE.test/expand?url=x",
      // The root-anchored (FQDN) spelling of the same DNS host: `new URL` keeps the terminal dot, so a
      // naive host comparison let one appended character through (full-rss-pbz).
      "https://service.test./feed.xml",
      "https://SERVICE.test./expand?url=x",
    ]
  ) {
    await assertRejects(
      () => parseFetchableUrl(url, { selfOrigins: ["https://service.test"] }),
      "this service's own address",
      `${url} to be refused as this service itself`,
    );
  }
});

Deno.test("an origin written with a terminal dot is still this service", async () => {
  // The caller's own origin spelling must not swap the hole around: both sides are normalised.
  await assertRejects(
    () =>
      parseFetchableUrl("https://service.test/feed.xml", {
        selfOrigins: ["https://service.test."],
      }),
    "this service's own address",
    "a terminal-dot origin refuses the plain host",
  );
});

Deno.test("the own-host check is exact: another port, host or subdomain is not this service", async () => {
  for (
    const url of [
      "https://service.test:8443/feed.xml",
      "https://other.test/feed.xml",
      "https://sub.service.test/feed.xml",
      // A terminal dot on ANOTHER host is that host's FQDN form, not this service.
      "https://other.test./feed.xml",
      // ... and the same host on a different port is a different service.
      "https://service.test.:8443/feed.xml",
    ]
  ) {
    const parsed = await parseFetchableUrl(url, {
      resolveDns: resolver(PUBLIC_A),
      selfOrigins: ["https://service.test"],
    });
    assertEqual(parsed.href, url, `${url} stays fetchable`);
  }
});

Deno.test("no self origins configured means the check never fires", async () => {
  const url = await parseFetchableUrl("https://service.test/feed.xml");
  assertEqual(url.hostname, "service.test", "hostname");
});

Deno.test("a redirect back to this service's own host is refused before that hop is fetched", async () => {
  const fetched: string[] = [];
  await withStubbedFetch(
    (url) => {
      fetched.push(url);
      return new Response("", {
        status: 302,
        headers: {
          location: "https://service.test/?url=https%3A%2F%2Fevil.test%2F",
        },
      });
    },
    async () => {
      await assertRejects(
        () =>
          guardedFetch("https://elsewhere.test/feed.xml", {
            selfOrigins: ["https://service.test"],
          }),
        "this service's own address",
        "a redirect aimed back at this service",
      );
      assertEqual(fetched.length, 1, "only the off-service hop was fetched");
    },
  );
});

Deno.test("a redirect to this service by a terminal-dot spelling is refused too", async () => {
  const fetched: string[] = [];
  await withStubbedFetch(
    (url) => {
      fetched.push(url);
      return new Response("", {
        status: 302,
        headers: { location: "https://service.test./?url=x" },
      });
    },
    async () => {
      await assertRejects(
        () =>
          guardedFetch("https://elsewhere.test/feed.xml", {
            selfOrigins: ["https://service.test"],
          }),
        "this service's own address",
        "a terminal-dot redirect back at this service",
      );
      assertEqual(fetched.length, 1, "only the off-service hop was fetched");
    },
  );
});

Deno.test("this service's own IP literal is refused", async () => {
  // The host comparison is one exact key, so it cannot see the same service spelled by address. That spelling
  // reopened the loop (full-rss-647).
  await assertRejects(
    () =>
      parseFetchableUrl("http://93.184.216.34/?url=x", {
        selfAddresses: ["93.184.216.34"],
      }),
    "this service's own address",
    "the IP-literal spelling of this service",
  );
  // An address that is NOT ours stays fetchable, and so does a literal when no self address is configured.
  const other = await parseFetchableUrl("https://93.184.216.35/feed.xml", {
    selfAddresses: ["93.184.216.34"],
  });
  assertEqual(
    other.href,
    "https://93.184.216.35/feed.xml",
    "another literal is fetchable",
  );
  const literal = await parseFetchableUrl("https://93.184.216.34/feed.xml", {
    selfAddresses: [],
  });
  assertEqual(
    literal.href,
    "https://93.184.216.34/feed.xml",
    "no self address configured: no refusal",
  );
});

Deno.test("an IP literal is refused when this deployment's own addresses are unknown", async () => {
  // `selfAddresses: null` is how the server says "this deployment has addresses, but the lookup did not give
  // them to me". The old code skipped the literal comparison on an empty answer, so the guard vanished exactly
  // when it was needed and nothing said so (full-rss-pxq). An unknown identity cannot rule a literal out, so it
  // is refused - and only the literal spelling, because a hostname still gets every check below it.
  const options = {
    resolveDns: resolver(PUBLIC_A),
    selfOrigins: ["https://service.example"],
    selfAddresses: null,
  };
  await assertRejects(
    () => parseFetchableUrl("https://93.184.216.34/feed.xml", options),
    "cannot be ruled out as this service itself",
    "a public IPv4 literal with our addresses unknown",
  );
  await assertRejects(
    () =>
      parseFetchableUrl(
        "http://[2606:2800:220:1:248:1893:25c8:1946]/x",
        options,
      ),
    "cannot be ruled out as this service itself",
    "a public IPv6 literal with our addresses unknown",
  );
  // A hostname is unaffected: it is judged by host and by its resolved addresses, both of which still work.
  const named = await parseFetchableUrl(
    "https://example.com/feed.xml",
    options,
  );
  assertEqual(
    named.href,
    "https://example.com/feed.xml",
    "a hostname is still fetchable while our own addresses are unknown",
  );
  // And a range-blocked literal keeps its more specific refusal: the address policy comes first.
  await assertRejects(
    () => parseFetchableUrl("http://192.168.1.10/feed.xml", options),
    "private, reserved or local address",
    "a private literal is still refused for being private",
  );
});

Deno.test("a shared CDN address is not an identity: an unrelated feed on our address is fetchable", () => {
  // Regression (full-rss-og0): comparing a target's RESOLVED addresses against ours refused every ordinary
  // feed behind the same CDN or reverse proxy, which is most of them for a hosted deployment. Only the
  // literal spelling is judged by address now.
  return (async () => {
    const shared = resolver(["93.184.216.34"]);
    const options = {
      resolveDns: shared,
      selfOrigins: ["https://service.example"],
      selfAddresses: ["93.184.216.34"],
    };
    await assertRejects(
      () => parseFetchableUrl("https://service.example/feed", options),
      "this service's own address",
      "the service itself is still refused, by host",
    );
    const unrelated = await parseFetchableUrl(
      "https://unrelated.example/feed",
      options,
    );
    assertEqual(
      unrelated.href,
      "https://unrelated.example/feed",
      "an unrelated feed on the same address stays fetchable",
    );
  })();
});

Deno.test("a self address is compared by value, not by spelling", async () => {
  // `new URL` canonicalises a literal, and so must the comparison: an IPv6 self address must be refused in any
  // of its compressed spellings.
  await assertRejects(
    () =>
      parseFetchableUrl("http://[2001:db8::1]/x", {
        selfAddresses: ["2001:db8:0:0:0:0:0:1"],
      }),
    "this service's own address",
    "the uncompressed spelling of our own IPv6 address",
  );
});

Deno.test("self hosts come from configuration, parsed strictly", () => {
  assertEqual(parseSelfHosts(undefined).length, 0, "unset means unconfigured");
  assertEqual(parseSelfHosts("").length, 0, "empty means unconfigured");
  assertEqual(
    parseSelfHosts("service.test").join(),
    "https://service.test",
    "a bare host",
  );
  assertEqual(
    parseSelfHosts("service.test,https://www.service.test/ ,").join(),
    "https://service.test,https://www.service.test",
    "a list, with a trailing comma and a trailing slash",
  );
  assertEqual(
    parseSelfHosts("http://service.test:8080").join(),
    "http://service.test:8080",
    "an explicit port is kept",
  );
  assertEqual(
    parseSelfHosts("https://service.test:443").join(),
    "https://service.test",
    "a default port is dropped, so the comparison is by host:port",
  );
  // A typo must fail loudly: a silently dropped entry would disable the guard while looking configured.
  // (Whitespace separates entries, so the smallest typo is a malformed port.) The same rule must catch an
  // entry that parses but does not MEAN the host it looks like.
  for (
    const bad of [
      "service.test:notaport",
      // `new URL` discards the userinfo, so this would configure the ATTACKER's host and leave the real
      // service fetchable with no warning (full-rss-56w).
      "https://service.test@attacker.test",
      "https://service.test/some/path",
      "https://service.test/?x=1",
      "https://service.test#frag",
      // A non-http(s) scheme parses cleanly and then yields the OPAQUE origin "null" (or, worse, a foreign
      // scheme's origin), which can never match a request: the guard matched nothing while the config looked
      // set, and the real public service stayed recursively expandable (full-rss-pm1).
      "file://service.test",
      "data://service.test",
      "ftp://service.test",
    ]
  ) {
    let threw = false;
    try {
      parseSelfHosts(bad);
    } catch {
      threw = true;
    }
    assert(threw, `${bad} is refused rather than reinterpreted`);
  }
});

Deno.test("resolveSelfAddresses uses a literal as its own address and resolves a name", async () => {
  // `?.join()` so a null (unknown) answer fails the equality instead of the type check: these two shapes must
  // be known, and the tests below pin what makes a set unknown.
  assertEqual(
    (await resolveSelfAddresses(["http://93.184.216.34"]))?.join(),
    "93.184.216.34",
    "a configured literal needs no lookup",
  );
  assertEqual(
    (await resolveSelfAddresses(
      ["https://service.test"],
      resolver(["93.184.216.34"]),
    ))?.join(),
    "93.184.216.34",
    "a configured name is resolved through the injected resolver",
  );
  // A lookup that fails makes the whole set unknown rather than answering with the rest (full-rss-0b2).
  assertEqual(
    await resolveSelfAddresses(
      ["https://gone.test"],
      () => Promise.reject(new Error("NXDOMAIN")),
    ),
    null,
    "a failed lookup is an unknown, not a partial answer",
  );
  // No configured hosts at all is complete knowledge - of nothing.
  assertEqual(
    (await resolveSelfAddresses([]))?.join(),
    "",
    "no origins configured is an empty, complete answer",
  );
});

Deno.test("a partial self-address resolution is an unknown, not a partial answer", async () => {
  // Regression (full-rss-0b2): with two configured hosts and a transient DNS failure on one, the old code
  // returned the surviving host's address alone. The caller cannot tell that from a complete answer, so the
  // failing host's own IP-literal spelling went unguarded for the whole cache TTL - the reviewer's driver
  // reproduced it as PARTIAL/ALLOW. The bead's exact repro shape, as a unit test:
  const stub: ResolveDns = (hostname) =>
    hostname === "good.example"
      ? Promise.resolve(["93.184.216.34"])
      : Promise.reject(new Error("SERVFAIL"));
  assertEqual(
    await resolveSelfAddresses(
      ["https://good.example", "https://bad.example"],
      stub,
    ),
    null,
    "one failing host among several makes the whole set unknown",
  );
  // A configured literal is always known without a lookup, but it does not make a failed sibling complete:
  // the set is only usable when EVERY configured host is known.
  assertEqual(
    await resolveSelfAddresses(
      ["http://93.184.216.34", "https://bad.example"],
      stub,
    ),
    null,
    "a known literal next to a failing name is still an unknown set",
  );
  assertEqual(
    (await resolveSelfAddresses(["https://good.example"], stub))?.join(),
    "93.184.216.34",
    "every host resolved is a complete answer",
  );
});

Deno.test("a self host that resolves to no records is an unknown, not a known-empty answer", async () => {
  // NODATA on our own name is a misconfiguration, not knowledge: an answer of zero records leaves this
  // deployment's address unknown, so the set is null and the literal guard fails closed (full-rss-0b2).
  assertEqual(
    await resolveSelfAddresses(["https://empty.test"], resolver([])),
    null,
    "a name that answers with no records is not a known address",
  );
});

// --- guardedFetch: redirects re-validated ----------------------------------------------------------------

Deno.test("a direct 200 is returned as-is and fetched with manual redirects and a timeout", async () => {
  await withStubbedFetch(
    (url, init) => {
      assertEqual(url, "https://example.com/feed.xml", "the fetched URL");
      assertEqual(init?.redirect, "manual", "the redirect mode");
      assert(init?.signal instanceof AbortSignal, "a per-request abort signal");
      return new Response("<feed/>", { status: 200 });
    },
    async () => {
      const res = await guardedFetch("https://example.com/feed.xml");
      assertEqual(res.status, 200, "status");
      assertEqual(await res.text(), "<feed/>", "body");
    },
  );
});

Deno.test("a URL object is validated before the first fetch", async () => {
  let calls = 0;
  await withStubbedFetch(
    () => {
      calls++;
      return new Response("unexpected");
    },
    async () => {
      for (
        const raw of [
          "http://127.0.0.1/private",
          "http://169.254.169.254/latest/meta-data/",
          "https://user:password@example.com/",
          "file:///etc/passwd",
        ]
      ) {
        await assertRejects(
          () => guardedFetch(new URL(raw)),
          "Blocked URL",
          `URL object ${raw} is refused`,
        );
      }
      assertEqual(calls, 0, "no forbidden URL reached fetch");
      const res = await guardedFetch(new URL("https://example.com/feed.xml"));
      assertEqual(res.status, 200, "valid URL objects still fetch");
      assertEqual(calls, 1, "the valid target reached fetch");
    },
  );
});

Deno.test("a public-to-public redirect is followed", async () => {
  await withStubbedFetch(
    (url) =>
      url === "https://cdn.example/feed.xml"
        ? new Response("", {
          status: 301,
          headers: { location: "https://origin.example/feed.xml" },
        })
        : new Response("<feed/>", { status: 200 }),
    async () => {
      const res = await guardedFetch("https://cdn.example/feed.xml");
      assertEqual(res.status, 200, "status after the redirect");
    },
  );
});

Deno.test("a redirect to a private network is refused, even mid-chain", async () => {
  await withStubbedFetch(
    () =>
      new Response("", {
        status: 302,
        headers: { location: "http://169.254.169.254/latest/meta-data/" },
      }),
    async () => {
      await assertRejects(
        () => guardedFetch("https://example.com/feed.xml"),
        "Blocked URL",
        "a redirect straight at the metadata address",
      );
    },
  );
  await withStubbedFetch(
    (url) =>
      url === "https://hop1.example/"
        ? new Response("", {
          status: 302,
          headers: { location: "https://hop2.example/" },
        })
        : url === "https://hop2.example/"
        ? new Response("", {
          status: 302,
          headers: { location: "http://10.0.0.5/admin" },
        })
        : new Response("?", { status: 200 }),
    async () => {
      await assertRejects(
        () => guardedFetch("https://hop1.example/"),
        "private",
        "a redirect arriving one hop into the chain",
      );
    },
  );
});

Deno.test("a redirect to credentials or a non-http scheme is refused", async () => {
  await withStubbedFetch(
    () =>
      new Response("", {
        status: 301,
        headers: { location: "http://user:pass@example.com/" },
      }),
    async () => {
      await assertRejects(
        () => guardedFetch("https://example.com/"),
        "credentials",
        "a redirect carrying userinfo",
      );
    },
  );
  await withStubbedFetch(
    () =>
      new Response("", {
        status: 301,
        headers: { location: "file:///etc/passwd" },
      }),
    async () => {
      await assertRejects(
        () => guardedFetch("https://example.com/"),
        "Blocked URL",
        "a redirect to a non-http scheme",
      );
    },
  );
});

Deno.test("a relative redirect is resolved against the redirecting URL", async () => {
  await withStubbedFetch(
    (url) =>
      url === "https://example.com/posts"
        ? new Response("", {
          status: 301,
          headers: { location: "/feed.xml" },
        })
        : new Response("<feed/>", { status: 200 }),
    async () => {
      const res = await guardedFetch("https://example.com/posts");
      assertEqual(res.status, 200, "status after following /feed.xml");
    },
  );
});

Deno.test("a redirect loop is stopped by the hop budget", async () => {
  await withStubbedFetch(
    () =>
      new Response("", {
        status: 302,
        headers: { location: "https://loop.example/again" },
      }),
    async () => {
      await assertRejects(
        () => guardedFetch("https://loop.example/start"),
        "Too many redirects",
        "an endless redirect loop",
      );
    },
  );
});

Deno.test("a redirect without a Location header is returned as the final response", async () => {
  await withStubbedFetch(
    () => new Response("", { status: 301 }),
    async () => {
      const res = await guardedFetch("https://example.com/feed.xml");
      assertEqual(res.status, 301, "the bare 301 handed to the caller");
    },
  );
});

// --- readCappedText ---------------------------------------------------------------------------------------

Deno.test("a body under the budget is returned as text", async () => {
  assertEqual(
    await readCappedText(new Response("hello article"), 1024),
    "hello article",
    "the body text",
  );
});

Deno.test("a body over the budget is refused, not buffered", async () => {
  await assertRejects(
    () => readCappedText(new Response("x".repeat(4096)), 1024),
    "exceeds the 1024-byte budget",
    "an oversized body",
  );
});

Deno.test("a decompression bomb is refused by the same budget", async () => {
  // The cached-article path (content.ts) hands a DecompressionStream to readCappedStream, so the budget has
  // to hold on the DECOMPRESSED bytes: 8 KiB of zeroes gzips to a few dozen bytes (full-rss-sc4).
  const gzipped = await new Response(
    new Blob([new Uint8Array(8192)]).stream().pipeThrough(
      new CompressionStream("gzip"),
    ),
  ).arrayBuffer();
  assert(
    gzipped.byteLength < 200,
    `the fixture to be small compressed (got ${gzipped.byteLength} bytes)`,
  );
  const decompressed = new Response(gzipped).body!.pipeThrough(
    new DecompressionStream("gzip"),
  );
  await assertRejects(
    () => readCappedStream(decompressed, 1024),
    "exceeds the 1024-byte budget",
    "a body that only exceeds the budget after decompression",
  );
});

// --- sanitizeForLog ---------------------------------------------------------------------------------------

Deno.test("log lines lose control characters and userinfo, and keep the rest", () => {
  assertEqual(
    sanitizeForLog("https://example.com/a\r\nEVIL: forged line"),
    "https://example.com/aEVIL: forged line",
    "CRLF stripped",
  );
  assertEqual(
    sanitizeForLog(
      "https://example.com/a\u{2028}EVIL: forged entry\u{2029}EVIL: forged article",
    ),
    "https://example.com/aEVIL: forged entryEVIL: forged article",
    "U+2028/U+2029 stripped (full-rss-2lr): they are not \\p{Cc} but split log streams just as CR does",
  );
  assertEqual(
    sanitizeForLog("https://user:secret@example.com/feed"),
    "https://***@example.com/feed",
    "userinfo masked",
  );
  assertEqual(
    sanitizeForLog("https://example.com/feed.xml"),
    "https://example.com/feed.xml",
    "an ordinary URL untouched",
  );
  assertIncludes(
    sanitizeForLog("\x1b[31mred\x1b[0m"),
    "red",
    "ANSI escapes gone, text kept",
  );
  assertEqual(
    sanitizeForLog(
      "Failed for https://example.com/feed?api_key=secret&next=other#token in parser",
    ),
    "Failed for https://example.com/feed?[redacted]",
    "all query values and fragments in an embedded URL are redacted",
  );
  assertEqual(
    sanitizeForLog("Invalid URL not-a-url?access_token=secret"),
    "Invalid URL not-a-url?[redacted]",
    "invalid URLs in errors do not reveal query values",
  );
  assertEqual(
    sanitizeForLog(
      "Fetching feed from https://example.com/feed?q=a b&api_key=SECRET",
    ),
    "Fetching feed from https://example.com/feed?[redacted]",
    "raw URL query whitespace cannot expose later credentials",
  );
  assertEqual(
    sanitizeForLog("Failed for https://example.com/feed#part a&token=SECRET"),
    "Failed for https://example.com/feed#[redacted]",
    "raw URL fragment whitespace cannot expose later credentials",
  );
});

Deno.test("userinfo is masked even when the '@' sits past the length bound", () => {
  // Regression (full-rss-al9): the length cut used to be applied BEFORE the redactions, so a userinfo longer
  // than MAX_LOG_CHARS never matched and was logged verbatim — `http://user:secretpasswordaaa...`. The bound
  // is a LOG-WRITE bound, never a licence to emit a secret whose delimiter was past it.
  const line = sanitizeForLog(
    "http://user:secretpassword" + "a".repeat(2000) + "@evil.example/path",
  );
  assertExcludes(line, "secretpassword", "the password is not logged");
  assertIncludes(line, "http://***@", "the userinfo is masked");
  // Masking a 2 KB userinfo shortens the line well under the bound, so there is nothing left to cut - the
  // property under test here is that the REDACTION ran, not that the cut did.
  assert(
    line.length <= MAX_LOG_CHARS + 40,
    `the log line stays near the bound, got ${line.length} chars`,
  );
});

Deno.test("a password is masked whichever legal userinfo character it contains", () => {
  // Regression (full-rss-96w): an earlier version of the authority scan stopped at ', ", < and > on the theory
  // that a URL authority cannot contain them, so a password holding one was logged verbatim - while the regex
  // it replaced had masked it. WHATWG retains all four in userinfo, so they are userinfo here too.
  for (const pw of ["sec'ret", 'sec"ret', "sec<ret", "sec>ret", "pa\\ss"]) {
    const line = sanitizeForLog(`http://user:${pw}@evil.example/x`);
    assertExcludes(line, pw, `the password with ${pw} is not logged`);
    assertEqual(
      line,
      "http://***@evil.example/x",
      `userinfo holding ${pw} is masked whole`,
    );
  }
});

Deno.test("userinfo masking reads through the last '@', not the first", () => {
  // A password may contain an '@'. Masking to the first one would log the rest of it.
  assertEqual(
    sanitizeForLog("http://user:p@ss@evil.example/x"),
    "http://***@evil.example/x",
    "the whole userinfo is masked, including an '@' inside the password",
  );
});

Deno.test("an '@' in the path is not userinfo and is left alone", () => {
  assertEqual(
    sanitizeForLog("https://example.com/@user/profile"),
    "https://example.com/@user/profile",
    "a path '@' is not masked (the authority ended at the first '/')",
  );
});

Deno.test("userinfo is masked in WHATWG's other authority spellings, not just '://'", () => {
  // Regression (full-rss-1xy): the anchor was a literal '://', so credentials behind the other spellings a
  // WHATWG parser accepts reached logs verbatim. A special scheme reads ANY run of '/' and '\' after its
  // colon as the authority delimiter - or none at all (full-rss-xv3) - and a scheme-relative reference
  // carries userinfo with no scheme.
  assertEqual(
    sanitizeForLog("http:user:secret@evil.example/x"),
    "http:***@evil.example/x",
    "a special scheme needs no slash: the colon alone opens the authority",
  );
  assertEqual(
    sanitizeForLog("ws:user:secret@evil.example/x"),
    "ws:***@evil.example/x",
    "every special scheme, not only http",
  );
  assertEqual(
    sanitizeForLog("HTTP:USER:SECRET@EVIL.EXAMPLE/X"),
    "HTTP:***@EVIL.EXAMPLE/X",
    "schemes are ASCII case-insensitive",
  );
  assertEqual(
    sanitizeForLog("http:\\user:secret@evil.example/x"),
    "http:\\***@evil.example/x",
    "a backslash after the scheme opens the authority too",
  );
  assertEqual(
    sanitizeForLog("http:\\\\user:secret@evil.example/x"),
    "http:\\\\***@evil.example/x",
    "doubled backslashes, which a WHATWG parser normalises the same way",
  );
  assertEqual(
    sanitizeForLog("http:/user:secret@evil.example/x"),
    "http:/***@evil.example/x",
    "a single slash after a special scheme still parses to an authority",
  );
  assertEqual(
    sanitizeForLog("//user:secret@evil.example/x"),
    "//***@evil.example/x",
    "scheme-relative reference",
  );
  assertEqual(
    sanitizeForLog("Invalid URL //user:secret@evil.example given"),
    "Invalid URL //***@evil.example given",
    "scheme-relative reference inside an error message",
  );
});

Deno.test("colon-and-slash text that is not an authority is left alone", () => {
  // The anchor needs a scheme token (WHATWG's grammar: a letter, then letters/digits/+/-/.), so timestamps
  // and ratios never mask, and a Windows path without an '@' has nothing to mask.
  assertEqual(
    sanitizeForLog("retried 10:30/45 at 2026-11-09T04:01:22"),
    "retried 10:30/45 at 2026-11-09T04:01:22",
    "timestamps and ratios are not an authority",
  );
  assertEqual(
    sanitizeForLog("scanning C:\\Users\\name\\notes"),
    "scanning C:\\Users\\name\\notes",
    "a Windows path without an '@' is untouched",
  );
  assertEqual(
    sanitizeForLog("http: rejected user@host"),
    "http: rejected user@host",
    "a special-scheme colon before prose is not an authority: the space ends it before any '@'",
  );
  assertEqual(
    sanitizeForLog("term:Monday@noon"),
    "term:Monday@noon",
    "a non-special scheme has no authority without '//'",
  );
});

Deno.test("a doubled slash inside a path masks liberally rather than leaking", () => {
  // The scheme-relative anchor cannot tell a path's '//' from a reference's '//' without parsing, and
  // masking one thing too many is the safe direction (the maskUserinfo docblock): a path '//b@cdn' is
  // masked even though a URL parser would call it path.
  assertEqual(
    sanitizeForLog("https://example.com/a//b@cdn/x"),
    "https://example.com/a//***@cdn/x",
    "a path '@' after a '//' is over-masked, never logged",
  );
});

Deno.test("an authority that runs past the scan window is masked fail-closed", () => {
  // MAX_LOG_SCAN bounds the work (full-rss-9ey), so on a value longer than the window the '@' that ends a
  // userinfo can sit outside anything this function looks at. Masking the whole visible authority is the
  // fail-closed answer; emitting it is the original leak again, one window further out.
  const line = sanitizeForLog(
    "http://user:hunter2" + "a".repeat(MAX_LOG_SCAN) + "@evil.example/p",
  );
  assertExcludes(
    line,
    "hunter2",
    "no password from an authority whose end was not seen",
  );
  assertIncludes(line, "http://***@", "the visible authority is masked");
});
