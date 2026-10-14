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
  assertIncludes,
  assertRejects,
} from "../asserts.ts";
import {
  guardedFetch,
  parseFetchableUrl,
  readCappedText,
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
const resolver = (answers: string[]) => () => Promise.resolve(answers);

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
    "http://[fe80::1]/",
    "http://[fc00::1]/",
    "http://[fd12:3456:789a::1]/",
    "http://[2001:db8::1]/",
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
});

Deno.test("local names are blocked before any DNS lookup", async () => {
  let resolved = false;
  const spy = () => {
    resolved = true;
    return Promise.resolve(PUBLIC_A);
  };
  for (
    const host of ["localhost", "box.localhost", "nas.local", "api.internal"]
  ) {
    await assertRejects(
      () => parseFetchableUrl(`https://${host}/`, { resolveDns: spy }),
      "local name",
      `${host} to be blocked`,
    );
  }
  assert(resolved === false, "no DNS lookup for syntactically local names");
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

Deno.test("the default resolver's DNS layer is skipped without net permission", async () => {
  // The unit and integration suites run under `deno test --allow-env`: no net permission, so egress is
  // impossible and the default resolver's permission gate must skip the DNS layer rather than fail every
  // hostname. This is the behaviour the server suite's stubbed-fetch tests rely on.
  const url = await parseFetchableUrl("https://example.com/feed.xml");
  assertEqual(url.hostname, "example.com", "hostname");
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

// --- sanitizeForLog ---------------------------------------------------------------------------------------

Deno.test("log lines lose control characters and userinfo, and keep the rest", () => {
  assertEqual(
    sanitizeForLog("https://example.com/a\r\nEVIL: forged line"),
    "https://example.com/aEVIL: forged line",
    "CRLF stripped",
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
    "Failed for https://example.com/feed?[redacted] in parser",
    "all query values and fragments in an embedded URL are redacted",
  );
  assertEqual(
    sanitizeForLog("Invalid URL not-a-url?access_token=secret"),
    "Invalid URL not-a-url?[redacted]",
    "invalid URLs in errors do not reveal query values",
  );
});
