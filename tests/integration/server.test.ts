// tests/integration/server.test.ts — the routing contract of `server.ts`.
//
// The split (full-rss-11b) is what makes this testable: `handleRequest` takes a Request and returns a
// Response without a socket, so every outcome of the one public endpoint can be asserted in-process. This
// is the boundary tier — status codes, the content type of the feed, and the shape of the document a reader
// receives — not the unit tier (content.ts and feed.ts have their own suites).
//
// The upstream feed is stubbed: `globalThis.fetch` is replaced per test and restored in a `finally`, so this
// suite needs no network, no server and no KV, and it does not depend on any real site being up.
//
// Articles' full content is deliberately NOT asserted here: `fetchContent` reads Deno KV, which the test
// process does not have (`--unstable-kv` is not part of the gate). Test 6 pins what matters in both worlds —
// an article that cannot be enriched must not remove the item from the feed.
import { assertEqual, assertIncludes } from "../asserts.ts";
import { handleRequest } from "../../server.ts";

const FEED = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
  <title>Routing Fixture</title>
  <description>Fixture</description>
  <link>https://example.com/</link>
  <item><title>First</title><link>https://example.com/first</link><guid>first</guid>
    <description>Summary one</description></item>
  <item><title>Second</title><link>https://example.com/second</link><guid>second</guid>
    <description>Summary two</description></item>
</channel></rss>`;

const FEED_WITHOUT_LINKS = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
  <title>No Links</title>
  <link>https://example.com/</link>
  <item><title>Linkless</title><guid>linkless</guid><description>No link to follow</description></item>
</channel></rss>`;

/** Replace `fetch` for the duration of `body`, then always restore it. */
async function withStubbedFetch(
  impl: (url: string) => Response,
  body: () => Promise<void>,
): Promise<void> {
  const original = globalThis.fetch;
  globalThis.fetch = ((input: string | URL | Request) =>
    Promise.resolve(
      impl(
        typeof input === "string"
          ? input
          : input instanceof URL
          ? input.href
          : input.url,
      ),
    )) as typeof globalThis.fetch;
  try {
    await body();
  } finally {
    globalThis.fetch = original;
  }
}

const get = (query = ""): Promise<Response> =>
  handleRequest(new Request(`http://localhost/${query}`));

const assertHtmlHeaders = (res: Response): void => {
  assertEqual(
    res.headers.get("content-type"),
    "text/html; charset=utf-8",
    "HTML content type",
  );
  assertEqual(
    res.headers.get("content-security-policy"),
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    "restrictive CSP with working local form and inline style",
  );
  assertEqual(
    res.headers.get("x-content-type-options"),
    "nosniff",
    "MIME sniffing disabled",
  );
  assertEqual(res.headers.get("x-frame-options"), "DENY", "framing disabled");
  assertEqual(
    res.headers.get("referrer-policy"),
    "no-referrer",
    "no referrer leakage",
  );
};

Deno.test("a non-GET request is refused with 405", async () => {
  const res = await handleRequest(
    new Request("http://localhost/", { method: "POST" }),
  );
  assertEqual(res.status, 405, "status");
  assertEqual(await res.text(), "Method not allowed", "body");
});

Deno.test("no url renders the index page", async () => {
  const res = await get();
  assertEqual(res.status, 200, "status");
  assertHtmlHeaders(res);
  assertIncludes(
    await res.text(),
    '<form action="/" toolname="expand-rss-feed"',
    "the native GET form advertises its WebMCP tool",
  );
});

Deno.test("an unusable url is refused with 400 and the warning page", async () => {
  const res = await get("?url=not-a-url");
  assertEqual(res.status, 400, "status");
  assertHtmlHeaders(res);
  assertIncludes(
    await res.text(),
    '<p class="warning">Invalid URL parameter.',
    "the warning message",
  );
});

Deno.test("a url aimed at a private or local target is refused with 403", async () => {
  // The first-order SSRF: ?url= used to be fetched with a syntax check only. The guard refuses such
  // targets before any fetch (no stub needed - nothing may be fetched at all), and the boundary answer
  // is its own status so a requester can tell a typo (400) from a refused target (403).
  for (
    const url of [
      "http://127.0.0.1:8000/inside",
      "http://169.254.169.254/latest/meta-data/",
      "http://192.168.1.10/feed.xml",
      "https://localhost/feed.xml",
    ]
  ) {
    const res = await get(`?url=${encodeURIComponent(url)}`);
    assertEqual(res.status, 403, `status for ${url}`);
    assertHtmlHeaders(res);
    assertIncludes(
      await res.text(),
      "only public http(s) addresses are supported",
      "the warning message",
    );
  }
});

Deno.test("a url naming this service's own origin is refused with 403 and never fetched", async () => {
  // The first-order amplification: the requester asks this service to expand this service. The origin that
  // arrived with the request is the one that counts, so the request host is what the guard is given
  // (full-rss-qxz).
  let fetches = 0;
  await withStubbedFetch(
    () => {
      fetches++;
      return new Response("unexpected", { status: 200 });
    },
    async () => {
      const self =
        "https://service.test/?url=https%3A%2F%2Fevil.test%2Ffeed.xml";
      const res = await handleRequest(
        new Request(`https://service.test/?url=${encodeURIComponent(self)}`),
      );
      assertEqual(res.status, 403, "status");
      assertHtmlHeaders(res);
      assertIncludes(
        await res.text(),
        "and not this service itself",
        "the warning names self-reference",
      );
      assertEqual(fetches, 0, "the service did not fetch itself");
    },
  );
});

Deno.test("a feed that redirects back to this service is refused with 403", async () => {
  // Redirect hops get the same policy as the first request, so a public feed that 302s back at us cannot
  // start the loop from the other end.
  await withStubbedFetch(
    () =>
      new Response("", {
        status: 302,
        headers: {
          location: "https://service.test/?url=https%3A%2F%2Fevil.test%2F",
        },
      }),
    async () => {
      const res = await handleRequest(
        new Request(
          "https://service.test/?url=" +
            encodeURIComponent("https://example.com/feed.xml"),
        ),
      );
      assertEqual(res.status, 403, "status");
      assertIncludes(
        await res.text(),
        "redirected to a URL that cannot be fetched",
        "the warning message",
      );
    },
  );
});

Deno.test("a feed that redirects to a private target is refused with 403", async () => {
  await withStubbedFetch(
    () =>
      new Response("", {
        status: 302,
        headers: { location: "http://10.0.0.5/admin" },
      }),
    async () => {
      const res = await get("?url=https://example.com/feed.xml");
      assertEqual(res.status, 403, "status");
      assertHtmlHeaders(res);
      assertIncludes(
        await res.text(),
        "redirected to a URL that cannot be fetched",
        "the warning message",
      );
    },
  );
});

Deno.test("the aggregate request deadline aborts the upstream fetch and returns 504", async () => {
  const original = globalThis.fetch;
  let aborted = false;
  globalThis.fetch =
    ((_input: string | URL | Request, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          aborted = true;
          reject(new DOMException("Aborted", "AbortError"));
        }, { once: true });
      })) as typeof globalThis.fetch;
  try {
    const res = await handleRequest(
      new Request("http://localhost/?url=https://example.com/feed.xml"),
      20,
    );
    assertEqual(res.status, 504, "deadline status");
    assertHtmlHeaders(res);
    const html = await res.text();
    assertIncludes(
      html,
      '<p class="warning">This feed took too long',
      "timeout warning",
    );
    assertIncludes(
      html,
      '<form action="/" toolname="expand-rss-feed"',
      "retry form",
    );
    assertEqual(aborted, true, "outbound fetch was aborted");
  } finally {
    globalThis.fetch = original;
  }
});

Deno.test("a feed that cannot be fetched is a 500 with the warning page", async () => {
  await withStubbedFetch(
    () => new Response("gone", { status: 404 }),
    async () => {
      const res = await get("?url=https://example.com/feed.xml");
      assertEqual(res.status, 500, "status");
      assertHtmlHeaders(res);
      assertIncludes(
        await res.text(),
        "There was an error fetching the feed",
        "the warning message",
      );
    },
  );
});

Deno.test("feed URL and fetch-error logs redact query credentials", async () => {
  const log = console.log;
  const error = console.error;
  const lines: string[] = [];
  console.log = (...parts) => lines.push(parts.join(" "));
  console.error = (...parts) => lines.push(parts.join(" "));
  try {
    const secret = "feed-secret-123";
    await withStubbedFetch(
      () => {
        throw new Error(
          `upstream failed https://example.com/feed?q=a b&token=${secret}`,
        );
      },
      async () => {
        const url = `https://example.com/feed?q=a b&api_key=${secret}`;
        const res = await get(`?url=${encodeURIComponent(url)}`);
        assertEqual(res.status, 500, "fetch error status");
      },
    );
    assertIncludes(lines.join("\n"), "?[redacted]", "query removed from logs");
    if (lines.join("\n").includes(secret)) {
      throw new Error("feed secret leaked to logs");
    }
  } finally {
    console.log = log;
    console.error = error;
  }
});

Deno.test("a parse error is logged as one sanitized line", async () => {
  const error = console.error;
  const lines: string[] = [];
  console.error = (...parts) => lines.push(parts.join(" "));
  try {
    await withStubbedFetch(
      () =>
        new Response(
          "not an XML feed\r\nEVIL: forged line ?token=parse-secret-123",
        ),
      async () => {
        const res = await get("?url=https://example.com/feed.xml");
        assertEqual(res.status, 500, "parse error status");
        assertHtmlHeaders(res);
      },
    );
    assertIncludes(
      lines.join("\n"),
      "Failed to parse feed or item:",
      "parse error logged",
    );
    if (lines.join("\n").includes("parse-secret-123")) {
      throw new Error("parse secret leaked to logs");
    }
    assertEqual(lines.length, 1, "parse error occupies one log line");
  } finally {
    console.error = error;
  }
});

Deno.test("article enrichment errors do not log article query credentials", async () => {
  const error = console.error;
  const lines: string[] = [];
  console.error = (...parts) => lines.push(parts.join(" "));
  try {
    await withStubbedFetch(
      () =>
        new Response(FEED.replace(
          "https://example.com/first",
          "https://example.com/first?q=a b&amp;token=article-secret-123",
        )),
      async () => {
        const res = await get("?url=https://example.com/feed.xml");
        assertEqual(
          res.status,
          200,
          "feed survives article enrichment failure",
        );
      },
    );
    assertIncludes(lines.join("\n"), "?[redacted]", "article query removed");
    if (lines.join("\n").includes("article-secret-123")) {
      throw new Error("article secret leaked to logs");
    }
  } finally {
    console.error = error;
  }
});

Deno.test("a valid feed comes back as RSS 2.0 with every item", async () => {
  await withStubbedFetch(
    () => new Response(FEED_WITHOUT_LINKS, { status: 200 }),
    async () => {
      const res = await get("?url=https://example.com/feed.xml");
      assertEqual(res.status, 200, "status");
      assertEqual(
        res.headers.get("content-type"),
        "application/rss+xml",
        "content type",
      );
      assertEqual(
        res.headers.get("content-security-policy"),
        "default-src 'none'; frame-ancestors 'none'",
        "the RSS document is not a script, style or frame context",
      );
      assertEqual(
        res.headers.get("x-content-type-options"),
        "nosniff",
        "MIME sniffing disabled on the feed",
      );
      assertEqual(
        res.headers.get("x-frame-options"),
        "DENY",
        "the feed cannot frame this service",
      );
      assertEqual(
        res.headers.get("referrer-policy"),
        "no-referrer",
        "no referrer leakage from the feed",
      );
      const xml = await res.text();
      assertIncludes(xml, "<title>No Links</title>", "the channel title");
      assertIncludes(xml, "<title>Linkless</title>", "the item");
    },
  );
});

Deno.test("an article that cannot be enriched does not remove its item from the feed", async () => {
  await withStubbedFetch(
    (url) =>
      new Response(url.includes("feed.xml") ? FEED : "not an article", {
        status: 200,
      }),
    async () => {
      // `handleRequest` must not reject even though enriching each article needs KV and a second fetch.
      const res = await get("?url=https://example.com/feed.xml");
      assertEqual(res.status, 200, "status");
      const xml = await res.text();
      assertIncludes(
        xml,
        "<title>Routing Fixture</title>",
        "the channel title",
      );
      assertIncludes(xml, "<title>First</title>", "the first item");
      assertIncludes(xml, "<title>Second</title>", "the second item");
      assertIncludes(
        xml,
        "<link>https://example.com/first</link>",
        "the first item's link",
      );
    },
  );
});
