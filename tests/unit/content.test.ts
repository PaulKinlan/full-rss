// tests/unit/content.test.ts — HTML -> markdown -> sanitized HTML for a fetched article.
//
// `convertToMarkdown` is the article transform: turndown plus a set of "drop this" rules (style, script,
// footer, iframe, head, img, input, nav, header, and any element with role=banner/navigation) and a
// keep-the-link-text-drop-the-href rule. `fetchContent` is the network + KV path; only its pure,
// network-free contract (URL validation) is asserted here.
//
// Not covered: a live Deno KV and a real network fetch, so the KV read/compression path is exercised against
// the deployed service rather than in a unit suite. The cache READ path is covered offline through the
// injectable `store` - the decompression budget in particular (full-rss-sc4).
import {
  assert,
  assertEqual,
  assertExcludes,
  assertIncludes,
  assertRejects,
} from "../asserts.ts";
import { convertToMarkdown, fetchContent } from "../../content.ts";

const PAGE = `<!doctype html>
<html>
<head><title>Post Title</title><style>body { color: red; }</style><script>analytics()</script></head>
<body>
  <nav role="navigation"><a href="/">Home</a></nav>
  <h1>Heading</h1>
  <p>Hello <a href="https://example.com/other">world</a>.</p>
  <img src="/x.png" alt="x">
  <footer>Footer text</footer>
</body>
</html>`;

Deno.test("convertToMarkdown prefixes the document title as a level-1 heading", () => {
  const markdown = convertToMarkdown(PAGE);
  assert(
    markdown.startsWith("# Post Title\n\n"),
    `the markdown to start with the page title heading, got ${
      JSON.stringify(markdown.slice(0, 40))
    }`,
  );
});

Deno.test("convertToMarkdown drops page chrome: style, script, nav, img and footer", () => {
  const markdown = convertToMarkdown(PAGE);
  for (
    const dropped of [
      "analytics()",
      "color: red",
      "Home",
      "Footer text",
      "<img",
      "<script",
    ]
  ) {
    assertExcludes(markdown, dropped, "dropped by the turndown rules");
  }
});

Deno.test("convertToMarkdown keeps link text but drops the href", () => {
  const markdown = convertToMarkdown(PAGE);
  assertIncludes(markdown, "Hello world.");
  assertExcludes(markdown, "https://example.com/other");
});

Deno.test("convertToMarkdown converts headings to markdown", () => {
  const markdown = convertToMarkdown(
    "<html><head><title>T</title></head><body><h1>Heading</h1></body></html>",
  );
  assertIncludes(markdown, "Heading");
  assertExcludes(markdown, "<h1>");
});

Deno.test("a failed cache write still returns converted article without an unhandled rejection", async () => {
  const originalFetch = globalThis.fetch;
  const originalError = console.error;
  const errors: string[] = [];
  const url = "https://example.com/post?token=secret-value";
  globalThis.fetch =
    ((_input: string | URL | Request) =>
      Promise.resolve(new Response(PAGE))) as typeof globalThis.fetch;
  console.error = (...parts) => errors.push(parts.join(" "));
  const store = {
    get: () => Promise.resolve({ value: null }),
    set: () => Promise.reject(new Error("cache write failed")),
  } as unknown as Pick<Deno.Kv, "get" | "set">;
  try {
    const html = await fetchContent(url, undefined, store);
    assertIncludes(
      html,
      "Hello world.",
      "converted article survives cache failure",
    );
    assertIncludes(
      errors.join("\n"),
      "cache write failed",
      "failure is logged",
    );
    assertExcludes(
      errors.join("\n"),
      "secret-value",
      "cache error hides query secret",
    );
  } finally {
    globalThis.fetch = originalFetch;
    console.error = originalError;
  }
});

Deno.test("a cached article that decompresses past the byte cap is refused", async () => {
  // content.ts caches gzip, and the read back used to be an unbounded `.text()`: a few kilobytes in KV could
  // expand to gigabytes in memory, undoing the cap the fetch itself enforces. The decompressed text is now
  // read under the same 5 MiB budget (full-rss-sc4). Fixture: 5 MiB + 1 of zeroes, which gzips to ~5 kB.
  const CAPPED_BYTES = 5 * 1024 * 1024;
  const gzipped = new Uint8Array(
    await new Response(
      new Blob([new Uint8Array(CAPPED_BYTES + 1)]).stream().pipeThrough(
        new CompressionStream("gzip"),
      ),
    ).arrayBuffer(),
  );
  const store = {
    get: () => Promise.resolve({ value: gzipped }),
    set: () => Promise.resolve({ ok: true }),
  } as unknown as Pick<Deno.Kv, "get" | "set">;
  await assertRejects(
    () => fetchContent("https://example.com/huge", undefined, store),
    `exceeds the ${CAPPED_BYTES}-byte budget`,
    "a cached article that expands past the cap",
  );
});

Deno.test("a 2xx article is converted and cached", async () => {
  // The positive half of the pair below: the status check must not stop a normal article from reaching the
  // cache.
  const originalFetch = globalThis.fetch;
  const writes: unknown[] = [];
  globalThis.fetch =
    (() => Promise.resolve(new Response(PAGE))) as typeof globalThis.fetch;
  const store = {
    get: () => Promise.resolve({ value: null }),
    set: (key: unknown, value: unknown) => {
      writes.push([key, value]);
      return Promise.resolve({ ok: true });
    },
  } as unknown as Pick<Deno.Kv, "get" | "set">;
  try {
    const html = await fetchContent(
      "https://example.com/post",
      undefined,
      store,
    );
    assertIncludes(html, "Hello world.", "the converted article");
    assertEqual(writes.length, 1, "the 2xx article is cached once");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

Deno.test("a non-2xx article response is neither converted nor cached", async () => {
  // A 404/500 body is an error page, not the article: converting it would cache that page as the article's
  // full content for the whole TTL, and a cached error is indistinguishable from real content to everyone
  // who asks for that URL afterwards (full-rss-qxz). The fetch fails instead, so feed.ts keeps the feed's
  // own summary for the item.
  const originalFetch = globalThis.fetch;
  const writes: unknown[] = [];
  globalThis.fetch = (() =>
    Promise.resolve(
      new Response("<html><body><h1>Not found</h1></body></html>", {
        status: 404,
      }),
    )) as typeof globalThis.fetch;
  const store = {
    get: () => Promise.resolve({ value: null }),
    set: (key: unknown, value: unknown) => {
      writes.push([key, value]);
      return Promise.resolve({ ok: true });
    },
  } as unknown as Pick<Deno.Kv, "get" | "set">;
  try {
    await assertRejects(
      () => fetchContent("https://example.com/missing", undefined, store),
      "HTTP 404",
      "a 404 article response",
    );
    assertEqual(writes.length, 0, "nothing was cached for a non-2xx article");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

Deno.test("a 304 is not an article either", async () => {
  // `ok` is 200-299: a 304 carries no body to convert, and caching the empty markdown would be worse than
  // failing the expansion.
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (() =>
    Promise.resolve(
      new Response(null, { status: 304 }),
    )) as typeof globalThis.fetch;
  const store = {
    get: () => Promise.resolve({ value: null }),
    set: () => Promise.resolve({ ok: true }),
  } as unknown as Pick<Deno.Kv, "get" | "set">;
  try {
    await assertRejects(
      () => fetchContent("https://example.com/not-modified", undefined, store),
      "HTTP 304",
      "a 304 article response",
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

Deno.test("an article URL on this service's own host is refused before any fetch or cache read", async () => {
  // The second-order amplification loop: the feed's item links back at this service, which would expand it
  // again, ten items at a time (full-rss-qxz). The refusal happens in egress.ts, so it precedes both the
  // network and the KV read.
  const originalFetch = globalThis.fetch;
  let fetched = 0;
  let cacheReads = 0;
  globalThis.fetch = (() => {
    fetched++;
    return Promise.resolve(new Response(PAGE));
  }) as typeof globalThis.fetch;
  const store = {
    get: () => {
      cacheReads++;
      return Promise.resolve({ value: null });
    },
    set: () => Promise.resolve({ ok: true }),
  } as unknown as Pick<Deno.Kv, "get" | "set">;
  try {
    await assertRejects(
      () =>
        fetchContent(
          "https://service.test/?url=https%3A%2F%2Fevil.test%2Ffeed.xml",
          undefined,
          store,
          { selfOrigins: ["https://service.test"] },
        ),
      "this service's own address",
      "an article link back at this service",
    );
    assertEqual(fetched, 0, "this service never fetched itself");
    assertEqual(cacheReads, 0, "the cache was not consulted first");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

Deno.test("an egress policy does not block articles on other hosts", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch =
    (() => Promise.resolve(new Response(PAGE))) as typeof globalThis.fetch;
  const store = {
    get: () => Promise.resolve({ value: null }),
    set: () => Promise.resolve({ ok: true }),
  } as unknown as Pick<Deno.Kv, "get" | "set">;
  try {
    const html = await fetchContent(
      "https://example.com/post",
      undefined,
      store,
      { selfOrigins: ["https://service.test"] },
    );
    assertIncludes(html, "Hello world.", "a public article still expands");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

Deno.test("fetchContent rejects a URL that cannot be parsed, before any network call", async () => {
  await assertRejects(
    () => fetchContent("not a url"),
    "Invalid URL not a url",
    "fetchContent",
  );
});

Deno.test("fetchContent refuses a private or local article URL, before any network call", async () => {
  // The second-order SSRF lived here: an attacker's feed could point an article link at localhost or a
  // cloud metadata address and this service would fetch it. egress.ts now refuses such targets up front
  // (full-rss-apm), and no fetch stub is needed to prove it - nothing may be fetched at all.
  for (
    const url of [
      "http://127.0.0.1/articles/1",
      "http://169.254.169.254/latest/meta-data/",
      "http://10.0.0.5:8080/inside",
      "http://[::1]/article",
      "https://localhost/article",
      "file:///etc/passwd",
    ]
  ) {
    await assertRejects(
      () => fetchContent(url),
      "Blocked URL",
      `${url} to be refused`,
    );
  }
});

/*
  Concurrent expansions of one article are ONE piece of work (full-rss-ca7, the factory finding
  tm-no-singleflight-article-conversion). A feed that names the same article twice, or two requests for the
  same cold feed arriving together, otherwise repeat the capped read, the turndown conversion, the gzip and the
  cache write per caller, with every copy holding its own buffers at the same moment.

  These tests drive the injectable `store`, so they need no KV and no network: the only upstream work they
  count is the stubbed `fetch`, and the only cache work they count is the stub's `set`.
*/
const countingStore = (writes: { count: number }) =>
  ({
    get: () => Promise.resolve({ value: null }),
    set: () => {
      writes.count++;
      return Promise.resolve({ ok: true });
    },
  }) as unknown as Pick<Deno.Kv, "get" | "set">;

Deno.test("concurrent expansions of one article share a single fetch", async () => {
  const originalFetch = globalThis.fetch;
  let fetches = 0;
  let release: () => void = () => {};
  const held = new Promise<void>((resolve) => (release = resolve));
  globalThis.fetch = (async () => {
    fetches++;
    await held; // keep the first expansion open until the second caller has joined it
    return new Response(PAGE);
  }) as typeof globalThis.fetch;
  const writes = { count: 0 };
  const store = countingStore(writes);
  const url = "https://example.com/single-flight";
  try {
    const first = fetchContent(url, undefined, store);
    // Let the first call reach the in-flight map before the second one looks for it.
    await new Promise((resolve) => setTimeout(resolve, 1));
    const second = fetchContent(url, undefined, store);
    release();
    const [a, b] = await Promise.all([first, second]);
    assertEqual(fetches, 1, "one upstream fetch for two concurrent callers");
    assertEqual(writes.count, 1, "one cache write");
    assertIncludes(a, "Hello world.", "the article is converted");
    assertEqual(a, b, "both callers get the same document");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

Deno.test("a failed expansion is shared with waiters but not remembered", async () => {
  const originalFetch = globalThis.fetch;
  let fetches = 0;
  let release: () => void = () => {};
  const held = new Promise<void>((resolve) => (release = resolve));
  globalThis.fetch = (async () => {
    fetches++;
    await held; // overlap the two callers, exactly as two slow upstream fetches would
    return new Response("error page", { status: 500 });
  }) as typeof globalThis.fetch;
  const writes = { count: 0 };
  const store = countingStore(writes);
  const url = "https://example.com/single-flight-error";
  try {
    const first = fetchContent(url, undefined, store);
    await new Promise((resolve) => setTimeout(resolve, 1));
    const second = fetchContent(url, undefined, store);
    release();
    const [a, b] = await Promise.allSettled([first, second]);
    assertEqual(a.status, "rejected", "the first caller sees the failure");
    assertEqual(b.status, "rejected", "the waiting caller sees it too");
    assertEqual(fetches, 1, "the failure was not fetched twice");
    // The entry is removed when the run settles, so the next caller tries again rather than re-reading a
    // remembered failure.
    await assertRejects(
      () => fetchContent(url, undefined, store),
      "HTTP 500",
      "a later call expands the article again",
    );
    assertEqual(fetches, 2, "the failure is not kept in the in-flight map");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

Deno.test("callers under different egress policies do not share one expansion", async () => {
  // The policy decides which redirect hops an expansion may follow, so two callers must not be handed an
  // article whose hop decisions were made against the other caller's configuration (full-rss-647).
  const originalFetch = globalThis.fetch;
  let fetches = 0;
  globalThis.fetch = (() => {
    fetches++;
    return Promise.resolve(new Response(PAGE));
  }) as typeof globalThis.fetch;
  const writes = { count: 0 };
  const store = countingStore(writes);
  const url = "https://example.com/two-policies";
  try {
    const [a, b] = await Promise.all([
      fetchContent(url, undefined, store, {
        selfOrigins: ["https://one.test"],
      }),
      fetchContent(url, undefined, store, {
        selfOrigins: ["https://two.test"],
      }),
    ]);
    assertEqual(fetches, 2, "each policy expands the article on its own");
    assertEqual(a, b, "the article itself is of course the same");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

Deno.test("callers that both miss the cache still coalesce", async () => {
  // The registration race: the cache read is a suspension point, so two callers arriving together can both
  // find the in-flight map empty, both read the cache, and then both start an expansion - measured as three
  // fetches of one article from three concurrent requests for one cold feed. The lookup and the registration
  // therefore happen in one uninterrupted block after the cache read, and a slow cache read is what makes the
  // difference visible here.
  const originalFetch = globalThis.fetch;
  let fetches = 0;
  let release: () => void = () => {};
  const held = new Promise<void>((resolve) => (release = resolve));
  globalThis.fetch = (async () => {
    fetches++;
    await held;
    return new Response(PAGE);
  }) as typeof globalThis.fetch;
  const writes = { count: 0 };
  const slowStore = {
    get: () =>
      new Promise((resolve) => setTimeout(() => resolve({ value: null }), 20)),
    set: () => {
      writes.count++;
      return Promise.resolve({ ok: true });
    },
  } as unknown as Pick<Deno.Kv, "get" | "set">;
  const url = "https://example.com/slow-cache-read";
  try {
    const first = fetchContent(url, undefined, slowStore);
    const second = fetchContent(url, undefined, slowStore);
    await new Promise((resolve) => setTimeout(resolve, 40));
    release();
    const [a, b] = await Promise.all([first, second]);
    assertEqual(fetches, 1, "a slow cache read does not defeat coalescing");
    assertEqual(writes.count, 1, "one cache write");
    assertEqual(a, b, "both callers get the same document");
  } finally {
    globalThis.fetch = originalFetch;
  }
});
