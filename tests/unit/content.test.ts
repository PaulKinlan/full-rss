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
