// tests/unit/content.test.ts — HTML -> markdown -> sanitized HTML for a fetched article.
//
// `convertToMarkdown` is the article transform: turndown plus a set of "drop this" rules (style, script,
// footer, iframe, head, img, input, nav, header, and any element with role=banner/navigation) and a
// keep-the-link-text-drop-the-href rule. `fetchContent` is the network + KV path; only its pure,
// network-free contract (URL validation) is asserted here.
//
// Not covered: the KV read/compression path in `fetchContent` needs a live Deno KV and a network fetch, so
// it is exercised against the deployed service rather than in a unit suite.
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
