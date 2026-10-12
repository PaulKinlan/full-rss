// tests/unit/index_template.test.ts — the HTML entry page (`templates/index.ts`).
//
// This is the served landing/error page: `main.ts` wraps the template's ReadableStream in a `Response`, so
// these tests pin BOTH the markup the page must keep (the URL form) and the stream contract main.ts depends
// on (a ReadableStream, not a string — `String(template)` is "[object ReadableStream]").
//
// ESCAPING: the interpolated `message` is HTML-escaped by `templates/index.ts` before it is streamed (the
// template engine interpolates verbatim, so escaping is the caller's job). It is not reachable with
// attacker-controlled input today — every call site in main.ts passes a literal — but the escaping is pinned
// here so that a future caller passing a URL or an upstream error string cannot turn this into reflected XSS
// (full-rss-2n6, which this file's assertions are the regression test for).
import {
  assert,
  assertEqual,
  assertExcludes,
  assertIncludes,
} from "../asserts.ts";
import { index } from "../../templates/index.ts";

// `index` returns the template's promise (whatwg-flora-tmpl's tag function is asynchronous), so the awaits
// here are load-bearing: without them this would put a Promise into the Response.
const render = async (message?: string): Promise<string> =>
  await new Response(await index(message)).text();

Deno.test("index returns a ReadableStream, which is what main.ts puts in a Response", async () => {
  assertEqual(
    await index(undefined) instanceof ReadableStream,
    true,
    "index() return type",
  );
});

Deno.test("index renders the feed-URL form and the page heading", async () => {
  const html = await render(undefined);
  assertIncludes(html, '<form action="/">', "the URL form");
  assertIncludes(
    html,
    '<input type="url" id="url" name="url" required>',
    "the URL input",
  );
  assertIncludes(
    html,
    '<input type="submit" value="Submit">',
    "the submit button",
  );
  assertIncludes(html, "<title>Full Feed RSS</title>", "the page title");
  assert(
    html.startsWith("<!DOCTYPE html>"),
    "the document starts with a doctype",
  );
});

Deno.test("index shows no warning paragraph when there is no message", async () => {
  assertEqual(
    (await render(undefined)).includes('class="warning"'),
    false,
    "warning paragraph present",
  );
});

Deno.test("index renders the message in the warning paragraph", async () => {
  assertIncludes(
    await render("Invalid URL parameter."),
    '<p class="warning">Invalid URL parameter.</p>',
  );
});

Deno.test("index escapes a message containing markup instead of streaming it as HTML", async () => {
  const html = await render("<script>alert(1)</script>");
  assertExcludes(
    html,
    "<script>alert(1)</script>",
    "a raw script tag in the page",
  );
  assertIncludes(
    html,
    '<p class="warning">&lt;script&gt;alert(1)&lt;/script&gt;</p>',
  );
});

Deno.test("index escapes &, quotes and apostrophes in a message exactly once", async () => {
  const html = await render(`Tom & Jerry said "hi" to O'Brien`);
  assertIncludes(html, "Tom &amp; Jerry said &quot;hi&quot; to O&#39;Brien");
  assertExcludes(html, "&amp;amp;", "double-escaped ampersand");
  assertExcludes(html, "&amp;quot;", "double-escaped quote");
});
