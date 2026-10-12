// tests/unit/index_template.test.ts — the HTML entry page (`templates/index.ts`).
//
// This is the served landing/error page: `main.ts` wraps the template's ReadableStream in a `Response`, so
// these tests pin BOTH the markup the page must keep (the URL form) and the stream contract main.ts depends
// on (a ReadableStream, not a string — `String(template)` is "[object ReadableStream]").
//
// NOTE ON ESCAPING: the interpolated `message` is inserted as raw markup (a nested template is streamed
// verbatim, not HTML-escaped). It is not currently reachable with attacker-controlled input — every call
// site in main.ts passes a literal — so this file does not assert on raw markup; the sink is tracked as its
// own finding rather than frozen into a green test.
import { assert, assertEqual, assertIncludes } from "../asserts.ts";
import { index } from "../../templates/index.ts";

const render = async (message?: string): Promise<string> =>
  await new Response(await index(message)).text();

Deno.test("index returns a ReadableStream, which is what main.ts puts in a Response", async () => {
  assertEqual(await index(undefined) instanceof ReadableStream, true, "index() return type");
});

Deno.test("index renders the feed-URL form and the page heading", async () => {
  const html = await render(undefined);
  assertIncludes(html, '<form action="/">', "the URL form");
  assertIncludes(html, '<input type="url" id="url" name="url" required>', "the URL input");
  assertIncludes(html, '<input type="submit" value="Submit">', "the submit button");
  assertIncludes(html, "<title>Full Feed RSS</title>", "the page title");
  assert(html.startsWith("<!DOCTYPE html>"), "the document starts with a doctype");
});

Deno.test("index shows no warning paragraph when there is no message", async () => {
  assertEqual((await render(undefined)).includes('class="warning"'), false, "warning paragraph present");
});

Deno.test("index renders the message in the warning paragraph", async () => {
  assertIncludes(await render("Invalid URL parameter."), '<p class="warning">Invalid URL parameter.</p>');
});
