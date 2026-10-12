// tests/unit/feed.test.ts — parsed feed -> RSS 2.0 output (`exportFeed`).
//
// `exportFeed` is the last step of every request: whatever the reader gets back is this document. These
// tests pin the parts of that contract a reader depends on (channel title/description/link, and per-item
// title, link, guid, date and escaped full content) for both input dialects the README claims: RSS 2.0 and
// Atom. The fixtures are inline strings — no network, no files, no shared state.
import { assert, assertExcludes, assertIncludes } from "../asserts.ts";
import { parseFeed } from "@mikaelporttila/rss";
import { exportFeed } from "../../feed.ts";

const RSS = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/">
  <channel>
    <title>Example Feed</title>
    <description>An example feed</description>
    <link>https://example.com/</link>
    <item>
      <title>First Post</title>
      <link>https://example.com/first</link>
      <guid>https://example.com/first</guid>
      <description>Short summary</description>
      <pubDate>Mon, 06 Oct 2025 10:00:00 GMT</pubDate>
      <content:encoded><![CDATA[<p>Full body</p>]]></content:encoded>
    </item>
  </channel>
</rss>`;

const RSS_WITH_UNTITLED_ITEM = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Mixed</title>
    <link>https://example.com/</link>
    <item><link>https://example.com/no-title</link><guid>https://example.com/no-title</guid></item>
    <item><title>Has Title</title><link>https://example.com/t</link><guid>https://example.com/t</guid></item>
  </channel>
</rss>`;

const ATOM = `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Atom Example</title>
  <id>urn:uuid:feed</id>
  <updated>2025-10-06T10:00:00Z</updated>
  <link href="https://example.com/"/>
  <entry>
    <title>Atom Post</title>
    <id>urn:uuid:post</id>
    <updated>2025-10-06T11:00:00Z</updated>
    <link href="https://example.com/atom-post"/>
    <content type="html">&lt;p&gt;Hi&lt;/p&gt;</content>
  </entry>
</feed>`;

const itemCount = (xml: string): number => (xml.match(/<item>/g) ?? []).length;

Deno.test("exportFeed emits RSS 2.0 channel metadata from an RSS 2.0 feed", async () => {
  const xml = exportFeed(await parseFeed(RSS));
  assertIncludes(xml, '<rss version="2.0">');
  assertIncludes(xml, "<title>Example Feed</title>");
  assertIncludes(xml, "<description>An example feed</description>");
  assertIncludes(xml, "<link>https://example.com/</link>");
});

Deno.test("exportFeed carries an RSS item's title, link, guid, date and full content", async () => {
  const xml = exportFeed(await parseFeed(RSS));
  assertIncludes(xml, "<title>First Post</title>");
  assertIncludes(xml, "<link>https://example.com/first</link>");
  assertIncludes(xml, "<guid>https://example.com/first</guid>");
  assertIncludes(xml, "<pubDate>Mon, 06 Oct 2025 10:00:00 GMT</pubDate>");
  // The full article body goes out escaped, inside content:encoded — not as raw markup.
  assertIncludes(xml, '<content:encoded type="html">');
  assertIncludes(xml, "&lt;p&gt;Full body&lt;/p&gt;");
  assertExcludes(xml, "<p>Full body</p>");
});

Deno.test("exportFeed skips an entry that has no title rather than emitting an empty item", async () => {
  const xml = exportFeed(await parseFeed(RSS_WITH_UNTITLED_ITEM));
  assertIncludes(xml, "<title>Has Title</title>");
  assertExcludes(xml, "no-title");
  assert(itemCount(xml) === 1, `exactly one <item>, got ${itemCount(xml)}`);
});

Deno.test("exportFeed converts an Atom feed into RSS 2.0", async () => {
  const xml = exportFeed(await parseFeed(ATOM));
  assertIncludes(xml, '<rss version="2.0">');
  assertIncludes(xml, "<title>Atom Example</title>");
  assertIncludes(xml, "<title>Atom Post</title>");
  assertIncludes(xml, "<link>https://example.com/atom-post</link>");
  assertIncludes(xml, "<guid>urn:uuid:post</guid>");
  assertIncludes(xml, "&lt;p&gt;Hi&lt;/p&gt;");
  assert(itemCount(xml) === 1, `exactly one <item>, got ${itemCount(xml)}`);
});

Deno.test("exportFeed is deterministic apart from lastBuildDate", async () => {
  const strip = (xml: string) =>
    xml.replace(/<lastBuildDate>[^<]*<\/lastBuildDate>/g, "");
  const first = exportFeed(await parseFeed(RSS));
  const second = exportFeed(await parseFeed(RSS));
  assert(
    strip(first) === strip(second),
    "two exports of the same feed to differ only in lastBuildDate",
  );
});
