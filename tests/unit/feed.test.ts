// tests/unit/feed.test.ts — parsed feed -> RSS 2.0 output (`exportFeed`).
//
// `exportFeed` is the last step of every request: whatever the reader gets back is this document. These
// tests pin the parts of that contract a reader depends on (channel title/description/link, and per-item
// title, link, guid, date and escaped full content) for both input dialects the README claims: RSS 2.0 and
// Atom. The fixtures are inline strings — no network, no files, no shared state.
import {
  assert,
  assertEqual,
  assertExcludes,
  assertIncludes,
} from "../asserts.ts";
import { parseFeed } from "@mikaelporttila/rss";
import { exportFeed, processFeed } from "../../feed.ts";

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

const RSS_WITH_ITEM_METADATA = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>With Authors</title>
    <link>https://example.com/</link>
    <item>
      <title>Authored</title>
      <link>https://example.com/authored</link>
      <guid>https://example.com/authored</guid>
      <description>Short summary</description>
      <author>ada@example.com (Ada Lovelace)</author>
      <category>history</category>
      <category>math</category>
    </item>
    <item>
      <title>Anonymous</title>
      <link>https://example.com/anon</link>
      <guid>https://example.com/anon</guid>
      <description>Short summary</description>
    </item>
  </channel>
</rss>`;

const ATOM_WITH_AUTHOR = `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Atom Authors</title>
  <id>urn:uuid:feed-authors</id>
  <updated>2025-10-06T10:00:00Z</updated>
  <link href="https://example.com/"/>
  <entry>
    <title>By Grace</title>
    <id>urn:uuid:grace</id>
    <updated>2025-10-06T11:00:00Z</updated>
    <link href="https://example.com/grace"/>
    <author><name>Grace &amp; Co &lt;x&gt;</name><email>grace@example.com</email></author>
    <category term="computing"/>
  </entry>
  <entry>
    <title>By Name Only</title>
    <id>urn:uuid:name-only</id>
    <updated>2025-10-06T12:00:00Z</updated>
    <link href="https://example.com/name-only"/>
    <author><name>Name Only</name></author>
  </entry>
</feed>`;

const itemCount = (xml: string): number => (xml.match(/<item>/g) ?? []).length;

/*
  A feed's links are publisher-controlled text this document re-emits for a reader: <link> is a navigation
  target and <guid> an identifier. A scheme decides what happens when the consumer acts on it, so the
  active ones (javascript:, data:) may not reach the output (full-rss-d2m). Atom-style opaque ids must keep
  working - dropping them would leave items with no id, and readers could not tell two versions apart.
*/
const RSS_WITH_HOSTILE_LINKS = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Hostile Links</title>
    <link>javascript:alert(1)</link>
    <item>
      <title>Script link</title>
      <link>javascript:alert(2)</link>
      <guid>https://example.com/real-guid</guid>
      <description>Script item</description>
    </item>
    <item>
      <title>Data link</title>
      <link>data:text/html,hello</link>
      <guid>tag:example.com,2025:data</guid>
      <description>Data item</description>
    </item>
    <item>
      <title>Obfuscated</title>
      <link>  JaVaScRiPt:alert(3)</link>
      <guid>javascript:alert(4)</guid>
      <description>Obfuscated item</description>
    </item>
  </channel>
</rss>`;

/*
  Feed-supplied markup is untrusted (full-rss-9vl): an item whose article expansion is skipped or falls back
  carries the publisher's raw HTML into content:encoded and description, and a feed reader renders it. The
  export boundary sanitizes both with the same defaults content.ts applies to expanded articles.
*/
const RSS_WITH_UNSAFE_CONTENT = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/">
  <channel>
    <title>Unsafe Feed</title>
    <link>https://example.com/</link>
    <item>
      <title>Unsafe Post</title>
      <link>https://example.com/unsafe</link>
      <guid>https://example.com/unsafe</guid>
      <pubDate>Mon, 06 Oct 2025 10:00:00 GMT</pubDate>
      <description><![CDATA[<p onclick="alert(1)">Summary</p><script>alert(2)</script>]]></description>
      <content:encoded><![CDATA[<p onclick="alert(1)">Safe text</p><script>alert(2)</script><img src="https://example.com/x.png" onerror="alert(3)"><a href="javascript:alert(4)">click</a><iframe src="https://evil.example/"></iframe>]]></content:encoded>
    </item>
  </channel>
</rss>`;

Deno.test("exportFeed sanitizes feed-supplied content:encoded and description", async () => {
  const xml = exportFeed(await parseFeed(RSS_WITH_UNSAFE_CONTENT));
  // The safe markup survives (escaped, as every item body is). Images do not: the default allowlist has
  // no <img>, which matches the expanded-article path (content.ts's markdown rules drop images too).
  assertIncludes(xml, "&lt;p&gt;Safe text&lt;/p&gt;");
  assertIncludes(xml, "&lt;a&gt;click&lt;/a&gt;");
  // Scripts, event handlers, javascript: URLs, iframes and images do not — in content or in description.
  assertExcludes(xml, "<script");
  assertExcludes(xml, "onclick");
  assertExcludes(xml, "onerror");
  assertExcludes(xml, "javascript:");
  assertExcludes(xml, "<img");
  assertExcludes(xml, "iframe");
});

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

/*
  An item's author and categories (full-rss-fhy). RSS 2.0 gives every item its own <author> and <category>,
  and @feed/feed can express neither, so they are written into the item's own block by feed.ts's subclass.
  These tests are the contract for that: the elements are present, they are escaped, they belong to the right
  item, and an item that has neither is untouched.
*/
Deno.test("exportFeed carries an RSS item's author and categories", async () => {
  const xml = exportFeed(await parseFeed(RSS_WITH_ITEM_METADATA));
  // An RSS 2.0 feed round-trips: the parser hands the author line back as a name, and it goes out unchanged.
  assertIncludes(xml, "<author>ada@example.com (Ada Lovelace)</author>");
  assertIncludes(xml, "<category>history</category>");
  assertIncludes(xml, "<category>math</category>");
  assert(itemCount(xml) === 2, `two <item>s, got ${itemCount(xml)}`);
  assertIncludes(xml, "</rss>");
});

Deno.test("exportFeed writes an item's author into that item, and leaves the next one alone", async () => {
  const xml = exportFeed(await parseFeed(RSS_WITH_ITEM_METADATA));
  const authored = xml.slice(
    xml.indexOf("<title>Authored</title>"),
    xml.indexOf("<title>Anonymous</title>"),
  );
  assertIncludes(authored, "<author>ada@example.com (Ada Lovelace)</author>");
  assertIncludes(authored, "</item>");
  // Everything from the anonymous item onwards is that item: no author, no empty <author>, no category.
  const anonymous = xml.slice(xml.indexOf("<title>Anonymous</title>"));
  assertExcludes(anonymous, "<author>");
  assertExcludes(anonymous, "<category>");
});

Deno.test("exportFeed writes an Atom author as 'email (Name)' and escapes what the feed sent", async () => {
  const xml = exportFeed(await parseFeed(ATOM_WITH_AUTHOR));
  assertIncludes(
    xml,
    "<author>grace@example.com (Grace &amp; Co &lt;x&gt;)</author>",
  );
  // The author is feed-provided text like any other: it cannot introduce markup into the document.
  assertExcludes(xml, "Grace & Co <x>");
  assertIncludes(xml, "<category>computing</category>");
});

Deno.test("exportFeed carries a name-only author rather than dropping it", async () => {
  // Atom authors commonly have a name and no email; <author> is the only element RSS 2.0 offers for it here.
  const xml = exportFeed(await parseFeed(ATOM_WITH_AUTHOR));
  assertIncludes(xml, "<author>Name Only</author>");
});

Deno.test("exportFeed drops feed item links and guids whose scheme a consumer can act on", async () => {
  const xml = exportFeed(await parseFeed(RSS_WITH_HOSTILE_LINKS));
  // No executable scheme survives anywhere in the document, in any spelling.
  const lower = xml.toLowerCase();
  assertExcludes(lower, "javascript:");
  assertExcludes(lower, "data:text/html");
  // The items themselves are not lost: their titles, summaries and identifiers still go out.
  assert(itemCount(xml) === 3, `three <item>s, got ${itemCount(xml)}`);
  for (const title of ["Script link", "Data link", "Obfuscated"]) {
    assertIncludes(xml, `<title>${title}</title>`);
  }
});

Deno.test("exportFeed keeps a hostile item's inert identifier and http(s) link", async () => {
  const xml = exportFeed(await parseFeed(RSS_WITH_HOSTILE_LINKS));
  // An https guid is an identifier AND a link: kept.
  assertIncludes(xml, "<guid>https://example.com/real-guid</guid>");
  // A tag: id cannot be acted on, so it stays (the Atom round-trip depends on this class of id).
  assertIncludes(xml, "<guid>tag:example.com,2025:data</guid>");
});

Deno.test("exportFeed drops a channel link whose scheme a consumer can act on", async () => {
  // The channel <link> is publisher-controlled too; the fixture's is javascript:alert(1).
  const xml = exportFeed(await parseFeed(RSS_WITH_HOSTILE_LINKS));
  assertIncludes(xml, "<title>Hostile Links</title>", "the channel survives");
  assertExcludes(xml.toLowerCase(), "javascript:");
});

Deno.test("exportFeed emits no author or category element when an entry has neither", async () => {
  const xml = exportFeed(await parseFeed(ATOM));
  assertExcludes(xml, "<author>");
  assertExcludes(xml, "<category>");
  assert(itemCount(xml) === 1, `exactly one <item>, got ${itemCount(xml)}`);
});

/*
  Feed expansion may not point back at the service doing the expanding (full-rss-qxz). A feed whose items link
  to this service's own endpoint turns one request into an unbounded tree of them, and none of the address
  checks catch it because the target is public - it is us.

  The link here carries no query on purpose: sanitizeForLog redacts everything after a '?' (a query can hold a
  credential), so a query-bearing self URL would hide the refusal reason this test asserts. That the redaction
  keeps working is egress.test.ts's business; this test is about the item's fate.
*/
const RSS_LINKING_TO_SELF = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Amplifier</title>
    <link>https://example.com/</link>
    <item>
      <title>Loop</title>
      <link>https://service.test/expand</link>
      <guid>loop</guid>
      <description>Summary survives</description>
    </item>
  </channel>
</rss>`;

Deno.test("processFeed refuses an item that links back at this service, and keeps the item", async () => {
  const originalFetch = globalThis.fetch;
  const originalError = console.error;
  const lines: string[] = [];
  let fetched = 0;
  globalThis.fetch = ((_input: string | URL | Request) => {
    fetched++;
    return Promise.resolve(new Response("unexpected"));
  }) as typeof globalThis.fetch;
  console.error = (...parts) => lines.push(parts.join(" "));
  try {
    const feed = await processFeed(
      await parseFeed(RSS_LINKING_TO_SELF),
      undefined,
      {
        selfOrigins: ["https://service.test"],
      },
    );
    assertEqual(fetched, 0, "the self-referential item was never fetched");
    // The item itself survives with the publisher's summary, the same fallback any expansion failure gets.
    assertEqual(feed.entries.length, 1, "the item is still in the feed");
    assertEqual(
      feed.entries[0].content?.value,
      undefined,
      "no expanded content was set",
    );
    assertEqual(
      feed.entries[0].description?.value,
      "Summary survives",
      "the feed's own summary is kept",
    );
    // And the reason logged is the egress refusal, not some later accident.
    assertIncludes(
      lines.join("\n"),
      "this service's own address",
      "the refusal is what skipped the item",
    );
  } finally {
    globalThis.fetch = originalFetch;
    console.error = originalError;
  }
});
