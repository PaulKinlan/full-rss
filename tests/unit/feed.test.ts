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

/*
  The characters XML 1.0 forbids (full-rss-7kn). Its Char production is
  #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF], so the C0 controls other than tab,
  newline and carriage return, U+FFFE/U+FFFF and unpaired surrogates cannot appear in a well-formed document -
  and a reader rejects the WHOLE feed for one of them, not just the item that carried it. They arrive the
  ordinary way: a scraped article that has a form feed in it, or a publisher that writes &#xD800;.

  This is a property of the finished document, so it is asserted that way: nothing the pattern below matches
  may survive anywhere in what exportFeed returns. escapeXml alone could not have covered it - it runs on
  <author> and <category> only, while title, description, link, guid and content:encoded are written by
  @feed/feed.
*/
const XML_1_0_FORBIDDEN =
  // deno-lint-ignore no-control-regex -- the pattern's job is to name the forbidden characters
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFE\uFFFF]|[\uD800-\uDFFF]/u;

const ATOM_WITH_LONE_SURROGATE = `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Surrogates</title>
  <id>urn:uuid:surrogates</id>
  <updated>2025-10-06T10:00:00Z</updated>
  <link href="https://example.com/"/>
  <entry>
    <title>X&#xD800;Y</title>
    <id>urn:uuid:lone</id>
    <updated>2025-10-06T11:00:00Z</updated>
    <link href="https://example.com/lone"/>
  </entry>
  <entry>
    <title>Smile \u{1F600}</title>
    <id>urn:uuid:astral</id>
    <updated>2025-10-06T12:00:00Z</updated>
    <link href="https://example.com/astral"/>
  </entry>
</feed>`;

const RSS_WITH_XML_ILLEGAL_CHARACTERS = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/">
  <channel>
    <title>Chan\u0000nel\uFFFF</title>
    <description>\u000BChannel\tdescription\uFFFE</description>
    <link>https://example.com/a\u000Cb</link>
    <item>
      <title>Item\u0001title</title>
      <link>https://example.com/c\u0002d</link>
      <guid>https://example.com/e\u0003f</guid>
      <description>Item\u0004description</description>
      <content:encoded><![CDATA[<p>Item\u0005body</p>]]></content:encoded>
      <author>ada\u0006@example.com</author>
      <category>his\u0007tory</category>
    </item>
  </channel>
</rss>`;

Deno.test("exportFeed strips the characters XML 1.0 forbids from every field it emits", async () => {
  const xml = exportFeed(await parseFeed(RSS_WITH_XML_ILLEGAL_CHARACTERS));

  const survivors = [...xml].filter((char) => XML_1_0_FORBIDDEN.test(char));
  assertEqual(survivors.length, 0, "forbidden characters left in the document");

  // Stripped, not dropped: the rest of each field is still there, on the same item.
  assertIncludes(xml, "<title>Channel</title>");
  assertIncludes(xml, "<link>https://example.com/ab</link>");
  assertIncludes(xml, "<title>Itemtitle</title>");
  assertIncludes(xml, "<link>https://example.com/cd</link>");
  assertIncludes(xml, "<guid>https://example.com/ef</guid>");
  assertIncludes(xml, "<description>Itemdescription</description>");
  assertIncludes(xml, "&lt;p&gt;Itembody&lt;/p&gt;");
  assertIncludes(xml, "<author>ada@example.com</author>");
  assertIncludes(xml, "<category>history</category>");
  assertIncludes(xml, "</rss>");
  // Tab, newline and carriage return are legal XML, and are how a pre-formatted body is laid out: kept.
  assertIncludes(xml, "<description>Channel\tdescription</description>");
  assert(itemCount(xml) === 1, `exactly one <item>, got ${itemCount(xml)}`);
});

Deno.test("exportFeed removes an unpaired surrogate and leaves a valid astral character alone", async () => {
  // &#xD800; is a lone surrogate: it cannot be encoded as UTF-8, so it cannot be in the document either. A
  // valid astral character (here an emoji) is ONE code point to a `u` regex, so the same surrogate range
  // must not touch it - otherwise the strip would quietly delete every emoji in a feed.
  const xml = exportFeed(await parseFeed(ATOM_WITH_LONE_SURROGATE));
  assertIncludes(xml, "<title>XY</title>");
  assertIncludes(xml, "<title>Smile \u{1F600}</title>");
  assertEqual(
    [...xml].filter((char) => XML_1_0_FORBIDDEN.test(char)).length,
    0,
    "forbidden characters left in the document",
  );
});

Deno.test("exportFeed emits RSS 2.0 channel metadata from an RSS 2.0 feed", async () => {
  const xml = exportFeed(await parseFeed(RSS));
  // The pin is the declaration a reader depends on - that this is an RSS 2.0 document - not the root
  // element's attribute layout: @feed/feed 1.3.0 lays the xmlns declarations across lines (and adds
  // xmlns:media), which is whitespace and attributes no reader parses (full-rss-vek).
  assertIncludes(xml, '<rss version="2.0"');
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
  // Same pin as above: the RSS 2.0 declaration, not the root element's attribute layout (full-rss-vek).
  assertIncludes(xml, '<rss version="2.0"');
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
  The export loop is bounded at MAX_ITEMS (200) emitted items (full-rss-l66): a feed with tens of thousands
  of entries may not turn into unbounded per-item sanitization and build work. The fixture is built, not
  pasted: one titled item per line, the same shape the hand-written fixtures above use.
*/
const rssWithTitledItems = (n: number): string => {
  const items = Array.from(
    { length: n },
    (_, i) =>
      `    <item><title>Item ${i + 1}</title><link>https://example.com/${
        i + 1
      }</link><guid>https://example.com/${i + 1}</guid></item>`,
  ).join("\n");
  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Big</title>
    <link>https://example.com/</link>
${items}
  </channel>
</rss>`;
};

Deno.test("exportFeed truncates a feed to its first 200 items", async () => {
  const xml = exportFeed(await parseFeed(rssWithTitledItems(205)));
  assertEqual(
    itemCount(xml),
    200,
    "the document holds exactly MAX_ITEMS items",
  );
  assertIncludes(
    xml,
    "<title>Item 200</title>",
    "the last kept item is the 200th",
  );
  assertExcludes(
    xml,
    "<title>Item 201</title>",
    "everything past the bound is cut",
  );
});

Deno.test("exportFeed's item bound counts emitted items, not entries scanned", async () => {
  // 210 untitled entries are skipped before any sanitize/build work, so they spend none of the budget:
  // the 5 titled entries after them all still emit.
  const untitled = Array.from(
    { length: 210 },
    (_, i) =>
      `    <item><link>https://example.com/u${i}</link><guid>https://example.com/u${i}</guid></item>`,
  ).join("\n");
  const titled = Array.from(
    { length: 5 },
    (_, i) =>
      `    <item><title>Item ${i + 1}</title><link>https://example.com/${
        i + 1
      }</link><guid>https://example.com/${i + 1}</guid></item>`,
  ).join("\n");
  const xml = exportFeed(
    await parseFeed(`<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Mixed</title>
    <link>https://example.com/</link>
${untitled}\n${titled}
  </channel>
</rss>`),
  );
  assertEqual(
    itemCount(xml),
    5,
    "all 5 titled items survive the untitled ones",
  );
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

/*
  The two bounded loops must select the same entries (full-rss-2t8, the factory finding
  tm-article-budget-vs-item-budget-mismatch). `exportFeed` drops an entry without a title, so an untitled
  entry can never become an emitted item - and `processFeed` must therefore not spend one of its ten article
  fetches on it either. When the predicates disagreed, a feed that leads with link-bearing untitled entries
  burned the whole expansion budget on entries the export then discarded, and the titled entries that
  followed came back unexpanded, having cost ten outbound fetches and conversions for nothing.

  What is observed here is which entries the expansion loop ATTEMPTED, because that attempt is the budget:
  the gate runs with `--allow-env` only, exactly as tests/integration/server.test.ts documents, so every
  attempt ends in the loop's error path (no KV handle without `--unstable-kv`, and no network permission),
  and processFeed logs the URL it failed on. The assertion holds in either world - with KV and network an
  attempt would succeed instead of logging - but the gate world is the one where nothing is spent.
*/
const RSS_LEADING_UNTITLED = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Untitled first</title>
    <link>https://example.com/</link>
${
  Array.from(
    { length: 12 },
    (_, i) =>
      `    <item><link>https://example.com/untitled-${i}</link><guid>u${i}</guid></item>`,
  ).join("\n")
}
${
  [1, 2, 3]
    .map(
      (n) =>
        `    <item><title>Titled ${n}</title><link>https://example.com/titled-${n}</link><guid>t${n}</guid></item>`,
    )
    .join("\n")
}
  </channel>
</rss>`;

Deno.test("processFeed spends its expansion budget only on entries the export can emit", async () => {
  const originalError = console.error;
  const lines: string[] = [];
  console.error = (...parts) => lines.push(parts.join(" "));
  try {
    await processFeed(await parseFeed(RSS_LEADING_UNTITLED));

    const attempted = lines
      .filter((line) => line.includes("Failed to fetch content for"))
      .join("\n");

    // The bug in one assertion: the twelve untitled entries in front must not consume any of the ten
    // fetches, so the three titled entries behind them are all still expanded.
    for (const n of [1, 2, 3]) {
      assertIncludes(
        attempted,
        `https://example.com/titled-${n}`,
        `titled entry ${n} still gets its expansion`,
      );
    }

    // And the converse: no untitled entry was ever a fetch target, because the export would drop it.
    assertExcludes(
      attempted,
      "https://example.com/untitled-",
      "a title-less entry never spends an article fetch",
    );
  } finally {
    console.error = originalError;
  }
});
