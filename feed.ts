/*
  feed.ts - the feed itself: `exportFeed` renders a parsed feed as the RSS 2.0 document a reader receives
  (at most MAX_ITEMS items and at most MAX_DOCUMENT_BYTES, so an upstream's entry count and item sizes cannot
  become unbounded export work - full-rss-l66, full-rss-nb7), and `processFeed` fills in each item's full
  article content (up to MAX_ARTICLES) using content.ts.

  Parsing the incoming XML document is deliberately NOT here: that happens at the HTTP boundary in
  server.ts, which hands this module a parsed Feed (full-rss-11b, the ADR full-rss-7d0).
*/

import { Rss } from "@feed/feed";
import { Feed } from "@mikaelporttila/rss";
import sanitizeHtml from "sanitize-html";
import { fetchContent } from "./content.ts";
import { type FetchUrlOptions } from "./egress.ts";
import { sanitizeForLog } from "./log-sanitize.ts";

/*
  Feed-supplied markup is untrusted input on its way to a reader: an item whose article expansion was
  skipped (no link, or past MAX_ARTICLES) or fell back after a fetch error carries the publisher's raw HTML
  into content:encoded and description, and a feed reader renders that HTML. Expanded articles pass through
  sanitize-html in content.ts already; run every item through the same defaults here at the single export
  boundary, so the guarantee does not depend on which path filled the item (full-rss-9vl). sanitize-html is
  idempotent under a fixed config, so the already-sanitized expanded content is unchanged by the second pass.
*/
const sanitizeFeedHtml = (html: string | undefined): string =>
  sanitizeHtml(html ?? "");

/*
  RSS 2.0 gives every item its own <author> and <category> elements, and @feed/feed can express neither: its
  RssItem is exactly {title, link, id, updated, description, content} (plus image since 1.3.0) and anything
  else handed to addItem() is silently ignored - measured against jsr:@feed/feed@1.1.0 and @1.3.0
  (full-rss-fhy, and the reason an item's parsed author used to be dead code in full-rss-dhz).

  Items are therefore added through the small subclass below, which writes those two elements at the single
  place the library emits for every item, "    </item>\n":
    * in the order addItem was called - entry order - so an item's metadata lands on its own item;
    * only when there is something to write, so an item with neither renders exactly as it did before;
    * after checking the item count, so a change to the library's item rendering fails loudly instead of
      putting one article's author on another article.
*/
const ITEM_END = "    </item>\n";

const XML_ESCAPES: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&apos;",
};

// One pass over the characters, so an entity that is already escaped is never escaped twice (the same
// reason templates/index.ts spells its HTML escaper out rather than chaining replaces).
//
// Escaping is not sanitising: this makes a string safe to place between tags, it does not make it legal XML
// (see stripXmlIllegal below, which runs once on the whole document).
const escapeXml = (value: string): string =>
  value.replace(/[&<>"']/g, (char) => XML_ESCAPES[char] ?? char);

/*
  XML 1.0 cannot represent every character a JavaScript string can hold. Its Char production is
  #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF], so the C0 controls other than tab,
  newline and carriage return, the two BMP noncharacters U+FFFE/U+FFFF, and unpaired surrogates (which cannot
  be encoded as UTF-8 at all) are all forbidden. A publisher's article that contains one - a form feed left
  behind by a PDF scrape is the everyday case - makes this document NOT well-formed, and a reader rejects the
  whole feed for it rather than skipping the one item that carried the character (full-rss-7kn).

  The strip happens ONCE, on the rendered document, rather than in each escaper. escapeXml above covers only
  the two elements this module writes itself (<author>, <category>); title, description, link, guid and
  content:encoded all go through @feed/feed, so a per-field fix is only ever as complete as the list of fields
  that happens to exist today. Running over the whole document is safe because it is assembled entirely from
  strings written here, and every entity escapeXml emits is ASCII - no character it removes can be part of
  one.

  Removing rather than substituting is deliberate: the surrounding text is what the publisher sent, and a
  replacement (a space, U+FFFD) would be text this service invented. Tab, newline and carriage return are
  kept, since they are legal and are how pre-formatted article bodies are laid out.

  The class IS the spec's complement, not a guessed set, and the surrogate arm relies on the `u` flag: in
  Unicode mode a surrogate range matches only a LONE surrogate, because a valid astral character reaches the
  regex as one code point (measured: "x\u{1F600}y" is unchanged by this replace).
*/
const XML_ILLEGAL =
  // deno-lint-ignore no-control-regex -- naming the forbidden characters IS the point of this pattern
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFE\uFFFF]|[\uD800-\uDFFF]/gu;

const stripXmlIllegal = (xml: string): string => xml.replace(XML_ILLEGAL, "");

type ItemAuthor = { name?: string; email?: string };

/*
  An item's author in the shape RSS 2.0 expects, "email (Name)" - the same shape @feed/feed writes for the
  channel's author, so an RSS 2.0 feed round-trips: the parser hands that line back as `name` (its shape is
  {name: "ada@example.com (Ada Lovelace)"}) and it is passed through unchanged.

  A name with no email is written as it stands rather than dropped. In the spec <author> is an email address,
  so the purist spelling of a name is Dublin Core's <dc:creator>, which would mean declaring a second namespace
  on <rss> for the everyday Atom case of "<author><name>Grace Hopper</name></author>". Carrying the name in
  <author> - which the channel block here already does - is the smaller change and still reaches readers.
*/
const itemAuthor = (author: ItemAuthor | undefined): string | undefined => {
  if (author == null) {
    return undefined;
  }
  const email = (author.email || "").trim();
  const name = (author.name || "").trim();
  if (email === "") {
    return name === "" ? undefined : name;
  }
  return name === "" ? email : `${email} (${name})`;
};

const itemCategories = (
  categories: { term?: string }[] | undefined,
): string[] =>
  (categories ?? [])
    .map((category) => (category.term ?? "").trim())
    .filter((term) => term !== "");

/*
  A feed's own links - the channel <link>, each item's <link> and its <guid> - are publisher-controlled text
  that this document re-emits verbatim into what a reader consumes. The scheme decides what happens when a
  reader, or the browser it hands an item to, acts on that string: `javascript:` runs in the page rendering
  the item and `data:` can carry a whole HTML document, so neither may be re-emitted (full-rss-d2m).

  <link> is a navigation target, so it is held to what RSS/Atom mean by a link: http(s), copied unchanged
  (the parser hands back absolute hrefs), otherwise dropped to an empty element - the same shape an item
  with no link at all already produces.

  <guid> is an IDENTIFIER, not a link. Atom ids are routinely `urn:uuid:...` or `tag:blogger.com,...`, and
  dropping those would leave items with no id, so readers could no longer tell two versions of a feed apart
  (Atom feeds round-trip through this document by design). Only schemes a consumer can be made to ACT on are
  dropped. Detection goes through the URL parser so the obfuscated spellings normalise - `  JaVaScRiPt:`,
  `java\tscript:` and friends - before they are compared.
*/
const ACTIVE_SCHEMES: ReadonlySet<string> = new Set([
  "javascript:",
  "vbscript:",
  "livescript:",
  "data:",
  "blob:",
  "filesystem:",
  "file:",
  "jar:",
  "about:",
  "view-source:",
  "chrome:",
  "chrome-extension:",
  "moz-extension:",
  "ms-msdt:",
  "search-ms:",
  "mocha:",
]);

/** The scheme of `value` according to the URL parser, or null when it is not a URL at all. */
const schemeOf = (value: string): string | null => {
  try {
    return new URL(value).protocol.toLowerCase();
  } catch {
    return null;
  }
};

/** A link this document may carry: http(s) exactly, otherwise nothing. */
const safeLink = (raw: string | undefined): string => {
  const value = (raw ?? "").trim();
  const scheme = schemeOf(value);
  return scheme === "http:" || scheme === "https:" ? value : "";
};

/** An identifier this document may carry: anything a consumer cannot be made to act on. */
const safeId = (raw: string | undefined): string => {
  const value = (raw ?? "").trim();
  return ACTIVE_SCHEMES.has(schemeOf(value) ?? "") ? "" : value;
};

type FeedItem = {
  title: string;
  link: string;
  id: string;
  updated: Date;
  description: string;
  content: { body: string; type: string };
};

type ItemMetadata = { author?: string; categories: string[] };

class RssWithItemMetadata extends Rss {
  #metadata: ItemMetadata[] = [];

  addItemWithMetadata(item: FeedItem, metadata: ItemMetadata): void {
    this.#metadata.push(metadata);
    this.addItem(item);
  }

  override build(): string {
    const xml = super.build();
    if (this.#metadata.length === 0) {
      return xml;
    }

    const parts = xml.split(ITEM_END);
    const itemCount = parts.length - 1;
    if (itemCount !== this.#metadata.length) {
      throw new Error(
        `feed: ${this.#metadata.length} item(s) were added but the built feed holds ${itemCount} - the RSS ` +
          `builder's item rendering changed, so an item's author would land on the wrong article (full-rss-fhy)`,
      );
    }

    let out = parts[0];
    for (let i = 0; i < itemCount; i++) {
      const { author, categories } = this.#metadata[i];
      if (author !== undefined) {
        out += `      <author>${escapeXml(author)}</author>\n`;
      }
      for (const category of categories) {
        out += `      <category>${escapeXml(category)}</category>\n`;
      }
      out += ITEM_END + parts[i + 1];
    }
    return out;
  }
}

/*
  The single entry-selection predicate for both bounded loops below.

  `exportFeed` may only emit an entry that has a title (an RSS item with no title is not a document a reader
  can use, so untitled entries are dropped), and `processFeed` may only spend an article fetch on an entry
  that can become an emitted item. Those two conditions are the same condition: when the loops disagree, a
  feed of link-bearing but title-less entries burns the whole MAX_ARTICLES expansion budget - ten outbound
  fetches, each one an article fetched and converted - on entries the export then drops, and the titled
  entries that follow come back unexpanded (the factory finding tm-article-budget-vs-item-budget-mismatch).
  Sharing the predicate is what keeps them from drifting apart again, so both loops call it rather than each
  writing down its own test.
*/
const isEmittable = (entry: Feed["entries"][number]): boolean =>
  entry.title != null;

/** Reused so measuring a document does not re-instantiate the encoder per export. */
const documentEncoder = new TextEncoder();

/**
 * The aggregate bound on the document a reader receives, in UTF-8 bytes (full-rss-nb7). The per-item bounds
 * (MAX_ITEMS on count, MAX_ARTICLE_BYTES on one article's input) do not bound their SUM: ten expanded
 * articles at the 5MB article cap plus two hundred stub items build a ~50MB document in memory and on the
 * wire. 8MB admits one maximal legitimate article (5MB) plus every stub item whole, so the bound never
 * costs a legitimate feed more than its most extreme single article, while capping what a publisher can
 * make this service assemble, hold and serve by an order of magnitude.
 */
export const MAX_DOCUMENT_BYTES = 8 * 1024 * 1024;

/**
 * The per-field character cap on the feed-supplied CHANNEL skeleton (title, description, author name,
 * email and link). The channel cannot be truncated the way items can - it is the document's skeleton - so
 * its fields are clamped at the source instead (full-rss-s08): the feed-input byte cap does not bound the
 * serialized channel, because escapeXml amplifies (`&` -> `&amp;` is 6x, so a 2MB input of ampersands
 * built a 13.5MB channel-only document). 128K characters x 6x amplification bounds one field at ~768KB
 * serialized; the whole skeleton stays under ~5MB even with every channel field pathological, below the
 * document budget, and the item walk below adapts for whatever the skeleton leaves. 128K characters is
 * already far beyond any legitimate title or blurb, so the clamp never touches a real feed.
 */
export const MAX_CHANNEL_FIELD_CHARS = 131_072;

/** The longest prefix of `value` that fits the channel-field cap, never splitting a surrogate pair. */
const clampChannelText = (value: string): string => {
  if (value.length <= MAX_CHANNEL_FIELD_CHARS) return value;
  let end = MAX_CHANNEL_FIELD_CHARS;
  const code = value.charCodeAt(end - 1);
  // A high surrogate at the cut has lost its partner: drop it rather than emit half a character.
  if (code >= 0xd800 && code <= 0xdbff) end -= 1;
  return value.slice(0, end);
};

export const exportFeed = (feed: Feed): string => {
  // Let's just assume RSS.

  const parseAuthors = (
    author: undefined | typeof feed.author,
  ): [] | [{ name: string; email: string; link?: string }] => {
    if (author == null) {
      return [];
    }
    return [
      {
        name: author.name || "",
        email: author.email || "",
        link: author.uri,
      },
    ];
  };

  // The channel's configuration is hoisted so an over-budget document can be re-rendered with a fresh
  // builder: sanitizeFeedHtml is idempotent, so the re-rendered channel is byte-identical to the first.
  const channelArgs = {
    title: clampChannelText(feed.title?.value || ""),
    // The channel's description is feed-supplied markup exactly as an item's is, and a reader that renders a
    // channel blurb renders this one: without the pass it reached the reader escaped-but-intact, so a
    // publisher could put a script, an event handler or a `javascript:` link in the CHANNEL and have it run
    // where the same markup in an item would have been stripped (full-rss-gab, the factory finding
    // tm-channel-metadata-unsanitized). Sanitising is idempotent, so nothing an item already carries changes.
    //
    // The channel TITLE is deliberately left as text, and so is every item title: a title is a text field,
    // `escapeXml` in the builder is the complete guarantee for one, and sanitising it would silently corrupt
    // legitimate titles (`C++ & <Rust>` loses the bracketed word to a tag stripper). Only the fields a reader
    // may render as HTML are sanitised, which is the same line the item loop draws.
    description: clampChannelText(sanitizeFeedHtml(feed.description)),
    link: clampChannelText(safeLink(feed.links[0])),
    authors: parseAuthors(feed.author).map((author) => ({
      ...author,
      // String() guards the shape: a parser revision that hands back a non-string author field must hit the
      // clamp, not a TypeError.
      name: clampChannelText(String(author.name ?? "")),
      email: clampChannelText(String(author.email ?? "")),
      link: author.link == null
        ? undefined
        : clampChannelText(String(author.link)),
    })),
  };

  /*
    The export is where an upstream's entry count becomes this service's work: every entry that reaches the
    body of this loop costs two sanitize-html passes and a place in the built document, so the loop is
    bounded at MAX_ITEMS EMITTED items (full-rss-l66, the factory finding tm-unbounded-item-emission).
    The bound counts emitted items, not entries scanned: an entry without a title is skipped before any of
    that work and costs the loop nothing, so it does not spend the budget. 200 keeps every realistic feed
    whole; a feed with tens of thousands of entries is truncated, as feed readers bound feeds themselves.

    The items are collected first and rendered afterwards, so the document budget below can re-render a
    prefix of them without re-running the sanitising passes.
  */
  const MAX_ITEMS = 200;
  const collected: { item: FeedItem; metadata: ItemMetadata }[] = [];
  for (const entry of feed.entries) {
    if (collected.length >= MAX_ITEMS) {
      break;
    }
    if (!isEmittable(entry)) {
      continue;
    }

    const content = sanitizeFeedHtml(entry.content?.value);

    const links = entry.links?.map((link) => link.href) || [];

    const date = entry.published || entry.updated || new Date();

    // The item's author and categories go with the item: the subclass above writes them into the item's own
    // block, because the builder cannot carry them itself (full-rss-fhy).
    collected.push({
      item: {
        title: entry.title?.value || "",
        description: sanitizeFeedHtml(entry.description?.value),
        link: safeLink(links[0]),
        id: safeId(entry.id),
        updated: date,
        content: {
          body: content,
          type: "html",
        },
      },
      metadata: {
        author: itemAuthor(entry.author),
        categories: itemCategories(entry.categories),
      },
    });
  }

  const render = (count: number): string => {
    const doc = new RssWithItemMetadata(channelArgs);
    for (const { item, metadata } of collected.slice(0, count)) {
      doc.addItemWithMetadata(item, metadata);
    }
    return doc.build();
  };

  /*
    The aggregate byte budget (full-rss-nb7): measure the whole document, and only when it is over
    MAX_DOCUMENT_BYTES, keep the longest PREFIX of items that fits and re-render just that. Truncation, not
    refusal: throwing here would fail the whole request because one article was huge, and a smaller whole
    feed is what the reader can still use. RSS items are newest-first, so the prefix that survives is the
    head of the feed. The walk derives each item's byte size from the one build (split on ITEM_END, which is
    pure ASCII, so per-part byte lengths sum to the document's), costing no extra serialisation passes on
    the happy path beyond the single measurement.

    A single item larger than the whole budget is dropped with the rest (keep lands on 0 and the document is
    channel-only): a document budget that could not drop an item would be no bound at all. The channel
    skeleton itself is clamped field by field (MAX_CHANNEL_FIELD_CHARS above) - clamping, not dropping,
    because the channel is the document's identity: without it a dropped-items feed would have no title or
    link, and refusing would fail the whole request.

    Interplay with processFeed: an article fetch may still be spent on an item the budget later drops, the
    same way one is spent on an item past MAX_ITEMS. Ten fetches is the worst such waste, bounded.
  */
  const built = render(collected.length);
  let keep = collected.length;
  if (
    documentEncoder.encode(built).byteLength > MAX_DOCUMENT_BYTES && keep > 0
  ) {
    const parts = built.split(ITEM_END);
    const endBytes = documentEncoder.encode(ITEM_END).byteLength;
    let running = documentEncoder.encode(parts[parts.length - 1]).byteLength;
    keep = 0;
    for (let i = 0; i < collected.length; i++) {
      running += endBytes + documentEncoder.encode(parts[i]).byteLength;
      if (running > MAX_DOCUMENT_BYTES) break;
      keep = i + 1;
    }
    let xml = render(keep);
    let size = documentEncoder.encode(xml).byteLength;
    // The walk's sizes come from the same build the prefix is re-rendered from, so the rebuild should sit
    // exactly where the walk put it. If a builder rendering change ever makes it differ, drop items one at
    // a time until the document fits - the bound is hard, not advisory (full-rss-nb7).
    while (size > MAX_DOCUMENT_BYTES && keep > 0) {
      keep--;
      xml = render(keep);
      size = documentEncoder.encode(xml).byteLength;
    }
    // stripXmlIllegal only removes, so a measured document cannot grow past the budget here.
    return stripXmlIllegal(xml);
  }
  // The single export boundary: whatever a reader receives has passed through here, so this is the one place
  // the document's character set has to be legal XML 1.0 (stripXmlIllegal above).
  return stripXmlIllegal(built);
};

/*
  Process the feed and attempt to get the full content of each article.
*/
export const processFeed = async (
  feed: Feed,
  signal?: AbortSignal,
  egressOptions?: FetchUrlOptions,
): Promise<Feed> => {
  const MAX_ARTICLES = 10;
  let articleCount = 0;
  for (const item of feed.entries) {
    signal?.throwIfAborted();
    if (articleCount >= MAX_ARTICLES) {
      // only process the first 10 articles
      break;
    }
    // Same predicate as the export loop: an entry the export can never emit must not spend an article
    // fetch from MAX_ARTICLES, or the budget is consumed by items the reader never receives.
    if (!isEmittable(item) || item.links == null || item.links.length === 0) {
      continue;
    }

    const url = item?.links[0].href;

    if (url == null) {
      continue;
    }

    if (item.content == null) {
      item.content = {};
    }

    try {
      item.content.value = await fetchContent(
        url,
        signal,
        undefined,
        egressOptions,
      );
    } catch (e) {
      // There was an error parsing the content, let's just skip this article rather than nuke the feed.
      if (signal?.aborted) throw e;
      console.error(sanitizeForLog(`Failed to fetch content for ${url}, ${e}`));
    }
    articleCount++;
  }
  return feed;
};
