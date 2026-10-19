/*
  feed.ts - the feed itself: `exportFeed` renders a parsed feed as the RSS 2.0 document a reader receives,
  and `processFeed` fills in each item's full article content (up to MAX_ARTICLES) using content.ts.

  Parsing the incoming XML document is deliberately NOT here: that happens at the HTTP boundary in
  server.ts, which hands this module a parsed Feed (full-rss-11b, the ADR full-rss-7d0).
*/

import { Rss } from "@feed/feed";
import { Feed } from "@mikaelporttila/rss";
import sanitizeHtml from "sanitize-html";
import { fetchContent } from "./content.ts";
import { sanitizeForLog } from "./egress.ts";

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
const escapeXml = (value: string): string =>
  value.replace(/[&<>"']/g, (char) => XML_ESCAPES[char] ?? char);

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

  const rssFeed = new RssWithItemMetadata({
    title: feed.title?.value || "",
    description: feed.description || "",
    link: feed.links[0] || "",
    authors: parseAuthors(feed.author),
  });

  for (const entry of feed.entries) {
    if (entry.title == null) {
      continue;
    }

    const content = sanitizeFeedHtml(entry.content?.value);

    const links = entry.links?.map((link) => link.href) || [];

    const date = entry.published || entry.updated || new Date();

    // The item's author and categories go with the item: the subclass above writes them into the item's own
    // block, because the builder cannot carry them itself (full-rss-fhy).
    rssFeed.addItemWithMetadata(
      {
        title: entry.title?.value || "",
        description: sanitizeFeedHtml(entry.description?.value),
        link: links[0] || "",
        id: entry.id || "",
        updated: date,
        content: {
          body: content,
          type: "html",
        },
      },
      {
        author: itemAuthor(entry.author),
        categories: itemCategories(entry.categories),
      },
    );
  }

  return rssFeed.build();
};

/*
  Process the feed and attempt to get the full content of each article.
*/
export const processFeed = async (
  feed: Feed,
  signal?: AbortSignal,
): Promise<Feed> => {
  const MAX_ARTICLES = 10;
  let articleCount = 0;
  for (const item of feed.entries) {
    signal?.throwIfAborted();
    if (articleCount >= MAX_ARTICLES) {
      // only process the first 10 articles
      break;
    }
    if (item.links == null || item.links.length === 0) {
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
      item.content.value = await fetchContent(url, signal);
    } catch (e) {
      // There was an error parsing the content, let's just skip this article rather than nuke the feed.
      if (signal?.aborted) throw e;
      console.error(sanitizeForLog(`Failed to fetch content for ${url}, ${e}`));
    }
    articleCount++;
  }
  return feed;
};
