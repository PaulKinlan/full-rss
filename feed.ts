/*
  feed.ts - the feed itself: `exportFeed` renders a parsed feed as the RSS 2.0 document a reader receives,
  and `processFeed` fills in each item's full article content (up to MAX_ARTICLES) using content.ts.

  Parsing the incoming XML document is deliberately NOT here: that happens at the HTTP boundary in
  server.ts, which hands this module a parsed Feed (full-rss-11b, the ADR full-rss-7d0).
*/

import { Rss } from "@feed/feed";
import { Feed } from "@mikaelporttila/rss";
import { fetchContent } from "./content.ts";

export const exportFeed = (feed: Feed): string => {
  // Let's just assume RSS.

  const parseAuthors = (
    author: undefined | typeof feed.author
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

  const rssFeed = new Rss({
    title: feed.title?.value || "",
    description: feed.description || "",
    link: feed.links[0] || "",
    authors: parseAuthors(feed.author),
  });

  for (const entry of feed.entries) {
    if (entry.title == null) {
      continue;
    }

    const content = entry.content?.value || "";

    const links = entry.links?.map((link) => link.href) || [];

    const date = entry.published || entry.updated || new Date();

    // The item's author and categories are NOT emitted, and that is a limit of the feed builder rather than
    // an omission here: @feed/feed's RssItem is exactly {title, link, id, updated, description, content} and
    // its RssFeed.build() renders only those fields, so an item has nowhere to carry an author or a
    // category. Parsing them and passing them to addItem() is silently ignored (measured 2026-10-12 against
    // jsr:@feed/feed@1.1.0), which is why the two locals that used to do it are gone (full-rss-dhz).
    // Emitting them needs the field upstream in @feed/feed, or a builder of our own - tracked separately.
    rssFeed.addItem({
      title: entry.title?.value || "",
      description: entry.description?.value || "",
      link: links[0] || "",
      id: entry.id || "",
      updated: date,
      content: {
        body: content,
        type: "html",
      },
    });
  }

  return rssFeed.build();
};

/*
  Process the feed and attempt to get the full content of each article.
*/
export const processFeed = async (feed: Feed): Promise<Feed> => {
  const MAX_ARTICLES = 10;
  let articleCount = 0;
  for (const item of feed.entries) {
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
      item.content.value = await fetchContent(url);
    } catch (e) {
      // There was an error parsing the content, let's just skip this article rather than nuke the feed.
      console.error(`Failed to fetch content for ${url}, ${e}`);
    }
    articleCount++;
  }
  return feed;
};
