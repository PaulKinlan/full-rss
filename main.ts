/*
  full-rss - takes an RSS feed and returns the full content of each article in the same RSS feed.

  Hosted using Deno.
  + KV storage for caching of the full content of each article.

  We never cache the feed, we want any RSS reader to always get the latest feed. (TODO: maybe introduce some basic caching for the feed itself)
*/

import crypto from "node:crypto";
import { load } from "cheerio";
import TurndownService from "turndown";
import { Rss } from "@feed/feed";
import { parseFeed, Feed } from "@mikaelporttila/rss";
import { marked } from "marked";
import sanitizeHtml from "sanitize-html";
import { index } from "./templates/index.ts";

const db = await Deno.openKv();

const covertToMarkdown = (html: string): string => {
  const turndown = new TurndownService();
  const $ = load(html);

  const title = $("title").first().text();
  const bodyText = $("body").first().html();

  turndown.addRule("no-style", {
    filter: [
      "style",
      "script",
      "footer",
      "iframe",
      "head",
      "img",
      "input",
      "footer",
      "nav",
      "header",
    ],
    replacement: function (content: any) {
      return "";
    },
  });

  turndown.addRule("no-header", {
    filter: (node: any) => {
      const role = node.getAttribute("role");

      return role == "banner" || role == "navigation";
    },
    replacement: (content: any) => {
      return "";
    },
  });

  turndown.addRule("no-link", {
    filter: ["a"],
    replacement: function (content: any) {
      return content;
    },
  });

  const markdown = turndown.turndown(bodyText);
  return `# ${title}\n\n${markdown}`;
};

const exportFeed = async (feed: Feed): Promise<string> => {
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

    const authors = parseAuthors(entry.author);

    const content = entry.content?.value || "";

    const links = entry.links?.map((link) => link.href) || [];

    const categories = entry.categories?.map((category) => category.term) || [];

    const date = entry.published || entry.updated || new Date();

    rssFeed.addItem({
      title: entry.title?.value || "",
      description: entry.description?.value || "",
      link: links[0] || "",
      id: entry.id || "",
      updated: date,
      content: {
        body: content,
        type: "text/html",
      },
    });
  }

  return rssFeed.build();
};

const fetchContent = async (url: string): Promise<string> => {
  if (URL.canParse(url) === false) {
    throw new Error(`Invalid URL ${url}`);
  }

  const urlHash = crypto.createHash("sha256").update(url).digest("hex");
  let contentKV = await db.get([urlHash]);
  let content: Uint8Array = contentKV?.value as Uint8Array;

  if (content == null) {
    // Think about queing this later.
    const newFeed = await fetch(url);

    // We are not going to save the HTML, we are going to convert it to markdown. We will take the encoding, decoding hit.

    const markDown = covertToMarkdown(await newFeed.text());

    const stringStream = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(markDown));
        controller.close();
      },
    });

    // Cache the content in KV, and compress it

    const compressedReadableStream = stringStream.pipeThrough(
      new CompressionStream("gzip")
    );

    let compressedContent: Uint8Array[] = [];
    let totalSize = 0;
    const reader = compressedReadableStream?.getReader();

    if (reader == undefined) {
      throw new Error("Failed to read compressed content");
    }

    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        // Do something with last chunk of data then exit reader
        break;
      }
      // Otherwise do something here to process current chunk
      compressedContent.push(value);
      totalSize += value.byteLength;
    }

    console.log(url, totalSize);

    const concatenated = new Uint8Array(totalSize);
    let offset = 0;
    //finally build the compressed array and return it
    for (const array of compressedContent) {
      concatenated.set(array, offset);
      offset += array.byteLength;
    }

    content = concatenated;

    db.set([urlHash], content, {
      expireIn: 60 * 1000, // 60 seconds
    });
  }

  // decompress the content
  const newContent = await new Response(
    new ReadableStream({
      pull(controller) {
        controller.enqueue(content);
        controller.close();
      },
    }).pipeThrough(new DecompressionStream("gzip"))
  ).text();

  return sanitizeHtml(marked.parse(newContent));
};

/*
  Process the feed and attempt to get the full content of each article.
*/
const processFeed = async (feed: Feed): Promise<Feed> => {
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

Deno.serve(async (req) => {
  if (req.method !== "GET") {
    return new Response("Method not allowed", { status: 405 });
  }

  const { searchParams } = new URL(req.url);
  const url = searchParams.get("url");

  if (!url) {
    return new Response(await index(undefined), {
      status: 200,
      headers: { "content-type": "text/html" },
    });
  }

  if (URL.canParse(url) === false) {
    return new Response(
      await index(
        "Invalid URL parameter. Please enter a valid URL e.g, https://paul.kinlan.me/index.xml"
      ),
      { status: 400 }
    );
  }

  console.log(`Fetching feed from ${url}`);

  const feedResponse = await fetch(url);
  if (!feedResponse.ok) {
    return new Response(
      await index("There was an error fetching the feed. Please check the URL"),
      {
        status: 500,
      }
    );
  }

  const feedXml = await feedResponse.text();

  const feed = await parseFeed(feedXml);
  const fullFeed = await processFeed(feed);

  return new Response(await exportFeed(fullFeed));
});
