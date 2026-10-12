/*
  content.ts - one article: fetch it, convert it to markdown, cache the compressed markdown in Deno KV.

  Nothing here knows about feeds or HTTP; the caller hands it a URL. Kept separate from feed.ts and
  server.ts so a change to the cache or the transform cannot collide with a change to the RSS output or the
  routing (full-rss-11b, the ADR full-rss-7d0).

  We never cache the source HTML: we cache the markdown we derived from it, gzipped.
*/

import crypto from "node:crypto";
import { load } from "cheerio";
import TurndownService from "turndown";
import { marked } from "marked";
import sanitizeHtml from "sanitize-html";

// Deno KV is opened LAZILY, on first use. Importing this module (a test importing the transform, for
// instance) must not need KV permissions or a database handle; only serving and fetching do.
let db: Deno.Kv | undefined;
const kv = async (): Promise<Deno.Kv> => (db ??= await Deno.openKv());

// Exported so the entrypoint can open the handle at boot and fail there, loudly, when KV is unavailable -
// rather than per article inside feed.ts's processFeed error handling, which would silently degrade every
// feed to summaries only.
export const openKv = (): Promise<Deno.Kv> => kv();

export const convertToMarkdown = (html: string): string => {
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

export const fetchContent = async (url: string): Promise<string> => {
  if (URL.canParse(url) === false) {
    throw new Error(`Invalid URL ${url}`);
  }

  const urlHash = crypto.createHash("sha256").update(url).digest("hex");
  const contentKV = await (await kv()).get([urlHash]);
  let content: Uint8Array = contentKV?.value as Uint8Array;

  if (content == null) {
    // Think about queing this later.
    const newFeed = await fetch(url);

    // We are not going to save the HTML, we are going to convert it to markdown. We will take the encoding, decoding hit.

    const markDown = convertToMarkdown(await newFeed.text());

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

    const compressedContent: Uint8Array[] = [];
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

    (await kv()).set([urlHash], content, {
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
