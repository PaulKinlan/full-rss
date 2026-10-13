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
import {
  guardedFetch,
  parseFetchableUrl,
  readCappedText,
  sanitizeForLog,
} from "./egress.ts";

// Deno KV is opened LAZILY, on first use. Importing this module (a test importing the transform, for
// instance) must not need KV permissions or a database handle; only serving and fetching do.
let db: Deno.Kv | undefined;
const kv = async (): Promise<Deno.Kv> => (db ??= await Deno.openKv());

// The most article we will read, decompressed. An upstream that hands us a giant "article" is refused
// here rather than buffered into memory (full-rss-apm).
const MAX_ARTICLE_BYTES = 5 * 1024 * 1024;

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
    // These three rules are typed for what they receive: the two "drop this" rules ignore the node's
    // content entirely, and only the role filter needs the node. `node` is an Element here (a
    // role attribute lives on elements) and the link rule keeps the text, so its content is a string.
    replacement: () => "",
  });

  turndown.addRule("no-header", {
    // `node` is what the DOM implementation hands the rule, and this type-check has no DOM lib (turndown
    // ships no types either), so the one method the rule uses is typed directly instead of `any`.
    filter: (node: { getAttribute(name: string): string | null }) => {
      const role = node.getAttribute("role");

      return role == "banner" || role == "navigation";
    },
    replacement: () => "",
  });

  turndown.addRule("no-link", {
    filter: ["a"],
    replacement: (content: string) => content,
  });

  const markdown = turndown.turndown(bodyText);
  return `# ${title}\n\n${markdown}`;
};

export const fetchContent = async (url: string): Promise<string> => {
  // What we may fetch is egress.ts's decision, not ours: this both keeps the historical "Invalid URL"
  // contract (the unit suite pins it) and refuses private/local targets before any network or cache work
  // (full-rss-apm - the second-order SSRF lived in this fetch).
  const target = await parseFetchableUrl(url);

  const urlHash = crypto.createHash("sha256").update(url).digest("hex");
  const contentKV = await (await kv()).get([urlHash]);
  let content: Uint8Array = contentKV?.value as Uint8Array;

  if (content == null) {
    // Think about queing this later.
    const newFeed = await guardedFetch(target);

    // We are not going to save the HTML, we are going to convert it to markdown. We will take the encoding, decoding hit.

    const markDown = convertToMarkdown(
      await readCappedText(newFeed, MAX_ARTICLE_BYTES),
    );

    const stringStream = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(markDown));
        controller.close();
      },
    });

    // Cache the content in KV, and compress it

    const compressedReadableStream = stringStream.pipeThrough(
      new CompressionStream("gzip"),
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

    console.log(sanitizeForLog(url), totalSize);

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
    }).pipeThrough(new DecompressionStream("gzip")),
  ).text();

  return sanitizeHtml(marked.parse(newContent));
};
