/*
  server.ts - the HTTP side: validate ?url=, fetch the feed document, parse it, hand the parsed feed to
  feed.ts, and turn every outcome into a response. `serve()` owns the socket and opens the KV handle, so
  importing this module binds nothing; main.ts is the thin file Deno Deploy runs (full-rss-11b).

  We never cache the feed, we want any RSS reader to always get the latest feed. (TODO: maybe introduce some
  basic caching for the feed itself)
*/

import { parseFeed } from "@mikaelporttila/rss";
import { index } from "./templates/index.ts";
import { openKv } from "./content.ts";
import { exportFeed, processFeed } from "./feed.ts";

export const handleRequest = async (req: Request): Promise<Response> => {
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
        "Invalid URL parameter. Please enter a valid URL e.g, https://paul.kinlan.me/index.xml",
      ),
      { status: 400 },
    );
  }

  console.log(`Fetching feed from ${url}`);

  const feedResponse = await fetch(url);
  if (!feedResponse.ok) {
    return new Response(
      await index("There was an error fetching the feed. Please check the URL"),
      {
        status: 500,
      },
    );
  }

  const feedXml = await feedResponse.text();

  try {
    const feed = await parseFeed(feedXml);
    const fullFeed = await processFeed(feed);

    return new Response(exportFeed(fullFeed), {
      headers: { "content-type": "application/rss+xml" },
    });
  } catch (e) {
    console.error(e);
    return new Response(
      await index(
        "There was an error parsing the feed or an item in the feed. Please check the URL is a valid feed",
      ),
      {
        status: 500,
      },
    );
  }
};

export const serve = async (): Promise<void> => {
  // Open the KV handle at boot and only at boot: an unavailable KV must fail here, loudly, instead of
  // failing per article inside processFeed's error handling (which would silently degrade every feed to
  // summaries only).
  await openKv();
  Deno.serve(handleRequest);
};
