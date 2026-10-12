import template from "whatwg-flora-tmpl";

// whatwg-flora-tmpl streams interpolations VERBATIM: it does not escape them. Everything interpolated into
// this page therefore has to be escaped here, and `message` is the only such value. It is a plain sentence
// today (every call site in main.ts passes a literal), which is exactly why the escaping belongs in the code
// rather than in a convention: nothing stops a future caller from passing `url` or an upstream error string
// through. Escaping is done in one pass over the original string, so "&" is not re-escaped by the other
// replacements. (full-rss-2n6.)
const HTML_ESCAPES: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

const escapeHtml = (value: string): string =>
  value.replace(/[&<>"']/g, (char) => HTML_ESCAPES[char] ?? char);

export const index = (
  message: string | undefined,
) =>
  template`<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Full Feed RSS</title>
  <style>
    p.warning { color: red; }
  </style>
</head>

<body>
  <h1>Full Feed RSS</h1>
  <p>Full Feed RSS is a simple RSS feed reader that displays the full content of the articles.</p>

  ${message ? template`<p class="warning">${escapeHtml(message)}</p>` : ""}

  <form action="/">
    <label for="url">Enter the URL of the RSS feed:</label><br>
    <input type="url" id="url" name="url" required><br><br>
    <input type="submit" value="Submit">
  </form>

  <footer>
    <p>Created by <a href="https://paul.kinlan.me/">Paul Kinlan</a></p>
  </footer>

</body>

</html>`;
