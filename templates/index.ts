import template from "whatwg-flora-tmpl";

export const index = async (
  message: string | undefined
) => template`<!DOCTYPE html>
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

  ${message ? template`<p class="warning">${message}</p>` : ""}

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
