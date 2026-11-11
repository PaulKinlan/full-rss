// tests/unit/log-sanitize.test.ts — one line of attacker-controlled text made safe to log.
//
// `sanitizeForLog` strips control characters and U+2028/U+2029, masks URL userinfo, redacts queries and
// fragments, and bounds the result, all as forward passes over a bounded window. It has its own suite since
// full-rss-had: the transform has no policy and no I/O, and four of the fifteen egress landings in a month were
// sanitizer-only changes that had to run the whole egress suite against the network policy. Separating the
// suites means a sanitizer change runs these cases and an egress change runs the egress ones, while neither
// file is edited by the other's work.
//
// Same house rules as the other unit suites: nothing here opens a socket, touches KV or depends on another
// test - every case is a function call on a string, except the cost test, which measures against a fixed
// budget rather than against the machine's speed on the day.
import {
  assert,
  assertEqual,
  assertExcludes,
  assertIncludes,
} from "../asserts.ts";
import {
  MAX_LOG_CHARS,
  MAX_LOG_SCAN,
  sanitizeForLog,
} from "../../log-sanitize.ts";

Deno.test("a short log value is unchanged by the length bound", () => {
  assertEqual(
    sanitizeForLog("Failed to fetch the feed: boom"),
    "Failed to fetch the feed: boom",
    "a line under the bound is untouched (no marker, no truncation)",
  );
});

Deno.test("an oversized attacker-controlled log value is truncated with a count", () => {
  // A feed may link to a megabyte-long path, and the URL is the log line: unbounded, one item is a
  // megabyte of log write per request (full-rss-d2m).
  const line = sanitizeForLog("https://evil.example/" + "a".repeat(100_000));
  assertIncludes(line, "https://evil.example/", "the useful prefix survives");
  assertIncludes(line, "...[truncated ", "the marker says it was cut");
  assertIncludes(line, "chars]", "the marker says how much");
  assert(
    line.length <= MAX_LOG_CHARS + 40,
    `the log line stays near the bound, got ${line.length} chars`,
  );
});

Deno.test("truncation keeps the redactions: a secret tail is still not logged", () => {
  // The redaction happens before the cut, so the query is already gone; what survives the cut is the prefix
  // of the path, which holds no secret. (A short value loses nothing: see the test above.)
  const long = "https://evil.example/" + "a".repeat(100_000) +
    "?token=secret-123";
  const line = sanitizeForLog(long);
  assertExcludes(line, "secret-123", "query redaction survives truncation");
  assertExcludes(line, "?token", "the query is redacted, not just cut");
  assertIncludes(line, "...[truncated ", "the cut is announced");
});

Deno.test("truncation never splits a surrogate pair", () => {
  // One leading char shifts the cut into the middle of an emoji, which would otherwise emit half a code
  // point (a lone surrogate) into the log.
  const line = sanitizeForLog("a" + "😀".repeat(2000));
  const prefix = line.slice(0, line.indexOf("...[truncated"));
  for (let i = 0; i < prefix.length; i++) {
    const code = prefix.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = prefix.charCodeAt(i + 1);
      assert(
        next >= 0xdc00 && next <= 0xdfff,
        `no lone high surrogate at index ${i}`,
      );
      i++;
    } else {
      assert(
        code < 0xdc00 || code > 0xdfff,
        `no lone low surrogate at index ${i}`,
      );
    }
  }
});

Deno.test("a long log value costs bounded time, not quadratic", () => {
  // The redactions are single forward passes over at most MAX_LOG_SCAN characters, so the cost of a log value
  // does not grow with the value at all (full-rss-9ey). The regression this guards: the userinfo pattern had
  // to find a literal '@', so on an '@'-free value it backtracked from every start position to the end -
  // measured at 40-100 ms of CPU for ONE ~920-character request line, and 161 SECONDS at 100k characters, on
  // the path every request takes before it fetches anything. Both sizes below measure ~0.01 ms, so the budget
  // does not fail on a slow machine; a return to the old order or the old pattern misses it by 10^4-10^6.
  const budget = 200;
  for (const size of [100_000, 5_000_000]) {
    const value = "https://evil.example/" + "a".repeat(size);
    sanitizeForLog(value); // warm up: JIT and the first use of each pattern
    const started = performance.now();
    sanitizeForLog(value);
    const elapsed = performance.now() - started;
    assert(
      elapsed < budget,
      `one ${size}-char log value to sanitize in under ${budget}ms, took ${
        Math.round(elapsed)
      }ms`,
    );
  }
});

// --- sanitizeForLog ---------------------------------------------------------------------------------------

Deno.test("log lines lose control characters and userinfo, and keep the rest", () => {
  assertEqual(
    sanitizeForLog("https://example.com/a\r\nEVIL: forged line"),
    "https://example.com/aEVIL: forged line",
    "CRLF stripped",
  );
  assertEqual(
    sanitizeForLog(
      "https://example.com/a\u{2028}EVIL: forged entry\u{2029}EVIL: forged article",
    ),
    "https://example.com/aEVIL: forged entryEVIL: forged article",
    "U+2028/U+2029 stripped (full-rss-2lr): they are not \\p{Cc} but split log streams just as CR does",
  );
  assertEqual(
    sanitizeForLog("https://user:secret@example.com/feed"),
    "https://***@example.com/feed",
    "userinfo masked",
  );
  assertEqual(
    sanitizeForLog("https://example.com/feed.xml"),
    "https://example.com/feed.xml",
    "an ordinary URL untouched",
  );
  assertIncludes(
    sanitizeForLog("\x1b[31mred\x1b[0m"),
    "red",
    "ANSI escapes gone, text kept",
  );
  assertEqual(
    sanitizeForLog(
      "Failed for https://example.com/feed?api_key=secret&next=other#token in parser",
    ),
    "Failed for https://example.com/feed?[redacted]",
    "all query values and fragments in an embedded URL are redacted",
  );
  assertEqual(
    sanitizeForLog("Invalid URL not-a-url?access_token=secret"),
    "Invalid URL not-a-url?[redacted]",
    "invalid URLs in errors do not reveal query values",
  );
  assertEqual(
    sanitizeForLog(
      "Fetching feed from https://example.com/feed?q=a b&api_key=SECRET",
    ),
    "Fetching feed from https://example.com/feed?[redacted]",
    "raw URL query whitespace cannot expose later credentials",
  );
  assertEqual(
    sanitizeForLog("Failed for https://example.com/feed#part a&token=SECRET"),
    "Failed for https://example.com/feed#[redacted]",
    "raw URL fragment whitespace cannot expose later credentials",
  );
});

Deno.test("userinfo is masked even when the '@' sits past the length bound", () => {
  // Regression (full-rss-al9): the length cut used to be applied BEFORE the redactions, so a userinfo longer
  // than MAX_LOG_CHARS never matched and was logged verbatim — `http://user:secretpasswordaaa...`. The bound
  // is a LOG-WRITE bound, never a licence to emit a secret whose delimiter was past it.
  const line = sanitizeForLog(
    "http://user:secretpassword" + "a".repeat(2000) + "@evil.example/path",
  );
  assertExcludes(line, "secretpassword", "the password is not logged");
  assertIncludes(line, "http://***@", "the userinfo is masked");
  // Masking a 2 KB userinfo shortens the line well under the bound, so there is nothing left to cut - the
  // property under test here is that the REDACTION ran, not that the cut did.
  assert(
    line.length <= MAX_LOG_CHARS + 40,
    `the log line stays near the bound, got ${line.length} chars`,
  );
});

Deno.test("a password is masked whichever legal userinfo character it contains", () => {
  // Regression (full-rss-96w): an earlier version of the authority scan stopped at ', ", < and > on the theory
  // that a URL authority cannot contain them, so a password holding one was logged verbatim - while the regex
  // it replaced had masked it. WHATWG retains all four in userinfo, so they are userinfo here too.
  for (const pw of ["sec'ret", 'sec"ret', "sec<ret", "sec>ret", "pa\\ss"]) {
    const line = sanitizeForLog(`http://user:${pw}@evil.example/x`);
    assertExcludes(line, pw, `the password with ${pw} is not logged`);
    assertEqual(
      line,
      "http://***@evil.example/x",
      `userinfo holding ${pw} is masked whole`,
    );
  }
});

Deno.test("userinfo masking reads through the last '@', not the first", () => {
  // A password may contain an '@'. Masking to the first one would log the rest of it.
  assertEqual(
    sanitizeForLog("http://user:p@ss@evil.example/x"),
    "http://***@evil.example/x",
    "the whole userinfo is masked, including an '@' inside the password",
  );
});

Deno.test("an '@' in the path is not userinfo and is left alone", () => {
  assertEqual(
    sanitizeForLog("https://example.com/@user/profile"),
    "https://example.com/@user/profile",
    "a path '@' is not masked (the authority ended at the first '/')",
  );
});

Deno.test("userinfo is masked in WHATWG's other authority spellings, not just '://'", () => {
  // Regression (full-rss-1xy): the anchor was a literal '://', so credentials behind the other spellings a
  // WHATWG parser accepts reached logs verbatim. A special scheme reads ANY run of '/' and '\' after its
  // colon as the authority delimiter - or none at all (full-rss-xv3) - and a scheme-relative reference
  // carries userinfo with no scheme.
  assertEqual(
    sanitizeForLog("http:user:secret@evil.example/x"),
    "http:***@evil.example/x",
    "a special scheme needs no slash: the colon alone opens the authority",
  );
  assertEqual(
    sanitizeForLog("ws:user:secret@evil.example/x"),
    "ws:***@evil.example/x",
    "every special scheme, not only http",
  );
  assertEqual(
    sanitizeForLog("HTTP:USER:SECRET@EVIL.EXAMPLE/X"),
    "HTTP:***@EVIL.EXAMPLE/X",
    "schemes are ASCII case-insensitive",
  );
  assertEqual(
    sanitizeForLog("http:\\user:secret@evil.example/x"),
    "http:\\***@evil.example/x",
    "a backslash after the scheme opens the authority too",
  );
  assertEqual(
    sanitizeForLog("http:\\\\user:secret@evil.example/x"),
    "http:\\\\***@evil.example/x",
    "doubled backslashes, which a WHATWG parser normalises the same way",
  );
  assertEqual(
    sanitizeForLog("http:/user:secret@evil.example/x"),
    "http:/***@evil.example/x",
    "a single slash after a special scheme still parses to an authority",
  );
  assertEqual(
    sanitizeForLog("//user:secret@evil.example/x"),
    "//***@evil.example/x",
    "scheme-relative reference",
  );
  assertEqual(
    sanitizeForLog("Invalid URL //user:secret@evil.example given"),
    "Invalid URL //***@evil.example given",
    "scheme-relative reference inside an error message",
  );
});

Deno.test("colon-and-slash text that is not an authority is left alone", () => {
  // The anchor needs a scheme token (WHATWG's grammar: a letter, then letters/digits/+/-/.), so timestamps
  // and ratios never mask, and a Windows path without an '@' has nothing to mask.
  assertEqual(
    sanitizeForLog("retried 10:30/45 at 2026-11-09T04:01:22"),
    "retried 10:30/45 at 2026-11-09T04:01:22",
    "timestamps and ratios are not an authority",
  );
  assertEqual(
    sanitizeForLog("scanning C:\\Users\\name\\notes"),
    "scanning C:\\Users\\name\\notes",
    "a Windows path without an '@' is untouched",
  );
  assertEqual(
    sanitizeForLog("http: rejected user@host"),
    "http: rejected user@host",
    "a special-scheme colon before prose is not an authority: the space ends it before any '@'",
  );
  assertEqual(
    sanitizeForLog("term:Monday@noon"),
    "term:Monday@noon",
    "a non-special scheme has no authority without '//'",
  );
});

Deno.test("a doubled slash inside a path masks liberally rather than leaking", () => {
  // The scheme-relative anchor cannot tell a path's '//' from a reference's '//' without parsing, and
  // masking one thing too many is the safe direction (the maskUserinfo docblock): a path '//b@cdn' is
  // masked even though a URL parser would call it path.
  assertEqual(
    sanitizeForLog("https://example.com/a//b@cdn/x"),
    "https://example.com/a//***@cdn/x",
    "a path '@' after a '//' is over-masked, never logged",
  );
});

Deno.test("an authority that runs past the scan window is masked fail-closed", () => {
  // MAX_LOG_SCAN bounds the work (full-rss-9ey), so on a value longer than the window the '@' that ends a
  // userinfo can sit outside anything this function looks at. Masking the whole visible authority is the
  // fail-closed answer; emitting it is the original leak again, one window further out.
  const line = sanitizeForLog(
    "http://user:hunter2" + "a".repeat(MAX_LOG_SCAN) + "@evil.example/p",
  );
  assertExcludes(
    line,
    "hunter2",
    "no password from an authority whose end was not seen",
  );
  assertIncludes(line, "http://***@", "the visible authority is masked");
});
