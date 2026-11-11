/*
  log-sanitize.ts - one line of attacker-controlled text made safe to log: control characters and line
  separators stripped, URL userinfo masked, queries/fragments redacted, and the result bounded in length
  (`sanitizeForLog`, plus the two bounds its behaviour is described by).

  This lived in egress.ts until full-rss-had, and the split is about COLLISION, not about speed: egress.ts is
  the network policy (which targets may be fetched, redirect re-validation, byte caps) and this is a pure
  string transform with no I/O and no policy in it, yet four of the fifteen egress landings in one month were
  sanitizer-only changes competing with DNS/IP/redirect edits for the same source file and the same test file.
  Split out, a change here touches ~250 lines nobody else edits and its suite is selected on its own
  (`tools/suite-map.tsv`), while egress.ts keeps every egress suite.

  It imports nothing, deliberately: a function over a string can be read, tested and reasoned about without the
  network policy, and a change to the policy cannot change how a log line is sanitized.
*/

/**
 * No log line carries more than this many characters of attacker-controlled text. A URL is the content of
 * these lines and a feed may link to a megabyte-long path, so without a bound one item becomes a megabyte of
 * log write per request (full-rss-d2m). Truncation happens LAST, after the redactions below, so the surviving
 * prefix is already sanitized and the marker only counts what was dropped.
 */
export const MAX_LOG_CHARS = 1024;

/**
 * Most characters of attacker-controlled text a log line is ever redacted from: four times the emitted bound,
 * because redactions can only shorten what they touch, so the surviving prefix of a real line is well inside
 * it. The cut here is a CPU bound (full-rss-9ey); MAX_LOG_CHARS is the log-write bound. A value longer than
 * this is redacted as a window - with the userinfo of an authority that runs past the window masked fail
 * closed, so no secret is emitted from text whose end could not be seen (full-rss-al9).
 */
export const MAX_LOG_SCAN = 4 * MAX_LOG_CHARS;

/**
 * Where the authority of an absolute URL ends: at the first '/' or whitespace, exactly the set the regex this
 * replaced excluded (`[^@/\s]`). That set is deliberate and must not grow. An earlier version of this function
 * also stopped at `'`, `"`, `<`, `>` and `\\` on the theory that a URL authority cannot contain them - it can:
 * WHATWG retains all of those in userinfo (percent-encoded in `href`, unencoded in the raw string we are handed),
 * so stopping there meant `sanitizeForLog("http://user:sec'ret@host/x")` returned the password verbatim while
 * the regex had masked it (full-rss-96w). Over-masking is the safe direction (the docblock below says so);
 * under-masking is the bug. Nothing before a '/' can be told apart from userinfo reliably enough to stop early,
 * and text before the '/' is exactly where a password can sit - a '?' or '#' or quote inside it is masked
 * too, which costs nothing: a query or fragment is redacted wholesale a moment later.
 */
const endsAuthority = (value: string, index: number): boolean =>
  value[index] === "/" || value.charCodeAt(index) <= 0x20;

/** A scheme token starts with a letter: WHATWG's scheme grammar is `[a-zA-Z][a-zA-Z0-9+.-]*`. */
const isSchemeStart = (code: number): boolean =>
  (code >= 97 && code <= 122) || (code >= 65 && code <= 90);

const isSchemeChar = (code: number): boolean =>
  isSchemeStart(code) ||
  (code >= 48 && code <= 57) ||
  code === 43 ||
  code === 45 ||
  code === 46;

/** '/' and '\\': each can follow a scheme's colon and open an authority, alone or in a mixed run. */
const isAuthoritySlash = (code: number): boolean => code === 47 || code === 92;

/**
 * The six WHATWG special schemes (lowercase, compared ASCII case-insensitively - `value.charCodeAt(c) | 0x20`
 * lowercases a letter and leaves every other scheme character unchanged). Only these parse an authority out
 * of the text directly after their colon, with no slash at all: `http:user:pass@host/x` is a validation
 * error that still yields username `user`, password `secret`, host `evil.example` (full-rss-xv3). A
 * non-special scheme needs the `//` - `term:Monday@noon` has a path, and no userinfo, without it.
 */
const SPECIAL_SCHEMES = ["http", "https", "ws", "wss", "ftp", "file"];

const isSpecialScheme = (value: string, from: number, to: number): boolean => {
  for (const scheme of SPECIAL_SCHEMES) {
    if (to - from !== scheme.length) continue;
    let same = true;
    for (let at = from; at < to; at++) {
      if ((value.charCodeAt(at) | 0x20) !== scheme.charCodeAt(at - from)) {
        same = false;
        break;
      }
    }
    if (same) return true;
  }
  return false;
};

/**
 * Where the next authority of `value` begins: just past a slash run that either follows a scheme token and
 * its colon, or stands scheme-relative - or, for a special scheme and no slash at all, right after the
 * colon. WHATWG gives a special scheme's authority to ANY run of `/` and `\\` after the colon -
 * `http:\\user:pass@host/x` and even `http:/u@host` parse with that authority - and those six schemes fall
 * into the authority state on any character, so `http:user:pass@host/x` carries that userinfo too
 * (full-rss-xv3); a non-special scheme needs the `//`, so `term:Monday@noon` never anchors. A scheme-
 * relative reference (`//user:pass@host/x`) carries userinfo with no scheme at all (full-rss-1xy).
 * A standalone run needs two or more slashes and must not follow `/`, `\\` or `:`, so the `//` of `scheme://`
 * (found through its colon a moment earlier) and the doubled slashes a path can start with do not turn an
 * `@` that a URL parser would call path into userinfo here. The scheme token must start with a letter, so
 * timestamps and ratios (`10:30/45`, `2026-11-09T04:01:22`) never anchor one.
 *
 * Linear and forward-only like the scan it serves (full-rss-9ey): `i` only moves forward, and the backward
 * walk over a scheme token visits each character at most once - a token ends at the first character outside
 * the scheme set, and a colon can end only the one token before it.
 */
const nextAuthorityStart = (value: string, from: number): number => {
  let i = from;
  while (i < value.length) {
    const code = value.charCodeAt(i);
    if (code === 58 /* ':' */) {
      let tokenAt = i;
      while (tokenAt > 0 && isSchemeChar(value.charCodeAt(tokenAt - 1))) {
        tokenAt--;
      }
      if (tokenAt < i && isSchemeStart(value.charCodeAt(tokenAt))) {
        let run = i + 1;
        while (run < value.length && isAuthoritySlash(value.charCodeAt(run))) {
          run++;
        }
        // Zero slashes anchor only for a special scheme: WHATWG's parser reaches the authority state from
        // those six no matter what follows the colon, while any other scheme reads the text as a path
        // (full-rss-xv3). The check runs only on this path, so the common `://` shape pays nothing.
        if (
          run > i + 1 ||
          (run === i + 1 && isSpecialScheme(value, tokenAt, i))
        ) {
          return run;
        }
      }
      i++;
    } else if (isAuthoritySlash(code)) {
      const before = i > 0 ? value.charCodeAt(i - 1) : 0;
      if (before !== 47 && before !== 92 && before !== 58) {
        let run = i;
        while (run < value.length && isAuthoritySlash(value.charCodeAt(run))) {
          run++;
        }
        if (run - i >= 2) return run;
        i = run;
      } else {
        i++;
      }
    } else {
      i++;
    }
  }
  return -1;
};

/**
 * Mask the userinfo of every absolute or scheme-relative URL in `value` (`user:password@host` becomes
 * `***@host`).
 *
 * One forward scan, and deliberately not a regular expression. The pattern that used to do this
 * (`([a-z][a-z0-9+.-]*:\/\/)([^/@\s:]+):?[^@/\s]*@`) has to find a literal '@' to match at all, so on a value
 * with no '@' in it it backtracked from every start position to the end of the string: O(n^2), measured at
 * 40-100 ms of CPU for ONE ~920-character request line (full-rss-9ey). Every cursor here only moves forward,
 * so the pass is linear in the value it is given.
 *
 * The mask runs over the value rather than a truncated prefix because the '@' can sit past the bound: a cut
 * applied first left `http://user:secretpasswordaaa...` in the log with the secrets intact (full-rss-al9).
 * Reading "absolute URL" liberally is intentional - masking one thing too many is safe, missing one is not.
 *
 * A password may itself contain an '@' (`http://user:p@ss@host/`), so the terminator is the LAST '@' before
 * the authority ends; masking to the first one would leave the rest of the password in the line.
 *
 * `windowed` says the caller already cut the value at MAX_LOG_SCAN, so an authority that runs to the end of
 * the value may be missing the '@' that terminates it. That case fails CLOSED: the whole visible authority
 * is masked, because the alternative is emitting a password prefix we could not see the end of.
 *
 * The authority is anchored on WHATWG's spellings, not just `://` (full-rss-1xy): a special scheme reads any
 * run of `/` and `\\` after its colon as the delimiter (`http:\\user:pass@host/x` parses with that userinfo,
 * so does `http:/u@host`), and with no slash at all for those six schemes (`http:u@host`, full-rss-xv3),
 * while a scheme-relative reference (`//user:pass@host/x`) carries userinfo with no
 * scheme at all. `nextAuthorityStart` finds each of those; everything after the anchor works as before.
 */
const maskUserinfo = (value: string, windowed: boolean): string => {
  // `copyFrom` is how much of the value is already in `masked`; `searchFrom` is where the next authority
  // search starts. They differ whenever an authority is scanned and found clean: the scan moves past it, the copy
  // does not. Both only ever move forward.
  let masked = "";
  let copyFrom = 0;
  let searchFrom = 0;
  for (;;) {
    const authorityStart = nextAuthorityStart(value, searchFrom);
    if (authorityStart < 0) break;
    let authorityEnd = authorityStart;
    while (authorityEnd < value.length && !endsAuthority(value, authorityEnd)) {
      authorityEnd++;
    }
    let terminator = -1;
    for (
      let at = value.indexOf("@", authorityStart);
      at >= 0 && at < authorityEnd;
      at = value.indexOf("@", at + 1)
    ) {
      terminator = at;
    }
    if (terminator >= 0) {
      masked += `${value.slice(copyFrom, authorityStart)}***@`;
      copyFrom = searchFrom = terminator + 1;
    } else if (windowed && authorityEnd === value.length) {
      masked += `${value.slice(copyFrom, authorityStart)}***@`;
      copyFrom = searchFrom = value.length;
    } else {
      searchFrom = authorityEnd;
    }
    if (searchFrom >= value.length) break;
  }
  return copyFrom === 0 ? value : masked + value.slice(copyFrom);
};

/**
 * Redact everything from the first '?' or '#' on. Incoming URLs are raw, decoded strings, so spaces inside a
 * query cannot be distinguished from the text after the URL: stopping at whitespace would leak later
 * parameters (full-rss-d2m). This also covers invalid URLs quoted in parse errors and fragments without a
 * query. `indexOf` is linear; the `.replace(/[?#].*$/s)` this replaces scanned the tail once per candidate.
 */
const redactQuery = (value: string): string => {
  const cut = value.search(/[?#]/);
  return cut < 0 ? value : `${value.slice(0, cut)}${value[cut]}[redacted]`;
};

/** Longest prefix of `value` that fits in `limit` characters without splitting a surrogate pair. */
const sliceChars = (value: string, limit: number): string => {
  let end = Math.min(limit, value.length);
  const code = value.charCodeAt(end - 1);
  // A high surrogate at the cut has lost its partner: drop it rather than emit half a character.
  if (code >= 0xd800 && code <= 0xdbff) end -= 1;
  return value.slice(0, end);
};

/**
 * One line of attacker-controlled text, safe for a log: control characters (forged log lines, ANSI) are
 * stripped, so are U+2028/U+2029 (LINE/PARAGRAPH SEPARATOR - a log consumer splitting on those would take the
 * rest of the line for a new entry), userinfo is masked, URL queries/fragments are redacted, and the result
 * is bounded in length.
 * Feed and article URLs can carry API keys even when the hostname is public, including inside exception
 * messages from upstream libraries.
 *
 * The redactions run FIRST, each as a single forward pass over a bounded window, and the cut comes LAST - the
 * order every statement of this function's contract already claimed (THREAT_MODEL.md, the MAX_LOG_CHARS note
 * above), and the one that makes the guarantee unconditional: redacting a truncated prefix could miss a
 * delimiter that sits past the cut and log the secret in front of it (full-rss-al9).
 *
 * Cost is bounded by MAX_LOG_SCAN, not by the value: nothing backtracks (full-rss-9ey - the old pattern cost
 * ~100 ms of CPU for ONE ~920-character request line), and the window is far more than the emitted prefix can
 * use. Together with the fail-closed authority rule in maskUserinfo, the bound does not weaken the guarantee.
 */
export const sanitizeForLog = (value: string): string => {
  const windowed = value.length > MAX_LOG_SCAN;
  const scanned = windowed ? sliceChars(value, MAX_LOG_SCAN) : value;
  const cleaned = redactQuery(
    maskUserinfo(
      // \p{Cc} is the control-character class (C0, DEL and C1) - the lint-quiet spelling of the same set.
      // U+2028/U+2029 sit outside it (categories Zl/Zp) yet forge log lines just as a CR does wherever a
      // consumer splits on them, so they are named code points here (full-rss-2lr).
      scanned.replace(/[\p{Cc}\u{2028}\u{2029}]/gu, ""),
      windowed,
    ),
  );
  const bounded = sliceChars(cleaned, MAX_LOG_CHARS);
  if (bounded === cleaned && !windowed) return cleaned;
  const dropped = value.length - bounded.length;
  return `${bounded}...[truncated ${dropped} chars]`;
};
