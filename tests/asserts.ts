// tests/asserts.ts — the fast tier's assertions.
//
// Deliberately a local helper rather than `jsr:@std/assert`: the fast tier must run with nothing but this
// checkout and the pinned toolchain, and a gate that has to download is a gate that fails offline.
// Same reason there is no fixtures directory — each suite builds its own input string.

export function assert(condition: unknown, what: string): void {
  if (!condition) throw new Error(`expected ${what}`);
}

export function assertEqual<T>(actual: T, expected: T, what: string): void {
  if (!Object.is(actual, expected)) {
    throw new Error(
      `${what}: expected ${JSON.stringify(expected)}, got ${
        JSON.stringify(actual)
      }`,
    );
  }
}

export function assertIncludes(
  haystack: string,
  needle: string,
  what?: string,
): void {
  if (!haystack.includes(needle)) {
    throw new Error(
      `expected to find ${JSON.stringify(needle)}${what ? ` (${what})` : ""}`,
    );
  }
}

export function assertExcludes(
  haystack: string,
  needle: string,
  what?: string,
): void {
  if (haystack.includes(needle)) {
    throw new Error(
      `expected NOT to find ${JSON.stringify(needle)}${
        what ? ` (${what})` : ""
      }`,
    );
  }
}

export async function assertRejects(
  fn: () => Promise<unknown>,
  messagePart: string,
  what: string,
): Promise<void> {
  try {
    await fn();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!message.includes(messagePart)) {
      throw new Error(
        `${what}: expected the error to mention ${
          JSON.stringify(messagePart)
        }, got ${JSON.stringify(message)}`,
      );
    }
    return;
  }
  throw new Error(`${what}: expected it to reject, but it resolved`);
}
