// tests/integration/main.test.ts — the entrypoint's one promise: importing it is side-effect free.
//
// `main.ts` is what Deno Deploy runs, and it deliberately holds nothing but the boot line:
// `if (import.meta.main) await serve()`. That guard is the property the whole testable layout rests on (every
// other module can be imported without binding a port), and the guard is also the easiest thing in the repo
// to lose while editing — a two-character change silently turns the test process into a server.
//
// This test fails if that happens: with the guard gone the dynamic import runs `serve()`, which opens Deno KV
// (not available in the gate's test process, so it rejects) or binds the port (so it rejects or hangs).
// A resolving import is therefore evidence that no server was started and no KV handle was opened.
import { assertEqual } from "../asserts.ts";

Deno.test("importing the entrypoint starts no server and opens no KV", async () => {
  const entry = await import("../../main.ts");
  assertEqual(
    Object.keys(entry).length,
    0,
    "the entrypoint's exports (it is a boot file, not a module other code imports)",
  );
});
