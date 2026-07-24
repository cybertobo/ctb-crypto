#!/usr/bin/env node
// Crypto P1 maintenance — vendor a freshly-built Signal wasm pkg into the app.
//
// Copies the wasm-pack output (signal-engine.js / .d.ts / _bg.wasm[.d.ts]) into the
// app's vendored locations and re-applies the `import.meta.url` neutralization on the
// JS glue (so the bundler never resolves a co-located wasm; the wasm ships as the
// static asset /pm/signal-engine_bg.wasm and loadSignalEngine passes the URL).
//
// Usage:  node crypto/vendor-signal-wasm.mjs [pkgDir]
//   pkgDir defaults to crypto/signal-wasm/pkg (wasm-pack --out-dir). In CI, point it
//   at the downloaded `cybertobo-signal-wasm` artifact dir.
//
// Idempotent: re-running on an already-vendored engine is a no-op. Exits non-zero if
// the glue's wasm-load fallback can't be found or neutralized (i.e. upstream changed
// the glue shape and this script needs updating) — a loud, intentional failure.

import { readFileSync, writeFileSync, copyFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..", "..", ".."); // packages/ctb-crypto/wasm/ -> repo root
const pkgDir = resolve(process.argv[2] ?? join(here, "signal-wasm", "pkg"));

const engineDir = join(repo, "packages", "ctb-crypto", "src", "engine");
const publicWasm = join(repo, "public", "pm", "signal-engine_bg.wasm");

const copies = [
  ["signal-engine.js", join(engineDir, "signal-engine.js")],
  ["signal-engine.d.ts", join(engineDir, "signal-engine.d.ts")],
  ["signal-engine_bg.wasm.d.ts", join(engineDir, "signal-engine_bg.wasm.d.ts")],
  ["signal-engine_bg.wasm", publicWasm],
];

// The generated glue's wasm-load fallback we must neutralize.
const FALLBACK =
  "if (module_or_path === undefined) {\n        module_or_path = new URL('signal-engine_bg.wasm', import.meta.url);\n    }";
const NEUTRALIZED =
  "if (module_or_path === undefined) {\n" +
  "        // Vendored for Cybertobo (Crypto P1): the .wasm ships as a static asset at\n" +
  "        // /pm/signal-engine_bg.wasm and the caller (loadSignalEngine) always passes an\n" +
  "        // explicit module_or_path. The original import.meta.url fallback is removed so\n" +
  "        // the bundler never tries to resolve a co-located wasm asset.\n" +
  "        throw new Error('signal-engine: module_or_path is required (pass the /pm/signal-engine_bg.wasm URL)');\n" +
  "    }";

function fail(msg) {
  console.error(`[vendor-signal-wasm] ERROR: ${msg}`);
  process.exit(1);
}

if (!existsSync(pkgDir)) fail(`pkg dir not found: ${pkgDir}`);
for (const [name] of copies) {
  if (!existsSync(join(pkgDir, name))) fail(`missing ${name} in ${pkgDir}`);
}

for (const [name, dest] of copies) {
  copyFileSync(join(pkgDir, name), dest);
  console.log(`[vendor-signal-wasm] vendored ${name}`);
}

// Neutralize the import.meta.url fallback in the freshly-copied glue.
const gluePath = join(engineDir, "signal-engine.js");
let glue = readFileSync(gluePath, "utf8");
if (glue.includes(NEUTRALIZED)) {
  console.log("[vendor-signal-wasm] glue already neutralized");
} else if (glue.includes(FALLBACK)) {
  glue = glue.replace(FALLBACK, NEUTRALIZED);
  writeFileSync(gluePath, glue);
  console.log("[vendor-signal-wasm] neutralized import.meta.url fallback");
} else {
  fail(
    "could not find the wasm-load fallback to neutralize — upstream glue changed; " +
      "update FALLBACK in crypto/vendor-signal-wasm.mjs",
  );
}

// Guard against the actual dangerous construct (a bare `import.meta.url` may still
// appear in our own neutralization comment — that's fine; the code fallback is what matters).
if (glue.includes("new URL('signal-engine_bg.wasm', import.meta.url)")) {
  fail("wasm-load fallback still present after neutralization");
}
console.log("[vendor-signal-wasm] done");
