#!/usr/bin/env node
// Crypto P1 maintenance — vendor a freshly-built Signal wasm pkg into the app.
//
// Copies the wasm-pack output (signal-engine.js / .d.ts / _bg.wasm[.d.ts]) into the
// app's vendored locations and re-applies the `import.meta.url` neutralization on the
// JS glue (so the bundler never resolves a co-located wasm; the wasm ships as the
// static asset /pm/signal-engine_bg.wasm and loadSignalEngine passes the URL).
//
// Usage:  node packages/ctb-crypto/wasm/vendor-signal-wasm.mjs [pkgDir] --tag vX.Y.Z
//   pkgDir defaults to crypto/signal-wasm/pkg (wasm-pack --out-dir). In CI, point it
//   at the downloaded `cybertobo-signal-wasm` artifact dir.
//
// --tag is REQUIRED and records which libsignal tag this binary was built from into
// wasm/shipped.json (with the wasm size + sha256). That manifest is the only machine-
// readable record of what users actually run, and `npm run test:kernel` fails when it
// disagrees with the LIBSIGNAL_TAG pin or with the bytes on disk. Rationale: a pin bump
// only changes the *recipe* — CI uploads an artifact, it never commits one — so twice
// (v0.99.3, v0.99.4) a bump was marked "done" while production still served the older
// engine. Prose in NOTICE/README could not catch that; this can.
//
// Idempotent: re-running on an already-vendored engine is a no-op. Exits non-zero if
// the glue's wasm-load fallback can't be found or neutralized (i.e. upstream changed
// the glue shape and this script needs updating) — a loud, intentional failure.

import { readFileSync, writeFileSync, copyFileSync, existsSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "..", "..", ".."); // packages/ctb-crypto/wasm/ -> repo root

const argv = process.argv.slice(2);
const tagIdx = argv.indexOf("--tag");
const tag = tagIdx === -1 ? null : argv[tagIdx + 1];
const positional = argv.filter((a, i) => a !== "--tag" && i !== tagIdx + 1);
const pkgDir = resolve(positional[0] ?? join(here, "signal-wasm", "pkg"));

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

// Fail BEFORE copying anything: a vendor run without --tag would leave new bytes on
// disk with a stale shipped.json, i.e. exactly the drift this manifest exists to catch.
if (!tag) {
  fail(
    "--tag vX.Y.Z is required — it records the libsignal tag these bytes were built " +
      "from into wasm/shipped.json (asserted by `npm run test:kernel`)",
  );
}
if (!/^v\d+\.\d+\.\d+$/.test(tag)) fail(`--tag must look like vX.Y.Z (got: ${tag})`);

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

// Record what was ACTUALLY shipped. This is the whole point of the script taking --tag:
// the manifest is derived from the bytes we just wrote, so it cannot claim a tag whose
// binary was never vendored. signal-shipped.test.ts asserts manifest == disk == pin.
const wasmBytes = readFileSync(publicWasm);
const manifest = {
  _comment:
    "MACHINE-READABLE RECORD OF THE SHIPPED libsignal BUILD. Written by " +
    "vendor-signal-wasm.mjs, asserted by src/kernel/addons/__tests__/signal-shipped.test.ts. " +
    "Never hand-edit to make the gate pass: the ONLY legitimate way to change this file is " +
    "to vendor a real CI artifact. A pin bump alone must NOT touch it -- that is exactly " +
    "the drift this file exists to catch.",
  tag,
  wasmBytes: statSync(publicWasm).size,
  wasmSha256: createHash("sha256").update(wasmBytes).digest("hex"),
  vendoredAt: new Date().toISOString().slice(0, 10),
  ciRunId: process.env.CI_RUN_ID ?? "unknown",
};
writeFileSync(join(here, "shipped.json"), JSON.stringify(manifest, null, 2) + "\n");
console.log(
  `[vendor-signal-wasm] recorded shipped.json (tag ${tag}, ${manifest.wasmBytes} bytes, sha256 ${manifest.wasmSha256.slice(0, 12)}…)`,
);

console.log("[vendor-signal-wasm] done");
