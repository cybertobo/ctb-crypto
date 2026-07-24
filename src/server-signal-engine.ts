import "server-only";

/**
 * Sealed sender — SERVER-SIDE libsignal, for the certificate-authority operations
 * only (root keypair, server certificate, per-user sender certificates). These are
 * pure functions of keys + rng (no store), so we can run the SAME vendored
 * `--target web` wasm engine inside Node: read the wasm bytes from the static asset
 * and pass them explicitly to the wasm-bindgen init (no fetch/import.meta.url).
 *
 * This is the ONLY place the server touches libsignal. Message encryption/
 * decryption stays 100% client-side; the server never holds a message key.
 */
import { readFile } from "node:fs/promises";
import path from "node:path";

interface ServerSealedEngine {
  sealed_sender_generate_root(): { rootPrivate: Uint8Array; rootPublic: Uint8Array };
  sealed_sender_create_server_cert(
    rootPrivate: Uint8Array,
    keyId: number,
  ): { serverCert: Uint8Array; serverPrivate: Uint8Array };
  sealed_sender_create_sender_cert(
    serverCert: Uint8Array,
    serverPrivate: Uint8Array,
    senderUuid: string,
    senderDeviceId: number,
    senderIdentityKey: Uint8Array,
    expiryMs: number,
  ): Uint8Array;
}

let enginePromise: Promise<ServerSealedEngine> | null = null;

/** Load + init the vendored wasm engine once per server process (Node runtime). */
export async function loadServerSignalEngine(): Promise<ServerSealedEngine> {
  if (enginePromise) return enginePromise;
  enginePromise = (async () => {
    const wasmPath = path.join(process.cwd(), "public", "pm", "signal-engine_bg.wasm");
    const bytes = await readFile(wasmPath);
    // The vendored glue is wasm-pack `--target web`; its default export is the async
    // init(). Pass the bytes directly (BufferSource) so it never fetches a URL.
    const mod = await import("./engine/signal-engine.js");
    await (mod as unknown as { default: (opts: { module_or_path: BufferSource }) => Promise<unknown> }).default(
      { module_or_path: bytes },
    );
    return mod as unknown as ServerSealedEngine;
  })();
  return enginePromise;
}
