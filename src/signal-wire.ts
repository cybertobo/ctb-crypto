"use client";

/**
 * Crypto P1 (Phase 4) — packs/unpacks the Signal ciphertext carried inside the
 * existing PM relay's opaque `ciphertext` string, and distinguishes Signal
 * messages from legacy libsodium `crypto_box` ones so both decode during the
 * migration window (docs/CRYPTO-P1-IMPLEMENTATION-PLAN.md Phase 4/5).
 *
 * A Signal payload is `sig1:<type>:<base64(body)>`. Legacy crypto_box payloads
 * are plain base64 ciphertext (paired with a separate `nonce`) and never begin
 * with the `sig1:` tag, so detection is unambiguous. The tag is versioned so a
 * future wire change (`sig2:` …) stays backward-decodable.
 */

import type { CiphertextType } from "./crypto-engine";

const SIG_PREFIX = "sig1:";
// Sealed sender (v1): `sss1:<base64(sealed envelope)>`. The opaque libsignal
// sealed-sender bytes carry the (encrypted) sender certificate + inner message.
const SEALED_PREFIX = "sss1:";

export function toBase64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

export function fromBase64(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

/** Pack an engine EncryptResult into the relay `ciphertext` string. */
export function packSignalPayload(type: CiphertextType, body: Uint8Array): string {
  return `${SIG_PREFIX}${type}:${toBase64(body)}`;
}

/** Pack a sealed-sender envelope into the relay `ciphertext` string. */
export function packSealedPayload(body: Uint8Array): string {
  return `${SEALED_PREFIX}${toBase64(body)}`;
}

export type UnpackedPayload =
  | { kind: "signal"; type: CiphertextType; body: Uint8Array }
  | { kind: "sealed"; body: Uint8Array }
  | { kind: "legacy" };

/** Classify + decode a relay `ciphertext` string. */
export function unpackPayload(ciphertext: string): UnpackedPayload {
  if (ciphertext.startsWith(SEALED_PREFIX)) {
    try {
      return { kind: "sealed", body: fromBase64(ciphertext.slice(SEALED_PREFIX.length)) };
    } catch {
      return { kind: "legacy" };
    }
  }
  if (!ciphertext.startsWith(SIG_PREFIX)) return { kind: "legacy" };
  const rest = ciphertext.slice(SIG_PREFIX.length);
  const sep = rest.indexOf(":");
  if (sep === -1) return { kind: "legacy" };
  const type = rest.slice(0, sep) as CiphertextType;
  try {
    return { kind: "signal", type, body: fromBase64(rest.slice(sep + 1)) };
  } catch {
    return { kind: "legacy" };
  }
}

/** True if a relay payload is a Signal (not legacy crypto_box) message. */
export function isSignalPayload(ciphertext: string): boolean {
  return ciphertext.startsWith(SIG_PREFIX);
}
