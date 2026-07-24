"use client";

import { loadSignalEngine } from "./crypto-engine";
import { IndexedDbSignalStore } from "./signal-store";

/**
 * Crypto P1 Phase 5 — full-Signal "Secure Backups". The recovery key is a Signal
 * **Account Entropy Pool** (64 chars `[a-z0-9]`, ~330 bits) — the same format
 * Signal uses. It roots a CONTENT backup of the whole device-local Signal state:
 * identity + registration id, sessions, prekeys, peer identities, and the
 * decrypted message/reaction history cache (the true history, since the Double
 * Ratchet destroys each message key on first decrypt).
 *
 * Key hierarchy (shared by every ecosystem client — web + native):
 *   AEP → Signal `BackupKey` (HKDF, in the wasm engine)
 *       → HKDF(salt = per-backup token) → AES-256 key ‖ HMAC-SHA256 key
 * Encryption is AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC) via WebCrypto — the
 * same construction libsignal's MessageBackupKey feeds. The recovery key never
 * leaves the browser; the server stores only opaque ciphertext. Lose it ⇒
 * history is unrecoverable, not even by us.
 */

/** Wire shape of the content backup (matches the server ContentBackupBlob). */
export interface ContentBackupBlob {
  version: number;
  ciphertext: string; // base64 AES-256-CBC ciphertext of the serialized dump
  iv: string; // base64 AES-CBC IV (16 bytes)
  token: string; // base64 per-backup forward-secrecy token (32 bytes; HKDF salt)
  mac: string; // base64 HMAC-SHA256(hmacKey, iv ‖ ciphertext)
}

const BACKUP_VERSION = 1;

// ── base64 <-> bytes (browser, no deps) ──────────────────────────────────────
function bytesToB64(bytes: Uint8Array): string {
  let bin = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}
function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
/** Copy into a fresh ArrayBuffer (satisfies WebCrypto's BufferSource typing cleanly). */
function ab(b: Uint8Array): ArrayBuffer {
  return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;
}

/** Generate a fresh recovery key (Signal Account Entropy Pool, 64 chars [a-z0-9]). */
export async function generateRecoveryKey(): Promise<{ raw: string; display: string }> {
  const engine = await loadSignalEngine();
  if (typeof engine.generate_account_entropy_pool !== "function") {
    throw new Error("backup-engine-unavailable");
  }
  const raw = engine.generate_account_entropy_pool();
  return { raw, display: formatRecoveryKey(raw) };
}

/** Group the 64-char key into 16 blocks of 4, space-separated (display only). */
export function formatRecoveryKey(raw: string): string {
  return (raw.match(/.{1,4}/g) ?? []).join(" ");
}

/** Canonicalize user-entered key input: strip separators, lowercase. */
export function normalizeRecoveryKey(input: string): string {
  return input.replace(/[^0-9a-zA-Z]/g, "").toLowerCase();
}

/** A well-formed recovery key is exactly 64 chars of [a-z0-9] (the AEP alphabet). */
export function isValidRecoveryKey(raw: string): boolean {
  return /^[0-9a-z]{64}$/.test(raw);
}

async function deriveKeys(
  recoveryKey: string,
  token: Uint8Array,
): Promise<{ aesKey: CryptoKey; hmacKey: CryptoKey }> {
  const engine = await loadSignalEngine();
  if (typeof engine.derive_backup_keys !== "function") {
    throw new Error("backup-engine-unavailable");
  }
  const { aesKey, hmacKey } = engine.derive_backup_keys(recoveryKey, token);
  const aes = await crypto.subtle.importKey("raw", ab(aesKey), { name: "AES-CBC" }, false, [
    "encrypt",
    "decrypt",
  ]);
  const hmac = await crypto.subtle.importKey(
    "raw",
    ab(hmacKey),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
  return { aesKey: aes, hmacKey: hmac };
}

// ── JSON (de)serialization of the IndexedDB dump ────────────────────────────
// Byte arrays (identity/session/prekey records) are tagged { __u8: base64 } and
// revived to Uint8Array on restore.
type Dump = Record<string, [IDBValidKey, unknown][]>;

function serializeDump(dump: Dump): string {
  return JSON.stringify(dump, (_k, v) =>
    v instanceof Uint8Array ? { __u8: bytesToB64(v) } : v,
  );
}
function deserializeDump(json: string): Dump {
  return JSON.parse(json, (_k, v) => {
    if (v && typeof v === "object" && typeof (v as { __u8?: unknown }).__u8 === "string") {
      return b64ToBytes((v as { __u8: string }).__u8);
    }
    return v;
  }) as Dump;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/**
 * Build + encrypt a content backup of the current device's Signal state under the
 * given recovery key. Returns the opaque blob to upload (server never sees the key).
 */
export async function encryptContentBackup(
  store: IndexedDbSignalStore,
  recoveryKey: string,
): Promise<ContentBackupBlob> {
  const dump = await store.exportAll();
  const plaintext = new TextEncoder().encode(serializeDump(dump));

  const token = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const { aesKey, hmacKey } = await deriveKeys(recoveryKey, token);

  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-CBC", iv: ab(iv) }, aesKey, ab(plaintext)),
  );
  // Encrypt-then-MAC over iv ‖ ciphertext.
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, ab(concat(iv, ct))));

  return {
    version: BACKUP_VERSION,
    ciphertext: bytesToB64(ct),
    iv: bytesToB64(iv),
    token: bytesToB64(token),
    mac: bytesToB64(mac),
  };
}

/**
 * Decrypt a content backup with the recovery key and restore it into this device's
 * IndexedDB. Returns true on success, false on a wrong key / corrupt-or-tampered blob.
 */
export async function restoreContentBackup(
  store: IndexedDbSignalStore,
  blob: ContentBackupBlob,
  recoveryKey: string,
): Promise<boolean> {
  try {
    const iv = b64ToBytes(blob.iv);
    const ct = b64ToBytes(blob.ciphertext);
    const { aesKey, hmacKey } = await deriveKeys(recoveryKey, b64ToBytes(blob.token));

    // Verify the MAC BEFORE decrypting (encrypt-then-MAC; fail closed).
    const ok = await crypto.subtle.verify(
      "HMAC",
      hmacKey,
      ab(b64ToBytes(blob.mac)),
      ab(concat(iv, ct)),
    );
    if (!ok) return false;

    const plaintext = new Uint8Array(
      await crypto.subtle.decrypt({ name: "AES-CBC", iv: ab(iv) }, aesKey, ab(ct)),
    );
    const dump = deserializeDump(new TextDecoder().decode(plaintext));
    await store.importAll(dump);
    return true;
  } catch {
    // Wrong recovery key or tampered blob — fail closed.
    return false;
  }
}
