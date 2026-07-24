"use client";

/**
 * IndexedDB-backed Signal Protocol store (Crypto P1, Phase 1).
 *
 * Implements the persistence surface the wasm engine calls back into for the six
 * libsignal store traits (Identity / Session / PreKey / SignedPreKey / KyberPreKey /
 * SenderKey). Records are opaque bytes produced by libsignal's `serialize()` and fed
 * back to `deserialize()` — this layer never interprets them. Private/identity/session
 * material lives ONLY here in the browser and never touches the server DB
 * (docs/CRYPTO-E2E-SIGNAL.md, docs/ARCHITECTURE.md: "keys never touch the DB").
 *
 * All methods are async (IndexedDB is async), matching libsignal's async store traits
 * so the Rust wrapper can await them across the wasm boundary (see crypto-engine.ts).
 */

const DB_NAME = "ctb-signal";
const DB_VERSION = 2;

const OBJECT_STORES = [
  "meta", // identityKeyPair, localRegistrationId
  "identities", // address -> identity public key bytes (TOFU)
  "sessions", // address -> session record bytes
  "prekeys", // preKeyId -> record bytes
  "signedprekeys", // signedPreKeyId -> record bytes
  "kyberprekeys", // kyberPreKeyId -> record bytes
  "senderkeys", // `${sender}::${distributionId}` -> record bytes
  "messages", // messageId -> decrypted body wire string (Phase 4 Option 1 cache)
] as const;

type StoreName = (typeof OBJECT_STORES)[number];

let dbPromise: Promise<IDBDatabase> | null = null;

function openDb(): Promise<IDBDatabase> {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise<IDBDatabase>((resolve, reject) => {
    if (typeof indexedDB === "undefined") {
      reject(new Error("IndexedDB unavailable (Signal store requires a browser)"));
      return;
    }
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      for (const name of OBJECT_STORES) {
        if (!db.objectStoreNames.contains(name)) db.createObjectStore(name);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("IndexedDB open failed"));
  });
  return dbPromise;
}

async function idbGet<T>(store: StoreName, key: IDBValidKey): Promise<T | undefined> {
  const db = await openDb();
  return new Promise<T | undefined>((resolve, reject) => {
    const req = db.transaction(store, "readonly").objectStore(store).get(key);
    req.onsuccess = () => resolve(req.result as T | undefined);
    req.onerror = () => reject(req.error);
  });
}

async function idbPut(store: StoreName, key: IDBValidKey, value: unknown): Promise<void> {
  const db = await openDb();
  return new Promise<void>((resolve, reject) => {
    const tx = db.transaction(store, "readwrite");
    tx.objectStore(store).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function idbDelete(store: StoreName, key: IDBValidKey): Promise<void> {
  const db = await openDb();
  return new Promise<void>((resolve, reject) => {
    const tx = db.transaction(store, "readwrite");
    tx.objectStore(store).delete(key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function idbCount(store: StoreName): Promise<number> {
  const db = await openDb();
  return new Promise<number>((resolve, reject) => {
    const req = db.transaction(store, "readonly").objectStore(store).count();
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

/** All [key, value] entries of a store (for the content-backup export). */
async function idbEntries(store: StoreName): Promise<[IDBValidKey, unknown][]> {
  const db = await openDb();
  return new Promise<[IDBValidKey, unknown][]>((resolve, reject) => {
    const os = db.transaction(store, "readonly").objectStore(store);
    const keysReq = os.getAllKeys();
    const valsReq = os.getAll();
    let keys: IDBValidKey[] | null = null;
    let vals: unknown[] | null = null;
    const done = () => {
      if (keys && vals) resolve(keys.map((k, i) => [k, (vals as unknown[])[i]]));
    };
    keysReq.onsuccess = () => {
      keys = keysReq.result as IDBValidKey[];
      done();
    };
    valsReq.onsuccess = () => {
      vals = valsReq.result as unknown[];
      done();
    };
    keysReq.onerror = () => reject(keysReq.error);
    valsReq.onerror = () => reject(valsReq.error);
  });
}

/** Local identity + registration id (the device's own long-term state). */
interface LocalState {
  identityKeyPair: Uint8Array;
  registrationId: number;
}

/**
 * Monotonic key-id cursors for prekey rotation/replenishment (Crypto P1, Phase 4).
 * A signed prekey record's private half must survive in the store as long as its
 * PUBLISHED public half might still be used by an inbound PreKey message, so we
 * NEVER reuse an id — each replenish mints the next unused ids. Persisted so the
 * cursor survives reloads (the initial batch is 1/1/1..100 → next = 2/2/101).
 */
export interface KeygenState {
  nextSignedId: number;
  nextKyberId: number;
  nextOneTimeId: number;
}

/**
 * The persistence layer passed to the wasm engine. Method names/shape mirror the
 * libsignal store traits so the Rust wrapper's JS-callback stores map 1:1.
 */
export class IndexedDbSignalStore {
  // ── Identity / registration (meta) ──────────────────────────────────────────
  async getLocalState(): Promise<LocalState | undefined> {
    return idbGet<LocalState>("meta", "local");
  }

  async setLocalState(identityKeyPair: Uint8Array, registrationId: number): Promise<void> {
    await idbPut("meta", "local", { identityKeyPair, registrationId } satisfies LocalState);
  }

  async hasLocalState(): Promise<boolean> {
    return (await this.getLocalState()) !== undefined;
  }

  /** Whether this device has already published its prekey bundle to the server. */
  async isProvisioned(): Promise<boolean> {
    return (await idbGet<number>("meta", "provisioned")) !== undefined;
  }

  /** Mark the device's bundle as published (timestamp) so we don't re-publish/rotate on every load. */
  async markProvisioned(nowMs = Date.now()): Promise<void> {
    await idbPut("meta", "provisioned", nowMs);
  }

  /** Read the prekey-id rotation cursor (undefined on a pre-Phase-4 device). */
  async getKeygenState(): Promise<KeygenState | undefined> {
    return idbGet<KeygenState>("meta", "keygen");
  }

  /** Persist the prekey-id rotation cursor after a publish/replenish. */
  async setKeygenState(state: KeygenState): Promise<void> {
    await idbPut("meta", "keygen", state);
  }

  // ── Multi-device identity (MD-P1) ───────────────────────────────────────────
  /**
   * This install's stable id — a random UUID persisted on first call. Identifies
   * the physical device to the server so a re-publish reuses its server-assigned
   * deviceId (rather than clobbering another device of the same user).
   */
  async getInstallationId(): Promise<string> {
    const existing = await idbGet<string>("meta", "installationId");
    if (existing) return existing;
    const id = crypto.randomUUID();
    await idbPut("meta", "installationId", id);
    return id;
  }

  /** The server-assigned Signal deviceId for this install (undefined until published). */
  async getDeviceId(): Promise<number | undefined> {
    return idbGet<number>("meta", "deviceId");
  }

  /** Persist the server-assigned deviceId (returned by /api/pm/keys/publish). */
  async setDeviceId(deviceId: number): Promise<void> {
    await idbPut("meta", "deviceId", deviceId);
  }

  // ── Identity keys (TOFU) ─────────────────────────────────────────────────────
  async getIdentity(address: string): Promise<Uint8Array | undefined> {
    return idbGet<Uint8Array>("identities", address);
  }

  /** Save a peer identity. Returns true if it CHANGED an existing (different) key. */
  async saveIdentity(address: string, key: Uint8Array): Promise<boolean> {
    const existing = await this.getIdentity(address);
    const changed = existing !== undefined && !bytesEqual(existing, key);
    await idbPut("identities", address, key);
    return changed;
  }

  /** Trust-on-first-use: trust if unknown, or if it matches the stored key. */
  async isTrustedIdentity(address: string, key: Uint8Array): Promise<boolean> {
    const existing = await this.getIdentity(address);
    return existing === undefined || bytesEqual(existing, key);
  }

  // ── Sessions ─────────────────────────────────────────────────────────────────
  async loadSession(address: string): Promise<Uint8Array | undefined> {
    return idbGet<Uint8Array>("sessions", address);
  }

  async storeSession(address: string, record: Uint8Array): Promise<void> {
    await idbPut("sessions", address, record);
  }

  // ── One-time pre-keys ─────────────────────────────────────────────────────────
  async getPreKey(id: number): Promise<Uint8Array | undefined> {
    return idbGet<Uint8Array>("prekeys", id);
  }
  async savePreKey(id: number, record: Uint8Array): Promise<void> {
    await idbPut("prekeys", id, record);
  }
  async removePreKey(id: number): Promise<void> {
    await idbDelete("prekeys", id);
  }
  async countPreKeys(): Promise<number> {
    return idbCount("prekeys");
  }

  // ── Signed pre-keys ────────────────────────────────────────────────────────────
  async getSignedPreKey(id: number): Promise<Uint8Array | undefined> {
    return idbGet<Uint8Array>("signedprekeys", id);
  }
  async saveSignedPreKey(id: number, record: Uint8Array): Promise<void> {
    await idbPut("signedprekeys", id, record);
  }

  // ── Kyber (ML-KEM) pre-keys ─────────────────────────────────────────────────────
  async getKyberPreKey(id: number): Promise<Uint8Array | undefined> {
    return idbGet<Uint8Array>("kyberprekeys", id);
  }
  async saveKyberPreKey(id: number, record: Uint8Array): Promise<void> {
    await idbPut("kyberprekeys", id, record);
  }
  /** last-resort Kyber prekeys are reusable, so "used" is a no-op marker for now. */
  async markKyberPreKeyUsed(_id: number): Promise<void> {
    // Intentionally not deleted: PQXDH last-resort Kyber prekeys are reusable.
  }

  // ── Sender keys (groups) ─────────────────────────────────────────────────────────
  async loadSenderKey(sender: string, distributionId: string): Promise<Uint8Array | undefined> {
    return idbGet<Uint8Array>("senderkeys", `${sender}::${distributionId}`);
  }
  async storeSenderKey(sender: string, distributionId: string, record: Uint8Array): Promise<void> {
    await idbPut("senderkeys", `${sender}::${distributionId}`, record);
  }

  // ── Decrypted-message cache (Phase 4 Option 1) ──────────────────────────────
  // The Double Ratchet consumes each message key on first decrypt, so a Signal
  // ciphertext can be decrypted exactly once. We therefore decrypt on first sight
  // and cache the resulting body-wire string locally, keyed by the server message
  // id; own sent messages are cached here at send time. The transcript renders
  // from this cache — never by re-decrypting server ciphertext. This is the
  // device-local history that a Phase 5 recovery-key backup will archive.
  async getCachedBody(messageId: string): Promise<string | undefined> {
    return idbGet<string>("messages", messageId);
  }
  async putCachedBody(messageId: string, bodyWire: string): Promise<void> {
    await idbPut("messages", messageId, bodyWire);
  }
  // Evict a cached body — used when a disappearing message expires or a view-once
  // message is consumed, so its plaintext is gone from this device too.
  async deleteCachedBody(messageId: string): Promise<void> {
    await idbDelete("messages", messageId);
  }

  // ── Decrypted-reaction cache ────────────────────────────────────────────────
  // Reactions are Signal ratchet messages too (decrypt-once), so their emoji is
  // cached locally like bodies. Stored in the same "messages" store under an
  // "rx:" key prefix to avoid a DB-version bump. Own reactions are cached at send.
  async getCachedReaction(reactionId: string): Promise<string | undefined> {
    return idbGet<string>("messages", `rx:${reactionId}`);
  }
  async putCachedReaction(reactionId: string, emoji: string): Promise<void> {
    await idbPut("messages", `rx:${reactionId}`, emoji);
  }

  // ── Content-backup export / import (Phase 5) ────────────────────────────────
  // Dump every object store as [key, value] entries so the recovery-key backup can
  // archive the full device-local Signal state (identity, sessions, prekeys, and
  // the decrypted history cache). Values are raw (Uint8Array / string / object);
  // the backup layer handles JSON-safe (base64) encoding of byte arrays.
  async exportAll(): Promise<Record<string, [IDBValidKey, unknown][]>> {
    const out: Record<string, [IDBValidKey, unknown][]> = {};
    for (const name of OBJECT_STORES) out[name] = await idbEntries(name);
    return out;
  }

  /** Restore a previously-exported dump into IndexedDB (used by recovery-key restore). */
  async importAll(dump: Record<string, [IDBValidKey, unknown][]>): Promise<void> {
    for (const name of OBJECT_STORES) {
      const entries = dump[name];
      if (!entries) continue;
      for (const [key, value] of entries) await idbPut(name, key, value);
    }
  }

  /** Wipe all Signal state (device reset / logout). */
  async clearAll(): Promise<void> {
    const db = await openDb();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(OBJECT_STORES as unknown as string[], "readwrite");
      for (const name of OBJECT_STORES) tx.objectStore(name).clear();
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
