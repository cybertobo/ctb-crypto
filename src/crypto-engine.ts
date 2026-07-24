"use client";

/**
 * CryptoEngine (Crypto P1, Phase 1) — the single app-facing boundary over the
 * official Signal Protocol / PQXDH engine. The rest of the app talks ONLY to this
 * interface; it never imports libsignal or the wasm module directly.
 *
 * Web/PWA fulfils this with the official `libsignal-protocol` crate compiled to wasm
 * (crypto/signal-wasm — see docs/CRYPTO-P1-IMPLEMENTATION-PLAN.md). Mobile fulfils the
 * same contract with `libsignal_dart` / `@signalapp/libsignal-client` at the same
 * pinned libsignal tag → byte-identical wire format.
 *
 * IMPORTANT (spike-derived): every operation that needs a clock takes an explicit
 * `nowMs` (JS `Date.now()`), because `SystemTime::now()` panics on wasm32.
 */

import { IndexedDbSignalStore } from "./signal-store";

/** libsignal ciphertext message types, as tagged on the wire. */
export type CiphertextType = "prekey" | "whisper" | "senderkey" | "plaintext";

export interface EncryptResult {
  type: CiphertextType;
  body: Uint8Array;
}

/** Public device registration material, published to the prekey server. */
export interface RegistrationInfo {
  identityPublicKey: Uint8Array;
  registrationId: number;
}

/**
 * Public prekey bundle as exchanged with the prekey server
 * (GET /api/pm/keys/[userId]/bundle → this shape; POST /publish sends the batch).
 * All values are base64 on the wire; decoded to bytes before reaching the engine.
 */
export interface PreKeyBundleWire {
  registrationId: number;
  deviceId: number;
  identityKey: string; // base64
  signedPreKeyId: number;
  signedPreKeyPublic: string; // base64
  signedPreKeySignature: string; // base64
  kyberPreKeyId: number;
  kyberPreKeyPublic: string; // base64
  kyberPreKeySignature: string; // base64
  preKeyId?: number; // one-time prekey (consumed); optional (last-resort fallback)
  preKeyPublic?: string; // base64
}

/** Publishable prekey material returned by `generate_prekeys` (→ prekey server). */
export interface PublishBundle {
  identityKey: Uint8Array;
  signedPreKey: { id: number; publicKey: Uint8Array; signature: Uint8Array };
  kyberPreKey: { id: number; publicKey: Uint8Array; signature: Uint8Array };
  oneTimePreKeys: { id: number; publicKey: Uint8Array }[];
}

/** A single peer bundle (bytes fields) passed to `process_peer_bundle`. */
export interface PeerBundle {
  registrationId: number;
  deviceId: number;
  identityKey: Uint8Array;
  signedPreKeyId: number;
  signedPreKeyPublic: Uint8Array;
  signedPreKeySignature: Uint8Array;
  kyberPreKeyId: number;
  kyberPreKeyPublic: Uint8Array;
  kyberPreKeySignature: Uint8Array;
  preKeyId?: number;
  preKeyPublic?: Uint8Array;
}

/**
 * The ABI the wasm engine exposes (implemented + verified in crypto/signal-wasm's
 * wrapper crate; full PQXDH session round-trip proven — docs/CHANGELOG.md). Every
 * fn takes the JS `store` first; the engine calls back into it for all persistence.
 * Addresses are `${serviceId}.${deviceId}` strings.
 */
export interface SignalWasmEngine {
  ping(): number;

  /** Generate + persist this device's identity + registration id via the store. */
  generate_registration(store: IndexedDbSignalStore): Promise<RegistrationInfo>;

  /** Generate + persist signed + kyber + `count` one-time prekeys; return publish material. */
  generate_prekeys(
    store: IndexedDbSignalStore,
    signedPreKeyId: number,
    kyberPreKeyId: number,
    preKeyStartId: number,
    count: number,
    nowMs: number,
  ): Promise<PublishBundle>;

  /** Establish an outbound session (PQXDH) from a peer's fetched bundle. */
  process_peer_bundle(
    store: IndexedDbSignalStore,
    remoteAddress: string,
    bundle: PeerBundle,
    nowMs: number,
  ): Promise<void>;

  /** Encrypt plaintext for a peer; returns the tagged ciphertext. */
  encrypt(
    store: IndexedDbSignalStore,
    remoteAddress: string,
    localAddress: string,
    plaintext: Uint8Array,
    nowMs: number,
  ): Promise<EncryptResult>;

  /** Decrypt a peer's ciphertext (type = "prekey" | "whisper"). */
  decrypt(
    store: IndexedDbSignalStore,
    remoteAddress: string,
    localAddress: string,
    msgType: CiphertextType,
    body: Uint8Array,
    nowMs: number,
  ): Promise<Uint8Array>;

  /**
   * Compute the Signal safety number from the local (store) + remote identity keys.
   * OPTIONAL: only present once the vendored wasm is rebuilt with the `fingerprint`
   * export (crypto/signal-wasm/src/lib.rs); callers must feature-detect and fall
   * back to the legacy fingerprint when absent.
   */
  fingerprint?(
    store: IndexedDbSignalStore,
    localId: string,
    remoteId: string,
    remoteIdentityKey: Uint8Array,
  ): Promise<{ displayText: string; scannable: Uint8Array }>;

  /**
   * Crypto P1 Phase 5 — recovery-key backup key material.
   * `generate_account_entropy_pool` mints the 64-char `[a-z0-9]` recovery key;
   * `derive_backup_keys` turns (recovery key + per-backup token) into an AES-256
   * key + HMAC-SHA256 key (Signal `BackupKey` root + app HKDF expansion). OPTIONAL:
   * present only once the wasm is rebuilt with these exports — callers feature-detect.
   */
  generate_account_entropy_pool?(): string;
  derive_backup_keys?(
    accountEntropyPool: string,
    token: Uint8Array,
  ): { aesKey: Uint8Array; hmacKey: Uint8Array };

  /**
   * Groups (SenderKey). OPTIONAL: present only once the wasm is rebuilt with the
   * group_cipher exports — callers feature-detect via `hasGroupSupport`.
   * `distributionId` is the group's stable UUID; addresses are `${userId}.${deviceId}`.
   *  • sender_key_distribution_message — create (persist on first use) this device's
   *    SenderKey distribution message, delivered to each member over a 1:1 session.
   *  • process_sender_key_distribution — ingest a member's distribution message.
   *  • group_encrypt_message — encrypt a group message once with our SenderKey.
   *  • group_decrypt_message — decrypt a member's SenderKeyMessage.
   */
  sender_key_distribution_message?(
    store: IndexedDbSignalStore,
    senderAddress: string,
    distributionId: string,
  ): Promise<Uint8Array>;
  process_sender_key_distribution?(
    store: IndexedDbSignalStore,
    senderAddress: string,
    skdmBytes: Uint8Array,
  ): Promise<void>;
  group_encrypt_message?(
    store: IndexedDbSignalStore,
    senderAddress: string,
    distributionId: string,
    plaintext: Uint8Array,
  ): Promise<Uint8Array>;
  group_decrypt_message?(
    store: IndexedDbSignalStore,
    senderAddress: string,
    skmBytes: Uint8Array,
  ): Promise<Uint8Array>;

  /**
   * Sealed sender (client side). OPTIONAL: present once the wasm is rebuilt with
   * the sealed-sender exports — callers feature-detect via `hasSealedSenderSupport`.
   *  • sealed_sender_encrypt_message — wrap+encrypt to `destinationAddress` carrying
   *    the caller's minted `senderCertBytes`; returns the opaque sealed envelope.
   *  • sealed_sender_decrypt_message — validate the cert against `trustRoot` and
   *    decrypt; returns { senderUuid, senderDeviceId, message }.
   */
  sealed_sender_encrypt_message?(
    store: IndexedDbSignalStore,
    destinationAddress: string,
    senderCertBytes: Uint8Array,
    plaintext: Uint8Array,
    nowMs: number,
  ): Promise<Uint8Array>;
  sealed_sender_decrypt_message?(
    store: IndexedDbSignalStore,
    trustRoot: Uint8Array,
    timestampMs: number,
    localUuid: string,
    localDeviceId: number,
    ciphertext: Uint8Array,
  ): Promise<{ senderUuid: string; senderDeviceId: number; message: Uint8Array }>;
}

/** Encodes a Signal ProtocolAddress. */
export function protocolAddress(serviceId: string, deviceId = 1): string {
  return `${serviceId}.${deviceId}`;
}

/**
 * App-facing engine. Wraps the wasm ABI + the IndexedDB store, injecting the store
 * into every engine call and defaulting `nowMs` to `Date.now()`.
 */
export class CryptoEngine {
  // Server-assigned Signal deviceId for THIS device (multi-device). Set after the
  // prekey bundle is published; defaults to 1 until then. Mutable because it's
  // learned from the publish response, not known at construction.
  deviceId: number;

  constructor(
    private readonly engine: SignalWasmEngine,
    private readonly store: IndexedDbSignalStore,
    readonly selfUserId: string,
    deviceId: number = 1,
  ) {
    this.deviceId = deviceId;
  }

  address(userId: string, deviceId = 1): string {
    return protocolAddress(userId, deviceId);
  }

  /** Provision this device's identity if not already present. Idempotent. */
  async ensureRegistered(): Promise<RegistrationInfo | null> {
    if (await this.store.hasLocalState()) return null;
    return this.engine.generate_registration(this.store);
  }

  /** Generate publishable prekey material (identity, signed, kyber, one-time batch). */
  async buildPublishableBundle(
    signedPreKeyId: number,
    kyberPreKeyId: number,
    preKeyStartId: number,
    count = 100,
    nowMs = Date.now(),
  ): Promise<PublishBundle> {
    return this.engine.generate_prekeys(
      this.store,
      signedPreKeyId,
      kyberPreKeyId,
      preKeyStartId,
      count,
      nowMs,
    );
  }

  async processPeerBundle(peer: string, bundle: PeerBundle, nowMs = Date.now()): Promise<void> {
    await this.engine.process_peer_bundle(this.store, peer, bundle, nowMs);
  }

  async encrypt(peer: string, plaintext: Uint8Array, nowMs = Date.now()): Promise<EncryptResult> {
    return this.engine.encrypt(this.store, peer, this.address(this.selfUserId, this.deviceId), plaintext, nowMs);
  }

  async decrypt(peer: string, type: CiphertextType, body: Uint8Array, nowMs = Date.now()): Promise<Uint8Array> {
    return this.engine.decrypt(this.store, peer, this.address(this.selfUserId, this.deviceId), type, body, nowMs);
  }

  /**
   * The official Signal safety number for the conversation with `peerUserId`,
   * grouped into 5-digit blocks — or null when it can't be computed (engine built
   * without the `fingerprint` export, or no session/identity with the peer yet, so
   * the caller falls back to the legacy public-key fingerprint). The number is
   * order-independent, so both parties see the same value.
   */
  /** True once the vendored wasm exposes the group (SenderKey) primitives. */
  hasGroupSupport(): boolean {
    return (
      typeof this.engine.sender_key_distribution_message === "function" &&
      typeof this.engine.process_sender_key_distribution === "function" &&
      typeof this.engine.group_encrypt_message === "function" &&
      typeof this.engine.group_decrypt_message === "function"
    );
  }

  /**
   * Create (persist on first use) this device's SenderKey distribution message for
   * `distributionId` (the group id). The returned bytes are sent to each group
   * member over a 1:1 Signal session so they can decrypt our group messages.
   */
  async createSenderKeyDistribution(distributionId: string): Promise<Uint8Array> {
    if (typeof this.engine.sender_key_distribution_message !== "function") {
      throw new Error("group messaging not supported by this engine build");
    }
    return this.engine.sender_key_distribution_message(
      this.store,
      this.address(this.selfUserId, this.deviceId),
      distributionId,
    );
  }

  /** Ingest a member's SenderKey distribution message (received over a 1:1 session). */
  async processSenderKeyDistribution(
    senderUserId: string,
    senderDeviceId: number,
    skdmBytes: Uint8Array,
  ): Promise<void> {
    if (typeof this.engine.process_sender_key_distribution !== "function") {
      throw new Error("group messaging not supported by this engine build");
    }
    await this.engine.process_sender_key_distribution(
      this.store,
      this.address(senderUserId, senderDeviceId),
      skdmBytes,
    );
  }

  /** Encrypt a group message once with our SenderKey for `distributionId`. */
  async groupEncrypt(distributionId: string, plaintext: Uint8Array): Promise<Uint8Array> {
    if (typeof this.engine.group_encrypt_message !== "function") {
      throw new Error("group messaging not supported by this engine build");
    }
    return this.engine.group_encrypt_message(
      this.store,
      this.address(this.selfUserId, this.deviceId),
      distributionId,
      plaintext,
    );
  }

  /** Decrypt a member's group SenderKeyMessage. */
  async groupDecrypt(
    senderUserId: string,
    senderDeviceId: number,
    skmBytes: Uint8Array,
  ): Promise<Uint8Array> {
    if (typeof this.engine.group_decrypt_message !== "function") {
      throw new Error("group messaging not supported by this engine build");
    }
    return this.engine.group_decrypt_message(
      this.store,
      this.address(senderUserId, senderDeviceId),
      skmBytes,
    );
  }

  /** True once the vendored wasm exposes the sealed-sender primitives. */
  hasSealedSenderSupport(): boolean {
    return (
      typeof this.engine.sealed_sender_encrypt_message === "function" &&
      typeof this.engine.sealed_sender_decrypt_message === "function"
    );
  }

  /**
   * Sealed-sender encrypt `plaintext` for a destination device, carrying our minted
   * sender certificate. The returned envelope hides our identity from the relay.
   */
  async sealedEncrypt(
    destinationAddress: string,
    senderCertBytes: Uint8Array,
    plaintext: Uint8Array,
    nowMs = Date.now(),
  ): Promise<Uint8Array> {
    if (typeof this.engine.sealed_sender_encrypt_message !== "function") {
      throw new Error("sealed sender not supported by this engine build");
    }
    return this.engine.sealed_sender_encrypt_message(
      this.store,
      destinationAddress,
      senderCertBytes,
      plaintext,
      nowMs,
    );
  }

  /**
   * Sealed-sender decrypt: validate the embedded sender certificate against the
   * pinned `trustRoot` and decrypt. Returns the recovered sender + plaintext.
   */
  async sealedDecrypt(
    trustRoot: Uint8Array,
    ciphertext: Uint8Array,
    nowMs = Date.now(),
  ): Promise<{ senderUuid: string; senderDeviceId: number; message: Uint8Array }> {
    if (typeof this.engine.sealed_sender_decrypt_message !== "function") {
      throw new Error("sealed sender not supported by this engine build");
    }
    return this.engine.sealed_sender_decrypt_message(
      this.store,
      trustRoot,
      nowMs,
      this.selfUserId,
      this.deviceId,
      ciphertext,
    );
  }

  async safetyNumber(peerUserId: string): Promise<string | null> {
    if (typeof this.engine.fingerprint !== "function") return null;
    const remoteIdentity = await this.store.getIdentity(this.address(peerUserId));
    if (!remoteIdentity) return null;
    try {
      const fp = await this.engine.fingerprint(this.store, this.selfUserId, peerUserId, remoteIdentity);
      return fp.displayText.replace(/(\d{5})(?=\d)/g, "$1 ");
    } catch {
      return null;
    }
  }
}

/**
 * URL of the wasm binary, served as a static asset from `/public/pm`. The engine
 * glue (wasm-pack `--target web`) is vendored under `./engine` for now (Phase 4
 * bootstrap). This graduates to the CI-published, provenance-attested
 * `@cybertobo/signal-wasm` package with zero change to callers — only this loader's
 * body changes (see docs/CRYPTO-P1-IMPLEMENTATION-PLAN.md, option A → option 3).
 */
const ENGINE_WASM_URL = "/pm/signal-engine_bg.wasm";

let enginePromise: Promise<SignalWasmEngine> | null = null;

/** Lazily import + initialize the wasm engine exactly once per document. */
export async function loadSignalEngine(): Promise<SignalWasmEngine> {
  if (enginePromise) return enginePromise;
  enginePromise = (async () => {
    // Dynamic import keeps the ~1 MB wasm glue out of the initial bundle.
    const mod = await import("./engine/signal-engine");
    // wasm-pack `--target web` default export is the async init(); it must run
    // (fetching the wasm URL) before any engine fn is callable.
    await mod.default({ module_or_path: ENGINE_WASM_URL });
    return mod as unknown as SignalWasmEngine;
  })();
  return enginePromise;
}
