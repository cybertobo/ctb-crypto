"use client";

/**
 * Crypto P1 (Phase 4) — client device provisioning for the Signal/PQXDH engine.
 *
 * On first use in a browser this generates the device identity + registration id,
 * builds the initial prekey batch (signed X25519 + ML-KEM Kyber + one-time), and
 * publishes ONLY the public material to the prekey server (POST /api/pm/keys/publish).
 * Private/identity/session state lives solely in IndexedDB and never leaves the device.
 *
 * This is ADDITIVE: it runs alongside the legacy libsodium `crypto_box` PM path and
 * never affects it. If anything fails (older browser, wasm unavailable, offline), it
 * degrades silently so the existing messaging UI keeps working (see useSignalEngine).
 */

import { useEffect, useRef, useState, type MutableRefObject } from "react";
import { CryptoEngine, loadSignalEngine, type PublishBundle } from "./crypto-engine";
import { IndexedDbSignalStore } from "./signal-store";
import { toBase64 } from "./signal-wire";

export interface ProvisionedEngine {
  engine: CryptoEngine;
  store: IndexedDbSignalStore;
}

// Initial key ids for a fresh device: one signed + one kyber + a one-time batch.
const INITIAL_SIGNED_PREKEY_ID = 1;
const INITIAL_KYBER_PREKEY_ID = 1;
const INITIAL_ONE_TIME_START_ID = 1;
const ONE_TIME_COUNT = 100;

// Replenish thresholds. Peers consume this device's one-time prekeys when they
// start a session with it (server-side, one per bundle handout), so the pool
// silently drains. When it drops below the watermark we mint a fresh batch (and
// rotate the signed + kyber prekeys, healthy Signal hygiene) and re-publish.
const ONE_TIME_LOW_WATERMARK = 20;
const ONE_TIME_REPLENISH_COUNT = 100;

/** Build the /api/pm/keys/publish request body from a freshly-generated bundle. */
function publishPayload(installationId: string, registrationId: number, bundle: PublishBundle) {
  return {
    installationId,
    registrationId,
    identityKey: toBase64(bundle.identityKey),
    signedPreKey: {
      id: bundle.signedPreKey.id,
      publicKey: toBase64(bundle.signedPreKey.publicKey),
      signature: toBase64(bundle.signedPreKey.signature),
    },
    kyberPreKey: {
      id: bundle.kyberPreKey.id,
      publicKey: toBase64(bundle.kyberPreKey.publicKey),
      signature: toBase64(bundle.kyberPreKey.signature),
    },
    oneTimePreKeys: bundle.oneTimePreKeys.map((k) => ({
      id: k.id,
      publicKey: toBase64(k.publicKey),
    })),
  };
}

/**
 * Ensure this device is registered + its bundle published. Idempotent: registration
 * is skipped if present, and the bundle is published at most once per device (guarded
 * by the store's `provisioned` marker). Returns the ready engine for send/receive use.
 */
export function provisionSignalDevice(userId: string): Promise<ProvisionedEngine> {
  // Serialize per user: concurrent mounts (StrictMode, several tabs) must not each
  // generate + publish their own identity/prekeys, or local and server keys diverge.
  let pending = inflightProvision.get(userId);
  if (!pending) {
    const run = () => provisionOnce(userId);
    const locks = typeof navigator !== "undefined" ? navigator.locks : undefined;
    pending = (locks ? locks.request(`ctb-signal-provision:${userId}`, run) : run()).finally(() =>
      inflightProvision.delete(userId),
    );
    inflightProvision.set(userId, pending);
  }
  return pending;
}

const inflightProvision = new Map<string, Promise<ProvisionedEngine>>();

async function provisionOnce(userId: string): Promise<ProvisionedEngine> {
  const wasm = await loadSignalEngine();
  const store = new IndexedDbSignalStore();
  const engine = new CryptoEngine(wasm, store, userId);

  await engine.ensureRegistered(); // idempotent (no-op if identity already exists)

  // Load our server-assigned deviceId if we already have one (multi-device).
  const storedDeviceId = await store.getDeviceId();
  if (storedDeviceId != null) engine.deviceId = storedDeviceId;

  if (!(await store.isProvisioned())) {
    const local = await store.getLocalState();
    if (!local) throw new Error("signal: local state missing after registration");

    const installationId = await store.getInstallationId();
    const bundle = await engine.buildPublishableBundle(
      INITIAL_SIGNED_PREKEY_ID,
      INITIAL_KYBER_PREKEY_ID,
      INITIAL_ONE_TIME_START_ID,
      ONE_TIME_COUNT,
    );

    const res = await fetch("/api/pm/keys/publish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(publishPayload(installationId, local.registrationId, bundle)),
    });
    if (res.ok) {
      // The server assigns this device's deviceId (1, 2, … per user). Persist it +
      // set it on the engine so all our addresses use the right device.
      const { deviceId } = (await res.json()) as { deviceId?: number };
      if (typeof deviceId === "number") {
        engine.deviceId = deviceId;
        await store.setDeviceId(deviceId);
      }
      await store.markProvisioned();
      // Seed the rotation cursor past the ids we just published (1/1/1..100).
      await store.setKeygenState({
        nextSignedId: INITIAL_SIGNED_PREKEY_ID + 1,
        nextKyberId: INITIAL_KYBER_PREKEY_ID + 1,
        nextOneTimeId: INITIAL_ONE_TIME_START_ID + ONE_TIME_COUNT,
      });
    }
  }

  // Top up the one-time pool if peers have drained it below the watermark. Runs
  // on every mount (cheap read-only probe first); best-effort, never blocks the
  // engine from being returned.
  await replenishIfLow(engine, store).catch(() => {});

  return { engine, store };
}

/**
 * Top up this device's one-time prekey pool when peers have drained it. First a
 * read-only probe (an empty /replenish returns the remaining count without
 * writing); if below {@link ONE_TIME_LOW_WATERMARK} we mint a fresh bundle at the
 * next unused ids (rotating the signed + kyber prekeys too — never reusing an id,
 * so already-published prekeys stay decryptable) and re-publish it. Idempotent and
 * safe to call on every mount; any failure is swallowed by the caller.
 */
async function replenishIfLow(engine: CryptoEngine, store: IndexedDbSignalStore): Promise<void> {
  const local = await store.getLocalState();
  if (!local) return;

  // Read-only remaining-count probe (no keys sent = no writes server-side).
  const probe = await fetch("/api/pm/keys/replenish", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ deviceId: engine.deviceId, oneTimePreKeys: [] }),
  });
  if (!probe.ok) return;
  const { remaining } = (await probe.json()) as { remaining?: number };
  if (typeof remaining !== "number" || remaining >= ONE_TIME_LOW_WATERMARK) return;

  // Advance from the persisted cursor (fallback covers a device provisioned
  // before the cursor existed — start past the initial 1/1/1..100 batch).
  const cursor = (await store.getKeygenState()) ?? {
    nextSignedId: INITIAL_SIGNED_PREKEY_ID + 1,
    nextKyberId: INITIAL_KYBER_PREKEY_ID + 1,
    nextOneTimeId: INITIAL_ONE_TIME_START_ID + ONE_TIME_COUNT,
  };

  const bundle = await engine.buildPublishableBundle(
    cursor.nextSignedId,
    cursor.nextKyberId,
    cursor.nextOneTimeId,
    ONE_TIME_REPLENISH_COUNT,
  );

  const installationId = await store.getInstallationId();
  const res = await fetch("/api/pm/keys/publish", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(publishPayload(installationId, local.registrationId, bundle)),
  });
  if (!res.ok) return;

  await store.setKeygenState({
    nextSignedId: cursor.nextSignedId + 1,
    nextKyberId: cursor.nextKyberId + 1,
    nextOneTimeId: cursor.nextOneTimeId + ONE_TIME_REPLENISH_COUNT,
  });
}

export interface SignalEngineHandle {
  /** The ready engine + store, or null until provisioning resolves (or if it failed). */
  ref: MutableRefObject<ProvisionedEngine | null>;
  /** Flips true once the engine is usable — include in effect deps so consumers re-run. */
  ready: boolean;
  /** Flips true if provisioning failed (Signal is the ONLY path — surface it to the user). */
  error: boolean;
}

/**
 * React hook: provision the Signal device once on mount and hold the ready engine in
 * a ref for the send/receive paths. Exposes `ready` (so callers can re-run effects when
 * the engine becomes available) and `error` (provisioning failed — since Signal/PQXDH is
 * the ONLY encryption path, the UI must surface this rather than silently degrade).
 */
export function useSignalEngine(userId: string): SignalEngineHandle {
  const ref = useRef<ProvisionedEngine | null>(null);
  const [ready, setReady] = useState(false);
  const [error, setError] = useState(false);
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const prov = await provisionSignalDevice(userId);
        if (!cancelled) {
          ref.current = prov;
          setReady(true);
        }
      } catch (err) {
        console.warn("[pm] Signal provisioning failed:", err);
        if (!cancelled) setError(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [userId]);
  return { ref, ready, error };
}
