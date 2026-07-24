"use client";

/**
 * Crypto P1 (Phase 4, Option 1) — Signal/PQXDH send + receive for PM bodies.
 *
 * Bodies (the `encodePmBody(format, text)` wire string) are the only thing moved to
 * Signal here; reactions, previews-of-legacy, and the safety number stay on the legacy
 * libsodium `crypto_box` path (they're stateless and unaffected). Each outbound body is
 * encrypted with the ratchet and packed into the relay's opaque `ciphertext` as a
 * `sig1:` payload (see signal-wire.ts); inbound `sig1:` payloads are decrypted exactly
 * once and cached locally (see IndexedDbSignalStore message cache), because the ratchet
 * destroys each message key on first use.
 *
 * Single-device assumption for now: everyone is device 1 (provision.ts). Multi-device
 * fan-out is a later step.
 */

import type { CryptoEngine, PeerBundle, PreKeyBundleWire } from "./crypto-engine";
import type { IndexedDbSignalStore } from "./signal-store";
import {
  fromBase64,
  packSignalPayload,
  packSealedPayload,
  unpackPayload,
  type UnpackedPayload,
} from "./signal-wire";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

/** Convert a server prekey bundle (base64 fields) into engine PeerBundle bytes. */
function wireToPeerBundle(w: PreKeyBundleWire): PeerBundle {
  return {
    registrationId: w.registrationId,
    deviceId: w.deviceId,
    identityKey: fromBase64(w.identityKey),
    signedPreKeyId: w.signedPreKeyId,
    signedPreKeyPublic: fromBase64(w.signedPreKeyPublic),
    signedPreKeySignature: fromBase64(w.signedPreKeySignature),
    kyberPreKeyId: w.kyberPreKeyId,
    kyberPreKeyPublic: fromBase64(w.kyberPreKeyPublic),
    kyberPreKeySignature: fromBase64(w.kyberPreKeySignature),
    preKeyId: w.preKeyId,
    preKeyPublic: w.preKeyPublic ? fromBase64(w.preKeyPublic) : undefined,
  };
}

/** A `sig1:` ciphertext fanned out to one recipient device (relay payload shape). */
export interface DevicePayload {
  recipientId: string;
  recipientDeviceId: number;
  ciphertext: string;
}

/** List a peer's registered Signal device ids (multi-device fan-out targets). */
export async function getPeerDeviceIds(peerUserId: string): Promise<number[]> {
  const res = await fetch(`/api/pm/keys/${encodeURIComponent(peerUserId)}/devices`);
  if (!res.ok) return [];
  const data = (await res.json()) as { deviceIds?: number[] };
  return Array.isArray(data.deviceIds) ? data.deviceIds : [];
}

/**
 * Ensure an outbound Signal session exists with a specific peer DEVICE. Returns
 * false if that device has published no bundle. Fetches a per-device prekey bundle
 * and establishes the PQXDH session addressed as `${peerUserId}.${deviceId}`.
 */
export async function ensurePeerSession(
  engine: CryptoEngine,
  store: IndexedDbSignalStore,
  peerUserId: string,
  deviceId: number,
): Promise<boolean> {
  const address = engine.address(peerUserId, deviceId);
  if (await store.loadSession(address)) return true;

  const res = await fetch(
    `/api/pm/keys/${encodeURIComponent(peerUserId)}/bundle?deviceId=${deviceId}`,
  );
  if (!res.ok) return false; // 404 = that device has no Signal bundle

  const data = (await res.json()) as { bundle?: PreKeyBundleWire };
  if (!data.bundle) return false;

  await engine.processPeerBundle(address, wireToPeerBundle(data.bundle));
  return true;
}

/**
 * Encrypt a body-wire string for EVERY one of `peerUserId`'s devices (multi-device
 * fan-out), each packed as a `sig1:` payload. Returns one entry per device we could
 * establish a session with; empty if the peer isn't Signal-capable / has no devices.
 */
export async function encryptBodyForPeerDevices(
  engine: CryptoEngine,
  store: IndexedDbSignalStore,
  peerUserId: string,
  bodyWire: string,
  // Skip this device id — used for own-device sync (don't encrypt to ourselves).
  excludeDeviceId?: number,
): Promise<DevicePayload[]> {
  const deviceIds = await getPeerDeviceIds(peerUserId);
  const out: DevicePayload[] = [];
  for (const deviceId of deviceIds) {
    if (deviceId === excludeDeviceId) continue;
    if (!(await ensurePeerSession(engine, store, peerUserId, deviceId))) continue;
    const enc = await engine.encrypt(
      engine.address(peerUserId, deviceId),
      textEncoder.encode(bodyWire),
    );
    out.push({
      recipientId: peerUserId,
      recipientDeviceId: deviceId,
      ciphertext: packSignalPayload(enc.type, enc.body),
    });
  }
  return out;
}

/**
 * Decrypt an inbound `sig1:` payload from a specific sender DEVICE exactly once,
 * returning the body-wire string. Addresses the ratchet session as
 * `${senderUserId}.${senderDeviceId}`. Returns null on failure (unknown session /
 * already-consumed key / corrupt) so the UI shows "can't decrypt on this device".
 */
export async function decryptBodyFromPeer(
  engine: CryptoEngine,
  senderUserId: string,
  senderDeviceId: number,
  payload: Extract<UnpackedPayload, { kind: "signal" }>,
): Promise<string | null> {
  try {
    const bytes = await engine.decrypt(
      engine.address(senderUserId, senderDeviceId),
      payload.type,
      payload.body,
    );
    return textDecoder.decode(bytes);
  } catch {
    return null;
  }
}

// ─────────────────────────── Groups (SenderKey) ───────────────────────────

/**
 * Distribute this device's SenderKey to every group member device (own other
 * devices included, sending device excluded). Creates the SenderKey distribution
 * message once for `groupId`, pairwise-encrypts it over each member's 1:1 Signal
 * session, and POSTs the batch to the relay. Members must process it (see
 * {@link processPendingSenderKeys}) before they can decrypt our group messages.
 * Returns true if at least one member device was reached.
 */
export async function distributeSenderKey(
  engine: CryptoEngine,
  store: IndexedDbSignalStore,
  conversationId: string,
  groupId: string,
  memberIds: string[],
): Promise<boolean> {
  const skdm = await engine.createSenderKeyDistribution(groupId);
  const items: DevicePayload[] = [];
  for (const memberId of memberIds) {
    const deviceIds = await getPeerDeviceIds(memberId);
    for (const deviceId of deviceIds) {
      // Never encrypt the handoff to the sending device itself.
      if (memberId === engine.selfUserId && deviceId === engine.deviceId) continue;
      if (!(await ensurePeerSession(engine, store, memberId, deviceId))) continue;
      const enc = await engine.encrypt(engine.address(memberId, deviceId), skdm);
      items.push({
        recipientId: memberId,
        recipientDeviceId: deviceId,
        ciphertext: packSignalPayload(enc.type, enc.body),
      });
    }
  }
  if (items.length === 0) return false;
  const res = await fetch(`/api/pm/conversations/${encodeURIComponent(conversationId)}/skdm`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ senderDeviceId: engine.deviceId, items }),
  });
  return res.ok;
}

/**
 * Fetch + process any pending SenderKey distribution messages addressed to this
 * device for a group, then tell the relay to delete the ones we processed. After
 * this, group messages from those senders can be decrypted. Safe to call on every
 * conversation open (idempotent; missing/failed items are left for a later retry).
 */
export async function processPendingSenderKeys(
  engine: CryptoEngine,
  conversationId: string,
): Promise<void> {
  const res = await fetch(
    `/api/pm/conversations/${encodeURIComponent(conversationId)}/skdm?deviceId=${engine.deviceId}`,
  );
  if (!res.ok) return;
  const data = (await res.json()) as {
    items?: { id: string; senderId: string; senderDeviceId: number; ciphertext: string }[];
  };
  const items = data.items ?? [];
  if (items.length === 0) return;

  const consumed: string[] = [];
  for (const it of items) {
    const unpacked = unpackPayload(it.ciphertext);
    if (unpacked.kind !== "signal") continue;
    try {
      const skdmBytes = await engine.decrypt(
        engine.address(it.senderId, it.senderDeviceId),
        unpacked.type,
        unpacked.body,
      );
      await engine.processSenderKeyDistribution(it.senderId, it.senderDeviceId, skdmBytes);
      consumed.push(it.id);
    } catch {
      // Leave unconsumed — a later open retries (e.g. our session wasn't ready).
    }
  }
  if (consumed.length > 0) {
    await fetch(`/api/pm/conversations/${encodeURIComponent(conversationId)}/skdm/consume`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ deviceId: engine.deviceId, ids: consumed }),
    });
  }
}

/** Encrypt a body-wire string once with our group SenderKey → `sig1:senderkey:` payload. */
export async function encryptGroupBody(
  engine: CryptoEngine,
  groupId: string,
  bodyWire: string,
): Promise<string> {
  const body = await engine.groupEncrypt(groupId, textEncoder.encode(bodyWire));
  return packSignalPayload("senderkey", body);
}

/**
 * Decrypt an inbound group `sig1:senderkey:` payload from a sender device, using
 * that sender's previously-distributed SenderKey. Returns null on failure (their
 * distribution message not yet processed, or a corrupt/duplicate message).
 */
export async function decryptGroupBody(
  engine: CryptoEngine,
  senderUserId: string,
  senderDeviceId: number,
  payload: Extract<UnpackedPayload, { kind: "signal" }>,
): Promise<string | null> {
  try {
    const bytes = await engine.groupDecrypt(senderUserId, senderDeviceId, payload.body);
    return textDecoder.decode(bytes);
  } catch {
    return null;
  }
}

// ─────────────────────────── sealed sender ───────────────────────────

/** A sealed-sender envelope for one recipient device + the access key that
 *  authorizes its unauthenticated delivery. */
export interface SealedDeliveryItem {
  recipientId: string;
  recipientDeviceId: number;
  accessKey: string;
  ciphertext: string;
}

/**
 * Sealed-sender-encrypt a body-wire string for every device of the given members
 * (own OTHER devices included for own-device sync; the sending device is skipped —
 * libsignal forbids sealing to yourself). Each envelope hides the sender; delivery
 * is authorized by the recipient's access key (from `accessKeys`). Returns the
 * items to POST to the unauthenticated sealed endpoint.
 */
export async function sealedEncryptForRecipients(
  engine: CryptoEngine,
  store: IndexedDbSignalStore,
  memberIds: string[],
  bodyWire: string,
  accessKeys: Record<string, string>,
  senderCertBytes: Uint8Array,
): Promise<SealedDeliveryItem[]> {
  const out: SealedDeliveryItem[] = [];
  for (const memberId of memberIds) {
    const accessKey = accessKeys[memberId];
    if (!accessKey) continue;
    const deviceIds = await getPeerDeviceIds(memberId);
    for (const deviceId of deviceIds) {
      if (memberId === engine.selfUserId && deviceId === engine.deviceId) continue;
      if (!(await ensurePeerSession(engine, store, memberId, deviceId))) continue;
      const sealed = await engine.sealedEncrypt(
        engine.address(memberId, deviceId),
        senderCertBytes,
        textEncoder.encode(bodyWire),
      );
      out.push({
        recipientId: memberId,
        recipientDeviceId: deviceId,
        accessKey,
        ciphertext: packSealedPayload(sealed),
      });
    }
  }
  return out;
}

/**
 * Decrypt an inbound sealed-sender envelope, validating the sender certificate
 * against the pinned trust root. Returns the recovered sender id + body-wire
 * string, or null on failure (bad cert / trust-root mismatch / corrupt).
 */
export async function decryptSealedBody(
  engine: CryptoEngine,
  trustRoot: Uint8Array,
  payload: Extract<UnpackedPayload, { kind: "sealed" }>,
): Promise<{ senderId: string; body: string } | null> {
  try {
    const res = await engine.sealedDecrypt(trustRoot, payload.body);
    return { senderId: res.senderUuid, body: textDecoder.decode(res.message) };
  } catch {
    return null;
  }
}
