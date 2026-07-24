/* tslint:disable */
/* eslint-disable */

/**
 * Decrypt a peer's ciphertext (`type` = "prekey" | "whisper"); returns plaintext.
 */
export function decrypt(store: any, remote_address: string, local_address: string, msg_type: string, body: Uint8Array, _now_ms: number): Promise<Uint8Array>;

/**
 * Derive the AES-256 + HMAC-SHA256 keys for the content backup from the recovery
 * key. Root step is Signal's own `BackupKey::derive_from_account_entropy_pool`
 * (HKDF, domain "20240801_SIGNAL_BACKUP_KEY"); we then expand to a 32-byte AES key
 * + 32-byte HMAC key with a per-backup `token` as HKDF salt (forward secrecy: a
 * fresh token per backup ⇒ fresh keys) under an app-specific info string. Returns
 * `{ aesKey, hmacKey }`; the JS layer does AES-256-CBC + HMAC (encrypt-then-MAC).
 */
export function derive_backup_keys(account_entropy_pool: string, token: Uint8Array): any;

/**
 * Encrypt `plaintext` for `remote_address`; returns `{ type, body }`.
 */
export function encrypt(store: any, remote_address: string, local_address: string, plaintext: Uint8Array, now_ms: number): Promise<any>;

/**
 * Compute the Signal safety number for a conversation. `local_id`/`remote_id` are
 * the stable per-party identifiers (we use the app userIds); the local identity
 * key is read from the store, the remote identity key is passed in (the caller has
 * it from the established session / TOFU store). Returns
 * `{ displayText, scannable }` where `displayText` is the 60-digit safety number
 * (order-independent between the two parties) and `scannable` is the QR-code
 * protobuf bytes. Pure/stateless beyond the one identity-key read — no clock.
 */
export function fingerprint(store: any, local_id: string, remote_id: string, remote_identity_key: Uint8Array): Promise<any>;

/**
 * Generate a Signal Account Entropy Pool — the 64-char `[a-z0-9]` recovery key
 * that roots the content backup. High-entropy (~330 bits); the user saves it and
 * it never leaves the client. Same format Signal uses for Secure Backups.
 */
export function generate_account_entropy_pool(): string;

/**
 * Generate + persist a signed prekey, a Kyber prekey, and `count` one-time prekeys.
 * Returns the publishable bundle material (public keys + signatures + ids).
 */
export function generate_prekeys(store: any, signed_prekey_id: number, kyber_prekey_id: number, prekey_start_id: number, count: number, now_ms: number): Promise<any>;

/**
 * Generate + persist this device's identity + registration id; return public info.
 */
export function generate_registration(store: any): Promise<any>;

/**
 * Decrypt a group SenderKeyMessage from `sender_address`. Requires this sender's
 * distribution message to have been processed first.
 */
export function group_decrypt_message(store: any, sender_address: string, skm_bytes: Uint8Array): Promise<Uint8Array>;

/**
 * Encrypt a group message ONCE with this sender's SenderKey. The same serialized
 * SenderKeyMessage is delivered to every group member.
 */
export function group_encrypt_message(store: any, sender_address: string, distribution_id: string, plaintext: Uint8Array): Promise<Uint8Array>;

export function ping(): number;

/**
 * Establish an outbound session from a peer's fetched prekey bundle.
 * `bundle` is a JS object with Uint8Array key fields + numeric ids.
 */
export function process_peer_bundle(store: any, remote_address: string, bundle: any, now_ms: number): Promise<void>;

/**
 * Process a peer's SenderKey distribution message (received over a 1:1 session),
 * persisting their SenderKey chain so their group messages decrypt.
 */
export function process_sender_key_distribution(store: any, sender_address: string, skdm_bytes: Uint8Array): Promise<void>;

/**
 * Mint a sender certificate binding (senderUuid, deviceId, identity key) with an
 * expiry, signed by the server cert's key. Run server-side per request.
 */
export function sealed_sender_create_sender_cert(server_cert_bytes: Uint8Array, server_private: Uint8Array, sender_uuid: string, sender_device_id: number, sender_identity_key: Uint8Array, expiry_ms: number): Uint8Array;

/**
 * Create the server certificate (a server signing keypair certified by the root).
 * `{ serverCert, serverPrivate }`. Run ONCE, server-side.
 */
export function sealed_sender_create_server_cert(root_private: Uint8Array, key_id: number): any;

/**
 * Sealed-sender decrypt: validate the embedded sender cert against `trust_root`,
 * then decrypt the inner message. Returns `{ senderUuid, senderDeviceId, message }`.
 */
export function sealed_sender_decrypt_message(store: any, trust_root: Uint8Array, timestamp_ms: number, local_uuid: string, local_device_id: number, ciphertext: Uint8Array): Promise<any>;

/**
 * Sealed-sender encrypt `plaintext` for `destination_address` (`userId.deviceId`),
 * carrying the caller's `sender_cert`. Returns the opaque sealed-sender envelope
 * (no sender id on the wire).
 */
export function sealed_sender_encrypt_message(store: any, destination_address: string, sender_cert_bytes: Uint8Array, plaintext: Uint8Array, now_ms: number): Promise<Uint8Array>;

/**
 * Generate the sealed-sender trust-root keypair. `{ rootPrivate, rootPublic }`.
 * Run ONCE, server-side; the public half is pinned by clients.
 */
export function sealed_sender_generate_root(): any;

export function self_test(): string;

/**
 * Create (and persist on first use) this device's SenderKey distribution message
 * for `distribution_id`. The returned serialized bytes are delivered to each
 * group member over a 1:1 Signal session so they can decrypt this sender's group
 * messages.
 */
export function sender_key_distribution_message(store: any, sender_address: string, distribution_id: string): Promise<Uint8Array>;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly decrypt: (a: any, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => any;
    readonly derive_backup_keys: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly encrypt: (a: any, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => any;
    readonly fingerprint: (a: any, b: number, c: number, d: number, e: number, f: number, g: number) => any;
    readonly generate_account_entropy_pool: () => [number, number];
    readonly generate_prekeys: (a: any, b: number, c: number, d: number, e: number, f: number) => any;
    readonly generate_registration: (a: any) => any;
    readonly group_decrypt_message: (a: any, b: number, c: number, d: number, e: number) => any;
    readonly group_encrypt_message: (a: any, b: number, c: number, d: number, e: number, f: number, g: number) => any;
    readonly ping: () => number;
    readonly process_peer_bundle: (a: any, b: number, c: number, d: any, e: number) => any;
    readonly process_sender_key_distribution: (a: any, b: number, c: number, d: number, e: number) => any;
    readonly sealed_sender_create_sender_cert: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number, number];
    readonly sealed_sender_create_server_cert: (a: number, b: number, c: number) => [number, number, number];
    readonly sealed_sender_decrypt_message: (a: any, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => any;
    readonly sealed_sender_encrypt_message: (a: any, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => any;
    readonly sealed_sender_generate_root: () => [number, number, number];
    readonly self_test: () => [number, number, number, number];
    readonly sender_key_distribution_message: (a: any, b: number, c: number, d: number, e: number) => any;
    readonly wasm_bindgen_e614a7afa8ab1e7e___convert__closures_____invoke___wasm_bindgen_e614a7afa8ab1e7e___JsValue__core_e55ac9a380c14330___result__Result_____wasm_bindgen_e614a7afa8ab1e7e___JsError___true_: (a: number, b: number, c: any) => [number, number];
    readonly wasm_bindgen_e614a7afa8ab1e7e___convert__closures_____invoke___js_sys_5811c592c0d150c8___Function_fn_wasm_bindgen_e614a7afa8ab1e7e___JsValue_____wasm_bindgen_e614a7afa8ab1e7e___sys__Undefined___js_sys_5811c592c0d150c8___Function_fn_wasm_bindgen_e614a7afa8ab1e7e___JsValue_____wasm_bindgen_e614a7afa8ab1e7e___sys__Undefined_______true_: (a: number, b: number, c: any, d: any) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_destroy_closure: (a: number, b: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
