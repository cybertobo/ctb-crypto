//! Cybertobo Signal wasm engine — thin wasm-bindgen wrapper over the official
//! `libsignal-protocol` crate. See docs/CRYPTO-P1-IMPLEMENTATION-PLAN.md.
//!
//! Persistence: the exposed async fns receive a JS store object (the TS
//! `IndexedDbSignalStore`). `JsStore` implements the five libsignal store traits by
//! calling back into that object's async methods (`call_store` awaits Promises via
//! wasm-bindgen-futures). All clock-taking calls take an explicit `now_ms` —
//! `SystemTime::now()` PANICS on wasm32, so we build `SystemTime` from `now_ms` and
//! construct Kyber prekeys with `::new` (never `KyberPreKeyRecord::generate`, which
//! calls `SystemTime::now()` internally).

use std::time::{Duration, UNIX_EPOCH};

use async_trait::async_trait;
use js_sys::{Array, Function, Promise, Reflect, Uint8Array};
use libsignal_core::DeviceId;
use libsignal_protocol::{
    create_sender_key_distribution_message, group_decrypt, group_encrypt, kem, message_decrypt,
    message_encrypt, process_prekey_bundle, process_sender_key_distribution_message,
    sealed_sender_decrypt, sealed_sender_encrypt, CiphertextMessage, CiphertextMessageType,
    Direction, Fingerprint, GenericSignedPreKey, IdentityChange, IdentityKey, IdentityKeyPair,
    IdentityKeyStore, KeyPair, KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore, PreKeyBundle,
    PreKeyId, PreKeyRecord, PreKeySignalMessage, PreKeyStore, PrivateKey, ProtocolAddress,
    PublicKey, SenderCertificate, SenderKeyDistributionMessage, SenderKeyRecord, SenderKeyStore,
    ServerCertificate, SessionRecord, SessionStore, SignalMessage, SignalProtocolError,
    SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore, Timestamp,
};
use rand::rngs::OsRng;
use rand::{RngCore as _, TryRngCore as _};
use uuid::Uuid;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

/// libsignal's own `Result` alias is private; mirror it locally.
type SignalResult<T> = std::result::Result<T, SignalProtocolError>;

// ─────────────────────────── smoke test (Phase 0) ───────────────────────────

#[wasm_bindgen]
pub fn ping() -> u32 {
    42
}

#[wasm_bindgen]
pub fn self_test() -> std::result::Result<String, JsValue> {
    let mut rng = OsRng.unwrap_err();
    let kp = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
    let (ss_sender, ct) = kp
        .public_key
        .encapsulate(&mut rng)
        .map_err(|e| JsValue::from_str(&format!("encapsulate: {e:?}")))?;
    let ss_recip = kp
        .secret_key
        .decapsulate(&ct)
        .map_err(|e| JsValue::from_str(&format!("decapsulate: {e:?}")))?;
    let ikp = KeyPair::generate(&mut rng);
    let msg = b"cybertobo pqxdh wasm engine";
    let sig = ikp
        .calculate_signature(msg, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("sign: {e:?}")))?;
    Ok(format!(
        "{{\"kem_ok\":{},\"sig_ok\":{}}}",
        ss_sender == ss_recip,
        ikp.public_key.verify_signature(msg, &sig)
    ))
}

// ─────────────────────────── JS bridge helpers ───────────────────────────

fn js_err(e: JsValue) -> SignalProtocolError {
    SignalProtocolError::InvalidArgument(format!("js store error: {e:?}"))
}

fn now_from_ms(now_ms: f64) -> std::time::SystemTime {
    UNIX_EPOCH + Duration::from_millis(now_ms as u64)
}

fn addr_str(a: &ProtocolAddress) -> String {
    format!("{}.{}", a.name(), u32::from(a.device_id()))
}

fn parse_addr(s: &str) -> std::result::Result<ProtocolAddress, JsValue> {
    let (name, dev) = s
        .rsplit_once('.')
        .ok_or_else(|| JsValue::from_str("address must be `name.deviceId`"))?;
    let device_id: u8 = dev
        .parse()
        .map_err(|_| JsValue::from_str("invalid deviceId in address"))?;
    let device = DeviceId::new(device_id).map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    Ok(ProtocolAddress::new(name.to_owned(), device))
}

/// Call an async method on the JS store and await it. Non-Promise returns are
/// wrapped so sync methods also work.
async fn call_store(
    store: &JsValue,
    method: &str,
    args: &[JsValue],
) -> std::result::Result<JsValue, JsValue> {
    let f = Reflect::get(store, &JsValue::from_str(method))?;
    let f: Function = f
        .dyn_into()
        .map_err(|_| JsValue::from_str(&format!("store.{method} is not a function")))?;
    let arr = Array::new();
    for a in args {
        arr.push(a);
    }
    let ret = Reflect::apply(&f, store, &arr)?;
    let promise: Promise = ret.dyn_into().unwrap_or_else(|v| Promise::resolve(&v));
    JsFuture::from(promise).await
}

/// Call the store and return `Some(bytes)` / `None` (undefined|null).
async fn store_opt_bytes(
    store: &JsValue,
    method: &str,
    args: &[JsValue],
) -> SignalResult<Option<Vec<u8>>> {
    let v = call_store(store, method, args).await.map_err(js_err)?;
    if v.is_undefined() || v.is_null() {
        return Ok(None);
    }
    let arr: Uint8Array = v
        .dyn_into()
        .map_err(|_| SignalProtocolError::InvalidArgument(format!("store.{method}: not bytes")))?;
    Ok(Some(arr.to_vec()))
}

/// Like `store_opt_bytes` but errors if the value is absent.
async fn store_bytes(store: &JsValue, method: &str, args: &[JsValue]) -> SignalResult<Vec<u8>> {
    store_opt_bytes(store, method, args)
        .await?
        .ok_or_else(|| SignalProtocolError::InvalidArgument(format!("store.{method}: not found")))
}

fn bytes_arg(b: &[u8]) -> JsValue {
    Uint8Array::from(b).into()
}
fn num_arg(n: u32) -> JsValue {
    JsValue::from_f64(n as f64)
}

// ─────────────────────────── the JS-backed store ───────────────────────────

/// Wraps the JS store object. Implements all five libsignal store traits by
/// delegating to the object's async methods. Instantiate one per `&mut` slot a
/// libsignal fn needs (they share the same JS object / IndexedDB).
struct JsStore(JsValue);

#[async_trait(?Send)]
impl IdentityKeyStore for JsStore {
    async fn get_identity_key_pair(&self) -> SignalResult<IdentityKeyPair> {
        let state = call_store(&self.0, "getLocalState", &[]).await.map_err(js_err)?;
        let bytes: Uint8Array = Reflect::get(&state, &JsValue::from_str("identityKeyPair"))
            .map_err(js_err)?
            .dyn_into()
            .map_err(|_| SignalProtocolError::InvalidArgument("no identityKeyPair".into()))?;
        IdentityKeyPair::try_from(bytes.to_vec().as_slice())
    }

    async fn get_local_registration_id(&self) -> SignalResult<u32> {
        let state = call_store(&self.0, "getLocalState", &[]).await.map_err(js_err)?;
        let n = Reflect::get(&state, &JsValue::from_str("registrationId"))
            .map_err(js_err)?
            .as_f64()
            .ok_or_else(|| SignalProtocolError::InvalidArgument("no registrationId".into()))?;
        Ok(n as u32)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> SignalResult<IdentityChange> {
        let changed = call_store(
            &self.0,
            "saveIdentity",
            &[JsValue::from_str(&addr_str(address)), bytes_arg(&identity.serialize())],
        )
        .await
        .map_err(js_err)?;
        Ok(IdentityChange::from_changed(changed.as_bool().unwrap_or(false)))
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> SignalResult<bool> {
        let trusted = call_store(
            &self.0,
            "isTrustedIdentity",
            &[JsValue::from_str(&addr_str(address)), bytes_arg(&identity.serialize())],
        )
        .await
        .map_err(js_err)?;
        Ok(trusted.as_bool().unwrap_or(false))
    }

    async fn get_identity(&self, address: &ProtocolAddress) -> SignalResult<Option<IdentityKey>> {
        match store_opt_bytes(&self.0, "getIdentity", &[JsValue::from_str(&addr_str(address))]).await? {
            Some(b) => Ok(Some(IdentityKey::decode(&b)?)),
            None => Ok(None),
        }
    }
}

#[async_trait(?Send)]
impl PreKeyStore for JsStore {
    async fn get_pre_key(&self, id: PreKeyId) -> SignalResult<PreKeyRecord> {
        let b = store_bytes(&self.0, "getPreKey", &[num_arg(id.into())]).await?;
        PreKeyRecord::deserialize(&b)
    }
    async fn save_pre_key(&mut self, id: PreKeyId, record: &PreKeyRecord) -> SignalResult<()> {
        call_store(&self.0, "savePreKey", &[num_arg(id.into()), bytes_arg(&record.serialize()?)])
            .await
            .map_err(js_err)?;
        Ok(())
    }
    async fn remove_pre_key(&mut self, id: PreKeyId) -> SignalResult<()> {
        call_store(&self.0, "removePreKey", &[num_arg(id.into())]).await.map_err(js_err)?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for JsStore {
    async fn get_signed_pre_key(&self, id: SignedPreKeyId) -> SignalResult<SignedPreKeyRecord> {
        let b = store_bytes(&self.0, "getSignedPreKey", &[num_arg(id.into())]).await?;
        SignedPreKeyRecord::deserialize(&b)
    }
    async fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> SignalResult<()> {
        call_store(&self.0, "saveSignedPreKey", &[num_arg(id.into()), bytes_arg(&record.serialize()?)])
            .await
            .map_err(js_err)?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStore for JsStore {
    async fn get_kyber_pre_key(&self, id: KyberPreKeyId) -> SignalResult<KyberPreKeyRecord> {
        let b = store_bytes(&self.0, "getKyberPreKey", &[num_arg(id.into())]).await?;
        KyberPreKeyRecord::deserialize(&b)
    }
    async fn save_kyber_pre_key(
        &mut self,
        id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> SignalResult<()> {
        call_store(&self.0, "saveKyberPreKey", &[num_arg(id.into()), bytes_arg(&record.serialize()?)])
            .await
            .map_err(js_err)?;
        Ok(())
    }
    async fn mark_kyber_pre_key_used(
        &mut self,
        id: KyberPreKeyId,
        _ec_prekey_id: SignedPreKeyId,
        _base_key: &PublicKey,
    ) -> SignalResult<()> {
        call_store(&self.0, "markKyberPreKeyUsed", &[num_arg(id.into())]).await.map_err(js_err)?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl SessionStore for JsStore {
    async fn load_session(&self, address: &ProtocolAddress) -> SignalResult<Option<SessionRecord>> {
        match store_opt_bytes(&self.0, "loadSession", &[JsValue::from_str(&addr_str(address))]).await? {
            Some(b) => Ok(Some(SessionRecord::deserialize(&b)?)),
            None => Ok(None),
        }
    }
    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> SignalResult<()> {
        call_store(
            &self.0,
            "storeSession",
            &[JsValue::from_str(&addr_str(address)), bytes_arg(&record.serialize()?)],
        )
        .await
        .map_err(js_err)?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl SenderKeyStore for JsStore {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
    ) -> SignalResult<()> {
        call_store(
            &self.0,
            "storeSenderKey",
            &[
                JsValue::from_str(&addr_str(sender)),
                JsValue::from_str(&distribution_id.to_string()),
                bytes_arg(&record.serialize()?),
            ],
        )
        .await
        .map_err(js_err)?;
        Ok(())
    }

    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
    ) -> SignalResult<Option<SenderKeyRecord>> {
        match store_opt_bytes(
            &self.0,
            "loadSenderKey",
            &[
                JsValue::from_str(&addr_str(sender)),
                JsValue::from_str(&distribution_id.to_string()),
            ],
        )
        .await?
        {
            Some(b) => Ok(Some(SenderKeyRecord::deserialize(&b)?)),
            None => Ok(None),
        }
    }
}

// ─────────────────────────── exposed engine API ───────────────────────────

/// Generate + persist this device's identity + registration id; return public info.
#[wasm_bindgen]
pub async fn generate_registration(store: JsValue) -> std::result::Result<JsValue, JsValue> {
    let mut rng = OsRng.unwrap_err();
    let idkp = IdentityKeyPair::generate(&mut rng);
    let registration_id: u32 = (rng.next_u32() % 16380) + 1;

    call_store(
        &store,
        "setLocalState",
        &[bytes_arg(&idkp.serialize()), num_arg(registration_id)],
    )
    .await?;

    let out = js_sys::Object::new();
    Reflect::set(
        &out,
        &JsValue::from_str("identityPublicKey"),
        &bytes_arg(&idkp.identity_key().public_key().serialize()),
    )?;
    Reflect::set(&out, &JsValue::from_str("registrationId"), &num_arg(registration_id))?;
    Ok(out.into())
}

/// Generate + persist a signed prekey, a Kyber prekey, and `count` one-time prekeys.
/// Returns the publishable bundle material (public keys + signatures + ids).
#[wasm_bindgen]
pub async fn generate_prekeys(
    store: JsValue,
    signed_prekey_id: u32,
    kyber_prekey_id: u32,
    prekey_start_id: u32,
    count: u32,
    now_ms: f64,
) -> std::result::Result<JsValue, JsValue> {
    let mut rng = OsRng.unwrap_err();
    let ident = JsStore(store.clone());
    let idkp = ident.get_identity_key_pair().await.map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    let signing = idkp.private_key();
    let ts = Timestamp::from_epoch_millis(now_ms as u64);

    // Signed prekey (X25519) signed by the identity key.
    let spk_pair = KeyPair::generate(&mut rng);
    let spk_sig = signing
        .calculate_signature(&spk_pair.public_key.serialize(), &mut rng)
        .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    let spk = SignedPreKeyRecord::new(signed_prekey_id.into(), ts, &spk_pair, &spk_sig);
    {
        let mut s = JsStore(store.clone());
        s.save_signed_pre_key(signed_prekey_id.into(), &spk)
            .await
            .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    }

    // Kyber prekey (ML-KEM) signed by the identity key — built via ::new (no SystemTime).
    let kyber_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
    let kyber_sig = signing
        .calculate_signature(&kyber_pair.public_key.serialize(), &mut rng)
        .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    let kpk = KyberPreKeyRecord::new(kyber_prekey_id.into(), ts, &kyber_pair, &kyber_sig);
    {
        let mut s = JsStore(store.clone());
        s.save_kyber_pre_key(kyber_prekey_id.into(), &kpk)
            .await
            .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    }

    // One-time prekeys.
    let one_time = Array::new();
    {
        let mut s = JsStore(store.clone());
        for i in 0..count {
            let id = prekey_start_id + i;
            let pair = KeyPair::generate(&mut rng);
            let rec = PreKeyRecord::new(id.into(), &pair);
            s.save_pre_key(id.into(), &rec)
                .await
                .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
            let o = js_sys::Object::new();
            Reflect::set(&o, &JsValue::from_str("id"), &num_arg(id))?;
            Reflect::set(&o, &JsValue::from_str("publicKey"), &bytes_arg(&pair.public_key.serialize()))?;
            one_time.push(&o);
        }
    }

    let out = js_sys::Object::new();
    Reflect::set(&out, &JsValue::from_str("identityKey"), &bytes_arg(&idkp.identity_key().public_key().serialize()))?;
    let spk_obj = js_sys::Object::new();
    Reflect::set(&spk_obj, &JsValue::from_str("id"), &num_arg(signed_prekey_id))?;
    Reflect::set(&spk_obj, &JsValue::from_str("publicKey"), &bytes_arg(&spk_pair.public_key.serialize()))?;
    Reflect::set(&spk_obj, &JsValue::from_str("signature"), &bytes_arg(&spk_sig))?;
    Reflect::set(&out, &JsValue::from_str("signedPreKey"), &spk_obj)?;
    let kpk_obj = js_sys::Object::new();
    Reflect::set(&kpk_obj, &JsValue::from_str("id"), &num_arg(kyber_prekey_id))?;
    Reflect::set(&kpk_obj, &JsValue::from_str("publicKey"), &bytes_arg(&kyber_pair.public_key.serialize()))?;
    Reflect::set(&kpk_obj, &JsValue::from_str("signature"), &bytes_arg(&kyber_sig))?;
    Reflect::set(&out, &JsValue::from_str("kyberPreKey"), &kpk_obj)?;
    Reflect::set(&out, &JsValue::from_str("oneTimePreKeys"), &one_time)?;
    Ok(out.into())
}

fn bundle_bytes(bundle: &JsValue, key: &str) -> std::result::Result<Vec<u8>, JsValue> {
    let arr: Uint8Array = Reflect::get(bundle, &JsValue::from_str(key))?
        .dyn_into()
        .map_err(|_| JsValue::from_str(&format!("bundle.{key} not bytes")))?;
    Ok(arr.to_vec())
}
fn bundle_num(bundle: &JsValue, key: &str) -> std::result::Result<u32, JsValue> {
    Reflect::get(bundle, &JsValue::from_str(key))?
        .as_f64()
        .map(|n| n as u32)
        .ok_or_else(|| JsValue::from_str(&format!("bundle.{key} not a number")))
}

/// Establish an outbound session from a peer's fetched prekey bundle.
/// `bundle` is a JS object with Uint8Array key fields + numeric ids.
#[wasm_bindgen]
pub async fn process_peer_bundle(
    store: JsValue,
    remote_address: String,
    bundle: JsValue,
    now_ms: f64,
) -> std::result::Result<(), JsValue> {
    let mut rng = OsRng.unwrap_err();
    let remote = parse_addr(&remote_address)?;

    let device = DeviceId::new(bundle_num(&bundle, "deviceId")? as u8)
        .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    let identity_key = IdentityKey::decode(&bundle_bytes(&bundle, "identityKey")?)
        .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    let signed_pub = PublicKey::deserialize(&bundle_bytes(&bundle, "signedPreKeyPublic")?)
        .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    let kyber_pub = kem::PublicKey::deserialize(&bundle_bytes(&bundle, "kyberPreKeyPublic")?)
        .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;

    // Optional one-time prekey.
    let pre_key = match Reflect::get(&bundle, &JsValue::from_str("preKeyPublic")) {
        Ok(v) if !v.is_undefined() && !v.is_null() => {
            let pk = PublicKey::deserialize(&bundle_bytes(&bundle, "preKeyPublic")?)
                .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
            Some((PreKeyId::from(bundle_num(&bundle, "preKeyId")?), pk))
        }
        _ => None,
    };

    let pkb = PreKeyBundle::new(
        bundle_num(&bundle, "registrationId")?,
        device,
        pre_key,
        SignedPreKeyId::from(bundle_num(&bundle, "signedPreKeyId")?),
        signed_pub,
        bundle_bytes(&bundle, "signedPreKeySignature")?,
        KyberPreKeyId::from(bundle_num(&bundle, "kyberPreKeyId")?),
        kyber_pub,
        bundle_bytes(&bundle, "kyberPreKeySignature")?,
        identity_key,
    )
    .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;

    let local = parse_addr("self.1")?;
    let mut session = JsStore(store.clone());
    let mut ident = JsStore(store.clone());
    process_prekey_bundle(&remote, &local, &mut session, &mut ident, &pkb, now_from_ms(now_ms), &mut rng)
        .await
        .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    Ok(())
}

/// Encrypt `plaintext` for `remote_address`; returns `{ type, body }`.
#[wasm_bindgen]
pub async fn encrypt(
    store: JsValue,
    remote_address: String,
    local_address: String,
    plaintext: Vec<u8>,
    now_ms: f64,
) -> std::result::Result<JsValue, JsValue> {
    let mut rng = OsRng.unwrap_err();
    let remote = parse_addr(&remote_address)?;
    let local = parse_addr(&local_address)?;
    let mut session = JsStore(store.clone());
    let mut ident = JsStore(store.clone());

    let msg = message_encrypt(&plaintext, &remote, &local, &mut session, &mut ident, now_from_ms(now_ms), &mut rng)
        .await
        .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;

    let ty = match msg.message_type() {
        CiphertextMessageType::PreKey => "prekey",
        CiphertextMessageType::Whisper => "whisper",
        CiphertextMessageType::SenderKey => "senderkey",
        CiphertextMessageType::Plaintext => "plaintext",
    };
    let out = js_sys::Object::new();
    Reflect::set(&out, &JsValue::from_str("type"), &JsValue::from_str(ty))?;
    Reflect::set(&out, &JsValue::from_str("body"), &bytes_arg(msg.serialize()))?;
    Ok(out.into())
}

/// Decrypt a peer's ciphertext (`type` = "prekey" | "whisper"); returns plaintext.
#[wasm_bindgen]
pub async fn decrypt(
    store: JsValue,
    remote_address: String,
    local_address: String,
    msg_type: String,
    body: Vec<u8>,
    _now_ms: f64,
) -> std::result::Result<Vec<u8>, JsValue> {
    let mut rng = OsRng.unwrap_err();
    let remote = parse_addr(&remote_address)?;
    let local = parse_addr(&local_address)?;

    let ciphertext = match msg_type.as_str() {
        "prekey" => CiphertextMessage::PreKeySignalMessage(
            PreKeySignalMessage::try_from(body.as_slice()).map_err(|e| JsValue::from_str(&format!("{e:?}")))?,
        ),
        "whisper" => CiphertextMessage::SignalMessage(
            SignalMessage::try_from(body.as_slice()).map_err(|e| JsValue::from_str(&format!("{e:?}")))?,
        ),
        other => return Err(JsValue::from_str(&format!("unsupported message type: {other}"))),
    };

    let mut session = JsStore(store.clone());
    let mut ident = JsStore(store.clone());
    let mut pk = JsStore(store.clone());
    let spk = JsStore(store.clone());
    let mut kpk = JsStore(store.clone());

    let plaintext = message_decrypt(
        &ciphertext, &remote, &local, &mut session, &mut ident, &mut pk, &spk, &mut kpk, &mut rng,
    )
    .await
    .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    Ok(plaintext)
}

// ─────────────────────── recovery-key backup (Phase 5) ───────────────────────

/// Generate a Signal Account Entropy Pool — the 64-char `[a-z0-9]` recovery key
/// that roots the content backup. High-entropy (~330 bits); the user saves it and
/// it never leaves the client. Same format Signal uses for Secure Backups.
#[wasm_bindgen]
pub fn generate_account_entropy_pool() -> String {
    let mut rng = OsRng.unwrap_err();
    libsignal_account_keys::AccountEntropyPool::generate(&mut rng).to_string()
}

/// Derive the AES-256 + HMAC-SHA256 keys for the content backup from the recovery
/// key. Root step is Signal's own `BackupKey::derive_from_account_entropy_pool`
/// (HKDF, domain "20240801_SIGNAL_BACKUP_KEY"); we then expand to a 32-byte AES key
/// + 32-byte HMAC key with a per-backup `token` as HKDF salt (forward secrecy: a
/// fresh token per backup ⇒ fresh keys) under an app-specific info string. Returns
/// `{ aesKey, hmacKey }`; the JS layer does AES-256-CBC + HMAC (encrypt-then-MAC).
#[wasm_bindgen]
pub fn derive_backup_keys(
    account_entropy_pool: String,
    token: Vec<u8>,
) -> std::result::Result<JsValue, JsValue> {
    use std::str::FromStr;
    let pool = libsignal_account_keys::AccountEntropyPool::from_str(&account_entropy_pool)
        .map_err(|e| JsValue::from_str(&format!("invalid recovery key: {e}")))?;
    let backup_key =
        libsignal_account_keys::BackupKey::derive_from_account_entropy_pool(&pool);

    let mut okm = [0u8; 64];
    hkdf::Hkdf::<sha2::Sha256>::new(Some(&token), &backup_key.0)
        .expand(b"20260723_CYBERTOBO_PM_BACKUP_AES_HMAC", &mut okm)
        .map_err(|_| JsValue::from_str("hkdf expand failed"))?;

    let out = js_sys::Object::new();
    Reflect::set(&out, &JsValue::from_str("hmacKey"), &bytes_arg(&okm[0..32]))?;
    Reflect::set(&out, &JsValue::from_str("aesKey"), &bytes_arg(&okm[32..64]))?;
    Ok(out.into())
}

/// Iteration count for the numeric fingerprint (Signal's standard value).
const FINGERPRINT_ITERATIONS: u32 = 5200;
/// Fingerprint version — 2 is the post-quantum-era scannable format (the display
/// numeric string is identical across versions).
const FINGERPRINT_VERSION: u32 = 2;

/// Compute the Signal safety number for a conversation. `local_id`/`remote_id` are
/// the stable per-party identifiers (we use the app userIds); the local identity
/// key is read from the store, the remote identity key is passed in (the caller has
/// it from the established session / TOFU store). Returns
/// `{ displayText, scannable }` where `displayText` is the 60-digit safety number
/// (order-independent between the two parties) and `scannable` is the QR-code
/// protobuf bytes. Pure/stateless beyond the one identity-key read — no clock.
#[wasm_bindgen]
pub async fn fingerprint(
    store: JsValue,
    local_id: String,
    remote_id: String,
    remote_identity_key: Vec<u8>,
) -> std::result::Result<JsValue, JsValue> {
    let ident = JsStore(store.clone());
    let idkp = ident
        .get_identity_key_pair()
        .await
        .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    let local_key = idkp.identity_key();
    let remote_key = IdentityKey::decode(&remote_identity_key)
        .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;

    let fp = Fingerprint::new(
        FINGERPRINT_VERSION,
        FINGERPRINT_ITERATIONS,
        local_id.as_bytes(),
        local_key,
        remote_id.as_bytes(),
        &remote_key,
    )
    .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;

    let display = fp
        .display_string()
        .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    let scannable = fp
        .scannable
        .serialize()
        .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;

    let out = js_sys::Object::new();
    Reflect::set(&out, &JsValue::from_str("displayText"), &JsValue::from_str(&display))?;
    Reflect::set(&out, &JsValue::from_str("scannable"), &bytes_arg(&scannable))?;
    Ok(out.into())
}

// ─────────────────────────── groups (SenderKey) ───────────────────────────
//
// Signal's group messaging: instead of pairwise-encrypting each message to every
// recipient device, a sender distributes a SenderKey ONCE (over the existing 1:1
// Signal sessions) and then encrypts each group message a single time with that
// SenderKey. `distribution_id` is the group's stable UUID; `sender_address` is the
// sender's `userId.deviceId`. Sender-key state persists via the JsStore
// SenderKeyStore impl (IndexedDB `senderkeys` object store).

/// Create (and persist on first use) this device's SenderKey distribution message
/// for `distribution_id`. The returned serialized bytes are delivered to each
/// group member over a 1:1 Signal session so they can decrypt this sender's group
/// messages.
#[wasm_bindgen]
pub async fn sender_key_distribution_message(
    store: JsValue,
    sender_address: String,
    distribution_id: String,
) -> std::result::Result<Vec<u8>, JsValue> {
    let mut rng = OsRng.unwrap_err();
    let sender = parse_addr(&sender_address)?;
    let did = Uuid::parse_str(&distribution_id)
        .map_err(|e| JsValue::from_str(&format!("bad distribution_id: {e}")))?;
    let mut skstore = JsStore(store.clone());
    let skdm = create_sender_key_distribution_message(&sender, did, &mut skstore, &mut rng)
        .await
        .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    Ok(skdm.serialized().to_vec())
}

/// Process a peer's SenderKey distribution message (received over a 1:1 session),
/// persisting their SenderKey chain so their group messages decrypt.
#[wasm_bindgen]
pub async fn process_sender_key_distribution(
    store: JsValue,
    sender_address: String,
    skdm_bytes: Vec<u8>,
) -> std::result::Result<(), JsValue> {
    let sender = parse_addr(&sender_address)?;
    let skdm = SenderKeyDistributionMessage::try_from(skdm_bytes.as_slice())
        .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    let mut skstore = JsStore(store.clone());
    process_sender_key_distribution_message(&sender, &skdm, &mut skstore)
        .await
        .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    Ok(())
}

/// Encrypt a group message ONCE with this sender's SenderKey. The same serialized
/// SenderKeyMessage is delivered to every group member.
#[wasm_bindgen]
pub async fn group_encrypt_message(
    store: JsValue,
    sender_address: String,
    distribution_id: String,
    plaintext: Vec<u8>,
) -> std::result::Result<Vec<u8>, JsValue> {
    let mut rng = OsRng.unwrap_err();
    let sender = parse_addr(&sender_address)?;
    let did = Uuid::parse_str(&distribution_id)
        .map_err(|e| JsValue::from_str(&format!("bad distribution_id: {e}")))?;
    let mut skstore = JsStore(store.clone());
    let skm = group_encrypt(&mut skstore, &sender, did, &plaintext, &mut rng)
        .await
        .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    Ok(skm.serialized().to_vec())
}

/// Decrypt a group SenderKeyMessage from `sender_address`. Requires this sender's
/// distribution message to have been processed first.
#[wasm_bindgen]
pub async fn group_decrypt_message(
    store: JsValue,
    sender_address: String,
    skm_bytes: Vec<u8>,
) -> std::result::Result<Vec<u8>, JsValue> {
    let sender = parse_addr(&sender_address)?;
    let mut skstore = JsStore(store.clone());
    let plaintext = group_decrypt(&skm_bytes, &mut skstore, &sender)
        .await
        .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    Ok(plaintext)
}

// ─────────────────────────── sealed sender ───────────────────────────
//
// Sealed sender hides the sender's identity from the relay. The server acts as a
// certificate authority: a long-lived ROOT keypair (trust root, published to
// clients) signs a SERVER certificate whose key signs per-user SENDER
// certificates binding (userId, deviceId, identity key, expiry). A sender wraps
// their message in an UnidentifiedSenderMessageContent (carrying their cert) and
// encrypts it to the recipient's identity key with an ephemeral key — the wire
// carries no sender id. The recipient validates the cert against the pinned trust
// root and recovers the real sender. The CA fns (generate_root / create_server_cert
// / create_sender_cert) are pure and run SERVER-SIDE (wasm-in-Node); the
// encrypt/decrypt fns run on the client with the JS store.

/// Generate the sealed-sender trust-root keypair. `{ rootPrivate, rootPublic }`.
/// Run ONCE, server-side; the public half is pinned by clients.
#[wasm_bindgen]
pub fn sealed_sender_generate_root() -> std::result::Result<JsValue, JsValue> {
    let mut rng = OsRng.unwrap_err();
    let kp = KeyPair::generate(&mut rng);
    let out = js_sys::Object::new();
    Reflect::set(&out, &JsValue::from_str("rootPrivate"), &bytes_arg(&kp.private_key.serialize()))?;
    Reflect::set(&out, &JsValue::from_str("rootPublic"), &bytes_arg(&kp.public_key.serialize()))?;
    Ok(out.into())
}

/// Create the server certificate (a server signing keypair certified by the root).
/// `{ serverCert, serverPrivate }`. Run ONCE, server-side.
#[wasm_bindgen]
pub fn sealed_sender_create_server_cert(
    root_private: Vec<u8>,
    key_id: u32,
) -> std::result::Result<JsValue, JsValue> {
    let mut rng = OsRng.unwrap_err();
    let root_priv =
        PrivateKey::deserialize(&root_private).map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    let server_kp = KeyPair::generate(&mut rng);
    let server_cert = ServerCertificate::new(key_id, server_kp.public_key, &root_priv, &mut rng)
        .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    let out = js_sys::Object::new();
    Reflect::set(
        &out,
        &JsValue::from_str("serverCert"),
        &bytes_arg(server_cert.serialized().map_err(|e| JsValue::from_str(&format!("{e:?}")))?),
    )?;
    Reflect::set(&out, &JsValue::from_str("serverPrivate"), &bytes_arg(&server_kp.private_key.serialize()))?;
    Ok(out.into())
}

/// Mint a sender certificate binding (senderUuid, deviceId, identity key) with an
/// expiry, signed by the server cert's key. Run server-side per request.
#[wasm_bindgen]
pub fn sealed_sender_create_sender_cert(
    server_cert_bytes: Vec<u8>,
    server_private: Vec<u8>,
    sender_uuid: String,
    sender_device_id: u32,
    sender_identity_key: Vec<u8>,
    expiry_ms: f64,
) -> std::result::Result<Vec<u8>, JsValue> {
    let mut rng = OsRng.unwrap_err();
    let server_cert = ServerCertificate::deserialize(&server_cert_bytes)
        .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    let signer_key =
        PrivateKey::deserialize(&server_private).map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    let identity = PublicKey::deserialize(&sender_identity_key)
        .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    let device =
        DeviceId::new(sender_device_id as u8).map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    let cert = SenderCertificate::new(
        sender_uuid,
        None,
        identity,
        device,
        Timestamp::from_epoch_millis(expiry_ms as u64),
        server_cert,
        &signer_key,
        &mut rng,
    )
    .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    Ok(cert.serialized().map_err(|e| JsValue::from_str(&format!("{e:?}")))?.to_vec())
}

/// Sealed-sender encrypt `plaintext` for `destination_address` (`userId.deviceId`),
/// carrying the caller's `sender_cert`. Returns the opaque sealed-sender envelope
/// (no sender id on the wire).
#[wasm_bindgen]
pub async fn sealed_sender_encrypt_message(
    store: JsValue,
    destination_address: String,
    sender_cert_bytes: Vec<u8>,
    plaintext: Vec<u8>,
    now_ms: f64,
) -> std::result::Result<Vec<u8>, JsValue> {
    let mut rng = OsRng.unwrap_err();
    let dest = parse_addr(&destination_address)?;
    let cert = SenderCertificate::deserialize(&sender_cert_bytes)
        .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    let mut session = JsStore(store.clone());
    let mut ident = JsStore(store.clone());
    let out = sealed_sender_encrypt(
        &dest,
        &cert,
        &plaintext,
        &mut session,
        &mut ident,
        now_from_ms(now_ms),
        &mut rng,
    )
    .await
    .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    Ok(out)
}

/// Sealed-sender decrypt: validate the embedded sender cert against `trust_root`,
/// then decrypt the inner message. Returns `{ senderUuid, senderDeviceId, message }`.
#[wasm_bindgen]
pub async fn sealed_sender_decrypt_message(
    store: JsValue,
    trust_root: Vec<u8>,
    timestamp_ms: f64,
    local_uuid: String,
    local_device_id: u32,
    ciphertext: Vec<u8>,
) -> std::result::Result<JsValue, JsValue> {
    let root =
        PublicKey::deserialize(&trust_root).map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    let device =
        DeviceId::new(local_device_id as u8).map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    let mut ident = JsStore(store.clone());
    let mut session = JsStore(store.clone());
    let mut pk = JsStore(store.clone());
    let spk = JsStore(store.clone());
    let mut kpk = JsStore(store.clone());
    let res = sealed_sender_decrypt(
        &ciphertext,
        &root,
        Timestamp::from_epoch_millis(timestamp_ms as u64),
        None,
        local_uuid,
        device,
        &mut ident,
        &mut session,
        &mut pk,
        &spk,
        &mut kpk,
    )
    .await
    .map_err(|e| JsValue::from_str(&format!("{e:?}")))?;
    let out = js_sys::Object::new();
    Reflect::set(&out, &JsValue::from_str("senderUuid"), &JsValue::from_str(&res.sender_uuid))?;
    Reflect::set(&out, &JsValue::from_str("senderDeviceId"), &num_arg(u32::from(res.device_id)))?;
    Reflect::set(&out, &JsValue::from_str("message"), &bytes_arg(&res.message))?;
    Ok(out.into())
}
