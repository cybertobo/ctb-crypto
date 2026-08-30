/* @ts-self-types="./signal-engine.d.ts" */

/**
 * Decrypt a peer's ciphertext (`type` = "prekey" | "whisper"); returns plaintext.
 * @param {any} store
 * @param {string} remote_address
 * @param {string} local_address
 * @param {string} msg_type
 * @param {Uint8Array} body
 * @param {number} _now_ms
 * @returns {Promise<Uint8Array>}
 */
export function decrypt(store, remote_address, local_address, msg_type, body, _now_ms) {
    const ptr0 = passStringToWasm0(remote_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(local_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(msg_type, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(body, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.decrypt(store, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, _now_ms);
    return ret;
}

/**
 * Derive the AES-256 + HMAC-SHA256 keys for the content backup from the recovery
 * key. Root step is Signal's own `BackupKey::derive_from_account_entropy_pool`
 * (HKDF, domain "20240801_SIGNAL_BACKUP_KEY"); we then expand to a 32-byte AES key
 * + 32-byte HMAC key with a per-backup `token` as HKDF salt (forward secrecy: a
 * fresh token per backup ⇒ fresh keys) under an app-specific info string. Returns
 * `{ aesKey, hmacKey }`; the JS layer does AES-256-CBC + HMAC (encrypt-then-MAC).
 * @param {string} account_entropy_pool
 * @param {Uint8Array} token
 * @returns {any}
 */
export function derive_backup_keys(account_entropy_pool, token) {
    const ptr0 = passStringToWasm0(account_entropy_pool, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(token, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.derive_backup_keys(ptr0, len0, ptr1, len1);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * Encrypt `plaintext` for `remote_address`; returns `{ type, body }`.
 * @param {any} store
 * @param {string} remote_address
 * @param {string} local_address
 * @param {Uint8Array} plaintext
 * @param {number} now_ms
 * @returns {Promise<any>}
 */
export function encrypt(store, remote_address, local_address, plaintext, now_ms) {
    const ptr0 = passStringToWasm0(remote_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(local_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.encrypt(store, ptr0, len0, ptr1, len1, ptr2, len2, now_ms);
    return ret;
}

/**
 * Compute the Signal safety number for a conversation. `local_id`/`remote_id` are
 * the stable per-party identifiers (we use the app userIds); the local identity
 * key is read from the store, the remote identity key is passed in (the caller has
 * it from the established session / TOFU store). Returns
 * `{ displayText, scannable }` where `displayText` is the 60-digit safety number
 * (order-independent between the two parties) and `scannable` is the QR-code
 * protobuf bytes. Pure/stateless beyond the one identity-key read — no clock.
 * @param {any} store
 * @param {string} local_id
 * @param {string} remote_id
 * @param {Uint8Array} remote_identity_key
 * @returns {Promise<any>}
 */
export function fingerprint(store, local_id, remote_id, remote_identity_key) {
    const ptr0 = passStringToWasm0(local_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(remote_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(remote_identity_key, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.fingerprint(store, ptr0, len0, ptr1, len1, ptr2, len2);
    return ret;
}

/**
 * Generate a Signal Account Entropy Pool — the 64-char `[a-z0-9]` recovery key
 * that roots the content backup. High-entropy (~330 bits); the user saves it and
 * it never leaves the client. Same format Signal uses for Secure Backups.
 * @returns {string}
 */
export function generate_account_entropy_pool() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.generate_account_entropy_pool();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * Generate + persist a signed prekey, a Kyber prekey, and `count` one-time prekeys.
 * Returns the publishable bundle material (public keys + signatures + ids).
 * @param {any} store
 * @param {number} signed_prekey_id
 * @param {number} kyber_prekey_id
 * @param {number} prekey_start_id
 * @param {number} count
 * @param {number} now_ms
 * @returns {Promise<any>}
 */
export function generate_prekeys(store, signed_prekey_id, kyber_prekey_id, prekey_start_id, count, now_ms) {
    const ret = wasm.generate_prekeys(store, signed_prekey_id, kyber_prekey_id, prekey_start_id, count, now_ms);
    return ret;
}

/**
 * Generate + persist this device's identity + registration id; return public info.
 * @param {any} store
 * @returns {Promise<any>}
 */
export function generate_registration(store) {
    const ret = wasm.generate_registration(store);
    return ret;
}

/**
 * Decrypt a group SenderKeyMessage from `sender_address`. Requires this sender's
 * distribution message to have been processed first.
 * @param {any} store
 * @param {string} sender_address
 * @param {Uint8Array} skm_bytes
 * @returns {Promise<Uint8Array>}
 */
export function group_decrypt_message(store, sender_address, skm_bytes) {
    const ptr0 = passStringToWasm0(sender_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(skm_bytes, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.group_decrypt_message(store, ptr0, len0, ptr1, len1);
    return ret;
}

/**
 * Encrypt a group message ONCE with this sender's SenderKey. The same serialized
 * SenderKeyMessage is delivered to every group member.
 * @param {any} store
 * @param {string} sender_address
 * @param {string} distribution_id
 * @param {Uint8Array} plaintext
 * @returns {Promise<Uint8Array>}
 */
export function group_encrypt_message(store, sender_address, distribution_id, plaintext) {
    const ptr0 = passStringToWasm0(sender_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(distribution_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.group_encrypt_message(store, ptr0, len0, ptr1, len1, ptr2, len2);
    return ret;
}

/**
 * @returns {number}
 */
export function ping() {
    const ret = wasm.ping();
    return ret >>> 0;
}

/**
 * Establish an outbound session from a peer's fetched prekey bundle.
 * `bundle` is a JS object with Uint8Array key fields + numeric ids.
 * @param {any} store
 * @param {string} remote_address
 * @param {any} bundle
 * @param {number} now_ms
 * @returns {Promise<void>}
 */
export function process_peer_bundle(store, remote_address, bundle, now_ms) {
    const ptr0 = passStringToWasm0(remote_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.process_peer_bundle(store, ptr0, len0, bundle, now_ms);
    return ret;
}

/**
 * Process a peer's SenderKey distribution message (received over a 1:1 session),
 * persisting their SenderKey chain so their group messages decrypt.
 * @param {any} store
 * @param {string} sender_address
 * @param {Uint8Array} skdm_bytes
 * @returns {Promise<void>}
 */
export function process_sender_key_distribution(store, sender_address, skdm_bytes) {
    const ptr0 = passStringToWasm0(sender_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(skdm_bytes, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.process_sender_key_distribution(store, ptr0, len0, ptr1, len1);
    return ret;
}

/**
 * Mint a sender certificate binding (senderUuid, deviceId, identity key) with an
 * expiry, signed by the server cert's key. Run server-side per request.
 * @param {Uint8Array} server_cert_bytes
 * @param {Uint8Array} server_private
 * @param {string} sender_uuid
 * @param {number} sender_device_id
 * @param {Uint8Array} sender_identity_key
 * @param {number} expiry_ms
 * @returns {Uint8Array}
 */
export function sealed_sender_create_sender_cert(server_cert_bytes, server_private, sender_uuid, sender_device_id, sender_identity_key, expiry_ms) {
    const ptr0 = passArray8ToWasm0(server_cert_bytes, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(server_private, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(sender_uuid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(sender_identity_key, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.sealed_sender_create_sender_cert(ptr0, len0, ptr1, len1, ptr2, len2, sender_device_id, ptr3, len3, expiry_ms);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v5 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v5;
}

/**
 * Create the server certificate (a server signing keypair certified by the root).
 * `{ serverCert, serverPrivate }`. Run ONCE, server-side.
 * @param {Uint8Array} root_private
 * @param {number} key_id
 * @returns {any}
 */
export function sealed_sender_create_server_cert(root_private, key_id) {
    const ptr0 = passArray8ToWasm0(root_private, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.sealed_sender_create_server_cert(ptr0, len0, key_id);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * Sealed-sender decrypt: validate the embedded sender cert against `trust_root`,
 * then decrypt the inner message. Returns `{ senderUuid, senderDeviceId, message }`.
 * @param {any} store
 * @param {Uint8Array} trust_root
 * @param {number} timestamp_ms
 * @param {string} local_uuid
 * @param {number} local_device_id
 * @param {Uint8Array} ciphertext
 * @returns {Promise<any>}
 */
export function sealed_sender_decrypt_message(store, trust_root, timestamp_ms, local_uuid, local_device_id, ciphertext) {
    const ptr0 = passArray8ToWasm0(trust_root, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(local_uuid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.sealed_sender_decrypt_message(store, ptr0, len0, timestamp_ms, ptr1, len1, local_device_id, ptr2, len2);
    return ret;
}

/**
 * Sealed-sender encrypt `plaintext` for `destination_address` (`userId.deviceId`),
 * carrying the caller's `sender_cert`. Returns the opaque sealed-sender envelope
 * (no sender id on the wire).
 * @param {any} store
 * @param {string} destination_address
 * @param {Uint8Array} sender_cert_bytes
 * @param {Uint8Array} plaintext
 * @param {number} now_ms
 * @returns {Promise<Uint8Array>}
 */
export function sealed_sender_encrypt_message(store, destination_address, sender_cert_bytes, plaintext, now_ms) {
    const ptr0 = passStringToWasm0(destination_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(sender_cert_bytes, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.sealed_sender_encrypt_message(store, ptr0, len0, ptr1, len1, ptr2, len2, now_ms);
    return ret;
}

/**
 * Generate the sealed-sender trust-root keypair. `{ rootPrivate, rootPublic }`.
 * Run ONCE, server-side; the public half is pinned by clients.
 * @returns {any}
 */
export function sealed_sender_generate_root() {
    const ret = wasm.sealed_sender_generate_root();
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return takeFromExternrefTable0(ret[0]);
}

/**
 * @returns {string}
 */
export function self_test() {
    let deferred2_0;
    let deferred2_1;
    try {
        const ret = wasm.self_test();
        var ptr1 = ret[0];
        var len1 = ret[1];
        if (ret[3]) {
            ptr1 = 0; len1 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred2_0 = ptr1;
        deferred2_1 = len1;
        return getStringFromWasm0(ptr1, len1);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Create (and persist on first use) this device's SenderKey distribution message
 * for `distribution_id`. The returned serialized bytes are delivered to each
 * group member over a 1:1 Signal session so they can decrypt this sender's group
 * messages.
 * @param {any} store
 * @param {string} sender_address
 * @param {string} distribution_id
 * @returns {Promise<Uint8Array>}
 */
export function sender_key_distribution_message(store, sender_address, distribution_id) {
    const ptr0 = passStringToWasm0(sender_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(distribution_id, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.sender_key_distribution_message(store, ptr0, len0, ptr1, len1);
    return ret;
}
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg___wbindgen_boolean_get_fa956cfa2d1bd751: function(arg0) {
            const v = arg0;
            const ret = typeof(v) === 'boolean' ? v : undefined;
            return isLikeNone(ret) ? 0xFFFFFF : ret ? 1 : 0;
        },
        __wbg___wbindgen_debug_string_c25d447a39f5578f: function(arg0, arg1) {
            const ret = debugString(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_is_function_1ff95bcc5517c252: function(arg0) {
            const ret = typeof(arg0) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_null_ea9085d691f535d3: function(arg0) {
            const ret = arg0 === null;
            return ret;
        },
        __wbg___wbindgen_is_undefined_c05833b95a3cf397: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
        __wbg___wbindgen_number_get_394265ed1e1b84ee: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'number' ? obj : undefined;
            getDataViewMemory0().setFloat64(arg0 + 8 * 1, isLikeNone(ret) ? 0 : ret, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, !isLikeNone(ret), true);
        },
        __wbg___wbindgen_throw_344f42d3211c4765: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg__wbg_cb_unref_fffb441def202758: function(arg0) {
            arg0._wbg_cb_unref();
        },
        __wbg_apply_23dd4d2439189415: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = Reflect.apply(arg0, arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_call_a6e5c5dce5018821: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.call(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_getRandomValues_3f44b700395062e5: function() { return handleError(function (arg0, arg1) {
            globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
        }, arguments); },
        __wbg_get_78f252d074a84d0b: function() { return handleError(function (arg0, arg1) {
            const ret = Reflect.get(arg0, arg1);
            return ret;
        }, arguments); },
        __wbg_instanceof_Promise_4cb210c0b8f8c959: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Promise;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_instanceof_Uint8Array_309b927aaf7a3fc7: function(arg0) {
            let result;
            try {
                result = arg0 instanceof Uint8Array;
            } catch (_) {
                result = false;
            }
            const ret = result;
            return ret;
        },
        __wbg_length_1f0964f4a5e2c6d8: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_new_32b398fb48b6d94a: function() {
            const ret = new Array();
            return ret;
        },
        __wbg_new_da52cf8fe3429cb2: function() {
            const ret = new Object();
            return ret;
        },
        __wbg_new_from_slice_77cdfb7977362f3c: function(arg0, arg1) {
            const ret = new Uint8Array(getArrayU8FromWasm0(arg0, arg1));
            return ret;
        },
        __wbg_new_typed_1824d93f294193e5: function(arg0, arg1) {
            try {
                var state0 = {a: arg0, b: arg1};
                var cb0 = (arg0, arg1) => {
                    const a = state0.a;
                    state0.a = 0;
                    try {
                        return wasm_bindgen_c9f030a71d9e9078___convert__closures_____invoke___js_sys_8cf9b46d44b3f9cb___Function_fn_wasm_bindgen_c9f030a71d9e9078___JsValue_____wasm_bindgen_c9f030a71d9e9078___sys__Undefined___js_sys_8cf9b46d44b3f9cb___Function_fn_wasm_bindgen_c9f030a71d9e9078___JsValue_____wasm_bindgen_c9f030a71d9e9078___sys__Undefined_______true_(a, state0.b, arg0, arg1);
                    } finally {
                        state0.a = a;
                    }
                };
                const ret = new Promise(cb0);
                return ret;
            } finally {
                state0.a = 0;
            }
        },
        __wbg_prototypesetcall_4770620bbe4688a0: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        },
        __wbg_push_d2ae3af0c1217ae6: function(arg0, arg1) {
            const ret = arg0.push(arg1);
            return ret;
        },
        __wbg_queueMicrotask_0ab5b2d2393e99b9: function(arg0) {
            const ret = arg0.queueMicrotask;
            return ret;
        },
        __wbg_queueMicrotask_6a09b7bc46549209: function(arg0) {
            queueMicrotask(arg0);
        },
        __wbg_resolve_2191a4dfe481c25b: function(arg0) {
            const ret = Promise.resolve(arg0);
            return ret;
        },
        __wbg_set_8535240470bf2500: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = Reflect.set(arg0, arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_static_accessor_GLOBAL_4ef717fb391d88b7: function() {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_GLOBAL_THIS_8d1badc68b5a74f4: function() {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_SELF_146583524fe1469b: function() {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_WINDOW_f2829a2234d7819e: function() {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_then_16d107c451e9905d: function(arg0, arg1, arg2) {
            const ret = arg0.then(arg1, arg2);
            return ret;
        },
        __wbg_then_6ec10ae38b3e92f7: function(arg0, arg1) {
            const ret = arg0.then(arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [Externref], shim_idx: 371, ret: Result(Unit), inner_ret: Some(Result(Unit)) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen_c9f030a71d9e9078___convert__closures_____invoke___wasm_bindgen_c9f030a71d9e9078___JsValue__core_bc22e89e72665a89___result__Result_____wasm_bindgen_c9f030a71d9e9078___JsError___true_);
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0) {
            // Cast intrinsic for `F64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_cast_0000000000000003: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000004: function(arg0, arg1) {
            var v0 = getArrayU8FromWasm0(arg0, arg1).slice();
            wasm.__wbindgen_free(arg0, arg1 * 1, 1);
            // Cast intrinsic for `Vector(U8) -> Externref`.
            const ret = v0;
            return ret;
        },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./signal-engine_bg.js": import0,
    };
}

function wasm_bindgen_c9f030a71d9e9078___convert__closures_____invoke___wasm_bindgen_c9f030a71d9e9078___JsValue__core_bc22e89e72665a89___result__Result_____wasm_bindgen_c9f030a71d9e9078___JsError___true_(arg0, arg1, arg2) {
    const ret = wasm.wasm_bindgen_c9f030a71d9e9078___convert__closures_____invoke___wasm_bindgen_c9f030a71d9e9078___JsValue__core_bc22e89e72665a89___result__Result_____wasm_bindgen_c9f030a71d9e9078___JsError___true_(arg0, arg1, arg2);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

function wasm_bindgen_c9f030a71d9e9078___convert__closures_____invoke___js_sys_8cf9b46d44b3f9cb___Function_fn_wasm_bindgen_c9f030a71d9e9078___JsValue_____wasm_bindgen_c9f030a71d9e9078___sys__Undefined___js_sys_8cf9b46d44b3f9cb___Function_fn_wasm_bindgen_c9f030a71d9e9078___JsValue_____wasm_bindgen_c9f030a71d9e9078___sys__Undefined_______true_(arg0, arg1, arg2, arg3) {
    wasm.wasm_bindgen_c9f030a71d9e9078___convert__closures_____invoke___js_sys_8cf9b46d44b3f9cb___Function_fn_wasm_bindgen_c9f030a71d9e9078___JsValue_____wasm_bindgen_c9f030a71d9e9078___sys__Undefined___js_sys_8cf9b46d44b3f9cb___Function_fn_wasm_bindgen_c9f030a71d9e9078___JsValue_____wasm_bindgen_c9f030a71d9e9078___sys__Undefined_______true_(arg0, arg1, arg2, arg3);
}

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

const CLOSURE_DTORS = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(state => wasm.__wbindgen_destroy_closure(state.a, state.b));

function debugString(val) {
    // primitive types
    const type = typeof val;
    if (type == 'number' || type == 'boolean' || val == null) {
        return  `${val}`;
    }
    if (type == 'string') {
        return `"${val}"`;
    }
    if (type == 'symbol') {
        const description = val.description;
        if (description == null) {
            return 'Symbol';
        } else {
            return `Symbol(${description})`;
        }
    }
    if (type == 'function') {
        const name = val.name;
        if (typeof name == 'string' && name.length > 0) {
            return `Function(${name})`;
        } else {
            return 'Function';
        }
    }
    // objects
    if (Array.isArray(val)) {
        const length = val.length;
        let debug = '[';
        if (length > 0) {
            debug += debugString(val[0]);
        }
        for(let i = 1; i < length; i++) {
            debug += ', ' + debugString(val[i]);
        }
        debug += ']';
        return debug;
    }
    // Test for built-in
    const builtInMatches = /\[object ([^\]]+)\]/.exec(toString.call(val));
    let className;
    if (builtInMatches && builtInMatches.length > 1) {
        className = builtInMatches[1];
    } else {
        // Failed to match the standard '[object ClassName]'
        return toString.call(val);
    }
    if (className == 'Object') {
        // we're a user defined class or Object
        // JSON.stringify avoids problems with cycles, and is generally much
        // easier than looping through ownProperties of `val`.
        try {
            return 'Object(' + JSON.stringify(val) + ')';
        } catch (_) {
            return 'Object';
        }
    }
    // errors
    if (val instanceof Error) {
        return `${val.name}: ${val.message}\n${val.stack}`;
    }
    // TODO we could test for more things here, like `Set`s and `Map`s.
    return className;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    return decodeText(ptr >>> 0, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function makeMutClosure(arg0, arg1, f) {
    const state = { a: arg0, b: arg1, cnt: 1 };
    const real = (...args) => {

        // First up with a closure we increment the internal reference
        // count. This ensures that the Rust closure environment won't
        // be deallocated while we're invoking it.
        state.cnt++;
        const a = state.a;
        state.a = 0;
        try {
            return f(a, state.b, ...args);
        } finally {
            state.a = a;
            real._wbg_cb_unref();
        }
    };
    real._wbg_cb_unref = () => {
        if (--state.cnt === 0) {
            wasm.__wbindgen_destroy_closure(state.a, state.b);
            state.a = 0;
            CLOSURE_DTORS.unregister(state);
        }
    };
    CLOSURE_DTORS.register(real, state, state);
    return real;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasmInstance, wasm;
function __wbg_finalize_init(instance, module) {
    wasmInstance = instance;
    wasm = instance.exports;
    wasmModule = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    wasm.__wbindgen_start();
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = module.ok && expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        // Vendored for Cybertobo (Crypto P1): the .wasm ships as a static asset at
        // /pm/signal-engine_bg.wasm and the caller (loadSignalEngine) always passes an
        // explicit module_or_path. The original import.meta.url fallback is removed so
        // the bundler never tries to resolve a co-located wasm asset.
        throw new Error('signal-engine: module_or_path is required (pass the /pm/signal-engine_bg.wasm URL)');
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
