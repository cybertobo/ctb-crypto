# crypto/ — Cybertobo Signal wasm engine (Crypto P1)

Builds the **official** `libsignal-protocol` crate to WebAssembly for the browser/PWA E2E messaging engine.
Same audited code as mobile's `@signalapp/libsignal-client` — see `docs/CRYPTO-E2E-SIGNAL.md` and
`docs/CRYPTO-P1-IMPLEMENTATION-PLAN.md`.

## Layout

- `signal-wasm/` — our wrapper crate **source** (`Cargo.toml`, `src/lib.rs`). Not built standalone.
- `build-signal-wasm.sh` — clones libsignal at the pinned tag, injects the wrapper as the workspace member
  `rust/bridge/wasm`, sets the getrandom wasm backend, runs `wasm-pack`. Output → `signal-wasm/pkg/`.
- `.github/workflows/signal-wasm.yml` — CI job that runs the build script and uploads the pkg artifact.

## Pinned version

`LIBSIGNAL_TAG=v0.101.2` (= npm `@signalapp/libsignal-client@0.101.2`), and v0.101.2 is also the tag the
**shipped** binary was built from. **Pin, don't float** — bump deliberately with Signal's security
releases (rationale in `docs/CRYPTO-E2E-SIGNAL.md` §6). Web and mobile must use the **same**
tag/version for wire compatibility.

### Bump log

| Date       | Tag       | Upstream contents                                                                                  | Impact on this engine                                                                                                             |
| ---------- | --------- | -------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| 2026-08-30 | `v0.101.2` | Rolls up v0.101.1: yanked-crate bump (chacha20 0.10.1 -> 0.10.2), `h2` update, aes-gcm-siv 0.12, ES2025 target, bridge macro removal (`jni_arg_type`/`jni_result_type`), gRPC proto sync, backup notification settings, SVR 2026Q3 enclave, `Backups.RedeemReceipt`. | **None functional.** No change to `rust/protocol` or `rust/crypto` wire, session, ratchet or cipher code; the touched crates are bridges, backups, net/attest and zkgroup, none of which this wrapper consumes. Required a build fix: libsignal now pulls getrandom 0.4, whose wasm backend is a crate feature rather than the `getrandom_backend` cfg that covers 0.3 — added as a third aliased dependency. Wasm 1 270 700 -> 1 265 445 bytes. Backup-derivation compat fixture re-verified (MAC + plaintext round-trip). |
| 2026-08-18 | `v0.101.0` | zkgroup: `GenericServerSecretParams`/`GenericServerPublicParams` reimplemented (no more `serde::Deserialize`, versioned call-link credentials); new `UnauthCallQualityService` and `AuthUsernamesService` typed APIs; JNI logging + bridge codegen changes. | **None functional.** `rust/protocol` and `rust/crypto` are untouched between the tags; the only change under `rust/core` is the two-line `version.rs` bump. Every other file is a Java/Node/Swift bridge, zkgroup, or a service this wrapper does not consume. No session, ratchet, cipher, or wire-format code changed. Wasm 1 270 715 → 1 270 700 bytes. Backup-derivation compat fixture re-verified (MAC + plaintext round-trip). |
| 2026-08-10 | `v0.100.0` | SPQR: `require_pq_ratio` removed from protocol + bridge — PQ is now required for every session; new `UnauthBackupsService.listBackupMedia`; zkgroup rejects invalid points as profile keys; bridge codegen cleanup. | **None functional.** In our dependency set only `rust/protocol` is touched, and only to delete the public helper `should_use_nonpq_session` and its re-export — this wrapper never called it, and no session/ratchet/cipher code or wire format changed. Wasm grew 1 270 606 → 1 270 715 bytes; glue byte-identical. Shipped 2026-08-10. |
| 2026-08-05 | `v0.99.4` | `LogSafeDisplay` for `socks::Protocol`; SVRB enclave rotation (2026Q1 → previous); TCB number enforced in the enclave identity; message-backup `blockedAtTimestamp` field; Java R8 keep-rule swap. | **None functional.** Every change lands in `rust/net`, `rust/attest`, `rust/message-backup` or the Java bridge. The only file touched under `rust/core` is `version.rs`; `libsignal-protocol` and `libsignal-account-keys` are untouched. Taken to keep web ≡ mobile on one tag. Shipped 2026-08-05. |
| 2026-08-01 | `v0.99.3` | zkgroup: `AuthCredentialWithPni` issuable without a PNI (derived "false PNI"); SVR: enforce TCB minimums on attestation. | **None functional.** Both land in `zkgroup` / `attest` — neither crate is in this wrapper's dependency set (`libsignal-protocol`, `libsignal-core`, `libsignal-account-keys`, `hkdf`, `uuid`). Pinned and CI-verified but never vendored; superseded by v0.99.4. |
| 2026-07-31 | `v0.99.2` | (previous shipped build)                                                                             | —                                                                                                                                   |

> A pin bump only changes the **recipe**. The vendored artifacts (`packages/ctb-crypto/src/engine/*`,
> `public/pm/signal-engine_bg.wasm`) are rebuilt by the `signal-wasm` CI job and re-vendored with
> `node packages/ctb-crypto/wasm/vendor-signal-wasm.mjs <artifactDir> --tag vX.Y.Z`. Until that runs, the
> shipped binary is still the previous tag's build — a green CI run is not "shipped".
>
> **This is enforced, not just documented.** `wasm/shipped.json` records the tag, byte size and sha256 of
> the binary users actually load; only the vendor script writes it. `npm run test:kernel` fails if that
> manifest disagrees with `LIBSIGNAL_TAG`, with the bytes in `public/pm/`, or with `NOTICE`. It caught
> nothing for two bumps because it did not exist — v0.99.3 and v0.99.4 were both recorded as done while
> production still served v0.99.2. Never hand-edit `shipped.json` to silence the gate; vendor a real
> artifact instead.

> **Mandatory gate on every bump:** `npx tsx --env-file=.env scripts/_pm-compat.ts verify` must PASS. It
> re-derives the frozen backup-key vector (`scripts/fixtures/pm-backup-compat.json`); a changed key
> hierarchy would silently orphan every existing content backup. Never regenerate that fixture to make
> it pass.

### Shipping a bump

v0.101.2 was vendored from run `33291734340` on 2026-08-30 — wasm 1 270 700 → 1 265 445 bytes.
Both gates re-run green against the vendored bytes: the backup-derivation compat fixture, and the
browser E2E (decrypt, sealed wire, reactions, multi-device fan-out, own-device sync, device revoke,
recovery-key backup/restore).

```bash
gh run list --workflow "Build Signal wasm engine" --limit 1   # take the run id
gh run download <runId> -n cybertobo-signal-wasm -D /tmp/sigwasm
CI_RUN_ID=<runId> node packages/ctb-crypto/wasm/vendor-signal-wasm.mjs /tmp/sigwasm --tag vX.Y.Z
# ^ --tag is required; it rewrites wasm/shipped.json from the bytes just vendored
npx tsx --env-file=.env scripts/_pm-compat.ts verify   # must PASS — never regenerate the fixture
# needs a built server already running on :3000; --conditions react-server resolves the
# `server-only` marker to its empty stub the way Next does (the driver reaches it through
# the login -> 2FA-email import chain and throws without it)
npx tsx --conditions react-server --env-file=.env scripts/_pm-e2e.ts   # old sessions/backups must still decrypt
npm run test:kernel                                    # signal-shipped: manifest == disk == pin == NOTICE
git add packages/ctb-crypto/src/engine packages/ctb-crypto/wasm/shipped.json public/pm/signal-engine_bg.wasm && git commit
```

Then set the `NOTICE` shipped-tag line to the tag the vendored binary was built from — `test:kernel`
fails until it matches, so the three records cannot drift apart silently.

## Build locally (Linux; needs rustup + wasm32 target + wasm-pack + protoc)

```bash
bash crypto/build-signal-wasm.sh          # --release into crypto/signal-wasm/pkg
BUILD_MODE=--dev bash crypto/build-signal-wasm.sh   # faster dev build
```

Do NOT build on Windows (rustup GNU toolchain is flaky, no MSVC linker) or on the prod box long-term —
this is a CI job. `signal-wasm/pkg/` is a build artifact (gitignored); the app consumes the CI-built package.

## Status

Phase 0 wrapper exposes `ping()` + `self_test()` (pipeline/functionality proof). Phase 1 replaces it with
the real `CryptoEngine` surface (registration, prekeys, processPreKeyBundle, encrypt, decrypt, fingerprint;
all clock-taking fns take `now_ms` — `SystemTime::now()` panics on wasm).
