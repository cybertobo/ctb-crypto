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

`LIBSIGNAL_TAG=v0.99.4` (= npm `@signalapp/libsignal-client@0.99.4`), and v0.99.4 is also the tag the
**shipped** binary was built from. **Pin, don't float** — bump deliberately with Signal's security
releases (rationale in `docs/CRYPTO-E2E-SIGNAL.md` §6). Web and mobile must use the **same**
tag/version for wire compatibility.

### Bump log

| Date       | Tag       | Upstream contents                                                                                  | Impact on this engine                                                                                                             |
| ---------- | --------- | -------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| 2026-08-05 | `v0.99.4` | `LogSafeDisplay` for `socks::Protocol`; SVRB enclave rotation (2026Q1 → previous); TCB number enforced in the enclave identity; message-backup `blockedAtTimestamp` field; Java R8 keep-rule swap. | **None functional.** Every change lands in `rust/net`, `rust/attest`, `rust/message-backup` or the Java bridge. The only file touched under `rust/core` is `version.rs`; `libsignal-protocol` and `libsignal-account-keys` are untouched. Taken to keep web ≡ mobile on one tag. Shipped 2026-08-05. |
| 2026-08-01 | `v0.99.3` | zkgroup: `AuthCredentialWithPni` issuable without a PNI (derived "false PNI"); SVR: enforce TCB minimums on attestation. | **None functional.** Both land in `zkgroup` / `attest` — neither crate is in this wrapper's dependency set (`libsignal-protocol`, `libsignal-core`, `libsignal-account-keys`, `hkdf`, `uuid`). Pinned and CI-verified but never vendored; superseded by v0.99.4. |
| 2026-07-31 | `v0.99.2` | (previous shipped build)                                                                             | —                                                                                                                                   |

> A pin bump only changes the **recipe**. The vendored artifacts (`packages/ctb-crypto/src/engine/*`,
> `public/pm/signal-engine_bg.wasm`) are rebuilt by the `signal-wasm` CI job and re-vendored with
> `node packages/ctb-crypto/wasm/vendor-signal-wasm.mjs <artifactDir>`. Until that runs, the shipped
> binary is still the previous tag's build — a green CI run is not "shipped".
>
> **Mandatory gate on every bump:** `npx tsx --env-file=.env scripts/_pm-compat.ts verify` must PASS. It
> re-derives the frozen backup-key vector (`scripts/fixtures/pm-backup-compat.json`); a changed key
> hierarchy would silently orphan every existing content backup. Never regenerate that fixture to make
> it pass.

### Shipping a bump

v0.99.4 was vendored from
[run 30957447218](https://github.com/cybertobo/ctb-forums/actions/runs/30957447218) on 2026-08-05 —
wasm 1 270 707 → 1 270 606 bytes, wasm-bindgen glue byte-identical (the exported API did not change).

```bash
gh run list --workflow "Build Signal wasm engine" --limit 1   # take the run id
gh run download <runId> -n cybertobo-signal-wasm -D /tmp/sigwasm
node packages/ctb-crypto/wasm/vendor-signal-wasm.mjs /tmp/sigwasm
npx tsx --env-file=.env scripts/_pm-compat.ts verify   # must PASS — never regenerate the fixture
npx tsx --env-file=.env scripts/_pm-e2e.ts             # old sessions/backups must still decrypt
git add packages/ctb-crypto/src/engine public/pm/signal-engine_bg.wasm && git commit
```

Then set the `NOTICE` shipped-tag line to the tag the vendored binary was built from.

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
