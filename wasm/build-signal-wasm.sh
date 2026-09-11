#!/usr/bin/env bash
#
# Builds the Cybertobo Signal wasm engine from a PINNED libsignal tag.
#
# Reproducible + no external repo/fork needed: clones signalapp/libsignal at the
# pinned tag, injects our wrapper crate (crypto/signal-wasm) as the workspace member
# rust/bridge/wasm so the workspace dependency set unifies (fixes the aes-gcm-siv
# version conflict), sets the getrandom wasm backend, and runs wasm-pack.
#
# Requirements (Linux/CI): rustup + target wasm32-unknown-unknown, wasm-pack, protoc.
# See docs/CRYPTO-P1-IMPLEMENTATION-PLAN.md (Phase 0). Do NOT run heavy builds on the
# prod box in the long run — this is a CI job.
#
# Env overrides: LIBSIGNAL_TAG, WORK, OUT, BUILD_MODE (--release|--dev), CARGO_BUILD_JOBS.
set -euo pipefail

LIBSIGNAL_TAG="${LIBSIGNAL_TAG:-v0.102.2}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WRAPPER="$HERE/signal-wasm"
WORK="${WORK:-/tmp/ctb-signal-wasm-build}"
OUT="${OUT:-$WRAPPER/pkg}"
BUILD_MODE="${BUILD_MODE:---release}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-6}"

echo "[build-signal-wasm] libsignal tag: $LIBSIGNAL_TAG"
rm -rf "$WORK"
git clone --depth 1 --branch "$LIBSIGNAL_TAG" https://github.com/signalapp/libsignal.git "$WORK"

# Inject our wrapper as a workspace member (non-persistent; only in this clone).
sed -i 's#^members = \[#members = [\n    "rust/bridge/wasm",#' "$WORK/Cargo.toml"
mkdir -p "$WORK/rust/bridge/wasm/src" "$WORK/.cargo"
cp "$WRAPPER/Cargo.toml" "$WORK/rust/bridge/wasm/Cargo.toml"
cp "$WRAPPER/src/lib.rs" "$WORK/rust/bridge/wasm/src/lib.rs"
cat > "$WORK/.cargo/config.toml" <<'EOF'
[target.wasm32-unknown-unknown]
rustflags = ["--cfg", "getrandom_backend=\"wasm_js\""]
EOF

cd "$WORK"
wasm-pack build rust/bridge/wasm $BUILD_MODE --target web --out-dir "$OUT" --out-name signal-engine

echo "[build-signal-wasm] OK -> $OUT (libsignal $LIBSIGNAL_TAG)"
ls -1 "$OUT"
