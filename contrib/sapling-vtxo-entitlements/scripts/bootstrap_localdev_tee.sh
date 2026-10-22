#!/usr/bin/env bash
# Reproducible public-source local-dev TEE bootstrap for disposable regtest.
# This signer is ephemeral and does not provide Nitro attestation.
set -euo pipefail
TEE_PIN=f083bdbd2343aad22fab861f1565c0f2c2e6b0af
SDK_PIN=b45e5ef7b9c151cfc18f0efd9f4fee9327e1a29d
ARK_PIN=758f7b730
WASM_SHA=0fbc4e2cc68722474e3a708ffb934c0784990806ea1fb4a3dda64805fdd340a1

if (( $# > 1 )) || { (( $# == 1 )) && [[ "$1" != "--build-only" ]]; }; then
    echo "Usage: bash bootstrap_localdev_tee.sh [--build-only]" >&2
    exit 2
fi
for binary in git nix sha256sum python3; do
    command -v "$binary" >/dev/null || {
        echo "Missing prerequisite: $binary" >&2
        exit 1
    }
done

CACHE="$HOME/.cache"
if [[ -v XDG_CACHE_HOME ]] && [[ -n "$XDG_CACHE_HOME" ]]; then
    CACHE="$XDG_CACHE_HOME"
fi
SOURCE="$CACHE/sapling-vtxo-audit/sapio_tee-$TEE_PIN"
if [[ -v SAPLING_TEE_SOURCE_DIR ]] && [[ -n "$SAPLING_TEE_SOURCE_DIR" ]]; then
    SOURCE="$SAPLING_TEE_SOURCE_DIR"
fi
mkdir -p "$(dirname "$SOURCE")"
SOURCE="$(cd "$(dirname "$SOURCE")" && pwd)/$(basename "$SOURCE")"
if [[ ! -e "$SOURCE" ]]; then
    git clone --filter=blob:none https://github.com/stutxo/sapio_tee.git "$SOURCE"
    git -C "$SOURCE" fetch --no-tags origin "$TEE_PIN"
    git -C "$SOURCE" checkout --detach "$TEE_PIN"
fi
[[ -d "$SOURCE/.git" ]] || {
    echo "TEE source is not a Git checkout." >&2
    exit 1
}
[[ "$(git -C "$SOURCE" rev-parse HEAD)" == "$TEE_PIN" ]] || {
    echo "Refusing non-pinned TEE source." >&2
    exit 1
}
[[ -z "$(git -C "$SOURCE" status --porcelain --untracked-files=all)" ]] || {
    echo "Refusing locally modified TEE source." >&2
    exit 1
}

if [[ -v SAPLINGOS_CHECKOUT ]] && [[ -n "$SAPLINGOS_CHECKOUT" ]]; then
    [[ "$(git -C "$SAPLINGOS_CHECKOUT" rev-parse "$SDK_PIN")" == "$SDK_PIN" ]]
    git -C "$SAPLINGOS_CHECKOUT" merge-base --is-ancestor "$ARK_PIN" "$SDK_PIN" || {
        echo "TEE Ark protocol revision is not an ancestor of the pinned SDK." >&2
        exit 1
    }
fi

python3 - "$SOURCE/Cargo.toml" "$ARK_PIN" <<'PY'
import sys, tomllib
from pathlib import Path
data = tomllib.loads(Path(sys.argv[1]).read_text())
ark = data["dependencies"]["ark-lib"]
assert ark["git"] == "https://github.com/stutxo/saplingos"
assert ark["rev"] == sys.argv[2]
assert "local-dev" in data["features"]
print("TEE's pinned Ark protocol and local-development feature confirmed.")
PY
printf '%s  %s\n' "$WASM_SHA" "$SOURCE/examples/templatehash/templatehash.wasm" |
    sha256sum --check

(
    cd "$SOURCE"
    nix develop --no-update-lock-file -c \
        cargo build --locked --features local-dev --bin sapio-tee
)
TEE_EXEC="$SOURCE/target/debug/sapio-tee"
WASM="$SOURCE/examples/templatehash/templatehash.wasm"
[[ -x "$TEE_EXEC" ]] || { echo "Expected Sapio TEE executable missing." >&2; exit 1; }

if (( $# == 0 )); then
    python3 - <<'PY'
import socket
for port in (8000, 8367):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", port))
print("TEE's fixed local test ports are free.")
PY
    (
        cd "$SOURCE"
        nix develop --no-update-lock-file -c bash -euo pipefail -c '
            target/debug/sapio-tee --local-dev &
            tee_pid=$!
            trap "kill $tee_pid 2>/dev/null || true; wait $tee_pid 2>/dev/null || true" EXIT
            ready=0
            for attempt in $(seq 1 100); do
                if curl -fsS http://127.0.0.1:8000/health >/dev/null 2>&1; then
                    ready=1
                    break
                fi
                kill -0 "$tee_pid" 2>/dev/null || exit 1
                sleep 0.1
            done
            [[ "$ready" == 1 ]] || { echo "Sapio TEE local-dev failed health check." >&2; exit 1; }
            curl -fsS http://127.0.0.1:8000/public-key |
                python3 -c '"'"'import json,sys; j=json.load(sys.stdin); assert j["mode"]=="local-dev"; assert isinstance(j["xpub"],str) and j["xpub"]; print("Ephemeral local-development signer verified.")'"'"'
        '
    )
fi

echo "Sapio TEE pinned at $TEE_PIN"
echo "Compatible SaplingOS SDK pinned at $SDK_PIN"
printf 'export SAPIO_TEE_EXEC=%q\n' "$TEE_EXEC"
printf 'export SAPIO_TEMPLATEHASH_WASM=%q\n' "$WASM"
echo "Apply these exports in your test shell before running the real two-holder fixture."
echo "The ephemeral signer is for disposable regtest only."
