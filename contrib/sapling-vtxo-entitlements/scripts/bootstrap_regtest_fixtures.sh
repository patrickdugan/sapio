#!/usr/bin/env bash
# Pin and build the external executable fixtures for actual SaplingOS recovery
# in a disposable Linux x86_64 regtest. No mainnet or production keys.
set -euo pipefail
SDK_PIN=b45e5ef7b9c151cfc18f0efd9f4fee9327e1a29d
BARK_PIN=626c9b241dd25d73212915d8fca959ab5e3b8f1f
HOLD_PIN=af0055b132f3b9f24d0b1d478a15005fcf8f014f
CORE_SHA=4753cd70416c629a2090503e8545a3c05e94a0f5037f8fb97b4c35c6e1afee0e
CLN_SHA=b09f4ed81628d4d60d9f9096f85dcae9533290f3ed409097e95f8d7414acd9c8
CORE_URL=https://bitcoincore.org/bin/bitcoin-core-30.3/bitcoin-30.3-x86_64-linux-gnu.tar.gz
CLN_URL=https://github.com/ElementsProject/lightning/releases/download/v26.06.7/clightning-v26.06.7-Ubuntu-24.04-amd64.tar.xz

[[ "$(uname -s)" == "Linux" && "$(uname -m)" == "x86_64" ]] || {
    echo "Requires x86_64 Linux." >&2
    exit 1
}
for executable in git nix curl sha256sum python3 tar pkg-config protoc realpath; do
    command -v "$executable" >/dev/null || { echo "Missing prerequisite: $executable" >&2; exit 1; }
done
for pkg in libpq openssl; do
    pkg-config --exists "$pkg" || { echo "Missing development package: $pkg" >&2; exit 1; }
done
POSTGRES=""
if [[ -x /usr/lib/postgresql/16/bin/initdb ]]; then
    POSTGRES=/usr/lib/postgresql/16/bin
elif [[ -v POSTGRES_BINS ]] && [[ -x "$POSTGRES_BINS/initdb" ]]; then
    POSTGRES="$POSTGRES_BINS"
else
    echo "Install PostgreSQL 16 or set POSTGRES_BINS before building." >&2
    exit 1
fi
for executable in initdb pg_ctl postgres psql; do
    [[ -x "$POSTGRES/$executable" ]] || { echo "Missing PostgreSQL executable: $executable" >&2; exit 1; }
done

CACHE="$HOME/.cache"
if [[ -v XDG_CACHE_HOME ]] && [[ -n "$XDG_CACHE_HOME" ]]; then CACHE="$XDG_CACHE_HOME"; fi
ROOT="$CACHE/sapling-vtxo-audit/fixture-tools"
if [[ -v SAPLING_FIXTURE_TOOLS_DIR ]] && [[ -n "$SAPLING_FIXTURE_TOOLS_DIR" ]]; then
    ROOT="$SAPLING_FIXTURE_TOOLS_DIR"
fi
mkdir -p "$ROOT"
ROOT="$(cd "$ROOT" && pwd)"

checkout_pinned() {
    local url="$1" ref="$2" directory="$3"
    if [[ ! -e "$directory" ]]; then
        git clone --filter=blob:none "$url" "$directory"
        git -C "$directory" fetch --no-tags origin "$ref"
        git -C "$directory" checkout --detach "$ref"
    fi
    [[ -d "$directory/.git" ]] || { echo "Expected Git source: $directory" >&2; exit 1; }
    [[ "$(git -C "$directory" rev-parse HEAD)" == "$ref" ]] || {
        echo "Refusing unpinned source: $directory" >&2
        exit 1
    }
    [[ -z "$(git -C "$directory" status --porcelain --untracked-files=all)" ]] || {
        echo "Refusing modified source: $directory" >&2
        exit 1
    }
}

SDK="$ROOT/saplingos-$SDK_PIN"
BARK="$ROOT/bark-$BARK_PIN"
HOLD="$ROOT/hold-$HOLD_PIN"
checkout_pinned https://github.com/stutxo/saplingos.git "$SDK_PIN" "$SDK"
checkout_pinned https://github.com/ark-bitcoin/bark.git "$BARK_PIN" "$BARK"
checkout_pinned https://github.com/BoltzExchange/hold.git "$HOLD_PIN" "$HOLD"

CORE="$ROOT/bitcoin-30.3-x86_64-linux-gnu.tar.gz"
CLN="$ROOT/clightning-v26.06.7-Ubuntu-24.04-amd64.tar.xz"
[[ -f "$CORE" ]] || curl --proto '=https' --tlsv1.2 -fsSLo "$CORE" "$CORE_URL"
[[ -f "$CLN" ]] || curl --proto '=https' --tlsv1.2 -fsSLo "$CLN" "$CLN_URL"
printf '%s  %s\n' "$CORE_SHA" "$CORE" | sha256sum --check
printf '%s  %s\n' "$CLN_SHA" "$CLN" | sha256sum --check

mkdir -p "$ROOT/core-release" "$ROOT/cln-release"
tar -xzf "$CORE" -C "$ROOT/core-release"
tar -xJf "$CLN" -C "$ROOT/cln-release"
BITCOIND="$ROOT/core-release/bitcoin-30.3/bin/bitcoind"
BITCOIN_CLI="$ROOT/core-release/bitcoin-30.3/bin/bitcoin-cli"
[[ -x "$BITCOIND" && -x "$BITCOIN_CLI" ]] || {
    echo "Unexpected official Bitcoin Core tar layout." >&2
    exit 1
}
LIGHTNINGD="$(find "$ROOT/cln-release" -name lightningd -type f -print -quit)"
CLN_GRPC="$(find "$ROOT/cln-release" -name cln-grpc -print -quit)"
[[ -n "$LIGHTNINGD" && -n "$CLN_GRPC" && -x "$LIGHTNINGD" && -x "$CLN_GRPC" ]] || {
    echo "Official Core Lightning tar lacks a usable lightningd or cln-grpc." >&2
    exit 1
}

# Match the exact Ark server implementation used by the pinned SDK.
(
    cd "$BARK"
    nix develop --no-update-lock-file "$SDK" -c \
        cargo build --locked --release -p bark-server --bin captaind --bin watchmand --jobs 2
)
CAPTAIND="$BARK/target/release/captaind"
WATCHMAND="$BARK/target/release/watchmand"
[[ -x "$CAPTAIND" && -x "$WATCHMAND" ]] || {
    echo "Pinned Bark build did not produce both server binaries." >&2
    exit 1
}

# Boltz hold v0.3.3 uses newer Rust; the earlier public TEE bootstrap has
# pinned Rust 1.98.1 in its own Nix flake.
TEE_SOURCE="$CACHE/sapling-vtxo-audit/sapio_tee-f083bdbd2343aad22fab861f1565c0f2c2e6b0af"
if [[ -v SAPLING_TEE_SOURCE_DIR ]] && [[ -n "$SAPLING_TEE_SOURCE_DIR" ]]; then
    TEE_SOURCE="$SAPLING_TEE_SOURCE_DIR"
fi
[[ -f "$TEE_SOURCE/flake.nix" ]] || {
    echo "Run bootstrap_localdev_tee.sh first for pinned modern Rust." >&2
    exit 1
}
(
    cd "$HOLD"
    nix develop --no-update-lock-file "$TEE_SOURCE" -c \
        cargo build --locked --release --jobs 2
)
[[ -x "$HOLD/target/release/hold" ]] || {
    echo "Pinned hold plugin build failed." >&2
    exit 1
}
PLUGIN_DIR="$ROOT/cln-plugins"
mkdir -p "$PLUGIN_DIR"
ln -sfn "$CLN_GRPC" "$PLUGIN_DIR/cln-grpc"
ln -sfn "$HOLD/target/release/hold" "$PLUGIN_DIR/hold"

echo "Pinned disposable regtest executables verified."
printf 'export SAPLINGOS_CHECKOUT=%q\n' "$SDK"
printf 'export CAPTAIND_EXEC=%q\n' "$CAPTAIND"
printf 'export WATCHMAND_EXEC=%q\n' "$WATCHMAND"
printf 'export BITCOIND_EXEC=%q\n' "$BITCOIND"
printf 'export SAPLING_TWO_HOLDER_BITCOIN_CLI=%q\n' "$BITCOIN_CLI"
printf 'export LIGHTNINGD_EXEC=%q\n' "$LIGHTNINGD"
printf 'export LIGHTNINGD_PLUGIN_DIR=%q\n' "$PLUGIN_DIR"
printf 'export POSTGRES_BINS=%q\n' "$POSTGRES"
echo "Apply these exports and those from bootstrap_localdev_tee.sh."
echo "Run run_real_two_holder.sh only inside an isolated disposable regtest environment."
