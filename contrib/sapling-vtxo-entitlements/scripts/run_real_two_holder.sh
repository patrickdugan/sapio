#!/usr/bin/env bash
# Real SaplingOS Alice/Bob outage proof in a detached pinned worktree.
# The upstream checkout remains untouched. Requires independently provisioned
# local-dev Sapio TEE, Bitcoin Core, Ark, CLN, PostgreSQL and Nix toolchain.
set -euo pipefail

PIN=b45e5ef7b9c151cfc18f0efd9f4fee9327e1a29d
SCRIPT_DIR="$(cd "$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../../.." && pwd)"
MANIFEST="$REPO/contrib/sapling-vtxo-entitlements/Cargo.toml"
UPSTREAM="\${SAPLINGOS_CHECKOUT:?Set SAPLINGOS_CHECKOUT to a local Git checkout containing the pinned SaplingOS commit}"
CAPTURE_DIR="\${SAPLING_TWO_HOLDER_CAPTURE_DIR:-$REPO/test/real-two-holder}"
BITCOIN_CLI="\${SAPLING_TWO_HOLDER_BITCOIN_CLI:-$(command -v bitcoin-cli || true)}"

if [[ "$UPSTREAM" != /* ]] || ! git -C "$UPSTREAM" cat-file -e "$PIN^{commit}" 2>/dev/null; then
    echo "SAPLINGOS_CHECKOUT must be an absolute Git checkout containing $PIN" >&2
    exit 1
fi
if [[ -z "$BITCOIN_CLI" || "$BITCOIN_CLI" != /* || ! -x "$BITCOIN_CLI" ]]; then
    echo "Set SAPLING_TWO_HOLDER_BITCOIN_CLI to an absolute trusted bitcoin-cli binary" >&2
    exit 1
fi
for variable in \
    CAPTAIND_EXEC WATCHMAND_EXEC BITCOIND_EXEC POSTGRES_BINS \
    LIGHTNINGD_EXEC LIGHTNINGD_PLUGIN_DIR \
    SAPIO_TEE_EXEC SAPIO_TEMPLATEHASH_WASM
do
    [[ -n "\${!variable:-}" ]] || { echo "Missing required external fixture: $variable" >&2; exit 1; }
done

mkdir -p "$CAPTURE_DIR"
CAPTURE_DIR="$(cd "$CAPTURE_DIR" && pwd)"
chmod 700 "$CAPTURE_DIR"
if [[ -e "$CAPTURE_DIR/alice-recovery.json" || -e "$CAPTURE_DIR/bob-recovery.json" ]]; then
    echo "Capture directory already holds signed exports. Choose a fresh SAPLING_TWO_HOLDER_CAPTURE_DIR" >&2
    exit 1
fi
TARGET_DIR="\${SAPLING_TWO_HOLDER_TARGET_DIR:-$REPO/contrib/sapling-vtxo-entitlements/target}"
cargo build --locked --manifest-path "$MANIFEST" --bins --target-dir "$TARGET_DIR"
MERGER="$TARGET_DIR/debug/merge-bundles"
AUDITOR="$TARGET_DIR/debug/sapling-vtxo-entitlements"
[[ -x "$MERGER" && -x "$AUDITOR" ]] || { echo "Audit binaries missing after build" >&2; exit 1; }

TEMP="$(mktemp -d)"
WORKTREE="$TEMP/saplingos"
cleanup() {
    git -C "$UPSTREAM" worktree remove --force "$WORKTREE" >/dev/null 2>&1 || true
    rm -rf "$TEMP"
}
trap cleanup EXIT

git -C "$UPSTREAM" worktree add --detach "$WORKTREE" "$PIN"
cp "$SCRIPT_DIR/../e2e/sapio_two_holder.rs" "$WORKTREE/testing/tests/sdk/sapio/two_holder.rs"
python3 - "$WORKTREE/testing/tests/sdk/sapio.rs" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
content = path.read_text()
anchor = "mod process;\n"
if content.count(anchor) != 1:
    raise SystemExit("pinned upstream SaplingOS test module shape changed")
path.write_text(content.replace(anchor, anchor + "mod two_holder;\n"))
PY
test "$(git -C "$WORKTREE" rev-parse HEAD)" = "$PIN"

export SAPLING_TWO_HOLDER_CAPTURE_DIR="$CAPTURE_DIR"
export SAPLING_TWO_HOLDER_BITCOIN_CLI="$BITCOIN_CLI"
export SAPLING_TWO_HOLDER_MERGER="$MERGER"
export SAPLING_TWO_HOLDER_AUDITOR="$AUDITOR"
export SAPLING_TWO_HOLDER_PY="$SCRIPT_DIR/prove_separate_spends.py"

echo "Pinned SaplingOS revision: $PIN"
echo "Capture directory: $CAPTURE_DIR"
cd "$WORKTREE"

# The upstream recipe validates real-service dependencies and creates a
# private network namespace if the platform supports bubblewrap isolation.
./contrib/sapio-e2e.sh sapio_real_two_holder_offline_recovery

test -s "$CAPTURE_DIR/two-holder-pre-spend-report.json"
test -s "$CAPTURE_DIR/two-holder-redemptions.json"
echo "Two-holder signed recovery and independent redemptions completed on regtest."
echo "Artifacts: $CAPTURE_DIR"
