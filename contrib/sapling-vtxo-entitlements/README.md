# Offline SaplingOS recovery-entitlement auditor

This workspace commits a complete Cargo.lock, currently pinning **343 package
entries** including every registry checksum and the exact SaplingOS Git
revision. Use `--locked` for builds and tests; update the lockfile only in
reviewed dependency-update commits.

This is a small **separate Rust workspace** inside the Sapio fork. It links
the [SaplingOS SDK](https://github.com/stutxo/saplingos) at
`b45e5ef7b9c151cfc18f0efd9f4fee9327e1a29d`. It does not patch SaplingOS,
Sapio's covenant code, or the Ark server.

SaplingOS's `ProgramRecoveryBundle::verify()` verifies each saved Bitcoin
recovery claim, witness, Merkle ancestry, program instance and construction
constraints. The SDK explicitly leaves application-specific beneficiary
agreements to the application. This tool takes a **second, independently
trusted document** and requires the saved payout scripts and satoshi amounts
to match it exactly.

## Running

```sh
cargo test --locked --manifest-path contrib/sapling-vtxo-entitlements/Cargo.toml
cargo run --locked --manifest-path contrib/sapling-vtxo-entitlements/Cargo.toml -- \
  /private/sapling-recovery-bundle.json /private/agreed-payouts.json
```

After the prepared recovery transaction is **actually confirmed**, you can
run an optional second stage against a trusted Bitcoin Core node:

```sh
cargo run --locked --manifest-path contrib/sapling-vtxo-entitlements/Cargo.toml -- \
  /private/sapling-recovery-bundle.json /private/agreed-payouts.json \
  --bitcoin-cli /trusted/path/to/bitcoin-cli --datadir /private/bitcoin \
  --confirmations 6
```

The local Bitcoin Core node should have completed initial sync and have
`txindex=1` enabled. The observer uses `getblockchaininfo`,
`getrawtransaction` and `gettxout` directly, with no shell interpolation.
It requires the **exact signed recovery transaction** to have reached the
requested confirmation depth on the expected network. For each participant,
it reports whether the confirmed payout outpoint remains in the UTXO set.
A spent output may already have been redeemed legitimately, and the tool
cannot identify the spending party. No unconfirmed or hypothetical recoveries
are treated as confirmed. The response is a JSON object with `offline`
and `chain` sections when Bitcoin Core mode is enabled.

This observes post-recovery Bitcoin finality. It does not proactively resolve
an unpublished Ark branch or predict whether a pending recovery can confirm.

The SDK's exported bundle can be obtained through
`wallet.program_recovery_bundle(&[])`. Preserve and protect that bundle;
its evidence and contract parameters can reveal private information.

The independent `agreed-payouts.json` follows this schema:

```json
{
  "version": 1,
  "network": "regtest",
  "targets": [
    {
      "outpoint": "<exact-controlled-vtxo-txid>:<vout>",
      "program": {
        "program_id": "<Sapio-Program-v1-id-hex>",
        "signer_root": "<independently-attested-Sapio-xpub>",
        "user_pubkey": "<agreed-compressed-public-key-hex>"
      },
      "beneficiaries": [
        {
          "holder": "alice",
          "script_pubkey_hex": "<exact-expected-bitcoin-output-script>",
          "sats": 60000
        },
        {
          "holder": "bob",
          "script_pubkey_hex": "<different-expected-output-script>",
          "sats": 40000
        }
      ]
    }
  ]
}
```

Replace each placeholder with an actual agreed transaction outpoint and full
Bitcoin scriptPubKey (hex). Pin the Sapio program ID, full signer xpub from
independent TEE attestation, and the participant wallet's public key from
the prior agreement. These fields prevent a self-selected signing service
or evaluator from satisfying an otherwise internally valid export.
The tool finds the matching signed recovery
record, verifies the bundle and requires `Complete` readiness. The combined
beneficiary amounts must equal the full backed input value. It permits
exactly one **zero-valued P2A fee anchor** (`51024e73`, BIP 433) and rejects
other outputs or beneficiary-script collisions. Output order is arbitrary;
the signed transaction has already committed to the actual order.

The selected outpoints must match `bundle.targets` exactly. The auditor
also checks the **recovery paths across selected positions**: a shared
ancestor can split into independently funded sibling outputs, while competing
transactions spending the same ancestor and parent-plus-child double counting
are rejected. Their cumulative claims cannot exceed a common anchor's value.
These are necessary structural checks rather than a complete proof that all
external positions have disjoint economic backing.

An unsigned
ancestor or `Conditional` recovery is rejected because it may require an
additional service publication. A mismatched output script, a 1-sat
misallocation, additional recipient, or missing anchor fails the audit.


## Two independently confirmed holders

For the two-holder experiment, prepare a genuine SaplingOS export with **two
different selected controlled VTXOs**. Supply independent terms with exactly
one beneficiary on each target (for example, Alice 60,000 sats and Bob
40,000 sats). This distinction matters: one joint claim paying two scripts
alone is not evidence that Alice and Bob can each recover a separate VTXO.

After the Sapio cosigner and Ark service have been stopped and the
**unchanged signed** claims have confirmed through an independently funded
ordinary fee wallet, ask the auditor for a strict two-holder receipt:

```sh
cargo run --locked --manifest-path contrib/sapling-vtxo-entitlements/Cargo.toml -- \
  /private/two-holder-export.json /private/two-holder-terms.json \
  --bitcoin-cli /trusted/path/to/bitcoin-cli --datadir /private/bitcoin \
  --confirmations 6 --two-holder
```

The new `two_holder` JSON section requires two distinct confirmed claim
txids, two different beneficiary scripts, the exact separately agreed
amounts and **two unspent** payout outpoints on the expected Bitcoin Core
chain. It binds each payout to its own claimed VTXO and rejects duplicate
holder labels, shared scripts, missing claims, ambiguous receipts and
spent outputs. The strict check is deliberately post-confirmation and
should run before redeeming either holder's Bitcoin UTXO.

`unilateral_spend_authority_checked=false` and
`services_offline_during_recovery_checked=false` remain explicit in the
report. They require **additional external evidence**, such as independently
signed and mined spends by Alice's and Bob's separate fee-capable Bitcoin
wallets, and a harness log showing that the Ark and Sapio signing services
were stopped **before** recovery publication. The reporting tool alone
cannot establish those facts.

The repository currently has deterministic fake-node regressions covering
the two-claim shape. A **real signed export** and Bitcoin Core regtest
service-shutdown capture must be supplied by a SaplingOS integration run
before a complete two-holder recovery claim can be made.



## Combining Alice's and Bob's independent signed exports

Alice and Bob may each have a **separate SaplingOS wallet export**. The
`merge-bundles` executable checks each signed original independently
and then validates the union under the existing cross-target ancestry
and backing checks. It accepts exactly one currently selected VTXO from
each original and requires a separately attested terms file with one
different holder on each target.

```sh
cargo run --locked --manifest-path contrib/sapling-vtxo-entitlements/Cargo.toml \
  --bin merge-bundles -- \
  /private/alice-recovery.json /private/bob-recovery.json \
  /private/two-holder-terms.json /private/two-holder-export.json
```

The output contains the original saved transaction bytes and signers'
descriptors, with duplicate identical descriptors deduplicated and no
transaction re-signing. It refuses conflicting duplicates, mismatched
networks, repeated target positions, incomplete original claims, unexpected
beneficiary output scripts and economic overlap detectable from the
signed ancestry. On Unix it writes a new private file with permissions
`0600`; it never overwrites an earlier saved bundle.

Carry the resulting verified bundle into the pinned SaplingOS **offline
recovery** implementation with a separately funded fee wallet after
both services have stopped. Once both claims have confirmed, run the
standard auditor with `--two-holder` and then the separate wallet
spend experiment below. The merger itself is an offline input-preparation
tool and makes no chain-availability claim.

## Separate holder-wallet spending on regtest

Once the exact recovery claims have confirmed and `--two-holder` succeeds,
save that combined JSON output to a private `two-holder-report.json` file.
The separate-wallet runner queries Bitcoin Core again, checks that the two
confirmed recovery outputs still exist and that two **different** Bitcoin
Core wallets mark their respective UTXOs as `spendable`. It relies solely
on Bitcoin Core RPC, and never contacts Sapio or Ark.

Its default mode is read-only:

```sh
python3 contrib/sapling-vtxo-entitlements/scripts/prove_separate_spends.py \
  /private/two-holder-report.json \
  --bitcoin-cli /trusted/path/to/bitcoin-cli --datadir /private/bitcoin \
  --wallet alice=alice-regtest --wallet bob=bob-regtest
```

For the actual independent-spend witness, provide separate regtest
destination addresses and explicitly opt into spending both outputs.
The runner builds one PSBT **per holder**, requires that it spend only that
holder's recovered UTXO, bounds its fee and pays the specified destination.
After both transactions are accepted, the supplied mining wallet mines one
regtest block and the runner checks confirmation:

```sh
python3 contrib/sapling-vtxo-entitlements/scripts/prove_separate_spends.py \
  /private/two-holder-report.json \
  --bitcoin-cli /trusted/path/to/bitcoin-cli --datadir /private/bitcoin \
  --wallet alice=alice-regtest --wallet bob=bob-regtest \
  --destination alice=bcrt1... --destination bob=bcrt1... \
  --mine-wallet miner-regtest --broadcast
```

Use newly created, distinct Bitcoin Core wallets whose spend keys are
retained separately. The two claimant wallets must import their own keys
and recognize the agreed scripts before the signing services are shut down.
Run this against an **isolated disposable regtest node only**. The
`--broadcast` step really spends the recovered outputs and therefore
invalidates a later two-holder **unspent** report. Retain the
runner's JSON signed-spend receipts and the pre-spend audit as separate
pieces of evidence; the read-only preflight will reject spent payouts.

These tests do not manufacture a valid SaplingOS export. Capture the actual
`wallet.program_recovery_bundle(&[])` result while the program signer is
available, stop all Ark and Sapio signing actors, then run SaplingOS's
native `recover_program_bundle` with a separately funded fee wallet and
publish ancestors one at a time as the SDK directs. The strict audit and
holder-wallet spend runner come **after** those Bitcoin confirmations.
Keep a separate service-stop log and fee-wallet funding record. They are
not attested by either verifier.


## Bitcoin Core wallet-only live regression

The separate Bitcoin Core PSBT runner has a **live regtest smoke test**:

```sh
python3 contrib/sapling-vtxo-entitlements/scripts/live_core_wallet_smoke.py \
  --bitcoind /absolute/path/to/bitcoind \
  --bitcoin-cli /absolute/path/to/bitcoin-cli \
  --output /private/regtest-wallet-smoke
```

It starts an isolated disposable Bitcoin Core node and three descriptor wallets
(miner, Alice and Bob). The miner makes two ordinary Bitcoin payments of
60,000 and 40,000 sats. Both payments confirm, and then the actual
`prove_separate_spends.py` checks separate wallet spendability, signs one
PSBT per holder, broadcasts both redemptions and mines their block.

**This is a wallet-only smoke test.** Its report is explicitly tagged
`BITCOIN_CORE_WALLET_SMOKE_ONLY` and
`cryptographic_sapling_recovery_proven=false`. It uses synthetic
SaplingOS-shaped claim metadata and never invokes native
`ProgramRecoveryBundle::verify()`. Signed Ark ancestry and publication
after service shutdown require the genuine fixture below.

The [Bitcoin Core wallet-only CI workflow](../../.github/workflows/sapling-core-wallet-smoke.yml)
downloads the official Bitcoin Core 30.3 x86_64 release and checks SHA-256
`4753cd70416c629a2090503e8545a3c05e94a0f5037f8fb97b4c35c6e1afee0e`
before executing. The same digest appears independently in the fanquake,
achow101, Sjors and Emzy builder attestations in the pinned
[Bitcoin Core 30.3 Guix evidence](https://github.com/bitcoin-core/guix.sigs/tree/d4a305fe827dbe88d4a5fa36f9b9f73d1249ab31/30.3).
The workflow artifact is named to distinguish wallet-only results from real
SaplingOS recovery evidence.

## Preparing the real local-dev Sapio signer

The source for the actual signing service is
[stutxo/sapio_tee](https://github.com/stutxo/sapio_tee), pinned to
`f083bdbd2343aad22fab861f1565c0f2c2e6b0af`.
The pinned signer passed its [upstream build and integration CI]
(https://github.com/stutxo/sapio_tee/actions/runs/39414465510).
Its `ark-lib` dependency uses `stutxo/saplingos@758f7b730`;
the auditor's SDK revision `b45e5ef7b9c151cfc18f0efd9f4fee9327e1a29d`
adds only wallet-hook and fixture-runner changes above that protocol source.

A public-source bootstrap is provided to fetch and build this exact signer
with its own Nix toolchain (Rust 1.98.1). It verifies the locked Ark library
revision and the reviewed BIP-446 template-hash v1 WASM digest.

```sh
bash contrib/sapling-vtxo-entitlements/scripts/bootstrap_localdev_tee.sh
```

After building, it starts the signer on isolated loopback ports, checks the
ephemeral `local-dev` identity, shuts it down and prints shell export commands
for `SAPIO_TEE_EXEC` and `SAPIO_TEMPLATEHASH_WASM`. Apply those commands
before running the two-holder recovery driver. The optional `--build-only`
mode skips the test service startup when ports 8000 and 8367 are unavailable.
`SAPLING_TEE_SOURCE_DIR` selects a custom clean public checkout.
If `SAPLINGOS_CHECKOUT` is already set and contains the pinned ancestors,
the bootstrap checks the tee's Ark protocol revision against that SDK.

**Local-dev is a disposable regtest signer.** Its root changes on every
restart and has no Nitro measurement or KMS key recovery. The full rehearsal
must prepare and save immutable claims before deliberately shutting it down.
The separate Ark server, Bitcoin Core, CLN, PostgreSQL and watchman
fixture binaries remain required by the native SaplingOS service suite.

### Preparing the remaining regtest fixture binaries

After the [locked Sapio TEE bootstrap](scripts/bootstrap_localdev_tee.sh),
run the [external fixture bootstrap](scripts/bootstrap_regtest_fixtures.sh)
on a disposable Ubuntu 24.04 / Linux x86_64 machine with Nix, Git,
protobuf, OpenSSL/libpq development libraries, and PostgreSQL 16 installed:

```sh
bash contrib/sapling-vtxo-entitlements/scripts/bootstrap_localdev_tee.sh
bash contrib/sapling-vtxo-entitlements/scripts/bootstrap_regtest_fixtures.sh
```

Copy the `export` assignments printed by both scripts into the same shell
before running `run_real_two_holder.sh`. The second bootstrap pins
`stutxo/saplingos@b45e5ef`, `ark-bitcoin/bark@626c9b`, and
`BoltzExchange/hold@af0055`, compiles the Bark server/watchman and the
hold plugin, and verifies release hashes of Bitcoin Core 31.0 and Core
Lightning 26.06.7. The Lightning release's gRPC plugin is included.
The pinned `captaind` refuses Bitcoin Core older than v31
(`MIN_BITCOIND_VERSION` in Bark's `server/src/bitcoind.rs`), and Bark's
own dev shell uses 31.0. The 31.0 archive digest
`d3e4c58a35b1d0a97a457462c94f55501ad167c660c245cb1ffa565641c65074`
matches bitcoincore.org's `SHA256SUMS` and the fanquake, achow101, Sjors
and Emzy attestations in
[guix.sigs@3962bb94](https://github.com/bitcoin-core/guix.sigs/tree/3962bb942102c4bc242d08a137e31b9a74cf8fbe/31.0).
Inside the pinned SaplingOS dev shell, `run_real_two_holder.sh` starts the
distribution-linked PostgreSQL and Core Lightning binaries through
wrappers that clear the shell's Nix `LD_LIBRARY_PATH`.
The preflight job checks the public source revisions and official CLN
archive layout. Its checksum is sourced from that release's GitHub
asset digest. Rebuilding service binaries may consume substantial CPU
and storage; the local-dev keys and Bitcoin balances remain disposable.

These scripts provision binaries and print their paths. The native
SaplingOS fixture itself creates its own Bitcoin, Ark and CLN test data
and runs the actual recovery only when `run_real_two_holder.sh` is invoked.
## Running the genuine two-holder service-shutdown fixture

An opt-in integration test at
`e2e/sapio_two_holder.rs` exercises a live SaplingOS TEE and Ark server
with real Bitcoin Core regtest transactions. The Bash driver builds the
standalone merger and auditor, creates a disposable detached Git worktree
of the **pinned upstream SaplingOS commit**, injects the test module into
upstream's existing integration suite, and runs the native offline SDK
recovery subprocesses. It leaves the original upstream checkout untouched.

Set `SAPLINGOS_CHECKOUT` to a local Git checkout containing
`b45e5ef7b9c151cfc18f0efd9f4fee9327e1a29d`. The real-service
fixture binaries and WASM artifacts required by upstream
[BUILDING.md](https://github.com/stutxo/saplingos/blob/b45e5ef7b9c151cfc18f0efd9f4fee9327e1a29d/BUILDING.md)
must be available: `CAPTAIND_EXEC`, `WATCHMAND_EXEC`,
`BITCOIND_EXEC`, `POSTGRES_BINS`, `LIGHTNINGD_EXEC`,
`LIGHTNINGD_PLUGIN_DIR`, `SAPIO_TEE_EXEC`, and
`SAPIO_TEMPLATEHASH_WASM`. Provide a matching
`SAPLING_TWO_HOLDER_BITCOIN_CLI` and the Nix, just, and Rust
toolchains used by the pinned SDK.

```sh
SAPLINGOS_CHECKOUT=/absolute/path/to/saplingos \
SAPLING_TWO_HOLDER_BITCOIN_CLI=/absolute/path/to/bitcoin-cli \
bash contrib/sapling-vtxo-entitlements/scripts/run_real_two_holder.sh
```

To exercise Alice and Bob as **common-root siblings** created by two
sequential native transfers of one real Ark VTXO, select the second
opt-in integration scenario:

```sh
bash contrib/sapling-vtxo-entitlements/scripts/run_real_two_holder.sh \
  sapio_real_common_anchor_two_holder_recovery
```

The common-root test starts with one 120,000-sat parent and explicitly
checks that Alice's 60,000-sat VTXO and Bob's 40,000-sat VTXO share
its actual Bitcoin chain anchor. It then runs both independently
saved recovery exports through the same cross-target backing auditor
and requires separate confirmed wallet redemptions after service
shutdown. Any remaining 20,000 sats in the parent wallet remain outside
these two selected claims. The pinned real-service suite first passed this
scenario at `18f6802` in run 39927925655; see [COMMON_ROOT_EVIDENCE.md](COMMON_ROOT_EVIDENCE.md)
for the receipt, its trust assumptions and what it does not establish.

The driver also accepts `SAPLING_TWO_HOLDER_CAPTURE_DIR`; otherwise it
chooses a new private directory under the user's local state home.
It fails if that directory already contains signed holder exports.
The real test records independent program identifiers and exact scripts
before exporting the signed evidence, confirms each claim while both
services are stopped, invokes the actual merged-bundle auditor with
`--two-holder`, and signs separate PSBT redemptions using Bitcoin Core
wallets `alice-recovered` and `bob-recovered` with their own keys.
A single regtest block confirms both spends. The saved audit is explicitly
**pre-spend** and the redemption receipt is **post-spend**. Its
`confirmed-p2a-fee-children.json` evidence records each claim wtxid,
the confirmed fee child, the external funding outpoints, and the mining
fee deducted from those external inputs. The signing service's fixed
loopback ports must be unreachable after shutdown. Before each wallet
redemption, the Python runner rechecks the current chain's witness hash
and required confirmation depth against the saved signed recovery.

### Independence of the Bitcoin fee sponsor

Both real-service scenarios now fund a third SaplingOS wallet,
`external-recovery-fees`, before the outage. Its wallet seed and
on-chain SQLite database are separate from Alice and Bob, and it
holds no Ark VTXOs. The fixture stops this sponsor's original
process alongside both owners and the signing services.

When each saved bundle is replayed, an **independent fresh-process
fee wallet** opens the sponsor's seed and database and passes its
ordinary Bitcoin coins to SaplingOS's native
`recover_program_bundle()`. Neither claimant wallet needs to be
reopened to authorize or pay the recovery transactions.

The fixture records the sponsor's originally confirmed UTXOs in
`external-fee-utxos-before-shutdown.json` and recursively checks
the external inputs of both confirmed P2A children. Every intervening
fee-change transaction must spend a P2A anchor belonging to the
**signed saved recovery transactions**, and its non-anchor funding
must eventually trace back to the pre-shutdown sponsor coins. Shared
signed ancestors between Alice and Bob are accepted. An unrelated
wallet coin or recovery-beneficiary input fails the run.

This tests external fee independence from the holders and Ark
signing infrastructure, with the same trusted Bitcoin Core regtest
node underlying all participants.

The pinned upstream fixture uses a **local-dev TEE**, meaning no
hardware-attestation assurance is claimed. The default two-holder test uses **separately boarded VTXOs**. The
optional common-root sibling fixture tests shared signed ancestry. A
single joint-output claim with two independently executable unilateral
withdrawals is a further distinct property. The real integration requires external service
binaries and has not been run by the lightweight dedicated CI.

### Immutable export checks during the service outage

Both real-service fixtures snapshot SHA-256 digests and byte counts for
the independently agreed payout terms and each holder's signed recovery
export **before** the Sapio cosigner and Ark service stop. After both
services shut down, after recovery, immediately before bundle merging,
and after separate Bitcoin Core withdrawals, each fixture recomputes those
digests. It also compares the saved pre-shutdown manifest to its
in-memory snapshot, rejecting edits to the manifest itself.

The `frozen_evidence_guard_rejects_substitution_and_manifest_rewrites`
unit test changes each original file and the manifest in turn, requiring
every substitution to fail the same guard used by the service fixtures.
These are checkpoint-integrity assertions over saved regtest evidence,
not filesystem immutability guarantees against a continuously active
adversary. Signed originals remain private; only their names, sizes and
hashes are eligible for the sanitized public receipt.

In the common-root fixture, native offline publication opens only the
separate `external-recovery-fees` SDK wallet, using independently funded
Bitcoin UTXOs. Alice's and Bob's program wallets remain stopped.

### Full-service GitHub Actions build blocker and isolated repair

[Full-service run 39807849809](https://github.com/patrickdugan/sapio/actions/runs/39807849809)
failed in pinned upstream Cargo compilation before any recovery fixture
ran. `utoipa-swagger-ui 9.0.2` tried to launch the host's `curl`
inside a Nix development shell and hit a mixed-glibc dynamic linker error.
The follow-up host-library-path repair
([branch `fix/sapling-regtest-host-curl-20261023`](https://github.com/patrickdugan/sapio/tree/fix/sapling-regtest-host-curl-20261023))
also failed at the same build-script download.

The separate QA branch prefetches Swagger UI version 5.17.14 from its
tagged commit `74ed0adebfc9c8dd0de2bf8e81495b022a66c083` before
entering the Nix build, validates the ZIP structure, and passes it to
the pinned crate through its supported `SWAGGER_UI_DOWNLOAD_URL=file://`
interface. The upstream SaplingOS revision and Cargo locks remain
unchanged. A fresh full-service run must still compile, execute native
SaplingOS recovery, and emit an independently validated receipt before
any shared-root cryptographic recovery claim can be promoted.

## Verification boundaries

A successful report means the existing SaplingOS cryptographic verifier
accepted the exported records and the beneficiary output scripts/amounts
match the independent plan. It **does not** mean:

* the Ark ancestry remains unspent or all ancestors are confirmed;
* timelocks, expiry margins, fee coins and mempool policy allow a timely exit;
* a beneficiary can actually spend the script (a script may require multiple
  signatures or be otherwise unspendable);
* any recipient has independent unilateral exit from a shared *joint* output;
* different Ark positions have disjoint backing, or no stale conflicting
  transaction is independently valid;
* the signer was honestly measured, KMS policies were historically immutable,
  or the exported bundle was preserved before a crash.

The offline JSON report includes `script_spendability_checked: false` and
`chain_availability_checked: false`, plus
`selected_paths_nonconflicting: true` when the cross-target checks pass.
The separate optional chain report requires a confirmed transaction and
still records `beneficiary_key_custody_checked: false`. For a serious shared
VTXO, the next integration must check the script's actual required keys,
observe competing spend branches using Bitcoin Core regtest, and verify that
each target references uniquely accounted-for backing.

## Test coverage

Fifteen pure tests exercise correct 60,000/40,000 outputs, a one-satoshi
redistribution, output redirection, invalid or duplicated beneficiary IDs,
shared script aliases, missing/unknown fee outputs, shared ancestor sibling
paths, conflicting ancestor spends, parent-child counting and common-root
principal conservation. Additional chain-observer tests cover exact
confirmed payouts, live UTXO flags, insufficient confirmations, mismatched
transaction data and duplicate recipient names. These tests use
**synthetic TxOuts**, since no signed exported SaplingOS bundle was included
in the upstream repo snapshot. The executable path invokes the *real*
SaplingOS verifier for actual bundle inputs. A successful signed-bundle
integration fixture remains a further step.

The crate is isolated from the root Cargo workspace, so it can be reviewed
without changing the pinned Sapio workspace lockfile.

Sources: [SaplingOS recovery source](https://github.com/stutxo/saplingos/blob/b45e5ef7b9c151cfc18f0efd9f4fee9327e1a29d/sdk/src/sapio/recovery.rs)
and [BIP 433](https://github.com/bitcoin/bips/blob/master/bip-0433.mediawiki).
