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
