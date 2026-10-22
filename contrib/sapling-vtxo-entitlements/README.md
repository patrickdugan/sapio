# Offline SaplingOS recovery-entitlement auditor

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
cargo test --manifest-path contrib/sapling-vtxo-entitlements/Cargo.toml
cargo run --manifest-path contrib/sapling-vtxo-entitlements/Cargo.toml -- \
  /private/sapling-recovery-bundle.json /private/agreed-payouts.json
```

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

The selected outpoints must match `bundle.targets` exactly. An unsigned
ancestor or `Conditional` recovery is rejected because it may require an
additional service publication. A mismatched output script, a 1-sat
misallocation, additional recipient, or missing anchor fails the audit.

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

The JSON report includes `script_spendability_checked: false` and
`chain_availability_checked: false` for that reason. For a serious shared
VTXO, the next integration must check the script's actual required keys,
observe competing spend branches using Bitcoin Core regtest, and verify that
each target references uniquely accounted-for backing.

## Test coverage

Six pure tests exercise correct 60,000/40,000 outputs, a one-satoshi
redistribution, output redirection, invalid or duplicated beneficiary IDs,
shared script aliases, and missing/unknown fee outputs. These tests use
**synthetic TxOuts**, since no signed exported SaplingOS bundle was included
in the upstream repo snapshot. The executable path invokes the *real*
SaplingOS verifier for actual bundle inputs. A successful signed-bundle
integration fixture remains a further step.

The crate is isolated from the root Cargo workspace, so it can be reviewed
without changing the pinned Sapio workspace lockfile.

Sources: [SaplingOS recovery source](https://github.com/stutxo/saplingos/blob/b45e5ef7b9c151cfc18f0efd9f4fee9327e1a29d/sdk/src/sapio/recovery.rs)
and [BIP 433](https://github.com/bitcoin/bips/blob/master/bip-0433.mediawiki).
