#!/usr/bin/env python3
"""Independent public receipt for a real, freshly signed watchman-expiry race.

The live harness proves that a watchman process emitted a claim log and a
Bitcoin Core node mined the observed transaction. This verifier checks the
economic relationship by decoding all signed prevouts itself. It is not a
separate witness to operator key custody or Bitcoin chain consensus.
"""
import argparse
import json
import os
from pathlib import Path
import sys

from write_public_proof import ALLOCATION, FROZEN, check, load, sha256, tx_ids
from write_stale_race_public_proof import saved_path, signed_inputs, signed_outputs

KIND = "actual-pinned-saplingos-operator-expiry-sweep-regtest"


def signed_honest(root):
    paths = {name: saved_path(root, name) for name in ALLOCATION}
    check(paths["alice"]["anchor"] == paths["bob"]["anchor"],
          "Alice/Bob did not sign paths with one on-chain root")
    check(paths["alice"]["anchor_sats"] == paths["bob"]["anchor_sats"] == 120_000,
          "the original on-chain root must back exactly 120k sats")
    terms = load(root, "two-holder-terms.json")
    check(terms["network"] == "regtest", "operator probe must use disposable regtest")
    check(len(terms["targets"]) == 2, "exactly two independent terms required")
    seen = set()
    for target in terms["targets"]:
        check(len(target["beneficiaries"]) == 1, "one owner per position is required")
        owner = target["beneficiaries"][0]
        name = owner["holder"]
        check(name in ALLOCATION and name not in seen, "duplicate or unknown beneficiary")
        seen.add(name)
        check(target["outpoint"] == paths[name]["target"], "independent target outpoint changed")
        check(owner["sats"] == ALLOCATION[name], "agreed beneficiary amount changed")
        record = next(r for r in load(root, f"{name}-recovery.json")["recoveries"]
                      if r["controlled_outpoint"] == paths[name]["target"])
        check(signed_inputs(record["claim"]) == [paths[name]["target"]],
              f"{name}: saved claim doesn't spend its agreed program output")
        check(signed_outputs(record["claim"]) == [
            (ALLOCATION[name], owner["script_pubkey_hex"].lower()), (0, "51024e73")
        ], f"{name}: saved claim doesn't preserve exact beneficiary script/value")
    check(seen == set(ALLOCATION), "missing a beneficiary")
    return paths


def canonical_honest(paths):
    honest = {}
    for name, path in paths.items():
        for txid, tx in path["txs"].items():
            if txid not in honest:
                honest[txid] = {**tx, "used_by": []}
            else:
                old = honest[txid]
                check(old["wtxid"] == tx["wtxid"] and
                      old["inputs"] == tx["inputs"] and old["role"] == tx["role"],
                      "sibling exports disagree on shared signed transaction")
            honest[txid]["used_by"].append(name)
    return honest


def build(root, revisions=None):
    revisions = revisions or {}
    manifest_path = root / "frozen-evidence-before-shutdown.json"
    manifest = load(root, manifest_path.name)
    files = manifest["files"]
    check(sorted(f["file"] for f in files) == sorted(FROZEN),
          "fixture must freeze exact Alice/Bob exports and independent terms")
    for file in files:
        path = root / file["file"]
        check(sha256(path) == file["sha256"] and path.stat().st_size == file["bytes"],
              file["file"] + " differs from its pre-shutdown hash")

    paths = signed_honest(root)
    honest = canonical_honest(paths)
    report = load(root, "operator-expiry-race.json")
    shutdown = load(root, "shutdown-before-recovery.json")
    check(report["scenario"] == "operator-fresh-watchman-expiry-sweep",
          "wrong native operator adversary")
    check(report["shared_chain_anchor"] == paths["alice"]["anchor"],
          "false economic root")
    check(report["server_kept_online_for_operator"] is True
          and report["sapio_tee_stopped_before_recovery"] is True,
          "operator actor and unavailable user cosigner were not separated")
    check(report["bitcoin_height_at_signer_shutdown"] == shutdown["bitcoin_height_at_shutdown"],
          "shutdown height differs")
    check(shutdown["sapio_api_8000_refused"] is True and shutdown["sapio_oracle_8367_refused"] is True,
          "Sapio signer ports remained live")
    check(shutdown["signed_recovery_transactions_unpublished"] is True,
          "saved honest recovery already published before signer outage")
    check("captaind" not in shutdown["stopped_in_order"],
          "operator watchman must be live while user cosigner is down")

    alice_ancestors = [
        (id, tx) for id, tx in paths["alice"]["txs"].items() if tx["role"] == "ancestor"
    ]
    check(alice_ancestors, "Alice has no saved ancestor")
    first, first_tx = alice_ancestors[0]
    check(first in paths["bob"]["txs"], "Bob lacks the same initial signed ancestor")
    check(report["alice_first_ancestor_txid"] == first
          and report["alice_first_ancestor_wtxid"] == first_tx["wtxid"],
          "Alice's reported first signed ancestor changed")
    check(report["bitcoin_height_at_signer_shutdown"] <
          report["alice_first_ancestor_height"] < report["expiry_height"],
          "Alice's first ancestor did not confirm before the expiry race")
    check(report["operator_sweep_earliest_height"] > report["alice_first_ancestor_height"]
          and report["operator_sweep_earliest_height"] >= report["expiry_height"],
          "sweep not staged after Alice's first confirmed ancestor and expiry")

    swept = set(report["watchman_claimed_outpoints"])
    anchor = report["shared_chain_anchor"]
    ancestors = {id for id, tx in honest.items() if tx["role"] == "ancestor"}
    check(any(point == anchor or point.split(":")[0] in ancestors for point in swept),
          "no real watchman ClaimBroadcast affected the recovery chain")

    operator = {}
    conflicts = []
    for row in report["operator_signed_spends"]:
        txid, wtxid = tx_ids(row["tx_hex"])
        check(txid == row["txid"] and wtxid == row["wtxid"] and wtxid != txid,
              "operator transaction has a changed txid or no signed witness")
        check(txid not in honest and txid not in operator,
              "operator transaction is duplicate or was signed by the earlier holder")
        check(row["block_height"] >= report["operator_sweep_earliest_height"],
              "fresh operator transaction confirmed before the actual sweep trigger")
        inputs = signed_inputs(row["tx_hex"])
        check(inputs, "operator sweep has no inputs")
        check(any(point == anchor or point.split(":")[0] in ancestors for point in inputs),
              "operator sweep does not spend the actual recovery chain")
        operator[txid] = { "wtxid": wtxid, "inputs": inputs, "block_height": row["block_height"] }
        for honest_id, record in honest.items():
            for point in set(inputs).intersection(record["inputs"]):
                conflicts.append({
                    "operator_txid": txid,
                    "honest_txid": honest_id,
                    "conflicted_outpoint": point,
                    "honest_used_by": sorted(record["used_by"]),
                    "honest_role": record["role"],
                })
    check(operator and conflicts, "watchman did not mine an independently signed conflicting spend")
    claimed = report["signed_input_conflicts"]
    def normalize(row):
        return (row["operator_txid"], row["honest_txid"], row["conflicted_outpoint"],
                tuple(sorted(row["honest_used_by"])), row["honest_role"])
    check(len(claimed) == len(conflicts) and
          sorted(map(normalize, claimed)) == sorted(map(normalize, conflicts)),
          "claimed watchman conflicts differ from signed Bitcoin prevouts")

    threatens_bob = any("bob" in row["honest_used_by"] for row in conflicts)
    check(report["operator_competes_with_bob"] is threatens_bob,
          "Bob conflict classification was manufactured")
    check(isinstance(report["bob_claim_confirmed"], bool) and
          isinstance(report["alice_claim_confirmed"], bool),
          "claim statuses must be measured as booleans")
    check(not (threatens_bob and report["bob_claim_confirmed"]),
          "Bob claim cannot confirm along a transaction input consumed by operator")
    check(isinstance(report["bob_native_recovery_process_ok"], bool),
          "missing independent native Bob recovery attempt")
    return {
        "proof_kind": KIND,
        **revisions,
        "shared_chain_anchor": anchor,
        "shared_chain_anchor_sats": paths["alice"]["anchor_sats"],
        "allocations_sats": ALLOCATION,
        "frozen_evidence_hashes": files,
        "frozen_manifest_sha256": sha256(manifest_path),
        "signer_shutdown_height": shutdown["bitcoin_height_at_shutdown"],
        "alice_first_signed_ancestor": {
            "txid": first, "wtxid": first_tx["wtxid"],
            "confirmed_height": report["alice_first_ancestor_height"],
        },
        "vtxo_expiry_height": report["expiry_height"],
        "watchman_trigger_height": report["operator_sweep_earliest_height"],
        "watchman_claimed_outpoints": sorted(swept),
        "operator_new_confirmed_spends": [
            {"txid": id, **entry} for id, entry in sorted(operator.items())
        ],
        "real_spent_input_conflicts": conflicts,
        "bob_conflict_on_signed_path": threatens_bob,
        "bob_native_recovery_process_completed": report["bob_native_recovery_process_ok"],
        "bob_claim_confirmed": report["bob_claim_confirmed"],
        "alice_claim_confirmed": report["alice_claim_confirmed"],
        "scope": ("actual Bitcoin Core regtest, one node; live Ark watchman expiry "
                  "sweep after a frozen Alice ancestor confirmed; no independent "
                  "verification of watchman process ownership"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--revision", action="append", default=[])
    parser.add_argument("--scenario", choices=["operator-expiry"], default="operator-expiry")
    args = parser.parse_args()
    proof = build(args.capture, dict(item.split("=", 1) for item in args.revision))
    args.output.write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("Actual operator expiry-race receipt structurally validated.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, IndexError) as exc:
        print("operator-expiry proof refused: " + str(exc), file=sys.stderr)
        if os.environ.get("GITHUB_ACTIONS") == "true":
            print("::error title=operator-expiry proof refused::" + str(exc).replace("%", "%25"))
        sys.exit(1)
