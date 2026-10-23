#!/usr/bin/env python3
"""Check a genuine common-root capture and write its public proof receipt.

Reads the private capture directory written by
``sapio_real_common_anchor_two_holder_recovery`` and emits only public
regtest facts: txids, wtxids, outpoints, heights, amounts and SHA-256
digests. The signed recovery bundles, terms, wallet seeds and RPC details
are never copied into the output.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

FROZEN = ("two-holder-terms.json", "alice-recovery.json", "bob-recovery.json")
ALLOCATION = {"alice": 60_000, "bob": 40_000}


def load(root, name):
    return json.loads((root / name).read_text(encoding="utf-8"))


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(condition, message):
    if not condition:
        raise ValueError(message)


def build(root, revisions):
    manifest_path = root / "frozen-evidence-before-shutdown.json"
    signed = json.loads(manifest_path.read_text(encoding="utf-8"))
    shutdown = load(root, "shutdown-before-recovery.json")
    sponsor = load(root, "external-fee-utxos-before-shutdown.json")
    fees = load(root, "confirmed-p2a-fee-children.json")
    audit = load(root, "two-holder-pre-spend-report.json")
    redeemed = load(root, "two-holder-redemptions.json")

    # The saved evidence still hashes to the pre-shutdown manifest.
    files = signed["files"]
    check(sorted(f["file"] for f in files) == sorted(FROZEN), "unexpected frozen file set")
    for record in files:
        path = root / record["file"]
        check(sha256(path) == record["sha256"], record["file"] + " changed after shutdown")
        check(path.stat().st_size == record["bytes"], record["file"] + " size changed")

    check(fees["real_common_root"] is True, "fixture did not use one funded root")
    check(fees["external_fee_wallet_keys_distinct_from_holders"] is True, "sponsor keys not distinct")
    check(shutdown["signed_recovery_transactions_unpublished"] is True,
          "recovery transactions were published before shutdown")
    height = shutdown["bitcoin_height_at_shutdown"]
    check(fees["bitcoin_height_at_shutdown"] == height, "two different shutdown heights")
    check(isinstance(sponsor, list) and sponsor, "no pre-shutdown sponsor coins recorded")

    txs = fees["recovery_transactions"]
    check(all(t["block_height"] > height for t in txs), "a recovery confirmed before shutdown")
    check(any(t["role"] == "ancestor" and sorted(t["used_by"]) == ["alice", "bob"] for t in txs),
          "the two recoveries share no signed ancestor")
    check(len({t["fee_child_txid"] for t in txs}) == len(txs), "one fee child bumped two parents")
    claims = {t["txid"]: t for t in txs if t["role"] == "claim"}

    check(audit["offline"]["total_protected_sats"] == 100_000, "protected total is not 100,000")
    check(audit["offline"]["selected_paths_nonconflicting"] is True, "selected paths conflict")
    check(audit["two_holder"]["total_payout_sats"] == 100_000, "payout total is not 100,000")
    check(fees["shared_chain_anchor_sats"] >= 100_000, "root cannot back both claims")
    holders = {h["holder"]: h for h in audit["two_holder"]["holders"]}
    check({k: v["sats"] for k, v in holders.items()} == ALLOCATION, "allocation differs from terms")
    for name, holder in holders.items():
        claim = claims.get(holder["confirmed_claim_txid"])
        check(claim is not None and claim["used_by"] == [name], name + " claim missing from chain")
        check(claim["wtxid"] == holder["confirmed_claim_wtxid"], name + " witness bytes differ")
        check(fees[name]["claim_txid"] == claim["txid"], name + " fee child names another claim")

    check(redeemed["independent_spends_confirmed"] is True, "redemptions not confirmed")
    spends = {p["holder"]: p for p in redeemed["redemptions"]}
    check(set(spends) == set(ALLOCATION), "missing holder redemption")
    check(len({p["txid"] for p in spends.values()}) == 2, "holders share a redemption")
    check(len({p["wallet"] for p in spends.values()}) == 2, "holders share a wallet")
    for name, spend in spends.items():
        check(spend["spent_outpoint"] == holders[name]["payout_outpoint"],
              name + " redemption spends another coin")

    return {
        "proof_kind": "actual-pinned-saplingos-common-root-regtest",
        **revisions,
        "conservation": {
            "shared_chain_anchor": fees["shared_chain_anchor"],
            "shared_chain_anchor_sats": fees["shared_chain_anchor_sats"],
            "selected_sats": 100_000,
            "allocations": ALLOCATION,
        },
        "pre_shutdown_export_hashes": files,
        "frozen_manifest_sha256": sha256(manifest_path),
        "shutdown": {
            "stopped_in_order": shutdown["stopped_in_order"],
            "bitcoin_height_at_shutdown": height,
            "sapio_ports_refused": shutdown["sapio_api_8000_refused"]
            and shutdown["sapio_oracle_8367_refused"],
        },
        "external_sponsor_utxos_before_shutdown": sorted(sponsor),
        "recovery_transactions": txs,
        "holder_claims": [
            {
                "holder": name,
                "controlled_outpoint": h["controlled_outpoint"],
                "claim_txid": h["confirmed_claim_txid"],
                "claim_wtxid": h["confirmed_claim_wtxid"],
                "payout_outpoint": h["payout_outpoint"],
                "sats": h["sats"],
            } for name, h in sorted(holders.items())
        ],
        "independent_redemptions": [
            {
                "holder": name,
                "txid": p["txid"],
                "wtxid": p["wtxid"],
                "spent_outpoint": p["spent_outpoint"],
                "paid_sats": p["paid_sats"],
                "fee_sats": p["fee_sats"],
            } for name, p in sorted(spends.items())
        ],
        "evidence_unchanged_through_final_spends": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--revision", action="append", default=[], help="name=value")
    args = parser.parse_args()
    revisions = dict(item.split("=", 1) for item in args.revision)
    proof = build(args.capture, revisions)
    args.output.write_text(json.dumps(proof, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print("Genuine common-root regtest evidence validated.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError) as exc:
        print("public proof refused: " + str(exc), file=sys.stderr)
        if os.environ.get("GITHUB_ACTIONS") == "true":
            # Job logs need sign-in; annotations are publicly readable.
            print("::error title=public proof refused::" + str(exc).replace("%", "%25"))
        sys.exit(1)
