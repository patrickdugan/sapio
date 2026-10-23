#!/usr/bin/env python3
"""Validate a genuine stale-branch regtest race from frozen signed exports.

A positive receipt means the previously signed sender branch confirmed and
conflicted with Alice/Bob's later sibling-recovery ancestry. It is a measured
negative outcome for the holders, not a claim of successful joint recovery.
Private exports stay inside the CI runner. Consensus signatures and chain
confirmations are checked by the Rust/Bitcoin Core fixture; this independent
receipt validator re-derives the conflicting graph and transaction identities.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

from write_public_proof import ALLOCATION, FROZEN, _varint, check, load, sha256, tx_ids

PARTICIPANTS = ("alice", "bob", "stale-sender")
FROZEN_RACE = (*FROZEN, "stale-sender-recovery.json")
KIND = "actual-pinned-saplingos-stale-sender-shared-root-regtest"


def signed_inputs(raw_hex):
    """Read consensus prevouts; tx_ids also checks witness framing/end-of-data."""
    tx_ids(raw_hex)
    raw = bytes.fromhex(raw_hex)
    at = 6 if raw[4:6] == b"\x00\x01" else 4
    size, at = _varint(raw, at)
    check(0 < size <= (len(raw) - at) // 41, "invalid transaction input count")
    result = []
    for _ in range(size):
        check(at + 36 <= len(raw), "truncated transaction input")
        txid = raw[at:at + 32][::-1].hex()
        vout = int.from_bytes(raw[at + 32:at + 36], "little")
        at += 36
        script_size, at = _varint(raw, at)
        check(at + script_size + 4 <= len(raw), "truncated transaction input script")
        at += script_size + 4
        result.append(f"{txid}:{vout}")
    return result


def saved_path(root, name):
    bundle = load(root, f"{name}-recovery.json")
    check(len(bundle["targets"]) == 1, f"{name}: expected one selected target")
    records = [record for record in bundle["recoveries"]
               if record["controlled_outpoint"] == bundle["targets"][0]]
    check(len(records) == 1, f"{name}: missing selected signed recovery")
    record = records[0]
    prevout = bytes.fromhex(record["chain_anchor_prevout"])
    check(len(prevout) >= 8, f"{name}: missing authenticated root value")
    txs = {}
    for tx_hex, role in (
        *((raw, "ancestor") for raw in record["ancestors"]),
        (record["claim"], "claim"),
    ):
        txid, wtxid = tx_ids(tx_hex)
        check(txid not in txs, f"{name}: duplicate saved transaction")
        txs[txid] = {"wtxid": wtxid, "role": role, "inputs": signed_inputs(tx_hex)}
    return {
        "target": bundle["targets"][0],
        "anchor": record["chain_anchor"],
        "anchor_sats": int.from_bytes(prevout[:8], "little"),
        "claim_txid": tx_ids(record["claim"])[0],
        "txs": txs,
    }


def derive_conflicts(paths):
    honest = {}
    for name in ALLOCATION:
        for txid, tx in paths[name]["txs"].items():
            if txid not in honest:
                honest[txid] = {**tx, "used_by": []}
            else:
                check(honest[txid]["wtxid"] == tx["wtxid"]
                      and honest[txid]["role"] == tx["role"]
                      and honest[txid]["inputs"] == tx["inputs"],
                      "different signed bytes for shared recovery transaction")
            honest[txid]["used_by"].append(name)

    conflicts = set()
    for stale_id, stale in paths["stale-sender"]["txs"].items():
        for honest_id, current in honest.items():
            if stale_id == honest_id:
                check(stale["wtxid"] == current["wtxid"], "shared txid changed witness")
                continue
            for point in set(stale["inputs"]).intersection(current["inputs"]):
                conflicts.add((stale_id, honest_id, point,
                               tuple(sorted(current["used_by"])), current["role"]))
    return honest, conflicts


def build(root, revisions):
    manifest_path = root / "frozen-evidence-before-shutdown.json"
    manifest = load(root, manifest_path.name)
    files = manifest["files"]
    check(sorted(row["file"] for row in files) == sorted(FROZEN_RACE),
          "frozen race must contain exactly the three parties and agreed terms")
    for row in files:
        file_path = root / row["file"]
        check(sha256(file_path) == row["sha256"] and file_path.stat().st_size == row["bytes"],
              row["file"] + " changed after pre-shutdown freeze")

    paths = {name: saved_path(root, name) for name in PARTICIPANTS}
    check(len({paths[n]["anchor"] for n in PARTICIPANTS}) == 1,
          "stale sender and new holders do not share an on-chain root")
    check(len({paths[n]["anchor_sats"] for n in PARTICIPANTS}) == 1,
          "root amounts disagree across signed exports")
    check(paths["alice"]["anchor_sats"] == 120_000,
          "race fixture must pin the 120,000-sat original root")
    honest, conflicts = derive_conflicts(paths)
    check(conflicts, "no genuinely conflicting signed transaction inputs")
    check(any("bob" in used_by for _, _, _, used_by, _ in conflicts),
          "rival branch does not threaten Bob's signed ancestry")
    check(any("alice" in used_by for _, _, _, used_by, _ in conflicts),
          "rival branch does not threaten Alice's signed ancestry")

    shutdown = load(root, "shutdown-before-recovery.json")
    check(shutdown["signed_recovery_transactions_unpublished"] is True,
          "honest transactions were already published before outage")
    check(shutdown["sapio_api_8000_refused"] is True
          and shutdown["sapio_oracle_8367_refused"] is True,
          "Sapio signer ports were reachable")
    height = shutdown["bitcoin_height_at_shutdown"]
    receipt = load(root, "stale-branch-race.json")
    check(receipt["scenario"] == "stale-sender-signed-branch", "wrong race scenario")
    check(receipt["bitcoin_height_at_shutdown"] == height, "mismatched shutdown tip")
    check(receipt["shared_chain_anchor"] == paths["alice"]["anchor"],
          "receipt replaced the actual signed funding root")
    check(receipt["stale_sender_controlled_outpoint"] == paths["stale-sender"]["target"],
          "receipt misidentified the stale sender position")
    check(receipt["stale_sender_claim_txid"] == paths["stale-sender"]["claim_txid"],
          "receipt claim differs from frozen sender signature")
    check(receipt["stale_sender_claim_confirmed"] is True,
          "stale signed claim never confirmed")
    check(receipt["alice_claim_confirmed"] is False
          and receipt["bob_claim_confirmed"] is False,
          "honest claimant confirmation contradicts the claimed race outcome")
    check(receipt["external_fee_sponsor_used"] is True, "no independent fee sponsor")

    captured = receipt["signed_input_conflicts"]
    captured_set = set()
    for row in captured:
        captured_set.add((row["stale_txid"], row["honest_txid"],
                          row["conflicted_outpoint"], tuple(sorted(row["honest_used_by"])),
                          row["honest_role"]))
    check(len(captured_set) == len(captured) and captured_set == conflicts,
          "self-reported conflicts differ from independently decoded signed inputs")

    observed = receipt["stale_recovery_transactions"]
    check(len({r["txid"] for r in observed}) == len(observed),
          "duplicate confirmed stale transactions")
    check({r["txid"] for r in observed} == set(paths["stale-sender"]["txs"]),
          "confirmed stale transaction set differs from signed export")
    for row in observed:
        expected = paths["stale-sender"]["txs"][row["txid"]]
        check(row["wtxid"] == expected["wtxid"] and row["role"] == expected["role"]
              and row["used_by"] == ["stale-sender"],
              "confirmed stale transaction bytes or role differ from frozen export")
        check(row["block_height"] > height,
              "stale claim was confirmed before shutdown")
        check(row["external_fee_inputs"] and row["external_fee_sats"] > 0,
              "stale transaction lacks a funded P2A child")

    check(paths["alice"]["claim_txid"] in honest and paths["bob"]["claim_txid"] in honest,
          "honest signed claim absent from reconstructed graph")
    return {
        "proof_kind": KIND,
        **revisions,
        "shared_chain_anchor": paths["alice"]["anchor"],
        "shared_chain_anchor_sats": paths["alice"]["anchor_sats"],
        "honest_allocations": ALLOCATION,
        "frozen_export_hashes": files,
        "frozen_manifest_sha256": sha256(manifest_path),
        "shutdown_height": height,
        "signed_input_conflicts": captured,
        "stale_sender_claim_txid": paths["stale-sender"]["claim_txid"],
        "stale_recovery_transactions": observed,
        "observed_claims": {
            "stale_sender": "confirmed",
            "alice": "unconfirmed",
            "bob": "unconfirmed",
        },
        "bob_recovery_under_stale_branch": "blocked_by_confirmed_double_spend",
        "scope": "adversarially published old valid sender branch after cooperative arkoor transfer; single-node regtest",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--revision", action="append", default=[])
    parser.add_argument("--scenario", choices=["stale-race"], default="stale-race")
    args = parser.parse_args()
    revisions = dict(item.split("=", 1) for item in args.revision)
    proof = build(args.capture, revisions)
    args.output.write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("Real stale-sender competing-branch evidence validated.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError, IndexError) as exc:
        print("stale-race proof refused: " + str(exc), file=sys.stderr)
        if os.environ.get("GITHUB_ACTIONS") == "true":
            print("::error title=stale-race proof refused::" + str(exc).replace("%", "%25"))
        sys.exit(1)
