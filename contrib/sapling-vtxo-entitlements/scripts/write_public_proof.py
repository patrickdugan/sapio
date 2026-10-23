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
PROOF_KINDS = {
    "common-root": "actual-pinned-saplingos-common-root-regtest",
    "separate-roots": "actual-pinned-saplingos-separate-roots-regtest",
}


def _varint(raw, at):
    first = raw[at]
    if first < 0xFD:
        return first, at + 1
    width = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
    return int.from_bytes(raw[at + 1:at + 1 + width], "little"), at + 1 + width


def _dsha256_id(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()[::-1].hex()


def tx_ids(tx_hex):
    """(txid, wtxid) of a consensus-encoded transaction, witness stripped for txid."""
    raw = bytes.fromhex(tx_hex)
    segwit = raw[4:6] == b"\x00\x01"
    at = 6 if segwit else 4
    body_start = at
    count, at = _varint(raw, at)
    for _ in range(count):
        at += 36
        length, at = _varint(raw, at)
        at += length + 4
    count_out, at = _varint(raw, at)
    for _ in range(count_out):
        at += 8
        length, at = _varint(raw, at)
        at += length
    body_end = at
    if segwit:
        for _ in range(count):
            items, at = _varint(raw, at)
            for _ in range(items):
                length, at = _varint(raw, at)
                at += length
    check(len(raw) == at + 4, "malformed saved transaction")
    stripped = raw[:4] + raw[body_start:body_end] + raw[at:]
    return _dsha256_id(stripped), _dsha256_id(raw)


def selected_paths(root, holders):
    """Derive each holder's saved recovery path from its frozen signed export.

    The published rows are checked against these, so neither a relabelled
    `used_by` list nor an arbitrary funding root can pass.
    """
    paths = {}
    for name in holders:
        bundle = load(root, f"{name}-recovery.json")
        check(len(bundle["targets"]) == 1, name + " export must select exactly one position")
        records = [r for r in bundle["recoveries"]
                   if r["controlled_outpoint"] == bundle["targets"][0]]
        check(len(records) == 1, name + " export lacks one selected recovery record")
        record = records[0]
        txs = {}
        for tx_hex in record["ancestors"]:
            txid, wtxid = tx_ids(tx_hex)
            txs[txid] = ("ancestor", wtxid)
        claim_txid, claim_wtxid = tx_ids(record["claim"])
        txs[claim_txid] = ("claim", claim_wtxid)
        prevout = bytes.fromhex(record["chain_anchor_prevout"])
        paths[name] = {
            "txs": txs,
            "claim_txid": claim_txid,
            "chain_anchor": record["chain_anchor"],
            "chain_anchor_sats": int.from_bytes(prevout[:8], "little"),
        }
    return paths


def load(root, name):
    return json.loads((root / name).read_text(encoding="utf-8"))


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(condition, message):
    if not condition:
        raise ValueError(message)


def build(root, revisions, scenario="common-root"):
    check(scenario in PROOF_KINDS, "unknown scenario " + str(scenario))
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

    check(fees["external_fee_wallet_keys_distinct_from_holders"] is True, "sponsor keys not distinct")
    check(shutdown["signed_recovery_transactions_unpublished"] is True,
          "recovery transactions were published before shutdown")
    height = shutdown["bitcoin_height_at_shutdown"]
    check(fees["bitcoin_height_at_shutdown"] == height, "two different shutdown heights")
    check(isinstance(sponsor, list) and sponsor, "no pre-shutdown sponsor coins recorded")

    txs = fees["recovery_transactions"]
    check(all(t["block_height"] > height for t in txs), "a recovery confirmed before shutdown")
    check(len({t["fee_child_txid"] for t in txs}) == len(txs), "one fee child bumped two parents")

    # Rows, roles, wtxids and holder membership must be exactly those of the
    # hash-frozen signed exports, never taken from the capture's own labels.
    paths = selected_paths(root, ALLOCATION)
    derived = {}
    for name, path in paths.items():
        for txid, (role, wtxid) in path["txs"].items():
            entry = derived.setdefault(txid, {"role": role, "wtxid": wtxid, "used_by": []})
            check(entry["role"] == role and entry["wtxid"] == wtxid,
                  "two exports disagree on a signed transaction")
            entry["used_by"].append(name)
    check(len({t["txid"] for t in txs}) == len(txs), "duplicate recovery row")
    check({t["txid"] for t in txs} == set(derived),
          "published recovery rows differ from the frozen signed exports")
    for row in txs:
        expected = derived[row["txid"]]
        check(row["role"] == expected["role"] and row["wtxid"] == expected["wtxid"]
              and sorted(row["used_by"]) == sorted(expected["used_by"]),
              "recovery row " + row["txid"] + " differs from the frozen exports")
    shared = [txid for txid, entry in derived.items() if len(entry["used_by"]) == 2]

    if scenario == "common-root":
        check(fees["real_common_root"] is True, "fixture did not use one funded root")
        check(any(derived[txid]["role"] == "ancestor" for txid in shared),
              "the two recoveries share no signed ancestor")
        check(paths["alice"]["chain_anchor"] == paths["bob"]["chain_anchor"]
              == fees["shared_chain_anchor"], "exports do not share the recorded root")
        check(paths["alice"]["chain_anchor_sats"] == fees["shared_chain_anchor_sats"],
              "recorded root value differs from the signed export")
        check(fees["shared_chain_anchor_sats"] >= 100_000, "root cannot back both claims")
        conservation = {
            "shared_chain_anchor": fees["shared_chain_anchor"],
            "shared_chain_anchor_sats": fees["shared_chain_anchor_sats"],
        }
    else:
        check(fees["real_common_root"] is False and fees["separate_roots"] is True,
              "fixture did not use separately funded roots")
        check(not shared, "separately boarded recoveries share a signed transaction")
        anchors = fees["chain_anchors"]
        check(set(anchors) == set(ALLOCATION), "missing holder funding root")
        check(len({a["outpoint"] for a in anchors.values()}) == 2, "holders share a funding root")
        for name, sats in ALLOCATION.items():
            check(anchors[name]["outpoint"] == paths[name]["chain_anchor"]
                  and anchors[name]["sats"] == paths[name]["chain_anchor_sats"],
                  name + "'s recorded root differs from its signed export")
            check(anchors[name]["sats"] >= sats, name + "'s root cannot back its claim")
        conservation = {"chain_anchors": anchors}
    claims = {t["txid"]: t for t in txs if t["role"] == "claim"}

    check(audit["offline"]["total_protected_sats"] == 100_000, "protected total is not 100,000")
    check(audit["offline"]["selected_paths_nonconflicting"] is True, "selected paths conflict")
    check(audit["two_holder"]["total_payout_sats"] == 100_000, "payout total is not 100,000")
    holders = {h["holder"]: h for h in audit["two_holder"]["holders"]}
    check({k: v["sats"] for k, v in holders.items()} == ALLOCATION, "allocation differs from terms")
    for name, holder in holders.items():
        claim = claims.get(holder["confirmed_claim_txid"])
        check(claim is not None and claim["used_by"] == [name], name + " claim missing from chain")
        check(claim["txid"] == paths[name]["claim_txid"], name + " claim is not its signed export's")
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
        "proof_kind": PROOF_KINDS[scenario],
        **revisions,
        "conservation": {
            **conservation,
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
    parser.add_argument("--scenario", choices=sorted(PROOF_KINDS), default="common-root")
    args = parser.parse_args()
    revisions = dict(item.split("=", 1) for item in args.revision)
    proof = build(args.capture, revisions, args.scenario)
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
