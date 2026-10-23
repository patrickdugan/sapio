import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from write_public_proof import FROZEN, build

ROOT_TX = "1" * 64
SHARED = "2" * 64
ALICE_CLAIM, BOB_CLAIM = "3" * 64, "4" * 64
BOB_PARENT = "5" * 64


def tx(txid, role, used_by, height, child):
    return {
        "role": role, "used_by": used_by, "txid": txid, "wtxid": txid[::-1] + "",
        "block_height": height, "p2a_anchor": txid + ":1", "fee_child_txid": child,
        "fee_child_wtxid": child, "external_fee_inputs": ["9" * 64 + ":0"],
        "external_fee_sats": 300,
    }


def capture():
    txs = [
        tx(SHARED, "ancestor", ["alice", "bob"], 111, "a" * 64),
        tx(ALICE_CLAIM, "claim", ["alice"], 130, "b" * 64),
        tx(BOB_PARENT, "ancestor", ["bob"], 131, "c" * 64),
        tx(BOB_CLAIM, "claim", ["bob"], 150, "d" * 64),
    ]
    holders = [
        {"holder": "alice", "controlled_outpoint": SHARED + ":0", "confirmed_claim_txid": ALICE_CLAIM,
         "confirmed_claim_wtxid": txs[1]["wtxid"], "payout_outpoint": ALICE_CLAIM + ":0", "sats": 60_000},
        {"holder": "bob", "controlled_outpoint": BOB_PARENT + ":0", "confirmed_claim_txid": BOB_CLAIM,
         "confirmed_claim_wtxid": txs[3]["wtxid"], "payout_outpoint": BOB_CLAIM + ":0", "sats": 40_000},
    ]
    return {
        "shutdown-before-recovery.json": {
            "stopped_in_order": ["alice-sdk", "bob-sdk", "sapio-tee", "captaind"],
            "sapio_api_8000_refused": True, "sapio_oracle_8367_refused": True,
            "signed_recovery_transactions_unpublished": True, "bitcoin_height_at_shutdown": 110,
        },
        "external-fee-utxos-before-shutdown.json": ["9" * 64 + ":0"],
        "confirmed-p2a-fee-children.json": {
            "alice": {"claim_txid": ALICE_CLAIM}, "bob": {"claim_txid": BOB_CLAIM},
            "real_common_root": True, "external_fee_wallet_keys_distinct_from_holders": True,
            "shared_chain_anchor": ROOT_TX + ":0", "shared_chain_anchor_sats": 120_000,
            "bitcoin_height_at_shutdown": 110, "recovery_transactions": txs,
        },
        "two-holder-pre-spend-report.json": {
            "offline": {"total_protected_sats": 100_000, "selected_paths_nonconflicting": True},
            "two_holder": {"total_payout_sats": 100_000, "holders": holders},
        },
        "two-holder-redemptions.json": {
            "independent_spends_confirmed": True,
            "redemptions": [
                {"holder": "alice", "wallet": "alice-recovered", "txid": "e" * 64, "wtxid": "e" * 64,
                 "spent_outpoint": ALICE_CLAIM + ":0", "paid_sats": 59_800, "fee_sats": 200},
                {"holder": "bob", "wallet": "bob-recovered", "txid": "f" * 64, "wtxid": "f" * 64,
                 "spent_outpoint": BOB_CLAIM + ":0", "paid_sats": 39_800, "fee_sats": 200},
            ],
        },
    }


class PublicProofTest(unittest.TestCase):
    def write(self, data):
        root = Path(self.tmp.name)
        for path in root.iterdir():
            path.unlink()
        files = []
        for name in FROZEN:
            raw = json.dumps({"private": name}).encode()
            (root / name).write_bytes(raw)
            files.append({"file": name, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)})
        manifest = {"schema": 1, "fixture": "local-regtest-saplingos-signed-evidence", "files": files}
        (root / "frozen-evidence-before-shutdown.json").write_text(json.dumps(manifest, indent=2))
        for name, value in data.items():
            (root / name).write_text(json.dumps(value))
        return root

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def test_valid_capture_publishes_only_public_facts(self):
        proof = build(self.write(capture()), {"sdk_revision": "b45e5ef"})
        self.assertEqual(proof["conservation"]["allocations"], {"alice": 60_000, "bob": 40_000})
        self.assertEqual(len(proof["recovery_transactions"]), 4)
        self.assertEqual(len(proof["frozen_manifest_sha256"]), 64)
        text = json.dumps(proof)
        self.assertNotIn("private", text)

    def rejects(self, mutate, root_mutation=None):
        data = copy.deepcopy(capture())
        mutate(data)
        root = self.write(data)
        if root_mutation:
            root_mutation(root)
        with self.assertRaises((ValueError, KeyError)):
            build(root, {})

    def test_rejects_changed_signed_export(self):
        self.rejects(lambda d: None, lambda r: (r / "bob-recovery.json").write_text("{}"))

    def test_rejects_recovery_before_shutdown(self):
        def early(d):
            d["confirmed-p2a-fee-children.json"]["recovery_transactions"][0]["block_height"] = 110
        self.rejects(early)

    def test_rejects_unshared_ancestry(self):
        def split(d):
            d["confirmed-p2a-fee-children.json"]["recovery_transactions"][0]["used_by"] = ["alice"]
        self.rejects(split)

    def test_rejects_witness_mismatch(self):
        def witness(d):
            d["two-holder-pre-spend-report.json"]["two_holder"]["holders"][0]["confirmed_claim_wtxid"] = "0" * 64
        self.rejects(witness)

    def test_rejects_wrong_allocation(self):
        def skew(d):
            holders = d["two-holder-pre-spend-report.json"]["two_holder"]["holders"]
            holders[0]["sats"], holders[1]["sats"] = 50_000, 50_000
        self.rejects(skew)

    def test_rejects_redemption_of_other_coin(self):
        def swap(d):
            d["two-holder-redemptions.json"]["redemptions"][0]["spent_outpoint"] = BOB_CLAIM + ":0"
        self.rejects(swap)

    def test_rejects_shared_redemption_wallet(self):
        def share(d):
            d["two-holder-redemptions.json"]["redemptions"][1]["wallet"] = "alice-recovered"
        self.rejects(share)


if __name__ == "__main__":
    unittest.main()
