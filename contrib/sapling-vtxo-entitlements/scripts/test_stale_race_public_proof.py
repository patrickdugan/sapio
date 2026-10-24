import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from test_write_public_proof import bundle, graph, key_script, make_tx, tx_ids
from write_stale_race_public_proof import (
    FROZEN_RACE, KIND, build, derive_conflicts, saved_path, signed_inputs
)


def fixtures():
    honest = graph(False)
    shared_parent = honest["alice"]["recoveries"][0]["ancestors"][0]
    first_child = tx_ids(shared_parent)[0] + ":0"
    root_point = "1" * 64 + ":0"
    old_claim = make_tx(first_child, [(120_000, key_script(99)), (0, "51024e73")], 99)
    stale = bundle(first_child, [shared_parent], old_claim, root_point, 120_000)
    return {**honest, "stale-sender": stale}


class StaleRaceProofTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, bundles):
        root = Path(self.tmp.name)
        for item in root.iterdir():
            item.unlink()
        terms = {"version": 1, "network": "regtest", "private": "test-only", "targets": [
            {
                "outpoint": bundles[name]["targets"][0],
                "beneficiaries": [{
                    "holder": name, "sats": sats,
                    "script_pubkey_hex": key_script(tag),
                }],
            }
            for name, sats, tag in (("alice", 60_000, 10), ("bob", 40_000, 11))
        ]}
        contents = {"two-holder-terms.json": json.dumps(terms).encode()}
        for name, bundle_value in bundles.items():
            contents[f"{name}-recovery.json"] = json.dumps(bundle_value).encode()
        files = []
        for name in FROZEN_RACE:
            raw = contents[name]
            (root / name).write_bytes(raw)
            files.append({
                "file": name, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
            })
        (root / "frozen-evidence-before-shutdown.json").write_text(
            json.dumps({"schema": 1, "files": files})
        )
        (root / "shutdown-before-recovery.json").write_text(json.dumps({
            "signed_recovery_transactions_unpublished": True,
            "sapio_api_8000_refused": True, "sapio_oracle_8367_refused": True,
            "bitcoin_height_at_shutdown": 112,
        }))
        paths = {name: saved_path(root, name) for name in bundles}
        _, derived = derive_conflicts(paths)
        conflicts = [
            {
                "stale_txid": stale_id, "honest_txid": honest_id,
                "conflicted_outpoint": spent, "honest_used_by": list(used_by),
                "honest_role": role,
            } for stale_id, honest_id, spent, used_by, role in sorted(derived)
        ]
        rows = [
            {
                "txid": txid, "wtxid": tx["wtxid"], "role": tx["role"],
                "used_by": ["stale-sender"], "block_height": 113 + i,
                "external_fee_inputs": ["c" * 64 + ":0"],
                "external_fee_sats": 300,
            } for i, (txid, tx) in enumerate(paths["stale-sender"]["txs"].items())
        ]
        receipt = {
            "scenario": "stale-sender-signed-branch",
            "bitcoin_height_at_shutdown": 112,
            "shared_chain_anchor": paths["alice"]["anchor"],
            "stale_sender_controlled_outpoint": paths["stale-sender"]["target"],
            "stale_sender_claim_txid": paths["stale-sender"]["claim_txid"],
            "stale_sender_claim_confirmed": True,
            "alice_claim_confirmed": False,
            "bob_claim_confirmed": False,
            "external_fee_sponsor_used": True,
            "signed_input_conflicts": conflicts,
            "stale_recovery_transactions": rows,
        }
        (root / "stale-branch-race.json").write_text(json.dumps(receipt))
        return root, receipt

    def rejects(self, mutate_bundle=None, mutate_receipt=None, mutate_root=None):
        current = copy.deepcopy(fixtures())
        if mutate_bundle:
            mutate_bundle(current)
        root, receipt = self.write(current)
        if mutate_receipt:
            mutate_receipt(receipt)
            (root / "stale-branch-race.json").write_text(json.dumps(receipt))
        if mutate_root:
            mutate_root(root)
        with self.assertRaises((ValueError, KeyError, TypeError, IndexError)):
            build(root, {})

    def test_unsigned_control_does_not_get_counted_as_a_race(self):
        a = make_tx("3" * 64 + ":0", [(1_000, key_script(7))], 7)
        self.assertEqual(signed_inputs(a), ["3" * 64 + ":0"])

    def test_real_shape_has_conflicting_spent_outpoint(self):
        root, _ = self.write(fixtures())
        proof = build(root, {"sdk_revision": "pinned"})
        self.assertEqual(proof["proof_kind"], KIND)
        self.assertEqual(proof["observed_claims"]["bob"], "unconfirmed")
        self.assertEqual(proof["shared_chain_anchor_sats"], 120_000)
        self.assertGreater(len(proof["signed_input_conflicts"]), 0)
        self.assertNotIn('"private"', json.dumps(proof))

    def test_corrupted_original_signed_export(self):
        self.rejects(mutate_root=lambda root: (root / "bob-recovery.json").write_text("{}"))

    def test_one_satoshi_wrong_independent_terms(self):
        def misallocate(root):
            path = root / "two-holder-terms.json"
            terms = json.loads(path.read_text())
            terms["targets"][1]["beneficiaries"][0]["sats"] = 39_999
            # A true pre-shutdown agreement would hash this altered document.
            data = json.dumps(terms).encode()
            path.write_bytes(data)
            manifest_path = root / "frozen-evidence-before-shutdown.json"
            manifest = json.loads(manifest_path.read_text())
            row = next(r for r in manifest["files"] if r["file"] == path.name)
            row["sha256"], row["bytes"] = hashlib.sha256(data).hexdigest(), len(data)
            manifest_path.write_text(json.dumps(manifest))
        self.rejects(mutate_root=misallocate)

    def test_changed_beneficiary_script_in_frozen_terms(self):
        def redirect(root):
            path = root / "two-holder-terms.json"
            terms = json.loads(path.read_text())
            terms["targets"][0]["beneficiaries"][0]["script_pubkey_hex"] = key_script(77)
            data = json.dumps(terms).encode()
            path.write_bytes(data)
            manifest_path = root / "frozen-evidence-before-shutdown.json"
            manifest = json.loads(manifest_path.read_text())
            row = next(r for r in manifest["files"] if r["file"] == path.name)
            row["sha256"], row["bytes"] = hashlib.sha256(data).hexdigest(), len(data)
            manifest_path.write_text(json.dumps(manifest))
        self.rejects(mutate_root=redirect)

    def test_altered_stale_sender_root(self):
        self.rejects(mutate_bundle=lambda b: b["stale-sender"]["recoveries"][0].update(
            chain_anchor="2" * 64 + ":0"
        ))

    def test_unrelated_stale_spend_is_not_a_signed_conflict(self):
        self.rejects(mutate_bundle=lambda b: b["stale-sender"]["recoveries"][0].update(
            claim=make_tx("e" * 64 + ":0", [(120_000, key_script(99)), (0, "51024e73")], 99)
        ))

    def test_fake_conflict_labels(self):
        self.rejects(mutate_receipt=lambda r: r["signed_input_conflicts"][0].update(
            conflicted_outpoint="f" * 64 + ":0"
        ))

    def test_wtxid_mismatch(self):
        self.rejects(mutate_receipt=lambda r: r["stale_recovery_transactions"][0].update(
            wtxid="0" * 64
        ))

    def test_claim_without_confirmation(self):
        self.rejects(mutate_receipt=lambda r: r.update(stale_sender_claim_confirmed=False))

    def test_honest_claim_confirmation_contradicts_loss_receipt(self):
        self.rejects(mutate_receipt=lambda r: r.update(bob_claim_confirmed=True))

    def test_confirmation_before_shutdown(self):
        self.rejects(mutate_receipt=lambda r: r["stale_recovery_transactions"][0].update(
            block_height=112
        ))

    def test_fee_sponsor_required(self):
        self.rejects(mutate_receipt=lambda r: r["stale_recovery_transactions"][0].update(
            external_fee_inputs=[]
        ))

    def test_missing_actual_stale_transaction(self):
        self.rejects(mutate_receipt=lambda r: r["stale_recovery_transactions"].pop())


if __name__ == "__main__":
    unittest.main()
