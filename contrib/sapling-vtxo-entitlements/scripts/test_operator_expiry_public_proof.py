import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from test_write_public_proof import graph, key_script, make_tx, tx_ids
from write_operator_expiry_public_proof import KIND, build
from write_public_proof import FROZEN


def fixture():
    bundles = graph(False)
    alice = bundles["alice"]["recoveries"][0]
    bob = bundles["bob"]["recoveries"][0]
    shared = alice["ancestors"][0]
    bob_last_parent = bob["ancestors"][-1]
    spent = tx_ids(bob["ancestors"][-2])[0] + ":1"
    operator_tx = make_tx(spent, [(40_000, key_script(33)), (0, "51024e73")], 55)
    operator_id, operator_wid = tx_ids(operator_tx)
    honest_id = tx_ids(bob_last_parent)[0]
    root = alice["chain_anchor"]
    terms = {
        "network": "regtest",
        "targets": [
            {
                "outpoint": bundles[name]["targets"][0],
                "beneficiaries": [{
                    "holder": name, "script_pubkey_hex": key_script(tag), "sats": sats,
                }],
            }
            for name, tag, sats in (("alice", 10, 60_000), ("bob", 11, 40_000))
        ],
    }
    payload = {
        "scenario": "operator-fresh-watchman-expiry-sweep",
        "shared_chain_anchor": root,
        "bitcoin_height_at_signer_shutdown": 110,
        "server_kept_online_for_operator": True,
        "sapio_tee_stopped_before_recovery": True,
        "alice_first_ancestor_txid": tx_ids(shared)[0],
        "alice_first_ancestor_wtxid": tx_ids(shared)[1],
        "alice_first_ancestor_height": 113,
        "expiry_height": 200,
        "operator_sweep_earliest_height": 220,
        "watchman_claimed_outpoints": [root],
        "operator_signed_spends": [{
            "tx_hex": operator_tx, "txid": operator_id,
            "wtxid": operator_wid, "block_height": 221,
        }],
        "signed_input_conflicts": [{
            "operator_txid": operator_id,
            "honest_txid": honest_id,
            "conflicted_outpoint": spent,
            "honest_used_by": ["bob"],
            "honest_role": "ancestor",
        }],
        "operator_competes_with_bob": True,
        "bob_native_recovery_process_ok": False,
        "bob_claim_confirmed": False,
        "alice_claim_confirmed": False,
    }
    return bundles, terms, payload


class OperatorExpiryProofTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, bundles, terms, payload):
        root = Path(self.tmp.name)
        for path in root.iterdir():
            path.unlink()
        data = {
            "two-holder-terms.json": json.dumps(terms).encode(),
            "alice-recovery.json": json.dumps(bundles["alice"]).encode(),
            "bob-recovery.json": json.dumps(bundles["bob"]).encode(),
        }
        files = []
        for name in FROZEN:
            path = root / name
            path.write_bytes(data[name])
            files.append({
                "file": name, "sha256": hashlib.sha256(data[name]).hexdigest(),
                "bytes": len(data[name]),
            })
        (root / "frozen-evidence-before-shutdown.json").write_text(
            json.dumps({"files": files, "schema": 1})
        )
        (root / "shutdown-before-recovery.json").write_text(json.dumps({
            "bitcoin_height_at_shutdown": 110,
            "stopped_in_order": ["alice-sdk", "bob-sdk", "sapio-tee"],
            "sapio_api_8000_refused": True,
            "sapio_oracle_8367_refused": True,
            "signed_recovery_transactions_unpublished": True,
        }))
        (root / "operator-expiry-race.json").write_text(json.dumps(payload))
        return root

    def rejects(self, bundles=None, terms=None, payload=None):
        b, t, p = fixture()
        if bundles:
            bundles(b)
        if terms:
            terms(t)
        if payload:
            payload(p)
        with self.assertRaises((ValueError, KeyError, TypeError, IndexError, StopIteration)):
            build(self.write(b, t, p))

    def test_valid_frozen_two_holder_watchman_conflict(self):
        b, t, p = fixture()
        proof = build(self.write(b, t, p), {"sdk_revision": "pinned"})
        self.assertEqual(proof["proof_kind"], KIND)
        self.assertTrue(proof["bob_conflict_on_signed_path"])
        self.assertEqual(proof["shared_chain_anchor_sats"], 120_000)
        self.assertNotIn("tx_hex", json.dumps(proof))

    def test_no_watchman_event(self):
        self.rejects(payload=lambda p: p.update(watchman_claimed_outpoints=[]))

    def test_wrong_operator_transaction(self):
        self.rejects(payload=lambda p: p["operator_signed_spends"][0].update(txid="f" * 64))

    def test_missing_bitcoin_witness(self):
        self.rejects(payload=lambda p: p["operator_signed_spends"][0].update(wtxid="f" * 64))

    def test_hypothetical_attack_missing_actual_input_conflict(self):
        self.rejects(payload=lambda p: p["signed_input_conflicts"][0].update(
            conflicted_outpoint="b" * 64 + ":0"
        ))

    def test_bob_reported_safe_despite_spent_ancestor(self):
        self.rejects(payload=lambda p: p.update(bob_claim_confirmed=True))

    def test_false_bob_conflict_classification(self):
        self.rejects(payload=lambda p: p.update(operator_competes_with_bob=False))

    def test_sweep_precedes_alice_recovery(self):
        self.rejects(payload=lambda p: p["operator_signed_spends"][0].update(block_height=112))

    def test_unfrozen_recovery(self):
        self.rejects(bundles=lambda b: b["alice"]["recoveries"][0].update(
            chain_anchor="0" * 64 + ":0"
        ))

    def test_one_satoshi_redirect_in_agreed_terms(self):
        self.rejects(terms=lambda t: t["targets"][1]["beneficiaries"][0].update(sats=39_999))

    def test_recipient_script_redirect(self):
        self.rejects(terms=lambda t: t["targets"][0]["beneficiaries"][0].update(
            script_pubkey_hex=key_script(99)
        ))

    def test_ark_operator_marked_offline(self):
        def counterfeit(p):
            p["server_kept_online_for_operator"] = False
        self.rejects(payload=counterfeit)


if __name__ == "__main__":
    unittest.main()
