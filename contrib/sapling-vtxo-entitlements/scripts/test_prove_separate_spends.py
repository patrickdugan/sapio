"""Deterministic adversarial tests for the external-wallet regtest proof."""
import copy
import unittest

from prove_separate_spends import (
    signed_redemption,
    validate_report,
    wallet_owns_payout,
)


A = "a" * 64
B = "b" * 64
X = "1" * 64
Y = "2" * 64
ALICE = "5120" + "11" * 32
BOB = "5120" + "22" * 32


def sample():
    amounts = [("alice", 60_000, ALICE, X, A), ("bob", 40_000, BOB, Y, B)]
    offline, chain, holders = [], [], []
    for label, sats, script, controlled_txid, claim in amounts:
        controlled = controlled_txid + ":0"
        payout = claim + ":0"
        offline.append({
            "outpoint": controlled, "claim_txid": claim, "claim_wtxid": claim,
            "protected_sats": sats, "readiness": "Complete",
        })
        chain.append({
            "controlled_outpoint": controlled, "claim_txid": claim, "claim_wtxid": claim,
            "confirmations": 8,
            "payouts": [{
                "holder": label, "outpoint": payout,
                "sats": sats, "unspent_at_tip": True,
            }],
        })
        holders.append({
            "holder": label, "controlled_outpoint": controlled,
            "confirmed_claim_txid": claim, "confirmed_claim_wtxid": claim, "payout_outpoint": payout,
            "script_pubkey_hex": script, "sats": sats,
            "confirmations": 8, "unspent_at_tip": True,
        })
    return {
        "offline": {"network": "regtest", "targets": offline, "total_protected_sats": 100_000},
        "chain": {
            "network": "regtest", "minimum_confirmations": 6,
            "targets": chain, "confirmed_claims_checked": True,
        },
        "two_holder": {
            "network": "regtest", "holders": holders, "total_payout_sats": 100_000,
            "distinct_confirmed_claims_checked": True,
            "separate_unspent_payouts_checked": True,
        },
    }


class FakeNode:
    def __init__(self):
        self.spendable = True
        self.payout_script = ALICE
        self.issued_fee = 500
        self.wrong_input = False
        self.wrong_witness = False
        self.confirmations = 8

    def call(self, method, *args, wallet=None):
        if method == "gettxout":
            return {"value": 0.00060000, "scriptPubKey": {"hex": self.payout_script}}
        if method == "getrawtransaction":
            return {
                "txid": A,
                "hash": B if self.wrong_witness else A,
                "confirmations": self.confirmations,
            }
        if method == "listunspent":
            return [{
                "txid": A, "vout": 0, "amount": 0.00060000,
                "scriptPubKey": ALICE, "spendable": self.spendable,
            }]
        if method == "validateaddress":
            return {"isvalid": True, "scriptPubKey": "0014" + "33" * 20}
        if method == "walletcreatefundedpsbt":
            return {"psbt": "unsigned"}
        if method == "walletprocesspsbt":
            return {"psbt": "signed", "complete": True}
        if method == "finalizepsbt":
            return {"hex": "rawtx", "complete": True}
        if method == "decoderawtransaction":
            return {
                "txid": "c" * 64,
                "vin": [{"txid": B if self.wrong_input else A, "vout": 0}],
                "vout": [{
                    "value": float((60_000 - self.issued_fee) / 100_000_000),
                    "scriptPubKey": {"hex": "0014" + "33" * 20},
                }],
            }
        raise AssertionError("unexpected method " + method)


class ReportTests(unittest.TestCase):
    def test_genuine_two_position_report_shape(self):
        receipts = validate_report(sample())
        self.assertEqual([r["holder"] for r in receipts], ["alice", "bob"])
        self.assertEqual(sum(x["sats"] for x in receipts), 100_000)

    def test_joint_claim_and_missing_confirmation(self):
        report = sample()
        report["chain"]["targets"].pop()
        with self.assertRaises(ValueError):
            validate_report(report)
        report = sample()
        report["chain"]["targets"][0]["confirmations"] = 0
        with self.assertRaises(ValueError):
            validate_report(report)

    def test_reused_script_wrong_claim_and_double_counting(self):
        report = sample()
        report["two_holder"]["holders"][1]["script_pubkey_hex"] = ALICE
        with self.assertRaises(ValueError):
            validate_report(report)
        report = sample()
        report["two_holder"]["holders"][1]["confirmed_claim_txid"] = A
        with self.assertRaises(ValueError):
            validate_report(report)
        report = sample()
        report["two_holder"]["total_payout_sats"] = 99_999
        with self.assertRaises(ValueError):
            validate_report(report)

    def test_report_witness_substitution_is_rejected(self):
        report = sample()
        report["chain"]["targets"][0]["claim_wtxid"] = B
        with self.assertRaises(ValueError):
            validate_report(report)
        report = sample()
        report["two_holder"]["holders"][1]["confirmed_claim_wtxid"] = "x" * 64
        with self.assertRaises(ValueError):
            validate_report(report)

    def test_regtest_only_and_no_spent_outputs(self):
        report = sample()
        report["chain"]["network"] = "main"
        with self.assertRaises(ValueError):
            validate_report(report)
        report = sample()
        report["two_holder"]["holders"][0]["unspent_at_tip"] = False
        with self.assertRaises(ValueError):
            validate_report(report)

    def test_wallet_must_have_actual_spending_authority(self):
        receipt = validate_report(sample())[0]
        node = FakeNode()
        self.assertTrue(wallet_owns_payout(node, receipt, "holder-alice"))
        node.spendable = False
        with self.assertRaises(ValueError):
            wallet_owns_payout(node, receipt, "watch-only")

    def test_node_witness_substitution_and_lost_confirmation_fails(self):
        receipt = validate_report(sample())[0]
        node = FakeNode()
        node.wrong_witness = True
        with self.assertRaises(ValueError):
            wallet_owns_payout(node, receipt, "holder-alice", 6)
        node.wrong_witness = False
        node.confirmations = 2
        with self.assertRaises(ValueError):
            wallet_owns_payout(node, receipt, "holder-alice", 6)

    def test_node_script_substitution_fails(self):
        receipt = validate_report(sample())[0]
        node = FakeNode()
        node.payout_script = BOB
        with self.assertRaises(ValueError):
            wallet_owns_payout(node, receipt, "holder-alice")

    def test_independent_signed_redemption_validates_input_and_fee(self):
        receipt = validate_report(sample())[0]
        node = FakeNode()
        proof = signed_redemption(node, receipt, "holder-alice", "bcrt1qtest", 2, 2_000)
        self.assertEqual(proof["fee_sats"], 500)
        self.assertEqual(proof["paid_sats"], 59_500)
        node.wrong_input = True
        with self.assertRaises(ValueError):
            signed_redemption(node, receipt, "holder-alice", "bcrt1qtest", 2, 2_000)
        node.wrong_input = False
        node.issued_fee = 5_000
        with self.assertRaises(ValueError):
            signed_redemption(node, receipt, "holder-alice", "bcrt1qtest", 2, 2_000)


if __name__ == "__main__":
    unittest.main()
