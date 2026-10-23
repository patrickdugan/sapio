import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from write_public_proof import FROZEN, build, tx_ids

P2A = "51024e73"
GENESIS_COINBASE = (
    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04"
    "ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e"
    "206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f205"
    "2a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6"
    "bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"
)


def txout(value, script_hex):
    script = bytes.fromhex(script_hex)
    return value.to_bytes(8, "little") + bytes([len(script)]) + script


def make_tx(prevout, outputs, tag, witness=True):
    """A v3 one-input transaction spending `prevout` ("txid:vout")."""
    txid, vout = prevout.split(":")
    body = bytes.fromhex(txid)[::-1] + int(vout).to_bytes(4, "little") + b"\x00" + b"\xff" * 4
    outs = b"".join(txout(v, s) for v, s in outputs)
    raw = (3).to_bytes(4, "little")
    if witness:
        raw += b"\x00\x01"
    raw += b"\x01" + body + bytes([len(outputs)]) + outs
    if witness:
        raw += b"\x01\x40" + bytes([tag]) * 64
    return (raw + b"\x00" * 4).hex()


def key_script(tag):
    return "5120" + f"{tag:02x}" * 32


def bundle(controlled, ancestors, claim, anchor, anchor_sats):
    return {
        "version": 1, "network": "regtest", "targets": [controlled], "keys": [],
        "recoveries": [{
            "controlled_outpoint": controlled, "claim": claim, "ancestors": ancestors,
            "chain_anchor": anchor, "chain_anchor_prevout": txout(anchor_sats, key_script(9)).hex(),
        }],
    }


def graph(separate):
    """Saved signed recovery paths: one shared root, or one root per holder."""
    if separate:
        ra, rb = "6" * 64 + ":0", "7" * 64 + ":0"
        a1 = make_tx(ra, [(60_000, key_script(1)), (0, P2A)], 1)
        b1 = make_tx(rb, [(40_000, key_script(2)), (0, P2A)], 2)
        alice = ([a1], a1, ra, 60_000)
        bob = ([b1], b1, rb, 40_000)
    else:
        root = "1" * 64 + ":0"
        s1 = make_tx(root, [(120_000, key_script(1)), (0, P2A)], 1)
        s2 = make_tx(tx_ids(s1)[0] + ":0",
                     [(60_000, key_script(2)), (60_000, key_script(3)), (0, P2A)], 2)
        b1 = make_tx(tx_ids(s2)[0] + ":1", [(40_000, key_script(4)), (0, P2A)], 3)
        alice = ([s1, s2], s2, root, 120_000)
        bob = ([s1, s2, b1], b1, root, 120_000)
    paths = {}
    for name, (ancestors, parent, anchor, anchor_sats), sats, tag in (
        ("alice", alice, 60_000, 10), ("bob", bob, 40_000, 11),
    ):
        controlled = tx_ids(parent)[0] + ":0"
        claim = make_tx(controlled, [(sats, key_script(tag)), (0, P2A)], tag)
        paths[name] = bundle(controlled, ancestors, claim, anchor, anchor_sats)
    return paths


def capture(separate=False):
    bundles = graph(separate)
    rows, height, child = {}, 113, 0x20
    for name in ("alice", "bob"):
        record = bundles[name]["recoveries"][0]
        for tx_hex, role in [(t, "ancestor") for t in record["ancestors"]] + [(record["claim"], "claim")]:
            txid, wtxid = tx_ids(tx_hex)
            if txid in rows:
                rows[txid]["used_by"].append(name)
                continue
            rows[txid] = {
                "role": role, "used_by": [name], "txid": txid, "wtxid": wtxid,
                "block_height": height, "p2a_anchor": txid + ":1",
                "fee_child_txid": f"{child:02x}" * 32, "fee_child_wtxid": f"{child:02x}" * 32,
                "external_fee_inputs": ["9" * 64 + ":0"], "external_fee_sats": 300,
            }
            height, child = height + 1, child + 1
    claims = {n: tx_ids(bundles[n]["recoveries"][0]["claim"]) for n in ("alice", "bob")}
    holders = [
        {"holder": n, "controlled_outpoint": bundles[n]["targets"][0],
         "confirmed_claim_txid": claims[n][0], "confirmed_claim_wtxid": claims[n][1],
         "payout_outpoint": claims[n][0] + ":0", "sats": s}
        for n, s in (("alice", 60_000), ("bob", 40_000))
    ]
    fees = {
        "alice": {"claim_txid": claims["alice"][0]}, "bob": {"claim_txid": claims["bob"][0]},
        "external_fee_wallet_keys_distinct_from_holders": True,
        "bitcoin_height_at_shutdown": 112, "recovery_transactions": list(rows.values()),
    }
    if separate:
        fees.update({"real_common_root": False, "separate_roots": True, "chain_anchors": {
            n: {"outpoint": bundles[n]["recoveries"][0]["chain_anchor"],
                "sats": 60_000 if n == "alice" else 40_000} for n in ("alice", "bob")}})
    else:
        fees.update({"real_common_root": True, "shared_chain_anchor": "1" * 64 + ":0",
                     "shared_chain_anchor_sats": 120_000})
    return {
        "__bundles": bundles,
        "shutdown-before-recovery.json": {
            "stopped_in_order": ["alice-sdk", "bob-sdk", "sapio-tee", "captaind"],
            "sapio_api_8000_refused": True, "sapio_oracle_8367_refused": True,
            "signed_recovery_transactions_unpublished": True, "bitcoin_height_at_shutdown": 112,
        },
        "external-fee-utxos-before-shutdown.json": ["9" * 64 + ":0"],
        "confirmed-p2a-fee-children.json": fees,
        "two-holder-pre-spend-report.json": {
            "offline": {"total_protected_sats": 100_000, "selected_paths_nonconflicting": True},
            "two_holder": {"total_payout_sats": 100_000, "holders": holders},
        },
        "two-holder-redemptions.json": {
            "independent_spends_confirmed": True,
            "redemptions": [
                {"holder": "alice", "wallet": "alice-recovered", "txid": "e" * 64, "wtxid": "e" * 64,
                 "spent_outpoint": claims["alice"][0] + ":0", "paid_sats": 59_800, "fee_sats": 200},
                {"holder": "bob", "wallet": "bob-recovered", "txid": "f" * 64, "wtxid": "f" * 64,
                 "spent_outpoint": claims["bob"][0] + ":0", "paid_sats": 39_800, "fee_sats": 200},
            ],
        },
    }


def separate_capture():
    return capture(separate=True)


class TxIdTest(unittest.TestCase):
    def test_genesis_coinbase_txid(self):
        txid, wtxid = tx_ids(GENESIS_COINBASE)
        self.assertEqual(txid, "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")
        self.assertEqual(wtxid, txid)

    def test_witness_is_stripped_from_txid_only(self):
        prevout = "ab" * 32 + ":3"
        with_witness = make_tx(prevout, [(5, key_script(1))], 7)
        without = make_tx(prevout, [(5, key_script(1))], 7, witness=False)
        self.assertEqual(tx_ids(with_witness)[0], tx_ids(without)[0])
        self.assertNotEqual(tx_ids(with_witness)[1], tx_ids(with_witness)[0])

    def test_rejects_trailing_bytes(self):
        with self.assertRaises(ValueError):
            tx_ids(GENESIS_COINBASE + "00")


class PublicProofTest(unittest.TestCase):
    def write(self, data):
        root = Path(self.tmp.name)
        for path in root.iterdir():
            path.unlink()
        contents = {
            "two-holder-terms.json": json.dumps({"private": "terms"}).encode(),
            "alice-recovery.json": json.dumps(data["__bundles"]["alice"]).encode(),
            "bob-recovery.json": json.dumps(data["__bundles"]["bob"]).encode(),
        }
        files = []
        for name in FROZEN:
            raw = contents[name]
            (root / name).write_bytes(raw)
            files.append({"file": name, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)})
        manifest = {"schema": 1, "fixture": "local-regtest-saplingos-signed-evidence", "files": files}
        (root / "frozen-evidence-before-shutdown.json").write_text(json.dumps(manifest, indent=2))
        for name, value in data.items():
            if not name.startswith("__"):
                (root / name).write_text(json.dumps(value))
        return root

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def rejects(self, mutate, root_mutation=None, scenario="common-root", base=capture):
        data = copy.deepcopy(base())
        mutate(data)
        root = self.write(data)
        if root_mutation:
            root_mutation(root)
        with self.assertRaises((ValueError, KeyError)):
            build(root, {}, scenario)

    @staticmethod
    def rows(d):
        return d["confirmed-p2a-fee-children.json"]["recovery_transactions"]

    def test_valid_capture_publishes_only_public_facts(self):
        proof = build(self.write(capture()), {"sdk_revision": "b45e5ef"})
        self.assertEqual(proof["conservation"]["allocations"], {"alice": 60_000, "bob": 40_000})
        self.assertEqual(len(proof["recovery_transactions"]), 5)
        self.assertEqual(len(proof["frozen_manifest_sha256"]), 64)
        self.assertNotIn("private", json.dumps(proof))

    def test_valid_separate_roots_capture(self):
        proof = build(self.write(separate_capture()), {}, "separate-roots")
        self.assertEqual(proof["proof_kind"], "actual-pinned-saplingos-separate-roots-regtest")
        self.assertEqual(set(proof["conservation"]["chain_anchors"]), {"alice", "bob"})

    def test_scenarios_reject_each_other(self):
        self.rejects(lambda d: None, scenario="separate-roots")
        self.rejects(lambda d: None, base=separate_capture)

    def test_rejects_changed_signed_export(self):
        self.rejects(lambda d: None, lambda r: (r / "bob-recovery.json").write_text("{}"))

    def test_rejects_recovery_before_shutdown(self):
        self.rejects(lambda d: self.rows(d)[0].update(block_height=112))

    def test_rejects_unshared_ancestry_label(self):
        self.rejects(lambda d: self.rows(d)[0].update(used_by=["alice"]))

    def test_rejects_missing_or_extra_row(self):
        self.rejects(lambda d: self.rows(d).pop())
        self.rejects(lambda d: self.rows(d).append(dict(self.rows(d)[0], txid="0" * 64)))

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
            redemptions = d["two-holder-redemptions.json"]["redemptions"]
            redemptions[0]["spent_outpoint"] = redemptions[1]["spent_outpoint"]
        self.rejects(swap)

    def test_rejects_shared_redemption_wallet(self):
        def share(d):
            d["two-holder-redemptions.json"]["redemptions"][1]["wallet"] = "alice-recovered"
        self.rejects(share)

    def test_rejects_common_root_value_not_in_export(self):
        self.rejects(lambda d: d["confirmed-p2a-fee-children.json"].update(shared_chain_anchor_sats=200_000))

    def test_separate_roots_reject_shared_transaction_label(self):
        self.rejects(lambda d: self.rows(d)[0].update(used_by=["alice", "bob"]),
                     scenario="separate-roots", base=separate_capture)

    def test_separate_roots_reject_relabelled_common_root(self):
        # Codex review: a common-root capture whose shared ancestor is relabelled
        # to one holder, with separate-root metadata added, must not pass.
        def disguise(d):
            fees = d["confirmed-p2a-fee-children.json"]
            for row in fees["recovery_transactions"]:
                row["used_by"] = row["used_by"][:1]
            fees.update({"real_common_root": False, "separate_roots": True, "chain_anchors": {
                "alice": {"outpoint": "6" * 64 + ":0", "sats": 60_000},
                "bob": {"outpoint": "7" * 64 + ":0", "sats": 40_000}}})
        self.rejects(disguise, scenario="separate-roots")

    def test_separate_roots_reject_root_not_in_export(self):
        # Codex review: arbitrary funded outpoints cannot stand in for the
        # roots the signed exports commit to.
        def forge(d):
            d["confirmed-p2a-fee-children.json"]["chain_anchors"]["alice"] = {
                "outpoint": "8" * 64 + ":0", "sats": 1_000_000}
        self.rejects(forge, scenario="separate-roots", base=separate_capture)

    def test_separate_roots_reject_one_funding_root(self):
        def same(d):
            anchors = d["confirmed-p2a-fee-children.json"]["chain_anchors"]
            anchors["bob"]["outpoint"] = anchors["alice"]["outpoint"]
        self.rejects(same, scenario="separate-roots", base=separate_capture)

    def test_separate_roots_reject_underfunded_root(self):
        def short(d):
            d["confirmed-p2a-fee-children.json"]["chain_anchors"]["alice"]["sats"] = 59_999
        self.rejects(short, scenario="separate-roots", base=separate_capture)


if __name__ == "__main__":
    unittest.main()
