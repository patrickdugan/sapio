#!/usr/bin/env python3
"""Prove that two separately controlled regtest wallets can spend the
confirmed Alice/Bob recovery payouts, using Bitcoin Core only.

This is the post-confirmation part of a SaplingOS outage rehearsal.
It consumes the JSON produced by the auditor's --two-holder mode.
No Ark server, Sapio signer, recovery seed, or program signing API is used.

Default mode performs read-only preflight. --broadcast explicitly spends
both recovered UTXOs on regtest and mines a block using a third wallet.
"""
import argparse
from decimal import Decimal
import json
import subprocess
import sys

COIN = Decimal(100_000_000)


def sats(value):
    value = Decimal(str(value)) * COIN
    if value != value.to_integral_value():
        raise ValueError("fractional satoshi in Bitcoin Core response")
    return int(value)


def btc(satoshi):
    return format(Decimal(satoshi) / COIN, ".8f")


def one_outpoint(text):
    txid, separator, vout = text.partition(":")
    if not separator or len(txid) != 64 or any(c not in "0123456789abcdefABCDEF" for c in txid):
        raise ValueError("invalid Bitcoin outpoint")
    if not vout.isascii() or not vout.isdigit():
        raise ValueError("invalid Bitcoin output index")
    return txid.lower(), int(vout)


def validate_report(report):
    offline = report["offline"]
    chain = report["chain"]
    checked = report["two_holder"]
    if offline["network"] != "regtest" or chain["network"] != "regtest" or checked["network"] != "regtest":
        raise ValueError("spend experiment is restricted to Bitcoin Core regtest")
    if not chain["confirmed_claims_checked"] or not checked["distinct_confirmed_claims_checked"]:
        raise ValueError("missing exact confirmed-claim evidence")
    if not checked["separate_unspent_payouts_checked"]:
        raise ValueError("two independently unspent Bitcoin outputs are required")
    if len(checked["holders"]) != 2 or len(chain["targets"]) != 2 or len(offline["targets"]) != 2:
        raise ValueError("exactly two separate VTXOs are required")
    depths = chain["minimum_confirmations"]
    if not isinstance(depths, int) or depths < 1:
        raise ValueError("invalid Bitcoin confirmation policy")
    by_controlled = {t["controlled_outpoint"]: t for t in chain["targets"]}
    by_offline = {t["outpoint"]: t for t in offline["targets"]}
    if len(by_controlled) != 2 or len(by_offline) != 2 or set(by_controlled) != set(by_offline):
        raise ValueError("mismatched confirmed and agreed VTXO sets")
    names, scripts, claims, outpoints = set(), set(), set(), set()
    total = 0
    for holder in checked["holders"]:
        name = holder["holder"]
        controlled = holder["controlled_outpoint"]
        claim_txid = holder["confirmed_claim_txid"]
        claim_wtxid = holder["confirmed_claim_wtxid"]
        payout = holder["payout_outpoint"]
        txid, _ = one_outpoint(payout)
        amount = holder["sats"]
        script = holder["script_pubkey_hex"].lower()
        if not isinstance(name, str) or not name.strip() or name in names:
            raise ValueError("duplicate or empty holder")
        names.add(name)
        if not isinstance(amount, int) or amount <= 0:
            raise ValueError("invalid holder principal")
        if script in scripts or len(script) < 2:
            raise ValueError("two holders cannot reuse a Bitcoin output script")
        scripts.add(script)
        if payout in outpoints:
            raise ValueError("same Bitcoin payout counted twice")
        outpoints.add(payout)
        if claim_txid.lower() != txid or claim_txid in claims:
            raise ValueError("two claims must have independent Bitcoin transaction IDs")
        if len(claim_wtxid) != 64 or any(c not in "0123456789abcdefABCDEF" for c in claim_wtxid):
            raise ValueError("invalid signed witness transaction ID")
        claims.add(claim_txid)
        if controlled not in by_controlled or not holder["unspent_at_tip"]:
            raise ValueError("missing unspent payout for selected VTXO")
        chain_target = by_controlled[controlled]
        expected = by_offline[controlled]
        if chain_target["claim_txid"] != claim_txid or expected["claim_txid"] != claim_txid:
            raise ValueError("confirmed claim differs from the saved recovery")
        if (chain_target["claim_wtxid"].lower() != claim_wtxid.lower()
                or expected["claim_wtxid"].lower() != claim_wtxid.lower()):
            raise ValueError("confirmed signed witness differs from the saved recovery")
        if len(chain_target["payouts"]) != 1 or chain_target["payouts"][0] != {
            "holder": name,
            "outpoint": payout,
            "sats": amount,
            "unspent_at_tip": True,
        }:
            raise ValueError("confirmed payout receipt has changed")
        if chain_target["confirmations"] < depths or holder["confirmations"] != chain_target["confirmations"]:
            raise ValueError("claim confirmation depth is insufficient")
        if expected["protected_sats"] != amount or expected["readiness"] != "Complete":
            raise ValueError("saved independent claim has different value or readiness")
        total += amount
    if total != checked["total_payout_sats"] or total != offline["total_protected_sats"]:
        raise ValueError("backed principal differs from total confirmed holder payouts")
    return sorted(checked["holders"], key=lambda h: h["holder"])


class BitcoinCli:
    def __init__(self, binary, datadir):
        self.prefix = [binary, "-regtest"]
        if datadir:
            self.prefix.append("-datadir=" + datadir)

    def call(self, method, *params, wallet=None):
        args = list(self.prefix)
        if wallet is not None:
            args.append("-rpcwallet=" + wallet)
        args += [method, *[str(x) for x in params]]
        result = subprocess.run(args, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise RuntimeError(method + ": " + result.stderr.strip())
        raw = result.stdout.strip()
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw


def wallet_owns_payout(node, receipt, wallet, min_confirmations=1):
    txid, vout = one_outpoint(receipt["payout_outpoint"])
    value = node.call("gettxout", txid, vout, "false")
    if value is None:
        raise ValueError("confirmed recovery output is missing or already spent")
    if sats(value["value"]) != receipt["sats"]:
        raise ValueError("Bitcoin Core reports a different payout value")
    if value["scriptPubKey"]["hex"].lower() != receipt["script_pubkey_hex"].lower():
        raise ValueError("Bitcoin Core reports a different payout script")

    confirmed = node.call("getrawtransaction", txid, "true")
    if confirmed["txid"].lower() != txid:
        raise ValueError("Bitcoin Core returned a different confirmed transaction")
    if confirmed["hash"].lower() != receipt["confirmed_claim_wtxid"].lower():
        raise ValueError("confirmed witness transaction changed after offline audit")
    if not isinstance(confirmed.get("confirmations"), int) or confirmed["confirmations"] < min_confirmations:
        raise ValueError("payout transaction no longer meets confirmation policy")

    coins = node.call("listunspent", 1, 9999999, wallet=wallet)
    matched = [
        coin for coin in coins
        if coin["txid"].lower() == txid and coin["vout"] == vout
    ]
    if len(matched) != 1 or matched[0].get("spendable") is not True:
        raise ValueError("holder wallet cannot independently sign for this output")
    if sats(matched[0]["amount"]) != receipt["sats"]:
        raise ValueError("holder wallet reports the wrong Bitcoin amount")
    if matched[0]["scriptPubKey"].lower() != receipt["script_pubkey_hex"].lower():
        raise ValueError("holder wallet reports a different controlled script")
    return True


def signed_redemption(node, receipt, wallet, destination, fee_rate, max_fee):
    txid, vout = one_outpoint(receipt["payout_outpoint"])
    address = node.call("validateaddress", destination)
    if address.get("isvalid") is not True:
        raise ValueError("invalid regtest redemption address for " + receipt["holder"])
    destination_script = address["scriptPubKey"].lower()
    inputs = json.dumps([{"txid": txid, "vout": vout}])
    outputs = "[{" + json.dumps(destination) + ":" + btc(receipt["sats"]) + "}]"
    options = json.dumps({
        "add_inputs": False,
        "subtractFeeFromOutputs": [0],
        "fee_rate": fee_rate,
    })
    funded = node.call("walletcreatefundedpsbt", inputs, outputs, 0, options, "false", wallet=wallet)
    processed = node.call("walletprocesspsbt", funded["psbt"], wallet=wallet)
    finalized = node.call("finalizepsbt", processed["psbt"])
    if not finalized.get("complete") or not finalized.get("hex"):
        raise ValueError("one holder wallet failed to finalize its own payout spend")

    raw = finalized["hex"]
    decoded = node.call("decoderawtransaction", raw)
    if len(decoded["vin"]) != 1:
        raise ValueError("wallet substituted another funding input")
    spent = decoded["vin"][0]
    if spent["txid"].lower() != txid or spent["vout"] != vout:
        raise ValueError("wallet substituted another payout coin")
    if len(decoded["vout"]) != 1 or decoded["vout"][0]["scriptPubKey"]["hex"].lower() != destination_script:
        raise ValueError("redemption pays an unexpected address or creates change")
    sent = sats(decoded["vout"][0]["value"])
    fee = receipt["sats"] - sent
    if fee < 1 or fee > max_fee:
        raise ValueError("redemption fee is outside the configured safe regtest bound")
    return {
        "holder": receipt["holder"],
        "wallet": wallet,
        "payout_outpoint": receipt["payout_outpoint"],
        "spent_outpoint": f"{spent['txid'].lower()}:{spent['vout']}",
        "txid": decoded["txid"],
        "wtxid": decoded["hash"],
        "raw_transaction": raw,
        "fee_sats": fee,
        "paid_sats": sent,
    }


def keyed_pairs(values):
    result = {}
    for item in values:
        name, separator, value = item.partition("=")
        if not separator or not name or not value or name in result:
            raise ValueError("expected each argument as a distinct holder=value")
        result[name] = value
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", help="JSON from auditor --two-holder mode")
    parser.add_argument("--bitcoin-cli", required=True, help="trusted local Bitcoin Core CLI")
    parser.add_argument("--datadir")
    parser.add_argument("--wallet", action="append", default=[], help="holder=bitcoin-core-wallet-name")
    parser.add_argument("--destination", action="append", default=[], help="holder=regtest-Bitcoin-address")
    mine = parser.add_mutually_exclusive_group()
    mine.add_argument("--mine-wallet", help="mining-only wallet name")
    mine.add_argument("--mine-address", help="preselected regtest address for mining the confirmation block")
    parser.add_argument("--fee-rate", type=float, default=2.0, help="sat/vB for each holder's spend")
    parser.add_argument("--max-fee-sats", type=int, default=2_000)
    parser.add_argument("--broadcast", action="store_true", help="spend two payouts and mine a regtest block")
    args = parser.parse_args()
    with open(args.report, encoding="utf-8") as f:
        report = json.load(f)
    receipts = validate_report(report)
    chain_depth = report["chain"]["minimum_confirmations"]
    wallets = keyed_pairs(args.wallet)
    destinations = keyed_pairs(args.destination)
    labels = {receipt["holder"] for receipt in receipts}
    if set(wallets) != labels or len(set(wallets.values())) != 2:
        raise ValueError("specify two distinct Bitcoin Core wallets, one per proven holder")
    if args.broadcast and (set(destinations) != labels or not (args.mine_wallet or args.mine_address)):
        raise ValueError("--broadcast needs a redemption address per holder and a miner wallet or address")
    if args.fee_rate < 1 or args.fee_rate > 100 or args.max_fee_sats < 1:
        raise ValueError("unsafe or invalid regtest fee policy")

    node = BitcoinCli(args.bitcoin_cli, args.datadir)
    info = node.call("getblockchaininfo")
    if info["chain"] != "regtest" or info.get("initialblockdownload", True):
        raise ValueError("requires a synced, trusted Bitcoin Core regtest node")

    for receipt in receipts:
        wallet_owns_payout(node, receipt, wallets[receipt["holder"]], chain_depth)
    result = {
        "network": "regtest",
        "holder_wallets_verified_spendable": True,
        "independent_spends_confirmed": False,
        "services_offline_during_recovery_checked": False,
        "holders": [{"holder": h["holder"], "payout_outpoint": h["payout_outpoint"]} for h in receipts],
    }
    if args.broadcast:
        prepared = [
            signed_redemption(node, r, wallets[r["holder"]], destinations[r["holder"]],
                              args.fee_rate, args.max_fee_sats)
            for r in receipts
        ]
        for item in prepared:
            sent_txid = node.call("sendrawtransaction", item["raw_transaction"])
            if sent_txid.lower() != item["txid"].lower():
                raise ValueError("Bitcoin Core accepted a different signed redemption")
            del item["raw_transaction"]
        miner_address = args.mine_address or node.call("getnewaddress", wallet=args.mine_wallet)
        if node.call("validateaddress", miner_address).get("isvalid") is not True:
            raise ValueError("invalid regtest mining address")
        node.call("generatetoaddress", 1, miner_address)
        for item in prepared:
            mined = node.call("getrawtransaction", item["txid"], "true")
            if mined.get("confirmations", 0) < 1:
                raise ValueError("individual wallet redemption failed to confirm")
        result["independent_spends_confirmed"] = True
        result["redemptions"] = prepared
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, RuntimeError, OSError) as exc:
        print("two-holder spend proof failed: " + str(exc), file=sys.stderr)
        sys.exit(1)
