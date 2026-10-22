#!/usr/bin/env python3
"""LIVE BITCOIN CORE WALLET SMOKE ONLY.

Start a private disposable bitcoind regtest, give separate Alice and Bob
descriptor wallets real UTXOs, and run prove_separate_spends.py to confirm
independent signed Bitcoin spends.

The payments funding Alice and Bob are ORDINARY BITCOIN TRANSACTIONS.
Synthetic audit-shaped JSON only exercises the separate wallet redemption
adapter. This script does NOT create SaplingOS ProgramRecoveryBundle,
verify an Ark ancestry, or prove service-free VTXO recovery.
"""
import argparse
from decimal import Decimal
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

from prove_separate_spends import BitcoinCli, btc


def port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run_cli(node, method, *arguments, wallet=None):
    return node.call(method, *arguments, wallet=wallet)


def check_btc_program(binpath, name):
    path = Path(binpath).resolve(strict=True)
    if not path.is_file():
        raise ValueError(name + " must be an executable file")
    return str(path)


def await_rpc(node, child):
    for _ in range(100):
        if child.poll() is not None:
            raise RuntimeError("disposable bitcoind quit during startup")
        try:
            info = run_cli(node, "getblockchaininfo")
            if info["chain"] == "regtest":
                return
            raise ValueError("Bitcoin Core started with the wrong network")
        except RuntimeError:
            time.sleep(0.15)
    raise RuntimeError("Bitcoin Core regtest RPC failed to start")


def holder_target(node, holder, amount, address, source_address):
    txid = run_cli(node, "sendtoaddress", address, btc(amount), wallet="miner")
    return {"holder": holder, "amount": amount, "txid": txid,
            "script": run_cli(node, "validateaddress", address)["scriptPubKey"],
            "source": source_address}


def from_confirmed_payment(node, item):
    confirmed = run_cli(node, "getrawtransaction", item["txid"], "true")
    if confirmed.get("confirmations", 0) < 6:
        raise ValueError("ordinary regtest deposit has insufficient confirmations")
    matches = [v["n"] for v in confirmed["vout"]
               if v["scriptPubKey"]["hex"].lower() == item["script"].lower()
               and int(Decimal(str(v["value"])) * 100_000_000) == item["amount"]]
    if len(matches) != 1:
        raise ValueError("ordinary Bitcoin wallet did not receive its expected deposit")
    outpoint = f'{item["txid"]}:{matches[0]}'
    original = confirmed["vin"][0]
    controlled = f'{original["txid"]}:{original["vout"]}'
    return {
        "holder": item["holder"],
        "controlled": controlled,
        "claim": item["txid"],
        "witness": confirmed["hash"],
        "outpoint": outpoint,
        "script": item["script"],
        "amount": item["amount"],
        "confirmations": confirmed["confirmations"],
    }


def make_simulated_report(items):
    """Produce the strict receipt shape, explicitly tagged SIMULATED.

    Never feed this into a claim of SaplingOS native cryptographic verification.
    The regtest wallet proof only needs known confirmed Bitcoin outputs.
    """
    assert len(items) == 2 and len({i["holder"] for i in items}) == 2
    expected, observed, holders = [], [], []
    for item in items:
        expected.append({
            "outpoint": item["controlled"],
            "claim_txid": item["claim"],
            "claim_wtxid": item["witness"],
            "protected_sats": item["amount"],
            "readiness": "Complete",
        })
        observed.append({
            "controlled_outpoint": item["controlled"],
            "claim_txid": item["claim"],
            "claim_wtxid": item["witness"],
            "confirmations": item["confirmations"],
            "payouts": [{
                "holder": item["holder"],
                "outpoint": item["outpoint"],
                "sats": item["amount"],
                "unspent_at_tip": True,
            }],
        })
        holders.append({
            "holder": item["holder"],
            "controlled_outpoint": item["controlled"],
            "confirmed_claim_txid": item["claim"],
            "confirmed_claim_wtxid": item["witness"],
            "payout_outpoint": item["outpoint"],
            "script_pubkey_hex": item["script"],
            "sats": item["amount"],
            "confirmations": item["confirmations"],
            "unspent_at_tip": True,
        })
    return {
        "fixture_kind": "BITCOIN_CORE_WALLET_SMOKE_ONLY",
        "cryptographic_sapling_recovery_proven": False,
        "offline": {
            "network": "regtest", "targets": expected,
            "total_protected_sats": 100_000,
        },
        "chain": {
            "network": "regtest", "targets": observed,
            "minimum_confirmations": 6, "confirmed_claims_checked": True,
        },
        "two_holder": {
            "network": "regtest", "holders": holders,
            "total_payout_sats": 100_000,
            "distinct_confirmed_claims_checked": True,
            "separate_unspent_payouts_checked": True,
        },
    }


def run(args, datadir, output):
    datadir.mkdir(mode=0o700, parents=True, exist_ok=True)
    datadir.chmod(0o700)
    conf = ("regtest=1\nserver=1\ntxindex=1\nfallbackfee=0.00002\n"
            "[regtest]\nlisten=0\n"
            f"rpcport={port()}\n")
    cfg = datadir / "bitcoin.conf"
    cfg.write_text(conf, encoding="utf-8")
    cfg.chmod(0o600)
    args_bin = [args.bitcoind, "-datadir=" + str(datadir), "-printtoconsole=0"]
    child = subprocess.Popen(args_bin, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    node = BitcoinCli(args.bitcoin_cli, str(datadir))
    try:
        await_rpc(node, child)
        for wallet in ["miner", "alice-smoke", "bob-smoke"]:
            run_cli(node, "createwallet", wallet)
        miner_address = run_cli(node, "getnewaddress", wallet="miner")
        run_cli(node, "generatetoaddress", 101, miner_address)
        alice_address = run_cli(node, "getnewaddress", wallet="alice-smoke")
        bob_address = run_cli(node, "getnewaddress", wallet="bob-smoke")
        deposits = [
            holder_target(node, "alice", 60_000, alice_address, miner_address),
            holder_target(node, "bob", 40_000, bob_address, miner_address),
        ]
        run_cli(node, "generatetoaddress", 6, miner_address)
        items = [from_confirmed_payment(node, deposit) for deposit in deposits]
        report = make_simulated_report(items)
        report_file = output / "synthetic-bitcoin-core-receipt.json"
        report_file.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        report_file.chmod(0o600)

        dest_alice = run_cli(node, "getnewaddress", wallet="alice-smoke")
        dest_bob = run_cli(node, "getnewaddress", wallet="bob-smoke")
        command = [
            sys.executable, str(Path(__file__).with_name("prove_separate_spends.py")),
            str(report_file), "--bitcoin-cli", args.bitcoin_cli,
            "--datadir", str(datadir),
            "--wallet", "alice=alice-smoke", "--wallet", "bob=bob-smoke",
            "--destination", "alice=" + dest_alice,
            "--destination", "bob=" + dest_bob,
            "--mine-address", miner_address, "--broadcast",
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode:
            raise RuntimeError("live Bitcoin Core wallet proof failed:\n" + result.stderr)
        receipt = json.loads(result.stdout)
        if (receipt["independent_spends_confirmed"] is not True
                or {x["holder"] for x in receipt["redemptions"]} != {"alice", "bob"}):
            raise ValueError("missing separately confirmed Bitcoin Core wallet redemptions")
        receipt["fixture_kind"] = "BITCOIN_CORE_WALLET_SMOKE_ONLY"
        receipt["cryptographic_sapling_recovery_proven"] = False
        redemption_file = output / "wallet-redemptions.json"
        redemption_file.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        redemption_file.chmod(0o600)
        return {
            "fixture_kind": "BITCOIN_CORE_WALLET_SMOKE_ONLY",
            "regtest_wallet_spends_confirmed": True,
            "claiming_sapling_vtxo_recovery": False,
            "holders": {r["holder"]: r["txid"] for r in receipt["redemptions"]},
            "evidence_dir": str(output),
        }
    finally:
        try:
            node.call("stop")
            child.wait(timeout=15)
        except (RuntimeError, subprocess.TimeoutExpired):
            child.kill()
            child.wait(timeout=5)
        if child.stderr:
            child.stderr.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitcoind", required=True)
    parser.add_argument("--bitcoin-cli", required=True)
    parser.add_argument("--output", help="directory for synthetic regtest evidence")
    args = parser.parse_args()
    args.bitcoind = check_btc_program(args.bitcoind, "bitcoind")
    args.bitcoin_cli = check_btc_program(args.bitcoin_cli, "bitcoin-cli")
    if args.output:
        output = Path(args.output).resolve()
        output.mkdir(parents=True, exist_ok=True, mode=0o700)
        output.chmod(0o700)
        with tempfile.TemporaryDirectory(prefix="sapling-bitcoin-core-regtest-") as d:
            report = run(args, Path(d), output)
    else:
        with tempfile.TemporaryDirectory(prefix="sapling-bitcoin-core-regtest-") as d:
            output = Path(d) / "evidence"
            output.mkdir(mode=0o700)
            report = run(args, Path(d) / "bitcoin-node", output)
            report["evidence_dir"] = "temporary private directory (removed on exit)"
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, KeyError, OSError) as error:
        print("live Bitcoin Core wallet smoke failed: " + str(error), file=sys.stderr)
        sys.exit(1)
