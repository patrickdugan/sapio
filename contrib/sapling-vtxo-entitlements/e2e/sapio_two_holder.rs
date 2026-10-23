//! Real two-holder SaplingOS outage rehearsal.
//!
//! This file is injected into the pinned upstream SaplingOS integration suite
//! as a *child* module of sdk::sapio, so it reuses the real TEE, captaind,
//! Bitcoin Core, and fresh-process recovery helpers. It is never a mock
//! cosigner test. Both owner wallets have different BIP39 seeds, and two
//! separate Bitcoin Core descriptor wallets own the final payout scripts.
//!
//! The run emits disposable regtest bundles plus independently recorded
//! terms. These are intentionally generated from test keys only.

use super::*;
use bitcoin::address::NetworkUnchecked;
use bitcoincore_rpc::{Auth, Client, RpcApi as _};
use serde_json::json;
use std::collections::HashSet;
use std::fs;

fn new_recipient_wallet(ctx: &TestContext, name: &str) -> (Client, ScriptBuf) {
    let general = ctx.bitcoind().sync_client();
    let _: serde_json::Value = general
        .call("createwallet", &[json!(name), json!(false), json!(false), json!(""), json!(false), json!(true)])
        .expect("create a distinct descriptor wallet for the recovery beneficiary");
    let base = ctx.bitcoind().rpc_url().to_string();
    let rpc_url = format!("{}/wallet/{name}", base.trim_end_matches('/'));
    let client = Client::new(&rpc_url, Auth::CookieFile(ctx.bitcoind().rpc_cookie()))
        .expect("connect to recipient's separate Bitcoin Core wallet");
    let raw: String = client.call("getnewaddress", &[])
        .expect("beneficiary must supply a native Bitcoin address");
    let address = raw
        .parse::<bitcoin::Address<NetworkUnchecked>>()
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap();
    set_recipient_wallets_loaded(ctx, &[name], false);
    (client, address.script_pubkey())
}

/// The shared fixture node funds SDK wallets and derives addresses through
/// its default wallet on the bare RPC path, which Bitcoin Core refuses while
/// a second wallet is loaded ("Multiple wallets are loaded"). Keep each
/// holder's separate descriptor wallet unloaded except while it signs its
/// own redemption; loading resynchronises it to the tip, so it still sees
/// the recovered payout to the address it issued before the outage.
fn set_recipient_wallets_loaded(ctx: &TestContext, names: &[&str], loaded: bool) {
    let general = ctx.bitcoind().sync_client();
    let method = if loaded { "loadwallet" } else { "unloadwallet" };
    for name in names {
        let _: serde_json::Value = general.call(method, &[json!(name)])
            .unwrap_or_else(|error| panic!("{method} {name}: {error}"));
    }
}

/// The holder's own wallet key U for an agreed program position. A program
/// VTXO is locked to KeyAgg(U, C), not to U, while the independent terms pin
/// U (`ProgramKey::user_pubkey`). The holder derives U from its own seed on
/// the wallet's m/350'/0'/i branch and checks that, under the agreed program
/// and signer root, it yields the live VTXO key. Nothing is read from the
/// recovery export the terms will later be checked against.
fn holder_user_pubkey(
    mnemonic: &bip39::Mnemonic,
    root: bitcoin::bip32::Xpub,
    program: &Program,
    vtxo_key: bitcoin::secp256k1::PublicKey,
) -> bitcoin::secp256k1::PublicKey {
    let master = Xpriv::new_master(Network::Regtest, &mnemonic.to_seed("")).unwrap();
    let branch = master.derive_priv(&ark::SECP, &[
        ChildNumber::from_hardened_idx(350).unwrap(),
        ChildNumber::from_hardened_idx(0).unwrap(),
    ]).unwrap();
    (0..128).map(|index| {
        branch.derive_priv(&ark::SECP, &[ChildNumber::from_normal_idx(index).unwrap()])
            .unwrap().to_keypair(&ark::SECP).public_key()
    }).find(|user| {
        ProgramKey { root, program: program.clone(), user_pubkey: *user }
            .public_key().ok() == Some(vtxo_key)
    }).expect("live VTXO key is not the holder's own key under the agreed program")
}

fn script_hex(script: &ScriptBuf) -> String {
    script.as_bytes().iter().map(|byte| format!("{byte:02x}")).collect()
}

fn save_json(path: &Path, value: &impl serde::Serialize) {
    // Bundles contain sensitive signer metadata and immutable claim evidence.
    // Create a new private file so an older signed export is never overwritten.
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).expect("create new private fixture artifact");
    serde_json::to_writer_pretty(&mut file, value).unwrap();
    use std::io::Write;
    file.write_all(b"\n").unwrap();
    file.sync_all().unwrap();
}

/// The recovery sponsor has its own BIP39 seed, SQLite database and
/// confirmed ordinary Bitcoin inputs. It carries no Sapio program signing keys.
async fn capture_fee_wallet_funding(wallet: &sapling::Wallet) -> HashSet<OutPoint> {
    let onchain = wallet.onchain().expect("fee wallet must have a Bitcoin wallet");
    let onchain = onchain.read().await;
    let bdk = (&*onchain as &dyn std::any::Any)
        .downcast_ref::<sapling::onchain::OnchainWallet>()
        .expect("real BDK wallet required for fee provenance");
    let coins = bdk.list_unspent().into_iter().map(|coin| coin.outpoint)
        .collect::<HashSet<_>>();
    assert!(!coins.is_empty(), "separate recovery fee wallet has no funded Bitcoin inputs");
    coins
}

/// Every fee input is traced to a UTXO that was in the independent
/// sponsor wallet before the cosigner disappeared. A change output may
/// pass through several previously confirmed P2A fee children while Ark
/// recovery ancestors mature on Bitcoin Core.
fn selected_recovery_anchors(bundles: &[&ProgramRecoveryBundle]) -> HashSet<OutPoint> {
    let mut anchors = HashSet::new();
    for bundle in bundles {
        for target in &bundle.targets {
            let record = bundle.recoveries.iter()
                .find(|record| record.controlled_outpoint == *target)
                .expect("selected VTXO has no signed recovery record");
            assert_eq!(bundle.readiness(*target).unwrap(), ProgramRecoveryReadiness::Complete);
            for tx in record.ancestors.iter().chain(std::iter::once(&record.claim)) {
                let matches = tx.output.iter().enumerate().filter(|(_, output)| {
                    output.value == Amount::ZERO
                        && output.script_pubkey.as_bytes() == [0x51, 0x02, 0x4e, 0x73]
                }).map(|(i, _)| OutPoint::new(tx.compute_txid(), i as u32))
                    .collect::<Vec<_>>();
                assert_eq!(matches.len(), 1, "signed recovery transaction has no unique P2A anchor");
                // Two sibling exports legitimately repeat one shared signed ancestor.
                anchors.insert(matches[0]);
            }
        }
    }
    anchors
}

fn trace_sponsor_coin(
    ctx: &TestContext,
    coin: OutPoint,
    initial: &HashSet<OutPoint>,
    recovery_anchors: &HashSet<OutPoint>,
    seen: &mut HashSet<OutPoint>,
) {
    if initial.contains(&coin) { return; }
    assert!(seen.insert(coin), "cyclic or repeated intermediate fee provenance");
    assert!(seen.len() <= 64, "unreasonably deep external fee ancestry");
    let tx = ctx.bitcoind().sync_client().get_raw_transaction(&coin.txid, None)
        .expect("fee change parent is missing from Bitcoin Core");
    let output = tx.output.get(coin.vout as usize).expect("missing fee change output");
    assert!(output.value > Amount::ZERO, "fee change outpoint is zero valued");
    assert!(tx.input.iter().any(|input| recovery_anchors.contains(&input.previous_output)),
        "fee input did not originate from a signed recovery P2A fee child");
    let from_fees = tx.input.iter()
        .map(|input| input.previous_output)
        .filter(|input| !recovery_anchors.contains(input))
        .collect::<Vec<_>>();
    assert!(!from_fees.is_empty(), "P2A child lacks funded inputs");
    for parent in from_fees {
        trace_sponsor_coin(ctx, parent, initial, recovery_anchors, seen);
    }
    // Shared ancestral funding may reach different outputs in a Bitcoin DAG.
    seen.remove(&coin);
}

fn require_external_fee_wallet_funding(
    ctx: &TestContext,
    proof: &serde_json::Value,
    initial: &HashSet<OutPoint>,
    recovery_anchors: &HashSet<OutPoint>,
) {
    let external = proof["external_fee_inputs"].as_array()
        .expect("missing external funding inputs");
    assert!(!external.is_empty(), "recovery sponsor paid no external funds");
    for item in external {
        let point: OutPoint = item.as_str().expect("non-string sponsor input")
            .parse().expect("invalid external sponsor outpoint");
        trace_sponsor_coin(ctx, point, initial, recovery_anchors, &mut HashSet::new());
    }
}

/// Every signed transaction a saved export can publish, shared ancestors
/// once, in the order a recovery must confirm them.
fn recovery_transactions<'a>(
    holders: &[(&'a str, &'a ProgramRecoveryBundle)],
) -> Vec<(bitcoin::Txid, &'a Transaction, Vec<&'a str>, &'static str)> {
    let mut rows: Vec<(bitcoin::Txid, &Transaction, Vec<&str>, &'static str)> = Vec::new();
    for &(holder, bundle) in holders {
        for target in &bundle.targets {
            let record = bundle.recoveries.iter()
                .find(|record| record.controlled_outpoint == *target)
                .expect("selected VTXO has no signed recovery record");
            let ancestors = record.ancestors.iter().map(|tx| (tx, "ancestor"));
            for (tx, role) in ancestors.chain(std::iter::once((&record.claim, "claim"))) {
                let txid = tx.compute_txid();
                match rows.iter_mut().find(|row| row.0 == txid) {
                    Some(row) => {
                        assert_eq!(row.1, tx, "two exports disagree on one signed ancestor");
                        assert_eq!(row.3, role, "one transaction is both a claim and an ancestor");
                        row.2.push(holder);
                    }
                    None => rows.push((txid, tx, vec![holder], role)),
                }
            }
        }
    }
    rows
}

/// None of the saved signed transactions may be on Bitcoin before the
/// services stop; recovery publication must happen strictly afterwards.
fn assert_unpublished(ctx: &TestContext, holders: &[(&str, &ProgramRecoveryBundle)]) {
    let rpc = ctx.bitcoind().sync_client();
    for (txid, _, _, role) in recovery_transactions(holders) {
        assert!(rpc.get_raw_transaction(&txid, None).is_err(),
            "signed recovery {role} {txid} was published before service shutdown");
    }
}

/// Record the chain tip once every signer and owner SDK is gone, after the
/// Sapio ports were found closed. Each saved recovery transaction must later
/// confirm strictly above the returned height.
fn record_shutdown(
    ctx: &TestContext,
    dir: &Path,
    holders: &[(&str, &ProgramRecoveryBundle)],
    stopped_in_order: &[&str],
) -> u64 {
    assert_unpublished(ctx, holders);
    let shutdown_height = ctx.bitcoind().sync_client().get_block_count().unwrap();
    save_json(&dir.join("shutdown-before-recovery.json"), &json!({
        "stopped_in_order": stopped_in_order,
        "sapio_api_8000_refused": true,
        "sapio_oracle_8367_refused": true,
        "signed_recovery_transactions_unpublished": true,
        "bitcoin_height_at_shutdown": shutdown_height,
    }));
    shutdown_height
}

/// Each Bitcoin Core wallet spent exactly its own recovered payout in a
/// distinct, wallet-signed, mined transaction.
fn verify_redemptions(ctx: &TestContext, report: &serde_json::Value, receipt: &serde_json::Value) {
    let rpc = ctx.bitcoind().sync_client();
    let mut redemption_txids = HashSet::new();
    for holder in report["two_holder"]["holders"].as_array().unwrap() {
        let name = holder["holder"].as_str().unwrap();
        let payout: OutPoint = holder["payout_outpoint"].as_str().unwrap().parse().unwrap();
        let row = receipt["redemptions"].as_array().unwrap().iter()
            .find(|row| row["holder"] == name).expect("holder has no redemption");
        assert_eq!(row["wallet"], format!("{name}-recovered"));
        let txid: bitcoin::Txid = row["txid"].as_str().unwrap().parse().unwrap();
        assert!(redemption_txids.insert(txid), "both holders share one redemption");
        let mined = rpc.get_raw_transaction(&txid, None).unwrap();
        assert_eq!(mined.compute_wtxid().to_string(), row["wtxid"].as_str().unwrap());
        assert_eq!(mined.input.len(), 1);
        assert_eq!(mined.input[0].previous_output, payout, "{name} spent another coin");
        assert!(!mined.input[0].witness.is_empty(), "{name}'s wallet produced no signature");
        assert!(ctx.bitcoind().transaction_confirmation(txid).unwrap()
            .confirmations.unwrap_or(0) >= 1);
    }
}

/// After recovery: each saved ancestor and claim is confirmed with exactly
/// its saved bytes (witnesses included), above the recorded shutdown height,
/// beside exactly one mined P2A fee child whose external inputs trace back
/// to the sponsor's pre-shutdown coins.
fn confirmed_recovery_chain(
    ctx: &TestContext,
    holders: &[(&str, &ProgramRecoveryBundle)],
    shutdown_height: u64,
    initial: &HashSet<OutPoint>,
    recovery_anchors: &HashSet<OutPoint>,
) -> Vec<serde_json::Value> {
    let rpc = ctx.bitcoind().sync_client();
    recovery_transactions(holders).into_iter().map(|(txid, saved, used_by, role)| {
        let confirmed = rpc.get_raw_transaction(&txid, None)
            .expect("saved signed recovery transaction is missing from Bitcoin Core");
        assert_eq!(&confirmed, saved, "confirmed bytes differ from the saved signed {role}");
        assert_eq!(bitcoin::consensus::serialize(&confirmed), bitcoin::consensus::serialize(saved));
        let info = ctx.bitcoind().transaction_confirmation(txid).unwrap();
        let blockhash = info.blockhash.expect("saved recovery transaction is unconfirmed");
        let height = rpc.get_block_header_info(&blockhash).unwrap().height as u64;
        assert!(height > shutdown_height, "{role} {txid} confirmed before the services stopped");
        let anchors = saved.output.iter().enumerate()
            .filter(|(_, out)| out.value == Amount::ZERO
                && out.script_pubkey.as_bytes() == [0x51, 0x02, 0x4e, 0x73])
            .map(|(i, _)| OutPoint::new(txid, i as u32))
            .collect::<Vec<_>>();
        assert_eq!(anchors.len(), 1, "signed {role} has no unique P2A anchor");
        let anchor = anchors[0];
        let block = rpc.get_block(&blockhash).unwrap();
        let children = block.txdata.iter()
            .filter(|tx| tx.input.iter().any(|input| input.previous_output == anchor))
            .collect::<Vec<_>>();
        assert_eq!(children.len(), 1, "{role} {txid} lacks one mined P2A fee child");
        let child = children[0];
        let external = child.input.iter().map(|input| input.previous_output)
            .filter(|point| *point != anchor).collect::<Vec<_>>();
        assert!(!external.is_empty(), "P2A fee child has no external funding input");
        let mut input_sat = 0u64;
        for point in child.input.iter().map(|input| input.previous_output) {
            let parent = rpc.get_raw_transaction(&point.txid, None).unwrap();
            input_sat += parent.output[point.vout as usize].value.to_sat();
        }
        for point in &external {
            trace_sponsor_coin(ctx, *point, initial, recovery_anchors, &mut HashSet::new());
        }
        let output_sat: u64 = child.output.iter().map(|out| out.value.to_sat()).sum();
        assert!(input_sat > output_sat, "P2A child paid no actual regtest mining fee");
        json!({
            "role": role,
            "used_by": used_by,
            "txid": txid.to_string(),
            "wtxid": saved.compute_wtxid().to_string(),
            "block_height": height,
            "p2a_anchor": anchor.to_string(),
            "fee_child_txid": child.compute_txid().to_string(),
            "fee_child_wtxid": child.compute_wtxid().to_string(),
            "external_fee_inputs": external.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "external_fee_sats": input_sat - output_sat,
        })
    }).collect()
}

/// The supplied terms and saved signed bundle bytes must survive the outage.
fn frozen_recovery_evidence(paths: &[&Path]) -> serde_json::Value {
    let records = paths.iter().map(|path| {
        let raw = fs::read(path).expect("read frozen signed regtest evidence");
        json!({
            "file": path.file_name().expect("named recovery evidence")
                .to_string_lossy().to_string(),
            "sha256": sha256::Hash::hash(&raw).to_string(),
            "bytes": raw.len(),
        })
    }).collect::<Vec<_>>();
    json!({
        "schema": 1,
        "fixture": "local-regtest-saplingos-signed-evidence",
        "files": records,
    })
}

/// Check the original independent agreement and immutable signed exports
/// against the bytes captured *before* signing services were stopped.
/// Catch silent on-disk rollback, replacement, or mutation after outage.
/// The manifest is pinned byte-for-byte, not only as a parsed JSON value,
/// so its published SHA-256 identifies exactly one pre-shutdown file.
fn assert_frozen_recovery_evidence(
    paths: &[&Path],
    frozen: &serde_json::Value,
    manifest: &Path,
    manifest_bytes: &[u8],
) {
    assert_eq!(
        &frozen_recovery_evidence(paths),
        frozen,
        "independent terms or signed recovery export changed after service shutdown"
    );
    let current = fs::read(manifest).expect("read pre-shutdown frozen-evidence manifest");
    assert!(current == manifest_bytes, "frozen-evidence manifest bytes changed after shutdown");
    let recorded: serde_json::Value = serde_json::from_slice(manifest_bytes)
        .expect("parse pre-shutdown frozen-evidence manifest");
    assert_eq!(&recorded, frozen, "frozen-evidence manifest does not describe the frozen files");
}

/// Write the manifest once and keep its exact bytes in memory as the
/// reference for every later check.
fn freeze_manifest(manifest: &Path, frozen: &serde_json::Value) -> Vec<u8> {
    save_json(manifest, frozen);
    fs::read(manifest).expect("read back new frozen-evidence manifest")
}

#[test]
fn frozen_evidence_guard_rejects_substitution_and_manifest_rewrites() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("sapling-freeze-{}-{nonce}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let terms = dir.join("two-holder-terms.json");
    let alice = dir.join("alice-recovery.json");
    let bob = dir.join("bob-recovery.json");
    for (path, value) in [
        (&terms, "independent-agreement"),
        (&alice, "signed-alice"),
        (&bob, "signed-bob"),
    ] {
        save_json(path, &json!({"synthetic": value}));
    }
    let paths = [terms.as_path(), alice.as_path(), bob.as_path()];
    let frozen = frozen_recovery_evidence(&paths);
    let manifest = dir.join("frozen-evidence-before-shutdown.json");
    let manifest_bytes = freeze_manifest(&manifest, &frozen);
    assert_frozen_recovery_evidence(&paths, &frozen, &manifest, &manifest_bytes);

    for path in &paths {
        let original = fs::read(path).unwrap();
        fs::write(path, b"{\"synthetic\":\"altered\"}\n").unwrap();
        assert!(
            std::panic::catch_unwind(|| {
                assert_frozen_recovery_evidence(&paths, &frozen, &manifest, &manifest_bytes)
            }).is_err(),
            "substituted original file unexpectedly passed frozen-evidence check"
        );
        fs::write(path, original).unwrap();
        assert_frozen_recovery_evidence(&paths, &frozen, &manifest, &manifest_bytes);
    }
    // A forged manifest, and a re-serialised copy that parses to the same
    // JSON value, must both fail: the published digest names exact bytes.
    for rewrite in [
        b"{\"schema\":1,\"files\":[]}\n".to_vec(),
        serde_json::to_vec(&frozen).unwrap(),
    ] {
        fs::write(&manifest, &rewrite).unwrap();
        assert!(
            std::panic::catch_unwind(|| {
                assert_frozen_recovery_evidence(&paths, &frozen, &manifest, &manifest_bytes)
            }).is_err(),
            "rewritten evidence manifest unexpectedly passed frozen-evidence check"
        );
    }
    fs::write(&manifest, &manifest_bytes).unwrap();
    assert_frozen_recovery_evidence(&paths, &frozen, &manifest, &manifest_bytes);
    fs::remove_dir_all(dir).unwrap();
}

fn assert_saved_claim(
    ctx: &TestContext,
    saved: &ProgramRecoveryBundle,
    point: OutPoint,
    expected_script: &ScriptBuf,
    expected_value: Amount,
) {
    assert_eq!(saved.targets, vec![point], "wrong selected recovery position");
    assert_eq!(saved.readiness(point).unwrap(), ProgramRecoveryReadiness::Complete);
    let record = saved.recoveries.iter().find(|r| r.controlled_outpoint == point).unwrap();
    assert_eq!(record.claim.output.len(), 2, "unexpected payout/fee-anchor shape");
    assert_eq!(record.claim.output[0].script_pubkey, *expected_script);
    assert_eq!(record.claim.output[0].value, expected_value);
    assert_eq!(record.claim.output[1].value, Amount::ZERO);
    assert_eq!(record.claim.output[1].script_pubkey.as_bytes(), &[0x51, 0x02, 0x4e, 0x73]);

    let claim = ctx.bitcoind().sync_client()
        .get_raw_transaction(&record.claim.compute_txid(), None)
        .expect("saved signed claim missing from Bitcoin Core");
    assert_eq!(claim, record.claim, "confirmed witness bytes changed after shutdown");
    let confirmation = ctx.bitcoind()
        .transaction_confirmation(record.claim.compute_txid())
        .unwrap();
    assert!(confirmation.confirmations.unwrap_or(0) > 0);
}

fn observed_fee_child(ctx: &TestContext, bundle: &ProgramRecoveryBundle) -> serde_json::Value {
    let record = bundle.recoveries.iter()
        .find(|r| r.controlled_outpoint == bundle.targets[0]).unwrap();
    let txid = record.claim.compute_txid();
    let rpc = ctx.bitcoind().sync_client();
    let confirmed = ctx.bitcoind().transaction_confirmation(txid).unwrap();
    let blockhash = confirmed.blockhash.expect("signed recovery claim is unconfirmed");
    let block = rpc.get_block(&blockhash).expect("get confirmed claim block");
    let anchor = OutPoint::new(txid, (record.claim.output.len() - 1) as u32);
    let children = block.txdata.iter().filter(|tx| {
        tx.input.iter().any(|input| input.previous_output == anchor)
    }).collect::<Vec<_>>();
    assert_eq!(children.len(), 1, "claim lacks one definite mined P2A fee child");
    let child = children[0];
    assert_eq!(child.input.iter().filter(|i| i.previous_output == anchor).count(), 1);
    let external = child.input.iter().filter(|i| i.previous_output != anchor)
        .map(|i| i.previous_output).collect::<Vec<_>>();
    assert!(!external.is_empty(), "P2A fee child has no independent funding input");
    let mut input_sat = 0u64;
    for input in &child.input {
        assert!(
            input.previous_output == anchor
                || (input.previous_output.txid != txid
                    && record.ancestors.iter()
                        .all(|ancestor| ancestor.compute_txid() != input.previous_output.txid)),
            "fee wallet consumed recovered beneficiary principal or Ark ancestry"
        );
        let parent = rpc.get_raw_transaction(&input.previous_output.txid, None)
            .expect("fee child references unavailable Bitcoin transaction");
        let prior = &parent.output[input.previous_output.vout as usize];
        if input.previous_output == anchor {
            assert_eq!(prior.value, Amount::ZERO);
        } else {
            assert!(prior.value > Amount::ZERO);
        }
        input_sat += prior.value.to_sat();
    }
    let output_sat: u64 = child.output.iter().map(|out| out.value.to_sat()).sum();
    assert!(input_sat > output_sat, "P2A child paid no actual regtest mining fee");
    json!({
        "claim_txid": txid.to_string(),
        "claim_wtxid": record.claim.compute_wtxid().to_string(),
        "controlled_outpoint": bundle.targets[0].to_string(),
        "claim_blockhash": blockhash.to_string(),
        "fee_child_txid": child.compute_txid().to_string(),
        "fee_child_wtxid": child.compute_wtxid().to_string(),
        "p2a_anchor": anchor.to_string(),
        "external_fee_inputs": external.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "external_fee_sats": input_sat - output_sat,
        "claim_confirmations": confirmed.confirmations.unwrap(),
    })
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn fixture_bitcoin_cli(ctx: &TestContext) -> PathBuf {
    let binary = PathBuf::from(std::env::var_os("SAPLING_TWO_HOLDER_BITCOIN_CLI")
        .expect("set SAPLING_TWO_HOLDER_BITCOIN_CLI to the trusted bitcoin-cli binary"));
    assert!(binary.is_file(), "bitcoin-cli binary does not exist");
    let raw_url = ctx.bitcoind().rpc_url().to_string();
    let after_scheme = raw_url.strip_prefix("http://")
        .expect("test fixture must use local plaintext Bitcoin Core RPC");
    let authority = after_scheme.split('/').next().unwrap().rsplit('@').next().unwrap();
    let (host, port) = authority.rsplit_once(':').expect("Bitcoin Core RPC port missing");
    assert!(host == "127.0.0.1" || host == "localhost",
        "the test must use an isolated loopback regtest node");
    let port: u16 = port.parse().expect("Bitcoin Core RPC port invalid");
    let cookie = ctx.bitcoind().rpc_cookie();
    let wrapper = ctx.datadir.join("two-holder-bitcoin-cli.sh");
    let shell = format!(
        "#!/bin/sh\nexec {} -rpcconnect={} -rpcport={} -rpccookiefile={} \"$@\"\n",
        shell_quote(&binary.to_string_lossy()),
        shell_quote(host),
        port,
        shell_quote(&cookie.to_string_lossy()),
    );
    fs::write(&wrapper, shell).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700)).unwrap();
    }
    wrapper
}

/// The merger, auditor, Python spender and bitcoin-cli are host programs.
/// Drop the pinned Nix dev shell's LD_LIBRARY_PATH so they never load Nix
/// OpenSSL/SQLite libraries against the host glibc.
fn run_fixture_executable(executable: &Path, args: &[&std::ffi::OsStr]) -> std::process::Output {
    let output = std::process::Command::new(executable)
        .args(args).env_remove("LD_LIBRARY_PATH")
        .output().expect("run external verifier in integration fixture");
    assert!(output.status.success(), "external fixture command {} failed:\n{}\n{}",
        executable.display(), String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr));
    output
}

#[tokio::test]
async fn sapio_real_two_holder_offline_recovery() {
    let _exclusive = TEE_LOCK.lock().await;
    let ctx = TestContext::new("sapling_sdk/sapio_real_two_holder_offline_recovery").await;
    let tee = SapioTee::launch(&ctx).await;
    let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc())
        .funded(btc(1)).create().await;
    let sponsor_seed = bip39::Mnemonic::generate(12).unwrap();
    let fee_wallet = ctx.sdk("external-recovery-fees", &srv)
        .mnemonic(sponsor_seed.clone()).funded(sat(800_000))
        .cfg(|c| c.daemon_manual_sync = true).create().await;
    assert!(fee_wallet.spendable_vtxos().await.unwrap().is_empty(),
        "recovery sponsor must have no Ark VTXOs");
    let sponsor_coins = capture_fee_wallet_funding(&fee_wallet).await;

    // Key custody is independent and observable through Bitcoin Core.
    let (alice_recipient, alice_script) = new_recipient_wallet(&ctx, "alice-recovered");
    let (bob_recipient, bob_script) = new_recipient_wallet(&ctx, "bob-recovered");
    assert_ne!(alice_script, bob_script);
    let program = lifecycle_program();
    let program_id = program.id().to_string();
    let signer_root = tee.public_root().to_string();
    let alice_seed = bip39::Mnemonic::generate(12).unwrap();
    let bob_seed = bip39::Mnemonic::generate(12).unwrap();
    let agreed_program = program.clone();
    let (owner_a, owner_b) = (alice_seed.clone(), bob_seed.clone());
    assert_ne!(alice_seed.to_string(), bob_seed.to_string());
    assert_ne!(sponsor_seed.to_string(), alice_seed.to_string());
    assert_ne!(sponsor_seed.to_string(), bob_seed.to_string());

    // Two genuine SaplingOS program-controlled VTXOs, created by live
    // signatures and actual Bitcoin boarding, have 60k/40k principal.
    let cfg_a = config(&tee, program.clone(),
        recovery(alice_script.clone(), 0u32.to_le_bytes().to_vec()), None);
    let seed_a = alice_seed.clone();
    let alice = ctx.sdk("alice", &srv).mnemonic(alice_seed).funded(sat(500_000))
        .boarded(sat(60_000))
        .cfg(move |c| configure_wallet(c, cfg_a, &seed_a)).create().await;

    let cfg_b = config(&tee, program,
        recovery(bob_script.clone(), 0u32.to_le_bytes().to_vec()), None);
    let seed_b = bob_seed.clone();
    let bob = ctx.sdk("bob", &srv).mnemonic(bob_seed).funded(sat(500_000))
        .boarded(sat(40_000))
        .cfg(move |c| configure_wallet(c, cfg_b, &seed_b)).create().await;

    let alice_positions = alice.spendable_vtxos().await.unwrap();
    let bob_positions = bob.spendable_vtxos().await.unwrap();
    assert_eq!(alice_positions.len(), 1);
    assert_eq!(bob_positions.len(), 1);
    let alice_point = alice_positions[0].vtxo.point();
    let bob_point = bob_positions[0].vtxo.point();
    assert_ne!(alice_point, bob_point);
    assert_eq!(alice_positions[0].amount(), sat(60_000));
    assert_eq!(bob_positions[0].amount(), sat(40_000));
    // Separately boarded: each position has its own on-chain funding root,
    // so neither holder's recovery can depend on the other's ancestry.
    let alice_anchor = alice_positions[0].vtxo.chain_anchor();
    let bob_anchor = bob_positions[0].vtxo.chain_anchor();
    assert_ne!(alice_anchor, bob_anchor, "separately boarded VTXOs share a funding root");

    // Independent terms originate from the configured, running signer and
    // owner VTXO state, BEFORE asking either wallet for a recovery export.
    // The SDK cannot supply the beneficiary scripts for this document.
    let terms = json!({
        "version": 1,
        "network": "regtest",
        "targets": [
            {
                "outpoint": alice_point.to_string(),
                "program": {
                    "program_id": program_id,
                    "signer_root": signer_root,
                    "user_pubkey": holder_user_pubkey(&owner_a, tee.public_root(), &agreed_program,
                        alice_positions[0].vtxo.user_pubkey()).to_string()
                },
                "beneficiaries": [
                    {"holder": "alice", "script_pubkey_hex": script_hex(&alice_script), "sats": 60000}
                ]
            },
            {
                "outpoint": bob_point.to_string(),
                "program": {
                    "program_id": program_id,
                    "signer_root": signer_root,
                    "user_pubkey": holder_user_pubkey(&owner_b, tee.public_root(), &agreed_program,
                        bob_positions[0].vtxo.user_pubkey()).to_string()
                },
                "beneficiaries": [
                    {"holder": "bob", "script_pubkey_hex": script_hex(&bob_script), "sats": 40000}
                ]
            }
        ]
    });
    drop(alice_positions);
    drop(bob_positions);

    let artifact_dir = std::env::var_os("SAPLING_TWO_HOLDER_CAPTURE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| ctx.datadir.join("two-holder-capture"));
    fs::create_dir_all(&artifact_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&artifact_dir, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut sponsor_points = sponsor_coins.iter().map(ToString::to_string)
        .collect::<Vec<_>>();
    sponsor_points.sort();
    save_json(&artifact_dir.join("external-fee-utxos-before-shutdown.json"), &sponsor_points);
    let terms_file = artifact_dir.join("two-holder-terms.json");
    save_json(&terms_file, &terms);

    let bundle_a = alice.program_recovery_bundle(&[alice_point]).await.unwrap();
    let bundle_b = bob.program_recovery_bundle(&[bob_point]).await.unwrap();
    assert_eq!(bundle_a.readiness(alice_point).unwrap(), ProgramRecoveryReadiness::Complete);
    assert_eq!(bundle_b.readiness(bob_point).unwrap(), ProgramRecoveryReadiness::Complete);
    bundle_a.verify().unwrap();
    bundle_b.verify().unwrap();
    let alice_file = artifact_dir.join("alice-recovery.json");
    let bob_file = artifact_dir.join("bob-recovery.json");
    save_json(&alice_file, &bundle_a);
    save_json(&bob_file, &bundle_b);
    let frozen_paths = [
        terms_file.as_path(), alice_file.as_path(), bob_file.as_path(),
    ];
    let frozen = frozen_recovery_evidence(&frozen_paths);
    let frozen_manifest = artifact_dir.join("frozen-evidence-before-shutdown.json");
    let frozen_manifest_bytes = freeze_manifest(&frozen_manifest, &frozen);
    let holders = [("alice", &bundle_a), ("bob", &bundle_b)];
    assert_unpublished(&ctx, &holders);

    // The Ark service and Sapio signing service now disappear. From this
    // point on each claimant reopens solely its persisted seed and unsigned/
    // signed Bitcoin recovery evidence in a fresh OS process.
    alice.stop_daemon_wait().await.unwrap();
    bob.stop_daemon_wait().await.unwrap();
    fee_wallet.stop_daemon_wait().await.unwrap();
    drop(fee_wallet);
    drop(alice);
    drop(bob);
    tee.stop().await.unwrap();
    srv.stop().await.unwrap();
    assert_frozen_recovery_evidence(&frozen_paths, &frozen, &frozen_manifest, &frozen_manifest_bytes);
    assert!(tokio::net::TcpStream::connect("127.0.0.1:8000").await.is_err(),
        "Sapio local-dev signing API still answers after shutdown");
    assert!(tokio::net::TcpStream::connect("127.0.0.1:8367").await.is_err(),
        "Sapio local-dev signing oracle still answers after shutdown");
    let shutdown_height = record_shutdown(&ctx, &artifact_dir, &holders, &[
        "alice-sdk", "bob-sdk", "external-recovery-fees-sdk", "sapio-tee", "captaind",
    ]);

    // Confirm Alice without Bob's wallet; then confirm Bob independently.
    // Both use the pinned SDK's ordinary, externally funded fee wallet and
    // validate exact P2A children, native CSV/CLTV and Bitcoin Core confirmations.
    recover_offline(&ctx, "external-recovery-fees", Some(&alice_file), &bundle_a).await;
    assert_saved_claim(&ctx, &bundle_a, alice_point, &alice_script, sat(60_000));
    let claim_txid = |bundle: &ProgramRecoveryBundle| bundle.recoveries.iter()
        .find(|r| r.controlled_outpoint == bundle.targets[0]).unwrap().claim.compute_txid();
    assert!(ctx.bitcoind().sync_client()
        .get_raw_transaction(&claim_txid(&bundle_b), None).is_err(),
        "Bob's recovery published without Bob initiating recovery");
    recover_offline(&ctx, "external-recovery-fees", Some(&bob_file), &bundle_b).await;
    assert_saved_claim(&ctx, &bundle_b, bob_point, &bob_script, sat(40_000));

    assert_frozen_recovery_evidence(&frozen_paths, &frozen, &frozen_manifest, &frozen_manifest_bytes);

    // Reach an independently chosen 6-confirmation policy before redemption.
    ctx.bitcoind().generate(6).await;
    for bundle in [&bundle_a, &bundle_b] {
        assert!(ctx.bitcoind().transaction_confirmation(claim_txid(bundle)).unwrap()
            .confirmations.unwrap_or(0) >= 6);
    }

    let alice_fee_child = observed_fee_child(&ctx, &bundle_a);
    let bob_fee_child = observed_fee_child(&ctx, &bundle_b);
    let recovery_anchors = selected_recovery_anchors(&[&bundle_a, &bundle_b]);
    require_external_fee_wallet_funding(&ctx, &alice_fee_child, &sponsor_coins, &recovery_anchors);
    require_external_fee_wallet_funding(&ctx, &bob_fee_child, &sponsor_coins, &recovery_anchors);
    let recovery_chain = confirmed_recovery_chain(
        &ctx, &holders, shutdown_height, &sponsor_coins, &recovery_anchors);
    // Separate roots: no signed recovery transaction serves both holders,
    // and each funding root alone backs its holder's agreed amount.
    assert!(recovery_chain.iter().all(|row| row["used_by"].as_array().unwrap().len() == 1),
        "separately boarded recoveries share a signed transaction");
    let rpc = ctx.bitcoind().sync_client();
    let mut chain_anchors = serde_json::Map::new();
    for (holder, anchor, agreed) in [
        ("alice", alice_anchor, sat(60_000)), ("bob", bob_anchor, sat(40_000)),
    ] {
        let value = rpc.get_raw_transaction(&anchor.txid, None)
            .expect("holder's funding root is missing from Bitcoin Core")
            .output[anchor.vout as usize].value;
        assert!(value >= agreed, "{holder}'s funding root cannot back its claim");
        chain_anchors.insert(holder.into(), json!({
            "outpoint": anchor.to_string(), "sats": value.to_sat(),
        }));
    }
    let fee_proof = json!({
        "alice": alice_fee_child,
        "bob": bob_fee_child,
        "external_fee_wallet": "external-recovery-fees",
        "external_fee_wallet_keys_distinct_from_holders": true,
        "real_common_root": false,
        "separate_roots": true,
        "chain_anchors": chain_anchors,
        "services_offline_when_fee_children_mined": true,
        "bitcoin_height_at_shutdown": shutdown_height,
        "recovery_transactions": recovery_chain,
    });
    save_json(&artifact_dir.join("confirmed-p2a-fee-children.json"), &fee_proof);

    // Invoke the actual PR #2 standalone auditor on genuinely signed exports.
    // The three executables are explicitly supplied by the external e2e
    // harness; their absence fails the test instead of silently skipping.
    let merger = PathBuf::from(std::env::var_os("SAPLING_TWO_HOLDER_MERGER")
        .expect("build the pinned two-holder bundle merger"));
    let auditor = PathBuf::from(std::env::var_os("SAPLING_TWO_HOLDER_AUDITOR")
        .expect("build the pinned SaplingOS standalone auditor"));
    let spender = PathBuf::from(std::env::var_os("SAPLING_TWO_HOLDER_PY")
        .expect("supply the two-holder regtest PSBT spender Python path"));
    let combined = artifact_dir.join("both-signed-recoveries.json");
    assert_frozen_recovery_evidence(&frozen_paths, &frozen, &frozen_manifest, &frozen_manifest_bytes);
    run_fixture_executable(&merger, &[
        alice_file.as_os_str(), bob_file.as_os_str(),
        terms_file.as_os_str(), combined.as_os_str(),
    ]);
    let cli = fixture_bitcoin_cli(&ctx);
    let audit = run_fixture_executable(&auditor, &[
        combined.as_os_str(), terms_file.as_os_str(),
        std::ffi::OsStr::new("--bitcoin-cli"), cli.as_os_str(),
        std::ffi::OsStr::new("--confirmations"), std::ffi::OsStr::new("6"),
        std::ffi::OsStr::new("--two-holder"),
    ]);
    let report: serde_json::Value = serde_json::from_slice(&audit.stdout)
        .expect("auditor returned invalid JSON");
    assert_eq!(report["offline"]["total_protected_sats"], 100_000);
    assert_eq!(report["offline"]["selected_paths_nonconflicting"], true);
    assert_eq!(report["two_holder"]["total_payout_sats"], 100_000);
    assert_eq!(report["two_holder"]["holders"].as_array().unwrap().len(), 2);
    let report_file = artifact_dir.join("two-holder-pre-spend-report.json");
    save_json(&report_file, &report);

    // The separate recipient wallets now sign PSBTs, spending only their
    // corresponding payouts. Python checks each recovered outpoint exactly,
    // puts a strict upper bound on fees, and mines both spends on regtest.
    let mine_addr = ctx.bitcoind().get_new_address().to_string();
    set_recipient_wallets_loaded(&ctx, &["alice-recovered", "bob-recovered"], true);
    let dest_a: String = alice_recipient.call("getnewaddress", &[]).unwrap();
    let dest_b: String = bob_recipient.call("getnewaddress", &[]).unwrap();
    let dest_a = format!("alice={dest_a}");
    let dest_b = format!("bob={dest_b}");
    let spend = run_fixture_executable(Path::new("/usr/bin/env"), &[
        std::ffi::OsStr::new("python3"),
        spender.as_os_str(), report_file.as_os_str(),
        std::ffi::OsStr::new("--bitcoin-cli"), cli.as_os_str(),
        std::ffi::OsStr::new("--wallet"), std::ffi::OsStr::new("alice=alice-recovered"),
        std::ffi::OsStr::new("--wallet"), std::ffi::OsStr::new("bob=bob-recovered"),
        std::ffi::OsStr::new("--destination"), std::ffi::OsStr::new(dest_a.as_str()),
        std::ffi::OsStr::new("--destination"), std::ffi::OsStr::new(dest_b.as_str()),
        std::ffi::OsStr::new("--mine-address"), std::ffi::OsStr::new(mine_addr.as_str()),
        std::ffi::OsStr::new("--broadcast"),
    ]);
    let receipt: serde_json::Value = serde_json::from_slice(&spend.stdout)
        .expect("independent-wallet redemption output was invalid JSON");
    set_recipient_wallets_loaded(&ctx, &["alice-recovered", "bob-recovered"], false);
    assert_eq!(receipt["independent_spends_confirmed"], true);
    assert_eq!(receipt["redemptions"].as_array().unwrap().len(), 2);
    // Earlier reports must remain separate from post-spend reports: both
    // recovered payout UTXOs have deliberately left the UTXO set.
    verify_redemptions(&ctx, &report, &receipt);
    save_json(&artifact_dir.join("two-holder-redemptions.json"), &receipt);
    assert_frozen_recovery_evidence(&frozen_paths, &frozen, &frozen_manifest, &frozen_manifest_bytes);
    fs::remove_file(cli).unwrap();
}

#[tokio::test]
async fn sapio_real_common_anchor_two_holder_recovery() {
    common_anchor_fixture(false).await;
}

/// Adversarial negative control: the prior program owner saves a signed exit
/// before the two-holder transfer, then publishes it after both services die.
#[tokio::test]
async fn sapio_real_stale_sender_recovery_race() {
    common_anchor_fixture(true).await;
}

async fn common_anchor_fixture(stale_sender_attack: bool) {
    let _exclusive = TEE_LOCK.lock().await;
    let ctx = TestContext::new(if stale_sender_attack {
        "sapling_sdk/sapio_real_stale_sender_recovery_race"
    } else {
        "sapling_sdk/sapio_real_common_anchor_two_holder_recovery"
    }).await;
    let tee = SapioTee::launch(&ctx).await;
    let srv = ctx.captaind("server").bitcoind(ctx.bitcoind_arc())
        .funded(btc(1)).create().await;
    let sponsor_seed = bip39::Mnemonic::generate(12).unwrap();
    let fee_wallet = ctx.sdk("external-recovery-fees", &srv)
        .mnemonic(sponsor_seed.clone()).funded(sat(800_000))
        .cfg(|c| c.daemon_manual_sync = true).create().await;
    assert!(fee_wallet.spendable_vtxos().await.unwrap().is_empty(),
        "recovery sponsor must have no Ark VTXOs");
    let sponsor_coins = capture_fee_wallet_funding(&fee_wallet).await;

    // In the adversarial run, the initial owner is a genuine program
    // wallet, allowing its earlier fully signed exit to be frozen before
    // the same economic root is transferred to Alice and Bob.
    let stale_script = ctx.bitcoind().get_new_address().script_pubkey();
    let sender = if stale_sender_attack {
        let sender_seed = bip39::Mnemonic::generate(12).unwrap();
        let sender_evidence = sender_seed.clone();
        let sender_config = config(&tee, lifecycle_program(),
            recovery(stale_script.clone(), 0u32.to_le_bytes().to_vec()), None);
        ctx.sdk("sender", &srv).mnemonic(sender_seed).boarded(sat(120_000))
            .cfg(move |c| configure_wallet(c, sender_config, &sender_evidence))
            .create().await
    } else {
        ctx.sdk("sender", &srv).boarded(sat(120_000)).create().await
    };
    let original = sender.spendable_vtxos().await.unwrap();
    assert_eq!(original.len(), 1);
    assert_eq!(original[0].amount(), sat(120_000));
    let anchor = original[0].vtxo.chain_anchor();
    let stale_sender = if stale_sender_attack {
        let position = original[0].vtxo.point();
        let saved = sender.program_recovery_bundle(&[position]).await.unwrap();
        saved.verify().unwrap();
        assert_eq!(saved.readiness(position).unwrap(), ProgramRecoveryReadiness::Complete);
        let claim = &saved.recoveries.iter()
            .find(|r| r.controlled_outpoint == position).unwrap().claim;
        assert_eq!(claim.output.len(), 2);
        assert_eq!(claim.output[0].value, sat(120_000));
        assert_eq!(claim.output[0].script_pubkey, stale_script);
        Some((position, saved))
    } else {
        None
    };
    drop(original);

    let (alice_core, alice_script) = new_recipient_wallet(&ctx, "alice-recovered");
    let (bob_core, bob_script) = new_recipient_wallet(&ctx, "bob-recovered");
    assert_ne!(alice_script, bob_script);
    let program = lifecycle_program();
    let program_id = program.id().to_string();
    let signer_root = tee.public_root().to_string();
    let seed_a = bip39::Mnemonic::generate(12).unwrap();
    let seed_b = bip39::Mnemonic::generate(12).unwrap();
    let agreed_program = program.clone();
    let (owner_a, owner_b) = (seed_a.clone(), seed_b.clone());
    assert_ne!(seed_a.to_string(), seed_b.to_string());
    assert_ne!(sponsor_seed.to_string(), seed_a.to_string());
    assert_ne!(sponsor_seed.to_string(), seed_b.to_string());

    let (alice_socket, alice_url) = listener().await;
    let (bob_socket, bob_url) = listener().await;
    let config_a = config(&tee, program.clone(),
        recovery(alice_script.clone(), 0u32.to_le_bytes().to_vec()), Some(alice_url));
    let config_b = config(&tee, program,
        recovery(bob_script.clone(), 0u32.to_le_bytes().to_vec()), Some(bob_url));
    let evidence_a = seed_a.clone();
    let evidence_b = seed_b.clone();
    let alice = ctx.sdk("alice", &srv).mnemonic(seed_a).funded(sat(500_000))
        .cfg(move |c| configure_wallet(c, config_a, &evidence_a)).create().await;
    let bob = ctx.sdk("bob", &srv).mnemonic(seed_b).funded(sat(500_000))
        .cfg(move |c| configure_wallet(c, config_b, &evidence_b)).create().await;
    let coordinator_a = Receiver::start(alice_socket, &alice);
    let coordinator_b = Receiver::start(bob_socket, &bob);

    let alice_address = alice.new_address().await.unwrap();
    sender.send_arkoor_payment(&alice_address, sat(60_000)).await
        .expect("real Sapio first transfer must commit Alice's 60k right");
    let bob_address = bob.new_address().await.unwrap();
    sender.send_arkoor_payment(&bob_address, sat(40_000)).await
        .expect("real Sapio second transfer must commit Bob's 40k right");

    let alice_positions = alice.spendable_vtxos().await.unwrap();
    let bob_positions = bob.spendable_vtxos().await.unwrap();
    assert_eq!(alice_positions.len(), 1);
    assert_eq!(bob_positions.len(), 1);
    assert_eq!(alice_positions[0].amount(), sat(60_000));
    assert_eq!(bob_positions[0].amount(), sat(40_000));
    let alice_point = alice_positions[0].vtxo.point();
    let bob_point = bob_positions[0].vtxo.point();
    assert_ne!(alice_point, bob_point);
    assert_eq!(alice_positions[0].vtxo.chain_anchor(), anchor,
        "Alice lost the source's common economic root");
    assert_eq!(bob_positions[0].vtxo.chain_anchor(), anchor,
        "Bob's signed VTXO does not share Alice's source funding anchor");

    let terms = json!({
        "version":1,
        "network":"regtest",
        "targets":[
            {
                "outpoint":alice_point.to_string(),
                "program":{
                    "program_id":program_id.clone(),
                    "signer_root":signer_root.clone(),
                    "user_pubkey":holder_user_pubkey(&owner_a, tee.public_root(), &agreed_program,
                        alice_positions[0].vtxo.user_pubkey()).to_string()
                },
                "beneficiaries":[
                    {"holder":"alice", "script_pubkey_hex":script_hex(&alice_script), "sats":60000}
                ]
            },
            {
                "outpoint":bob_point.to_string(),
                "program":{
                    "program_id":program_id,
                    "signer_root":signer_root,
                    "user_pubkey":holder_user_pubkey(&owner_b, tee.public_root(), &agreed_program,
                        bob_positions[0].vtxo.user_pubkey()).to_string()
                },
                "beneficiaries":[
                    {"holder":"bob", "script_pubkey_hex":script_hex(&bob_script), "sats":40000}
                ]
            }
        ]
    });
    drop(alice_positions);
    drop(bob_positions);
    let dir = std::env::var_os("SAPLING_TWO_HOLDER_CAPTURE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| ctx.datadir.join("two-holder-common-anchor"));
    fs::create_dir_all(&dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut sponsor_points = sponsor_coins.iter().map(ToString::to_string)
        .collect::<Vec<_>>();
    sponsor_points.sort();
    save_json(&dir.join("external-fee-utxos-before-shutdown.json"), &sponsor_points);
    let terms_file = dir.join("two-holder-terms.json");
    save_json(&terms_file, &terms);

    let bundle_a = alice.program_recovery_bundle(&[alice_point]).await.unwrap();
    let bundle_b = bob.program_recovery_bundle(&[bob_point]).await.unwrap();
    assert_eq!(bundle_a.targets, vec![alice_point]);
    assert_eq!(bundle_b.targets, vec![bob_point]);
    assert_eq!(bundle_a.readiness(alice_point).unwrap(), ProgramRecoveryReadiness::Complete);
    assert_eq!(bundle_b.readiness(bob_point).unwrap(), ProgramRecoveryReadiness::Complete);
    bundle_a.verify().unwrap();
    bundle_b.verify().unwrap();
    let alice_file = dir.join("alice-recovery.json");
    let bob_file = dir.join("bob-recovery.json");
    save_json(&alice_file, &bundle_a);
    save_json(&bob_file, &bundle_b);
    let stale_file = dir.join("stale-sender-recovery.json");
    if let Some((_, saved)) = &stale_sender {
        save_json(&stale_file, saved);
    }
    let mut frozen_paths = vec![
        terms_file.as_path(), alice_file.as_path(), bob_file.as_path(),
    ];
    if stale_sender.is_some() {
        frozen_paths.push(stale_file.as_path());
    }
    let frozen = frozen_recovery_evidence(&frozen_paths);
    let frozen_manifest = dir.join("frozen-evidence-before-shutdown.json");
    let frozen_manifest_bytes = freeze_manifest(&frozen_manifest, &frozen);
    let holders = [("alice", &bundle_a), ("bob", &bundle_b)];
    assert_unpublished(&ctx, &holders);
    if let Some((_, saved)) = &stale_sender {
        assert_unpublished(&ctx, &[("stale-sender", saved)]);
    }
    drop(coordinator_a);
    drop(coordinator_b);

    // Stop every signer and every owner SDK before recovery publication.
    alice.stop_daemon_wait().await.unwrap();
    bob.stop_daemon_wait().await.unwrap();
    fee_wallet.stop_daemon_wait().await.unwrap();
    sender.stop_daemon_wait().await.unwrap();
    drop(fee_wallet);
    drop(alice);
    drop(bob);
    drop(sender);
    tee.stop().await.unwrap();
    srv.stop().await.unwrap();
    assert_frozen_recovery_evidence(&frozen_paths, &frozen, &frozen_manifest, &frozen_manifest_bytes);
    assert!(tokio::net::TcpStream::connect("127.0.0.1:8000").await.is_err(),
        "Sapio local-dev signing API still answers after shutdown");
    assert!(tokio::net::TcpStream::connect("127.0.0.1:8367").await.is_err(),
        "Sapio local-dev signing oracle still answers after shutdown");
    let shutdown_height = record_shutdown(&ctx, &dir, &holders, &[
        "alice-sdk", "bob-sdk", "external-recovery-fees-sdk", "sender-sdk",
        "sapio-tee", "captaind",
    ]);

    recover_offline(&ctx, "external-recovery-fees", Some(&alice_file), &bundle_a).await;
    assert_saved_claim(&ctx, &bundle_a, alice_point, &alice_script, sat(60_000));
    assert!(ctx.bitcoind().sync_client().get_raw_transaction(
        &bundle_b.recoveries.iter().find(|r| r.controlled_outpoint == bob_point)
            .unwrap().claim.compute_txid(), None).is_err(),
        "Bob's VTXO paid out before Bob independently requested his recovery");
    recover_offline(&ctx, "external-recovery-fees", Some(&bob_file), &bundle_b).await;
    assert_saved_claim(&ctx, &bundle_b, bob_point, &bob_script, sat(40_000));
    ctx.bitcoind().generate(6).await;

    assert_frozen_recovery_evidence(&frozen_paths, &frozen, &frozen_manifest, &frozen_manifest_bytes);

    let merger = PathBuf::from(std::env::var_os("SAPLING_TWO_HOLDER_MERGER")
        .expect("build the pinned merged-bundle verifier"));
    let auditor = PathBuf::from(std::env::var_os("SAPLING_TWO_HOLDER_AUDITOR")
        .expect("build the independently pinned SaplingOS auditor"));
    let spender = PathBuf::from(std::env::var_os("SAPLING_TWO_HOLDER_PY")
        .expect("supply independent Bitcoin Core PSBT spend runner"));
    let merged = dir.join("both-signed-recoveries.json");
    assert_frozen_recovery_evidence(&frozen_paths, &frozen, &frozen_manifest, &frozen_manifest_bytes);
    run_fixture_executable(&merger, &[
        alice_file.as_os_str(), bob_file.as_os_str(),
        terms_file.as_os_str(), merged.as_os_str()
    ]);
    let cli = fixture_bitcoin_cli(&ctx);
    let audited = run_fixture_executable(&auditor, &[
        merged.as_os_str(), terms_file.as_os_str(),
        std::ffi::OsStr::new("--bitcoin-cli"), cli.as_os_str(),
        std::ffi::OsStr::new("--confirmations"), std::ffi::OsStr::new("6"),
        std::ffi::OsStr::new("--two-holder"),
    ]);
    let report: serde_json::Value = serde_json::from_slice(&audited.stdout).unwrap();
    assert_eq!(report["offline"]["total_protected_sats"], 100_000);
    assert_eq!(report["two_holder"]["total_payout_sats"], 100_000);
    assert_eq!(report["offline"]["selected_paths_nonconflicting"], true);
    assert_eq!(report["two_holder"]["holders"].as_array().unwrap().len(), 2);
    save_json(&dir.join("two-holder-pre-spend-report.json"), &report);

    let alice_fee_child = observed_fee_child(&ctx, &bundle_a);
    let bob_fee_child = observed_fee_child(&ctx, &bundle_b);
    let recovery_anchors = selected_recovery_anchors(&[&bundle_a, &bundle_b]);
    require_external_fee_wallet_funding(&ctx, &alice_fee_child, &sponsor_coins, &recovery_anchors);
    require_external_fee_wallet_funding(&ctx, &bob_fee_child, &sponsor_coins, &recovery_anchors);
    let recovery_chain = confirmed_recovery_chain(
        &ctx, &holders, shutdown_height, &sponsor_coins, &recovery_anchors);
    // The sibling claims descend from one signed transaction that both
    // exports carry, which spends the single funded root.
    assert!(recovery_chain.iter().any(|row| row["role"] == "ancestor"
            && row["used_by"] == json!(["alice", "bob"])),
        "Alice's and Bob's recoveries share no signed ancestor");
    let anchor_value = ctx.bitcoind().sync_client()
        .get_raw_transaction(&anchor.txid, None)
        .expect("shared chain anchor is missing from Bitcoin Core")
        .output[anchor.vout as usize].value;
    assert!(anchor_value >= sat(100_000), "common root cannot back both claims");
    let fee_proof = json!({
        "alice": alice_fee_child,
        "bob": bob_fee_child,
        "external_fee_wallet": "external-recovery-fees",
        "external_fee_wallet_keys_distinct_from_holders": true,
        "shared_chain_anchor": anchor.to_string(),
        "shared_chain_anchor_sats": anchor_value.to_sat(),
        "real_common_root": true,
        "services_offline_when_fee_children_mined": true,
        "bitcoin_height_at_shutdown": shutdown_height,
        "recovery_transactions": recovery_chain,
    });
    save_json(&dir.join("confirmed-p2a-fee-children.json"), &fee_proof);

    let mine_addr = ctx.bitcoind().get_new_address().to_string();
    set_recipient_wallets_loaded(&ctx, &["alice-recovered", "bob-recovered"], true);
    let alice_dest: String = alice_core.call("getnewaddress", &[]).unwrap();
    let bob_dest: String = bob_core.call("getnewaddress", &[]).unwrap();
    let alice_arg = format!("alice={alice_dest}");
    let bob_arg = format!("bob={bob_dest}");
    let redemption = run_fixture_executable(Path::new("/usr/bin/env"), &[
        std::ffi::OsStr::new("python3"), spender.as_os_str(),
        dir.join("two-holder-pre-spend-report.json").as_os_str(),
        std::ffi::OsStr::new("--bitcoin-cli"), cli.as_os_str(),
        std::ffi::OsStr::new("--wallet"), std::ffi::OsStr::new("alice=alice-recovered"),
        std::ffi::OsStr::new("--wallet"), std::ffi::OsStr::new("bob=bob-recovered"),
        std::ffi::OsStr::new("--destination"), std::ffi::OsStr::new(alice_arg.as_str()),
        std::ffi::OsStr::new("--destination"), std::ffi::OsStr::new(bob_arg.as_str()),
        std::ffi::OsStr::new("--mine-address"), std::ffi::OsStr::new(mine_addr.as_str()),
        std::ffi::OsStr::new("--broadcast"),
    ]);
    let receipt: serde_json::Value = serde_json::from_slice(&redemption.stdout).unwrap();
    set_recipient_wallets_loaded(&ctx, &["alice-recovered", "bob-recovered"], false);
    assert_eq!(receipt["independent_spends_confirmed"], true);
    assert_eq!(receipt["redemptions"].as_array().unwrap().len(), 2);
    verify_redemptions(&ctx, &report, &receipt);
    save_json(&dir.join("two-holder-redemptions.json"), &receipt);
    assert_frozen_recovery_evidence(&frozen_paths, &frozen, &frozen_manifest, &frozen_manifest_bytes);
    fs::remove_file(cli).unwrap();
}
