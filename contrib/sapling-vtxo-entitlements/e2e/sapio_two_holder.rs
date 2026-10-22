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
    (client, address.script_pubkey())
}

fn script_hex(script: &ScriptBuf) -> String {
    script.as_bytes().iter().map(|byte| format!("{byte:02x}")).collect()
}

fn save_json(path: &Path, value: &impl serde::Serialize) {
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
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

fn run_fixture_executable(executable: &Path, args: &[&std::ffi::OsStr]) -> std::process::Output {
    let output = std::process::Command::new(executable)
        .args(args).output().expect("run external verifier in integration fixture");
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

    // Key custody is independent and observable through Bitcoin Core.
    let (alice_recipient, alice_script) = new_recipient_wallet(&ctx, "alice-recovered");
    let (bob_recipient, bob_script) = new_recipient_wallet(&ctx, "bob-recovered");
    assert_ne!(alice_script, bob_script);
    let program = lifecycle_program();
    let program_id = program.id().to_string();
    let signer_root = tee.public_root().to_string();
    let alice_seed = bip39::Mnemonic::generate(12).unwrap();
    let bob_seed = bip39::Mnemonic::generate(12).unwrap();
    assert_ne!(alice_seed.to_string(), bob_seed.to_string());

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
                    "user_pubkey": alice_positions[0].vtxo.user_pubkey().to_string()
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
                    "user_pubkey": bob_positions[0].vtxo.user_pubkey().to_string()
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

    // The Ark service and Sapio signing service now disappear. From this
    // point on each claimant reopens solely its persisted seed and unsigned/
    // signed Bitcoin recovery evidence in a fresh OS process.
    alice.stop_daemon_wait().await.unwrap();
    bob.stop_daemon_wait().await.unwrap();
    drop(alice);
    drop(bob);
    tee.stop().await.unwrap();
    srv.stop().await.unwrap();
    assert!(tokio::net::TcpStream::connect("127.0.0.1:8000").await.is_err(),
        "Sapio local-dev signing API still answers after shutdown");
    assert!(tokio::net::TcpStream::connect("127.0.0.1:8367").await.is_err(),
        "Sapio local-dev signing oracle still answers after shutdown");

    // Confirm Alice without Bob's wallet; then confirm Bob independently.
    // Both use the pinned SDK's ordinary, externally funded fee wallet and
    // validate exact P2A children, native CSV/CLTV and Bitcoin Core confirmations.
    recover_offline(&ctx, "alice", Some(&alice_file), &bundle_a).await;
    assert_saved_claim(&ctx, &bundle_a, alice_point, &alice_script, sat(60_000));
    assert!(ctx.bitcoind().sync_client()
        .get_raw_transaction(&bundle_b.recoveries[0].claim.compute_txid(), None).is_err(),
        "Bob's recovery published without Bob initiating recovery");
    recover_offline(&ctx, "bob", Some(&bob_file), &bundle_b).await;
    assert_saved_claim(&ctx, &bundle_b, bob_point, &bob_script, sat(40_000));

    // Reach an independently chosen 6-confirmation policy before redemption.
    ctx.bitcoind().generate(6).await;
    for bundle in [&bundle_a, &bundle_b] {
        let txid = bundle.recoveries[0].claim.compute_txid();
        assert!(ctx.bitcoind().transaction_confirmation(txid).unwrap()
            .confirmations.unwrap_or(0) >= 6);
    }

    let fee_proof = json!({
        "alice": observed_fee_child(&ctx, &bundle_a),
        "bob": observed_fee_child(&ctx, &bundle_b),
        "services_offline_when_fee_children_mined": true,
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
    assert_eq!(report["two_holder"]["total_payout_sats"], 100_000);
    assert_eq!(report["two_holder"]["holders"].as_array().unwrap().len(), 2);
    let report_file = artifact_dir.join("two-holder-pre-spend-report.json");
    save_json(&report_file, &report);

    // The separate recipient wallets now sign PSBTs, spending only their
    // corresponding payouts. Python checks each recovered outpoint exactly,
    // puts a strict upper bound on fees, and mines both spends on regtest.
    let dest_a: String = alice_recipient.call("getnewaddress", &[]).unwrap();
    let dest_b: String = bob_recipient.call("getnewaddress", &[]).unwrap();
    let mine_addr = ctx.bitcoind().get_new_address().to_string();
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
    assert_eq!(receipt["independent_spends_confirmed"], true);
    assert_eq!(receipt["redemptions"].as_array().unwrap().len(), 2);
    save_json(&artifact_dir.join("two-holder-redemptions.json"), &receipt);

    // Earlier reports must remain separate from post-spend reports: both
    // recovered payout UTXOs have deliberately left the UTXO set.
    for holder in ["alice", "bob"] {
        let redemption = receipt["redemptions"].as_array().unwrap()
            .iter().find(|row| row["holder"] == holder).unwrap();
        let txid: bitcoin::Txid = redemption["txid"].as_str().unwrap().parse().unwrap();
        assert!(ctx.bitcoind().transaction_confirmation(txid).unwrap()
            .confirmations.unwrap_or(0) >= 1);
    }
    fs::remove_file(cli).unwrap();
}
