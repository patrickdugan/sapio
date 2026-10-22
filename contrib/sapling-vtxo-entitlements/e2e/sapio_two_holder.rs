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

fn spend_one_recipient(
    ctx: &TestContext,
    wallet: &Client,
    bundle: &ProgramRecoveryBundle,
    expected_amount: Amount,
) -> bitcoin::Txid {
    let point = bundle.targets[0];
    let record = bundle.recoveries.iter().find(|r| r.controlled_outpoint == point).unwrap();
    let paid = OutPoint::new(record.claim.compute_txid(), 0);
    let unspent: serde_json::Value = wallet.call("listunspent", &[json!(1), json!(9999999)])
        .expect("read beneficiary's own wallet UTXOs");
    let spendable = unspent.as_array().unwrap().iter().filter(|coin| {
        coin["txid"] == paid.txid.to_string() && coin["vout"] == paid.vout
            && coin["spendable"] == true
    }).count();
    assert_eq!(spendable, 1, "beneficiary wallet lacks its own payout key");

    let address: String = wallet.call("getnewaddress", &[]).unwrap();
    let sent: String = wallet.call("sendtoaddress", &[
        json!(address),
        json!(format!("{:.8}", expected_amount.to_sat() as f64 / 100_000_000.0)),
        json!(""), json!(""), json!(true),
    ]).expect("independent Bitcoin Core wallet failed to sign and broadcast its recovered output");
    let spend_txid: bitcoin::Txid = sent.parse().unwrap();
    let spend = ctx.bitcoind().sync_client().get_raw_transaction(&spend_txid, None).unwrap();
    assert_eq!(spend.input.len(), 1, "holder wallet secretly spent another funding input");
    assert_eq!(spend.input[0].previous_output, paid,
        "holder wallet substituted another holder's recovered coins");
    let spent_value: Amount = spend.output.iter().map(|o| o.value).sum();
    assert!(spent_value < expected_amount && spent_value > Amount::ZERO,
        "external redemption must pay a positive miner fee");
    spend_txid
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
                    {"holder": "alice", "script_pubkey_hex": hex::encode(alice_script.as_bytes()), "sats": 60000}
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
                    {"holder": "bob", "script_pubkey_hex": hex::encode(bob_script.as_bytes()), "sats": 40000}
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

    // Save pre-redemption evidence, which can be used with PR #2's
    // independent verifier while both payout coins still remain unspent.
    let metadata = json!({
        "network": "regtest",
        "setup": "real pinned SaplingOS, Bitcoin Core, and local-dev signing service",
        "services_stopped_before_recovery": true,
        "holders": [
            {"holder":"alice", "controlled_outpoint":alice_point.to_string(),
             "claim_txid":bundle_a.recoveries[0].claim.compute_txid().to_string(),
             "sats":60000},
            {"holder":"bob", "controlled_outpoint":bob_point.to_string(),
             "claim_txid":bundle_b.recoveries[0].claim.compute_txid().to_string(),
             "sats":40000}
        ],
        "independent_core_wallets": ["alice-recovered", "bob-recovered"]
    });
    save_json(&artifact_dir.join("before-redemption.json"), &metadata);

    // Separate wallet signatures prove the beneficiaries control their own
    // output keys; the signing actors remain stopped the entire time.
    let spend_a = spend_one_recipient(&ctx, &alice_recipient, &bundle_a, sat(60_000));
    let spend_b = spend_one_recipient(&ctx, &bob_recipient, &bundle_b, sat(40_000));
    assert_ne!(spend_a, spend_b);
    ctx.bitcoind().generate(1).await;
    for txid in [spend_a, spend_b] {
        assert!(ctx.bitcoind().transaction_confirmation(txid).unwrap()
            .confirmations.unwrap_or(0) >= 1,
            "independent payout spend did not confirm");
    }

    save_json(&artifact_dir.join("redemptions.json"), &json!({
        "network":"regtest",
        "alice_spend_txid":spend_a.to_string(),
        "bob_spend_txid":spend_b.to_string(),
        "services_stopped_before_recovery":true,
        "independent_wallet_spends_confirmed":true
    }));
}
