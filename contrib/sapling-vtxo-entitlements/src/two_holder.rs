//! A narrow two-holder recovery checkpoint based on two distinct, confirmed
//! SaplingOS claims. It is intentionally stricter than verifying a joint
//! recovery transaction with two beneficiary outputs.
//!
//! This is evaluated only after audit_bundle and audit_chain succeed.
//! Independent key custody and post-confirmation spends are separate exercises.

use anyhow::{Context, Result, ensure};
use bitcoin::{OutPoint, Txid};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::str::FromStr;

use crate::Terms;
use crate::chain::{ChainReport, ConfirmedTarget};

#[derive(Clone, Debug, Serialize)]
pub struct HolderReceipt {
    pub holder: String,
    pub controlled_outpoint: String,
    pub confirmed_claim_txid: String,
    pub payout_outpoint: String,
    pub script_pubkey_hex: String,
    pub sats: u64,
    pub confirmations: u64,
    pub unspent_at_tip: bool,
}

/// Strict evidence for two separately controlled VTXOs.
/// Both claims must have confirmed and both distinct payout outputs must
/// still be unspent in the confirmed chain view.
#[derive(Clone, Debug, Serialize)]
pub struct TwoHolderReport {
    pub network: String,
    pub holders: Vec<HolderReceipt>,
    pub total_payout_sats: u64,
    pub distinct_confirmed_claims_checked: bool,
    pub separate_unspent_payouts_checked: bool,
    pub unilateral_spend_authority_checked: bool,
    pub services_offline_during_recovery_checked: bool,
}

/// Apply an intentionally narrow two-holder requirement to an already
/// authenticated independent plan and an already verified Bitcoin Core report.
///
/// Exactly two selected VTXOs, one beneficiary each, are required. A single
/// shared claim paying two addresses is insufficient evidence that either
/// holder could independently recover their position. A further regtest wallet
/// spend is needed to demonstrate control of the two beneficiary scripts.
pub fn verify_two_holder(terms: &Terms, chain: &ChainReport) -> Result<TwoHolderReport> {
    ensure!(
        terms.targets.len() == 2 && chain.targets.len() == 2,
        "two-holder proof requires exactly two selected recovery VTXOs"
    );
    ensure!(
        chain.confirmed_claims_checked && chain.minimum_confirmations > 0,
        "two-holder proof requires validated confirmed claims"
    );
    let expected_network = match terms.network.as_str() {
        "bitcoin" => "main",
        "testnet" => "test",
        "testnet4" => "testnet4",
        "signet" => "signet",
        "regtest" => "regtest",
        _ => anyhow::bail!("unrecognized independently agreed network"),
    };
    ensure!(
        chain.network == expected_network,
        "two-holder proof network differs from independently agreed terms"
    );

    let mut by_target = HashMap::<OutPoint, &ConfirmedTarget>::new();
    let mut confirmed_txids = HashSet::<Txid>::new();
    for observed in &chain.targets {
        let point = OutPoint::from_str(&observed.controlled_outpoint)
            .context("invalid confirmed controlled outpoint")?;
        ensure!(
            by_target.insert(point, observed).is_none(),
            "duplicate confirmed controlled outpoint"
        );
        ensure!(
            observed.confirmations >= chain.minimum_confirmations,
            "confirmed claim below required depth"
        );
        ensure!(
            confirmed_txids.insert(Txid::from_str(&observed.claim_txid)?),
            "two VTXOs refer to the same confirmed recovery claim"
        );
    }

    let mut used_scripts = HashSet::<Vec<u8>>::new();
    let mut used_payouts = HashSet::<OutPoint>::new();
    let mut holders = BTreeMap::<String, HolderReceipt>::new();
    let mut protected = 0u64;
    for target in &terms.targets {
        ensure!(
            target.beneficiaries.len() == 1,
            "each independently recoverable VTXO must pay exactly one holder"
        );
        let point = OutPoint::from_str(&target.outpoint)
            .context("invalid independently selected VTXO outpoint")?;
        let observed = by_target
            .remove(&point)
            .context("missing confirmed recovery for independently selected VTXO")?;
        ensure!(
            observed.payouts.len() == 1,
            "confirmed claim has an unexpected number of holder payouts"
        );
        let beneficiary = &target.beneficiaries[0];
        ensure!(
            !beneficiary.holder.trim().is_empty() && beneficiary.sats > 0,
            "invalid independently agreed holder or amount"
        );
        let receipt = &observed.payouts[0];
        ensure!(
            receipt.holder == beneficiary.holder && receipt.sats == beneficiary.sats,
            "confirmed holder or amount differs from independently agreed plan"
        );
        ensure!(
            receipt.unspent_at_tip,
            "a holder payout was already spent at the observed chain tip"
        );
        let script =
            hex::decode(&beneficiary.script_pubkey_hex).context("invalid holder payout script")?;
        ensure!(
            !script.is_empty() && used_scripts.insert(script.clone()),
            "two holders use the same payout script"
        );
        let paid =
            OutPoint::from_str(&receipt.outpoint).context("invalid confirmed payout outpoint")?;
        ensure!(
            paid.txid == Txid::from_str(&observed.claim_txid)?,
            "holder payout belongs to another claim transaction"
        );
        ensure!(
            used_payouts.insert(paid),
            "two holders refer to the same Bitcoin payout outpoint"
        );
        protected = protected
            .checked_add(beneficiary.sats)
            .context("two-holder total overflows satoshi range")?;
        ensure!(
            holders
                .insert(
                    beneficiary.holder.clone(),
                    HolderReceipt {
                        holder: beneficiary.holder.clone(),
                        controlled_outpoint: target.outpoint.clone(),
                        confirmed_claim_txid: observed.claim_txid.clone(),
                        payout_outpoint: paid.to_string(),
                        script_pubkey_hex: hex::encode(script),
                        sats: receipt.sats,
                        confirmations: observed.confirmations,
                        unspent_at_tip: true,
                    }
                )
                .is_none(),
            "two recovery positions name the same beneficiary"
        );
    }
    ensure!(
        by_target.is_empty(),
        "unexpected additional confirmed recovery"
    );
    ensure!(
        holders.len() == 2,
        "two distinct beneficiaries are required"
    );

    Ok(TwoHolderReport {
        network: expected_network.into(),
        holders: holders.into_values().collect(),
        total_payout_sats: protected,
        distinct_confirmed_claims_checked: true,
        separate_unspent_payouts_checked: true,
        unilateral_spend_authority_checked: false,
        services_offline_during_recovery_checked: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{ChainView, ConfirmedPayout, ObservedTransaction, verify_confirmed_claim};
    use crate::{Beneficiary, ExpectedProgram, TargetTerms};
    use anyhow::Result;
    use bitcoin::{Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut};
    use std::collections::HashMap;

    struct ConfirmedFakeChain {
        transactions: HashMap<Txid, ObservedTransaction>,
        unspent: HashSet<OutPoint>,
    }

    impl ChainView for ConfirmedFakeChain {
        fn chain(&self) -> Result<String> {
            Ok("regtest".into())
        }
        fn transaction(&self, txid: Txid) -> Result<ObservedTransaction> {
            self.transactions
                .get(&txid)
                .cloned()
                .context("missing recovery")
        }
        fn unspent(&self, point: OutPoint, _: &ScriptBuf) -> Result<bool> {
            Ok(self.unspent.contains(&point))
        }
    }

    fn script(byte: u8) -> String {
        hex::encode([vec![0x51, 0x20], vec![byte; 32]].concat())
    }

    fn pair() -> (Terms, ChainReport) {
        let mut terms = Terms {
            version: 1,
            network: "regtest".into(),
            targets: Vec::new(),
        };
        let mut transactions = HashMap::new();
        let mut unspent = HashSet::new();
        let mut claims = Vec::new();
        for (i, (holder, amount, key_byte)) in [("alice", 60_000, 1u8), ("bob", 40_000, 2u8)]
            .into_iter()
            .enumerate()
        {
            let controlled = OutPoint::new(Txid::from_str(&format!("{:064x}", i + 1)).unwrap(), 0);
            let beneficiary = Beneficiary {
                holder: holder.into(),
                script_pubkey_hex: script(key_byte),
                sats: amount,
            };
            let claim = Transaction {
                version: bitcoin::transaction::Version(3),
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: controlled,
                    sequence: Sequence::ZERO,
                    ..Default::default()
                }],
                output: vec![
                    TxOut {
                        value: Amount::from_sat(amount),
                        script_pubkey: ScriptBuf::from_bytes(
                            hex::decode(&beneficiary.script_pubkey_hex).unwrap(),
                        ),
                    },
                    TxOut {
                        value: Amount::ZERO,
                        script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x02, 0x4e, 0x73]),
                    },
                ],
            };
            let txid = claim.compute_txid();
            unspent.insert(OutPoint::new(txid, 0));
            transactions.insert(
                txid,
                ObservedTransaction {
                    transaction: claim.clone(),
                    confirmations: 8,
                },
            );
            claims.push((controlled, claim, beneficiary.clone()));
            terms.targets.push(TargetTerms {
                outpoint: controlled.to_string(),
                program: ExpectedProgram {
                    program_id: "independently-pinned-program".into(),
                    signer_root: "independently-attested-root".into(),
                    user_pubkey: "independently-pinned-user".into(),
                },
                beneficiaries: vec![beneficiary],
            });
        }
        let fake = ConfirmedFakeChain {
            transactions,
            unspent,
        };
        let targets = claims
            .iter()
            .map(|(point, claim, b)| {
                verify_confirmed_claim(&fake, claim, std::slice::from_ref(b), *point, 6).unwrap()
            })
            .collect();
        (
            terms,
            ChainReport {
                network: "regtest".into(),
                minimum_confirmations: 6,
                targets,
                confirmed_claims_checked: true,
                beneficiary_key_custody_checked: false,
            },
        )
    }

    #[test]
    fn accepts_two_separate_confirmed_and_unspent_claims() {
        let (terms, report) = pair();
        let checked = verify_two_holder(&terms, &report).unwrap();
        assert_eq!(checked.total_payout_sats, 100_000);
        assert_eq!(checked.holders.len(), 2);
        assert_eq!(checked.holders[0].holder, "alice");
        assert_eq!(checked.holders[0].sats, 60_000);
        assert_eq!(checked.holders[1].holder, "bob");
        assert_eq!(checked.holders[1].sats, 40_000);
        assert!(checked.distinct_confirmed_claims_checked);
        assert!(checked.separate_unspent_payouts_checked);
        assert!(!checked.unilateral_spend_authority_checked);
        assert!(!checked.services_offline_during_recovery_checked);
    }

    #[test]
    fn rejects_joint_transaction_as_two_independent_exits() {
        let (mut terms, mut report) = pair();
        let bob = terms.targets.pop().unwrap().beneficiaries.pop().unwrap();
        terms.targets[0].beneficiaries.push(bob);
        report.targets.pop();
        assert!(verify_two_holder(&terms, &report).is_err());
    }

    #[test]
    fn rejects_reused_script_and_holder_alias() {
        let (mut terms, report) = pair();
        terms.targets[1].beneficiaries[0].script_pubkey_hex =
            terms.targets[0].beneficiaries[0].script_pubkey_hex.clone();
        assert!(verify_two_holder(&terms, &report).is_err());
        let (mut terms, report) = pair();
        terms.targets[1].beneficiaries[0].holder = "alice".into();
        assert!(verify_two_holder(&terms, &report).is_err());
    }

    #[test]
    fn rejects_wrong_amount_spent_payout_and_claim_swaps() {
        let (mut terms, report) = pair();
        terms.targets[1].beneficiaries[0].sats += 1;
        assert!(verify_two_holder(&terms, &report).is_err());

        let (terms, mut report) = pair();
        report.targets[1].payouts[0].unspent_at_tip = false;
        assert!(verify_two_holder(&terms, &report).is_err());

        let (terms, mut report) = pair();
        report.targets[1].payouts[0].outpoint = report.targets[0].payouts[0].outpoint.clone();
        assert!(verify_two_holder(&terms, &report).is_err());

        let (terms, mut report) = pair();
        report.targets[1].claim_txid = report.targets[0].claim_txid.clone();
        assert!(verify_two_holder(&terms, &report).is_err());
    }

    #[test]
    fn rejects_missing_evidence_and_wrong_network() {
        let (terms, mut report) = pair();
        report.targets[0].confirmations = 5;
        assert!(verify_two_holder(&terms, &report).is_err());

        let (terms, mut report) = pair();
        report.network = "main".into();
        assert!(verify_two_holder(&terms, &report).is_err());

        let (terms, mut report) = pair();
        report.confirmed_claims_checked = false;
        assert!(verify_two_holder(&terms, &report).is_err());
    }

    #[test]
    fn rejects_fabricated_extra_payout() {
        let (terms, mut report) = pair();
        let reused = report.targets[0].payouts[0].outpoint.clone();
        report.targets[0].payouts.push(ConfirmedPayout {
            holder: "mallory".into(),
            outpoint: reused,
            sats: 1,
            unspent_at_tip: true,
        });
        assert!(verify_two_holder(&terms, &report).is_err());
    }
}
