//! Offline verification of a SaplingOS recovery bundle against independent
//! participant payout terms.
//!
//! SaplingOS verifies the saved claim signatures, ancestry and construction.
//! This verifier additionally binds each target's *actual Bitcoin output
//! scripts and amounts* to the participants' separately agreed plan. It
//! requires Complete readiness and an exact zero-satoshi P2A fee anchor.
//!
//! A matched script is not evidence of the beneficiary's private-key custody,
//! executable dispute rights, or confirmed chain availability. Neither
//! underlying Ark expiry nor overlapping backing across different VTXOs is
//! established by this offline report.

pub mod chain;

use anyhow::{Context, Result, bail, ensure};
use bitcoin::{Network, OutPoint, TxOut};
use sapling::sapio::recovery::{ProgramRecoveryBundle, ProgramRecoveryReadiness};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::str::FromStr;

const ANCHOR_SPK: [u8; 4] = [0x51, 0x02, 0x4e, 0x73];

/// Terms that a participant must obtain independently of the Ark/Sapio signer.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Terms {
    /// Terms document schema version.
    pub version: u32,
    /// Bitcoin network encoded as "regtest", "signet", "testnet", or "bitcoin".
    pub network: String,
    /// Exact set of recovery targets, one record per separate VTXO backing.
    pub targets: Vec<TargetTerms>,
}

/// Expected final Bitcoin allocation of one program-controlled VTXO.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetTerms {
    /// Controlled UTXO that the saved SaplingOS claim spends.
    pub outpoint: String,
    /// Independently pinned exact program identity and signer root.
    pub program: ExpectedProgram,
    /// Recipient rights as explicit output scripts and satoshi amounts.
    pub beneficiaries: Vec<Beneficiary>,
}

/// Contract identity pinned independently of the exported bundle.
/// The trusted root must come from a separately verified TEE attestation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedProgram {
    /// Sapio program ID commits to evaluator, program bytes and parameters.
    pub program_id: String,
    /// Independently verified Sapio signer xpub.
    pub signer_root: String,
    /// Actual wallet user public key of the program instance.
    pub user_pubkey: String,
}

/// One expected beneficiary, identified by the external contract's party ID.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Beneficiary {
    /// Unique participant label within one parent output.
    pub holder: String,
    /// Exact Bitcoin scriptPubKey, lower/upper hex accepted.
    pub script_pubkey_hex: String,
    /// Positive amount of satoshis reserved for this holder.
    pub sats: u64,
}

/// One verified current recovery position.
#[derive(Clone, Debug, Serialize)]
pub struct TargetReport {
    /// Controlled VTXO outpoint.
    pub outpoint: String,
    /// Signed terminal recovery transaction ID.
    pub claim_txid: String,
    /// Total amount, excluding the zero-valued P2A anchor.
    pub protected_sats: u64,
    /// Number of distinct expected beneficiary scripts.
    pub beneficiaries: usize,
    /// Offline construction readiness: "Complete" for every accepted target.
    pub readiness: &'static str,
}

/// Offline audit report. On-chain liveness and beneficiary spendability
/// require separate tests even when this report is successful.
#[derive(Clone, Debug, Serialize)]
pub struct AuditReport {
    /// Network verified against the independent plan.
    pub network: String,
    /// One report for each explicitly selected recovery position.
    pub targets: Vec<TargetReport>,
    /// Sum of selected target principal; other historical branches excluded.
    pub total_protected_sats: u64,
    /// Makes the spending-key/dispute scope explicit to downstream consumers.
    pub script_spendability_checked: bool,
    /// Makes the on-chain availability scope explicit to downstream consumers.
    pub chain_availability_checked: bool,
    /// Necessary cross-target lineage checks only, not a complete backing proof.
    pub selected_paths_nonconflicting: bool,
}

fn payout_map(outputs: &[TxOut]) -> BTreeMap<(u64, Vec<u8>), usize> {
    let mut map = BTreeMap::new();
    for output in outputs {
        *map.entry((
            output.value.to_sat(),
            output.script_pubkey.as_bytes().to_vec(),
        ))
        .or_insert(0) += 1;
    }
    map
}

/// Independently compare all exact payout amounts/scripts and the sole fee
/// anchor. No unknown outputs, short payments or shared/duplicated recipient
/// scripts are accepted. The P2A script is defined in BIP 433.
pub fn verify_payouts(
    actual: &[TxOut],
    terms: &[Beneficiary],
    principal: u64,
) -> Result<()> {
    ensure!(!terms.is_empty(), "recovery requires independently agreed beneficiaries");
    let mut holders = HashSet::new();
    let mut scripts = HashSet::new();
    let mut planned_sum = 0u64;
    let mut outputs = Vec::with_capacity(terms.len() + 1);
    for term in terms {
        ensure!(!term.holder.trim().is_empty(), "empty participant identifier");
        ensure!(holders.insert(term.holder.clone()), "duplicate participant identifier");
        ensure!(term.sats > 0, "zero or negative beneficiary amount");
        let script = hex::decode(&term.script_pubkey_hex)
            .with_context(|| format!("invalid script hex for {}", term.holder))?;
        ensure!(!script.is_empty() && script.len() <= 10_000, "invalid beneficiary script length");
        ensure!(script != ANCHOR_SPK.to_vec(), "fee anchor cannot be a beneficiary");
        ensure!(script[0] != 0x6a, "OP_RETURN is not a beneficiary");
        ensure!(scripts.insert(script.clone()), "two participants share one output script");
        planned_sum = planned_sum.checked_add(term.sats).context("participant total overflows")?;
        outputs.push(TxOut {
            value: bitcoin::Amount::from_sat(term.sats),
            script_pubkey: bitcoin::ScriptBuf::from_bytes(script),
        });
    }
    ensure!(planned_sum == principal, "beneficiary totals differ from backed VTXO principal");
    outputs.push(TxOut {
        value: bitcoin::Amount::ZERO,
        script_pubkey: bitcoin::ScriptBuf::from_bytes(ANCHOR_SPK.to_vec()),
    });
    ensure!(payout_map(actual) == payout_map(&outputs), "signed Bitcoin payout outputs differ from agreed terms");
    Ok(())
}

// A compact structural view of a signed recovery path. SaplingOS's own
// verifier first checks the authentic Bitcoin transactions and ancestors.
// These traces then rule out double counting across the selected records.
#[derive(Clone, Debug)]
struct BackingTrace {
    controlled: OutPoint,
    anchor: OutPoint,
    anchor_amount: u64,
    anchor_script: Vec<u8>,
    value: u64,
    // One ancestor transaction per spent input. Identical shared ancestors
    // are allowed, as are different child vouts of the same ancestor txid.
    spends: Vec<(OutPoint, bitcoin::Txid)>,
}

/// Necessary cross-target backing checks for simultaneously selected claims.
///
/// Different branches spending the same parent outpoint cannot both be live.
/// Two leaf claims may share ancestor transactions if the ancestor allocates
/// them to distinct outputs, and their total cannot exceed common backing.
fn verify_backing_traces(traces: &[BackingTrace]) -> Result<()> {
    let selected = traces.iter().map(|trace| trace.controlled).collect::<HashSet<_>>();
    ensure!(selected.len() == traces.len(), "duplicate canonical VTXO position");

    let mut already_spent = HashMap::<OutPoint, bitcoin::Txid>::new();
    let mut roots = HashMap::<OutPoint, (u64, Vec<u8>, u64)>::new();
    for trace in traces {
        for (input, txid) in &trace.spends {
            ensure!(
                !selected.contains(input),
                "one selected VTXO is an ancestor of another selected claim"
            );
            if let Some(earlier) = already_spent.insert(*input, *txid) {
                ensure!(
                    earlier == *txid,
                    "selected recoveries use conflicting Bitcoin spends of one ancestor"
                );
            }
        }
        let entry = roots.entry(trace.anchor).or_insert_with(|| {
            (trace.anchor_amount, trace.anchor_script.clone(), 0)
        });
        ensure!(
            entry.0 == trace.anchor_amount && entry.1 == trace.anchor_script,
            "one chain anchor has inconsistent Bitcoin backing data"
        );
        entry.2 = entry.2.checked_add(trace.value).context("backing sum overflow")?;
        ensure!(
            entry.2 <= entry.0,
            "selected VTXO positions exceed their common chain anchor backing"
        );
    }
    Ok(())
}

/// Validate signed saved SaplingOS claims, then compare actual outputs to a
/// separately agreed allocation. This remains an *offline* report.
pub fn audit_bundle(bundle: &ProgramRecoveryBundle, terms: &Terms) -> Result<AuditReport> {
    ensure!(terms.version == 1, "unsupported independent payout terms version");
    let network = Network::from_str(&terms.network).context("unknown Bitcoin network")?;
    ensure!(network == bundle.network, "independent plan uses a different network");

    // SaplingOS verifies BIP340 signatures, native antecedents, script
    // commitments, program descriptors, exact configured payout templates
    // and exported recovery completeness constraints.
    bundle.verify().context("SaplingOS cryptographic recovery verification failed")?;

    let mut targets = HashSet::new();
    for expected in &terms.targets {
        let outpoint = OutPoint::from_str(&expected.outpoint)
            .with_context(|| format!("invalid outpoint {}", expected.outpoint))?;
        ensure!(targets.insert(outpoint), "duplicate target in independent terms");
    }
    ensure!(!targets.is_empty(), "no independently specified recovery positions");
    let exported = bundle.targets.iter().copied().collect::<HashSet<_>>();
    ensure!(exported == targets, "exported targets differ from the independent plan");

    let mut reports = Vec::new();
    let mut traces = Vec::new();
    let mut total = 0u64;
    for expected in &terms.targets {
        let point = OutPoint::from_str(&expected.outpoint)?;
        let record = bundle.recoveries.iter()
            .find(|record| record.controlled_outpoint == point)
            .context("bundle missing selected recovery record")?;
        // Cryptographically valid signatures from a self-selected program
        // remain meaningless until its exact evaluator/parameters and
        // signer root are independently pinned by the beneficiaries.
        let descriptor = bundle.keys.iter()
            .find(|key| key.program.public_key().ok() == Some(record.program_key))
            .context("missing signed program identity for recovery")?;
        ensure!(
            descriptor.program.program.id().to_string().eq_ignore_ascii_case(&expected.program.program_id),
            "recovery program ID differs from the independently trusted identity"
        );
        ensure!(
            descriptor.program.root.to_string() == expected.program.signer_root,
            "recovery signer root differs from independently attested xpub"
        );
        ensure!(
            descriptor.program.user_pubkey.to_string().eq_ignore_ascii_case(&expected.program.user_pubkey),
            "recovery user public key differs from agreed owner"
        );
        match bundle.readiness(point)? {
            ProgramRecoveryReadiness::Complete => {}
            ProgramRecoveryReadiness::Prepared => bail!("{} has incomplete prepared ancestors", point),
            ProgramRecoveryReadiness::Conditional { .. } =>
                bail!("{} has a conditional branch requiring additional publication", point),
        };
        let amount = record.prevout.value.to_sat();
        verify_payouts(&record.claim.output, &expected.beneficiaries, amount)
            .with_context(|| format!("wrong beneficiary allocation for {point}"))?;
        total = total.checked_add(amount).context("total backing overflows u64")?;
        traces.push(BackingTrace {
            controlled: point,
            anchor: record.chain_anchor,
            anchor_amount: record.chain_anchor_prevout.value.to_sat(),
            anchor_script: record.chain_anchor_prevout.script_pubkey.as_bytes().to_vec(),
            value: amount,
            spends: record.ancestors.iter().flat_map(|tx| {
                tx.input.iter().map(move |input| (input.previous_output, tx.compute_txid()))
            }).collect(),
        });
        reports.push(TargetReport {
            outpoint: point.to_string(),
            claim_txid: record.claim.compute_txid().to_string(),
            protected_sats: amount,
            beneficiaries: expected.beneficiaries.len(),
            readiness: "Complete",
        });
    }
    verify_backing_traces(&traces)
        .context("selected recovery positions do not have disjoint backing")?;
    Ok(AuditReport {
        network: terms.network.clone(),
        targets: reports,
        total_protected_sats: total,
        script_spendability_checked: false,
        chain_availability_checked: false,
        selected_paths_nonconflicting: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Amount, ScriptBuf};

    fn script(byte: u8) -> Vec<u8> {
        let mut bytes = vec![0x51, 0x20];
        bytes.extend([byte; 32]);
        bytes
    }
    fn beneficiaries() -> Vec<Beneficiary> {
        vec![
            Beneficiary {
                holder: "alice".into(),
                script_pubkey_hex: hex::encode(script(1)),
                sats: 60_000,
            },
            Beneficiary {
                holder: "bob".into(),
                script_pubkey_hex: hex::encode(script(2)),
                sats: 40_000,
            },
        ]
    }
    fn txout(sats: u64, spk: Vec<u8>) -> TxOut {
        TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: ScriptBuf::from_bytes(spk),
        }
    }
    fn outputs() -> Vec<TxOut> {
        vec![txout(60_000, script(1)), txout(40_000, script(2)), txout(0, ANCHOR_SPK.to_vec())]
    }

    #[test]
    fn exact_two_holder_payout_and_fee_anchor() {
        verify_payouts(&outputs(), &beneficiaries(), 100_000).unwrap();
        let mut swapped = outputs();
        swapped.reverse();
        verify_payouts(&swapped, &beneficiaries(), 100_000).unwrap();
    }

    #[test]
    fn rejects_one_satoshi_redirection_even_when_total_is_conserved() {
        let mut altered = outputs();
        altered[0].value = Amount::from_sat(60_001);
        altered[1].value = Amount::from_sat(39_999);
        assert!(verify_payouts(&altered, &beneficiaries(), 100_000).is_err());
    }

    #[test]
    fn refuses_double_counted_joint_script_and_aliases() {
        let mut beneficiaries = beneficiaries();
        beneficiaries[1].script_pubkey_hex = beneficiaries[0].script_pubkey_hex.clone();
        assert!(verify_payouts(&outputs(), &beneficiaries, 100_000).is_err());
        beneficiaries[1].script_pubkey_hex = hex::encode(script(2));
        beneficiaries[1].holder = "alice".into();
        assert!(verify_payouts(&outputs(), &beneficiaries, 100_000).is_err());
    }

    #[test]
    fn missing_anchor_or_unknown_extra_outputs_fail() {
        let mut bad = outputs();
        bad.pop();
        assert!(verify_payouts(&bad, &beneficiaries(), 100_000).is_err());
        let mut bad = outputs();
        bad.push(txout(0, script(3)));
        assert!(verify_payouts(&bad, &beneficiaries(), 100_000).is_err());
    }

    #[test]
    fn rejects_malformed_amounts_and_beneficiaries() {
        let mut beneficiaries = beneficiaries();
        beneficiaries[0].sats = 0;
        assert!(verify_payouts(&outputs(), &beneficiaries, 100_000).is_err());
        beneficiaries[0].sats = 60_000;
        beneficiaries[0].script_pubkey_hex = "6a0101".into();
        assert!(verify_payouts(&outputs(), &beneficiaries, 100_000).is_err());
        beneficiaries[0].script_pubkey_hex = "zzzz".into();
        assert!(verify_payouts(&outputs(), &beneficiaries, 100_000).is_err());
    }

    #[test]
    fn signed_output_mutation_is_rejected_as_unexpected_allocation() {
        let mut bad = outputs();
        bad[0].script_pubkey = ScriptBuf::from_bytes(script(3));
        assert!(verify_payouts(&bad, &beneficiaries(), 100_000).is_err());
    }

    fn point(id: u8, vout: u32) -> OutPoint {
        OutPoint::new(<bitcoin::Txid as bitcoin::hashes::Hash>::from_byte_array([id; 32]), vout)
    }
    fn backing(id: u8, vout: u32, value: u64, spend: u8, root_value: u64) -> BackingTrace {
        BackingTrace {
            controlled: point(id, vout),
            anchor: point(1, 0),
            anchor_amount: root_value,
            anchor_script: script(42),
            value,
            spends: vec![(point(1, 0), point(spend, 0).txid)],
        }
    }

    #[test]
    fn sibling_claims_can_share_a_transaction_without_double_counting() {
        let alice = backing(2, 0, 60_000, 2, 100_000);
        let bob = backing(2, 1, 40_000, 2, 100_000);
        verify_backing_traces(&[alice, bob]).unwrap();
    }

    #[test]
    fn conflicting_ancestor_transactions_cannot_both_back_selected_claims() {
        let alice = backing(2, 0, 60_000, 2, 100_000);
        let bob = backing(3, 0, 40_000, 3, 100_000);
        assert!(verify_backing_traces(&[alice, bob]).is_err());
    }

    #[test]
    fn selected_parent_and_descendant_cannot_be_counted_together() {
        let alice = backing(2, 0, 60_000, 2, 100_000);
        let mut descendant = backing(3, 0, 40_000, 2, 100_000);
        descendant.spends.push((point(2, 0), point(3, 0).txid));
        assert!(verify_backing_traces(&[alice, descendant]).is_err());
    }

    #[test]
    fn common_anchor_caps_child_principal_and_commits_to_one_root() {
        let alice = backing(2, 0, 60_000, 2, 100_000);
        let bob = backing(2, 1, 50_000, 2, 100_000);
        assert!(verify_backing_traces(&[alice.clone(), bob.clone()]).is_err());
        let mut substituted = bob;
        substituted.value = 40_000;
        substituted.anchor_script = script(43);
        assert!(verify_backing_traces(&[alice, substituted]).is_err());
    }
}
