//! Optional Bitcoin Core confirmation observer for independently verified
//! SaplingOS recovery claims.
//!
//! A saved, valid signature does not establish which conflicting Bitcoin
//! branch confirmed. This module requires the *actual* signed recovery
//! transaction to exist on the trusted node's active chain at a chosen
//! confirmation depth. It compares the confirmed transaction's exact outputs
//! to the saved recovery, then queries the confirmed UTXO set for every
//! beneficiary payout.
//!
//! The node is a separate trust assumption: callers must authenticate its RPC,
//! ensure it is sufficiently synced and use adequate reorg depth. The checks
//! do not establish beneficiary key custody or script satisfiability, and a
//! spent payout may have been spent legitimately by its beneficiary.

use anyhow::{Context, Result, bail, ensure};
use bitcoin::{OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use sapling::sapio::recovery::ProgramRecoveryBundle;
use serde::Serialize;
use serde_json::Value;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

use crate::{Terms, audit_bundle};

/// A transaction retrieved from the trusted Bitcoin node's active chain.
#[derive(Clone, Debug)]
pub struct ObservedTransaction {
    /// Consensus-decoded confirmed Bitcoin transaction.
    pub transaction: Transaction,
    /// Positive active-chain confirmation depth reported by the node.
    pub confirmations: u64,
}

/// Minimal chain observer interface, also implemented by deterministic tests.
///
/// The output query is against the **confirmed** UTXO set, ignoring mempool
/// spends; its boolean cannot prove beneficiary key ownership.
pub trait ChainView {
    /// Trusted full node's active chain identity: main, test, regtest or signet.
    fn chain(&self) -> Result<String>;
    /// Fetch the claimed transaction, including confirmation depth.
    fn transaction(&self, txid: Txid) -> Result<ObservedTransaction>;
    /// Return true iff the exact outpoint is in the confirmed UTXO set.
    fn unspent(&self, outpoint: OutPoint, script: &ScriptBuf) -> Result<bool>;
}

/// Bitcoin Core RPC invoked without shell interpolation.
///
/// The binary, datadir and RPC credentials are supplied by the operator.
/// Pass a trusted `bitcoin-cli` executable, not a downloader or remote URL.
#[derive(Clone, Debug)]
pub struct BitcoinCoreCli {
    binary: PathBuf,
    datadir: Option<PathBuf>,
    network: &'static str,
}

fn core_network(network: &str) -> Result<&'static str> {
    match network.to_lowercase().as_str() {
        "bitcoin" | "main" => Ok("main"),
        "testnet" | "test" => Ok("test"),
        "testnet4" => Ok("testnet4"),
        "signet" => Ok("signet"),
        "regtest" => Ok("regtest"),
        _ => bail!("unsupported Bitcoin Core network selector"),
    }
}

impl BitcoinCoreCli {
    /// Create a local-RPC client using an independently selected binary.
    pub fn new(binary: PathBuf, network: &str, datadir: Option<PathBuf>) -> Result<Self> {
        ensure!(!binary.as_os_str().is_empty(), "bitcoin-cli binary path is empty");
        Ok(Self {
            binary,
            datadir,
            network: core_network(network)?,
        })
    }

    fn rpc(&self, method: &str, args: &[String]) -> Result<Value> {
        let mut command = Command::new(&self.binary);
        command.arg(format!("-chain={}", self.network));
        if let Some(datadir) = &self.datadir {
            let mut option = OsString::from("-datadir=");
            option.push(datadir.as_os_str());
            command.arg(option);
        }
        command.arg(method).args(args);
        let result = command.output().context("running trusted bitcoin-cli")?;
        ensure!(
            result.status.success(),
            "Bitcoin Core RPC {method} failed: {}",
            String::from_utf8_lossy(&result.stderr).trim()
        );
        serde_json::from_slice(&result.stdout)
            .with_context(|| format!("invalid JSON returned by Bitcoin Core {method}"))
    }
}

impl ChainView for BitcoinCoreCli {
    fn chain(&self) -> Result<String> {
        let info = self.rpc("getblockchaininfo", &[])?;
        let chain = info["chain"]
            .as_str()
            .context("Bitcoin Core omitted chain identity")?;
        ensure!(
            !info["initialblockdownload"].as_bool().unwrap_or(true),
            "Bitcoin Core reports initial block download still in progress"
        );
        Ok(chain.to_string())
    }

    fn transaction(&self, txid: Txid) -> Result<ObservedTransaction> {
        let object = self
            .rpc("getrawtransaction", &[txid.to_string(), "true".into()])
            .context("getrawtransaction needs a synced node with transaction index")?;
        let raw = object["hex"].as_str().context("node did not return transaction hex")?;
        let bytes = hex::decode(raw).context("node supplied non-hex raw transaction")?;
        let transaction: Transaction = bitcoin::consensus::deserialize(&bytes)
            .context("cannot decode node's Bitcoin transaction")?;
        ensure!(transaction.compute_txid() == txid, "node returned wrong transaction ID");
        let depth = object["confirmations"]
            .as_u64()
            .context("claim is unconfirmed, conflicted or absent from active chain")?;
        ensure!(depth > 0, "claim is not confirmed on active chain");
        Ok(ObservedTransaction {
            transaction,
            confirmations: depth,
        })
    }

    fn unspent(&self, outpoint: OutPoint, script: &ScriptBuf) -> Result<bool> {
        let response = self.rpc(
            "gettxout",
            &[
                outpoint.txid.to_string(),
                outpoint.vout.to_string(),
                "false".into(),
            ],
        )?;
        if response.is_null() {
            return Ok(false);
        }
        let actual = response["scriptPubKey"]["hex"]
            .as_str()
            .context("Bitcoin Core gettxout omitted output script")?;
        let bytes = hex::decode(actual).context("invalid gettxout script hex")?;
        ensure!(
            bytes == script.as_bytes(),
            "confirmed unspent payout has unexpected script"
        );
        Ok(true)
    }
}

/// Confirmed payout information from the trusted node.
#[derive(Clone, Debug, Serialize)]
pub struct ConfirmedPayout {
    /// Participant label from independently agreed payout terms.
    pub holder: String,
    /// Vout of the participant's confirmed Bitcoin payout.
    pub outpoint: String,
    /// Full output amount.
    pub sats: u64,
    /// Confirmed UTXO-set status, excluding mempool transactions.
    pub unspent_at_tip: bool,
}

/// Confirmed recovery of one exact SaplingOS target.
#[derive(Clone, Debug, Serialize)]
pub struct ConfirmedTarget {
    /// Original program-controlled VTXO outpoint.
    pub controlled_outpoint: String,
    /// Exact saved and confirmed recovery transaction ID.
    pub claim_txid: String,
    /// Active-chain confirmation count at observation.
    pub confirmations: u64,
    /// Payouts whose scripts were independently authenticated offline.
    pub payouts: Vec<ConfirmedPayout>,
}

/// Full-node observation supplementing the offline signature audit.
#[derive(Clone, Debug, Serialize)]
pub struct ChainReport {
    /// Trusted node's network name.
    pub network: String,
    /// Operator-selected minimum confirmation depth.
    pub minimum_confirmations: u64,
    /// Only confirmed exact SaplingOS claims appear in this report.
    pub targets: Vec<ConfirmedTarget>,
    /// Whether the node reported initial sync complete and confirmed all claims.
    pub confirmed_claims_checked: bool,
    /// This checker cannot establish private-key or script-witness availability.
    pub beneficiary_key_custody_checked: bool,
}

/// Require a Bitcoin Core confirmation of one exact terminal recovery claim.
///
/// Payout matching is already performed by the offline `audit_bundle` before
/// callers invoke this method in `audit_chain`. We nevertheless recheck the
/// physical transaction outputs and txid against the saved bytes.
pub fn verify_confirmed_claim(
    view: &impl ChainView,
    claim: &Transaction,
    recipients: &[crate::Beneficiary],
    controlled: OutPoint,
    min_confirmations: u64,
) -> Result<ConfirmedTarget> {
    ensure!(min_confirmations > 0, "minimum confirmation depth must be positive");
    let txid = claim.compute_txid();
    let onchain = view.transaction(txid)?;
    ensure!(
        onchain.confirmations >= min_confirmations,
        "saved recovery claim has insufficient confirmations"
    );
    ensure!(
        onchain.transaction.compute_txid() == txid &&
        onchain.transaction.output == claim.output,
        "confirmed transaction differs from the signed recovery claim"
    );
    let mut payouts = Vec::new();
    for recipient in recipients {
        let target_script = hex::decode(&recipient.script_pubkey_hex)
            .context("invalid independently specified beneficiary script")?;
        let matches = claim.output.iter().enumerate().filter(|(_, output)| {
            output.value.to_sat() == recipient.sats &&
            output.script_pubkey.as_bytes() == target_script
        }).collect::<Vec<_>>();
        ensure!(
            matches.len() == 1,
            "beneficiary does not have one unambiguous signed payout"
        );
        let (index, output) = matches[0];
        let outpoint = OutPoint::new(txid, u32::try_from(index)?);
        payouts.push(ConfirmedPayout {
            holder: recipient.holder.clone(),
            outpoint: outpoint.to_string(),
            sats: recipient.sats,
            unspent_at_tip: view.unspent(outpoint, &output.script_pubkey)?,
        });
    }
    Ok(ConfirmedTarget {
        controlled_outpoint: controlled.to_string(),
        claim_txid: txid.to_string(),
        confirmations: onchain.confirmations,
        payouts,
    })
}

/// Match an independently verified bundle to the trusted active Bitcoin chain.
///
/// A positive report requires every signed claim to have already confirmed.
/// Unpublished, pending or conflicting branches are reported as failures,
/// without claiming that the underlying funds are necessarily lost.
pub fn audit_chain(
    bundle: &ProgramRecoveryBundle,
    terms: &Terms,
    view: &impl ChainView,
    minimum_confirmations: u64,
) -> Result<ChainReport> {
    audit_bundle(bundle, terms)?;
    ensure!(minimum_confirmations > 0, "zero confirmations cannot prove an active-chain payout");
    let chain = view.chain()?;
    ensure!(
        chain == core_network(&terms.network)?,
        "Bitcoin Core chain differs from independent payout terms"
    );
    let mut targets = Vec::new();
    for expected in &terms.targets {
        let point: OutPoint = expected.outpoint.parse().context("invalid selected outpoint")?;
        let record = bundle.recoveries.iter()
            .find(|item| item.controlled_outpoint == point)
            .context("missing previously verified recovery")?;
        targets.push(verify_confirmed_claim(
            view, &record.claim, &expected.beneficiaries, point,
            minimum_confirmations,
        )?);
    }
    Ok(ChainReport {
        network: chain,
        minimum_confirmations,
        targets,
        confirmed_claims_checked: true,
        beneficiary_key_custody_checked: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Amount, Sequence, TxIn, TxOut};
    use std::collections::HashSet;

    struct FakeView {
        network: String,
        tx: Option<ObservedTransaction>,
        unspent: HashSet<OutPoint>,
    }

    impl ChainView for FakeView {
        fn chain(&self) -> Result<String> {
            Ok(self.network.clone())
        }
        fn transaction(&self, _txid: Txid) -> Result<ObservedTransaction> {
            self.tx.clone().context("missing confirmed recovery transaction")
        }
        fn unspent(&self, point: OutPoint, _script: &ScriptBuf) -> Result<bool> {
            Ok(self.unspent.contains(&point))
        }
    }

    fn fixture() -> (Transaction, Vec<crate::Beneficiary>) {
        let alice = ScriptBuf::from_bytes({
            let mut s = vec![0x51, 0x20];
            s.extend([1; 32]);
            s
        });
        let bob = ScriptBuf::from_bytes({
            let mut s = vec![0x51, 0x20];
            s.extend([2; 32]);
            s
        });
        let recipients = vec![
            crate::Beneficiary {
                holder: "alice".to_string(),
                script_pubkey_hex: hex::encode(alice.as_bytes()),
                sats: 60_000,
            },
            crate::Beneficiary {
                holder: "bob".to_string(),
                script_pubkey_hex: hex::encode(bob.as_bytes()),
                sats: 40_000,
            },
        ];
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                sequence: Sequence::MAX,
                ..Default::default()
            }],
            output: vec![
                TxOut { value: Amount::from_sat(60_000), script_pubkey: alice },
                TxOut { value: Amount::from_sat(40_000), script_pubkey: bob },
            ],
        };
        (tx, recipients)
    }

    #[test]
    fn confirms_exact_claim_and_tracks_unspent_payouts() {
        let (claim, recipients) = fixture();
        let txid = claim.compute_txid();
        let view = FakeView {
            network: "regtest".into(),
            tx: Some(ObservedTransaction { transaction: claim.clone(), confirmations: 8 }),
            unspent: [OutPoint::new(txid, 0)].into_iter().collect(),
        };
        let result = verify_confirmed_claim(
            &view, &claim, &recipients, OutPoint::null(), 6,
        ).unwrap();
        assert_eq!(result.confirmations, 8);
        assert!(result.payouts[0].unspent_at_tip);
        assert!(!result.payouts[1].unspent_at_tip);
    }

    #[test]
    fn rejects_missing_or_immature_confirmation() {
        let (claim, recipients) = fixture();
        let view = FakeView {
            network: "regtest".into(),
            tx: Some(ObservedTransaction { transaction: claim.clone(), confirmations: 2 }),
            unspent: HashSet::new(),
        };
        assert!(verify_confirmed_claim(
            &view, &claim, &recipients, OutPoint::null(), 6,
        ).is_err());
        let absent = FakeView { tx: None, ..view };
        assert!(verify_confirmed_claim(
            &absent, &claim, &recipients, OutPoint::null(), 1,
        ).is_err());
    }

    #[test]
    fn mismatched_confirmed_payout_or_txid_fails() {
        let (claim, recipients) = fixture();
        let mut different = claim.clone();
        different.output[0].value += Amount::ONE_SAT;
        let view = FakeView {
            network: "regtest".into(),
            tx: Some(ObservedTransaction { transaction: different, confirmations: 20 }),
            unspent: HashSet::new(),
        };
        assert!(verify_confirmed_claim(
            &view, &claim, &recipients, OutPoint::null(), 6,
        ).is_err());
    }

    #[test]
    fn unique_recipient_script_is_required_for_confirmation_report() {
        let (claim, recipients) = fixture();
        let mut aliases = recipients.clone();
        aliases.push(recipients[0].clone());
        let view = FakeView {
            network: "regtest".into(),
            tx: Some(ObservedTransaction { transaction: claim.clone(), confirmations: 20 }),
            unspent: HashSet::new(),
        };
        // Already rejected by audit_bundle's script/identity uniqueness check.
        // The helper only examines the exact beneficiary payout, so it
        // returns separate entries when invoked without the offline guard.
        assert_eq!(
            verify_confirmed_claim(&view, &claim, &aliases, OutPoint::null(), 6)
                .unwrap().payouts.len(),
            3
        );
    }

    #[test]
    fn network_selector_allowlist_is_strict() {
        assert_eq!(core_network("bitcoin").unwrap(), "main");
        assert_eq!(core_network("regtest").unwrap(), "regtest");
        assert!(core_network("../../../../../").is_err());
    }
}
