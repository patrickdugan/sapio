//! Independently verify a saved SaplingOS recovery bundle.
//!
//! Default mode checks cryptographic recovery validity, signer identity,
//! economic backing and exact final beneficiary output scripts offline.
//! Optional Bitcoin Core mode additionally requires each recovered payout to
//! be confirmed on a trusted active chain with sufficient depth.

use anyhow::{Context, Result, bail};
use sapling::sapio::recovery::ProgramRecoveryBundle;
use sapling_vtxo_entitlements::chain::{BitcoinCoreCli, audit_chain};
use sapling_vtxo_entitlements::two_holder::verify_two_holder;
use sapling_vtxo_entitlements::{Terms, audit_bundle};
use std::ffi::OsString;
use std::fs::File;
use std::path::PathBuf;

fn value(args: &mut impl Iterator<Item = OsString>, flag: &str) -> Result<OsString> {
    args.next()
        .with_context(|| format!("missing value for {flag}"))
}

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let bundle_path = args
        .next()
        .context("missing SaplingOS recovery bundle path")?;
    let terms_path = args
        .next()
        .context("missing independently agreed payout terms path")?;

    let mut bitcoin_cli: Option<PathBuf> = None;
    let mut datadir: Option<PathBuf> = None;
    let mut confirmations: u64 = 6;
    let mut two_holder = false;
    while let Some(flag) = args.next() {
        match flag.to_str().context("CLI option must be UTF-8")? {
            "--two-holder" => two_holder = true,
            "--bitcoin-cli" => {
                bitcoin_cli = Some(PathBuf::from(value(&mut args, "--bitcoin-cli")?))
            }
            "--datadir" => datadir = Some(PathBuf::from(value(&mut args, "--datadir")?)),
            "--confirmations" => {
                confirmations = value(&mut args, "--confirmations")?
                    .to_str()
                    .context("invalid UTF-8 confirmation depth")?
                    .parse()
                    .context("confirmation depth must be a positive integer")?;
                if confirmations == 0 {
                    bail!("confirmation depth must be positive");
                }
            }
            _ => bail!(
                "unknown option; usage: sapling-vtxo-entitlements BUNDLE.json TERMS.json [--bitcoin-cli PATH] [--datadir PATH] [--confirmations N] [--two-holder]"
            ),
        }
    }

    let bundle: ProgramRecoveryBundle =
        serde_json::from_reader(File::open(&bundle_path).context("opening bundle")?)
            .context("decoding SaplingOS ProgramRecoveryBundle")?;
    let terms: Terms = serde_json::from_reader(File::open(&terms_path).context("opening terms")?)
        .context("decoding independently agreed payout terms")?;
    let offline = audit_bundle(&bundle, &terms)?;

    if let Some(binary) = bitcoin_cli {
        let node = BitcoinCoreCli::new(binary, &terms.network, datadir)?;
        let onchain = audit_chain(&bundle, &terms, &node, confirmations)?;
        if two_holder {
            let proof = verify_two_holder(&terms, &onchain)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "offline": offline, "chain": onchain, "two_holder": proof
                }))?
            );
        } else {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "offline": offline, "chain": onchain
                }))?
            );
        }
    } else {
        if two_holder {
            bail!("--two-holder requires --bitcoin-cli and two confirmed claims");
        }
        ensure_offline_options(datadir)?;
        println!("{}", serde_json::to_string_pretty(&offline)?);
    }
    Ok(())
}

fn ensure_offline_options(datadir: Option<PathBuf>) -> Result<()> {
    if datadir.is_some() {
        bail!("--datadir requires --bitcoin-cli");
    }
    Ok(())
}
