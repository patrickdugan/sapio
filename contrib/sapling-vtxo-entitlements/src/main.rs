//! Command-line runner for independent offline payout verification.
//!
//! Usage:
//!   cargo run --manifest-path contrib/sapling-vtxo-entitlements/Cargo.toml -- \\
//!     /private/recovery-bundle.json /private/payout-terms.json
//!
//! The bundle may include confidential transaction/contract evidence.
//! Only the audit summary is printed.

use anyhow::{Context, Result, bail};
use sapling::sapio::recovery::ProgramRecoveryBundle;
use sapling_vtxo_entitlements::{Terms, audit_bundle};
use std::fs::File;

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let bundle_path = args.next().context("missing SaplingOS recovery bundle path")?;
    let terms_path = args.next().context("missing independently agreed payout terms path")?;
    if args.next().is_some() {
        bail!("usage: sapling-vtxo-entitlements BUNDLE.json TERMS.json");
    }
    let bundle: ProgramRecoveryBundle =
        serde_json::from_reader(File::open(&bundle_path).context("opening bundle")?)
            .context("decoding SaplingOS ProgramRecoveryBundle")?;
    let terms: Terms = serde_json::from_reader(File::open(&terms_path).context("opening terms")?)
        .context("decoding independently agreed payout terms")?;
    let result = audit_bundle(&bundle, &terms)?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
