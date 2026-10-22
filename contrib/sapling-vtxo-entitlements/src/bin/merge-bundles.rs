//! Merge two independently exported, signed SaplingOS recovery bundles.
//!
//! This is an offline operation: the tool never asks a cosigner to re-sign
//! recovery transactions. The independent payout terms must already exist.
//! No Bitcoin Core or online Ark service is needed for this step.

use anyhow::{Context, Result, ensure};
use sapling::sapio::recovery::ProgramRecoveryBundle;
use sapling_vtxo_entitlements::{Terms, audit_bundle};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

fn read_bundle(path: &PathBuf) -> Result<ProgramRecoveryBundle> {
    let bundle: ProgramRecoveryBundle = serde_json::from_reader(
        File::open(path).with_context(|| format!("opening {}", path.display()))?,
    )
    .with_context(|| format!("decoding SaplingOS export {}", path.display()))?;
    bundle
        .verify()
        .with_context(|| format!("cryptographic rejection of {}", path.display()))?;
    ensure!(
        bundle.targets.len() == 1,
        "each holder's original export must select exactly one current VTXO"
    );
    ensure!(
        matches!(
            bundle.readiness(bundle.targets[0])?,
            sapling::sapio::recovery::ProgramRecoveryReadiness::Complete
        ),
        "holder's saved standalone recovery export is incomplete"
    );
    Ok(bundle)
}

/// Exact merging of two already validated exports, without modifying signed
/// transactions, outputs, witnesses, or the independently attested terms.
fn combine(
    alice: ProgramRecoveryBundle,
    bob: ProgramRecoveryBundle,
) -> Result<ProgramRecoveryBundle> {
    ensure!(alice.version == bob.version, "recovery export version mismatch");
    ensure!(alice.network == bob.network, "recovery network mismatch");
    ensure!(
        alice.targets.len() == 1 && bob.targets.len() == 1,
        "merge requires one current controlled position per original export"
    );
    ensure!(
        alice.targets[0] != bob.targets[0],
        "two holders selected the same controlled VTXO outpoint"
    );

    // Duplicate identical descriptors may appear in two wallet exports.
    // A repeated public key with different recovery terms is never silently
    // resolved in favor of either wallet.
    let mut keys = Vec::new();
    let mut seen_keys = HashMap::new();
    for key in alice.keys.into_iter().chain(bob.keys) {
        let pubkey = key.program.public_key()?.to_string();
        let descriptor = serde_json::to_value(&key)?;
        if let Some(previous) = seen_keys.insert(pubkey.clone(), descriptor.clone()) {
            ensure!(
                previous == descriptor,
                "same Sapio program key has inconsistent saved signing descriptors"
            );
        } else {
            keys.push(key);
        }
    }

    let mut records = Vec::new();
    let mut seen_points = HashSet::new();
    for record in alice.recoveries.into_iter().chain(bob.recoveries) {
        ensure!(
            seen_points.insert(record.controlled_outpoint),
            "two exports contain the same saved recovery record"
        );
        records.push(record);
    }

    let merged = ProgramRecoveryBundle {
        version: alice.version,
        network: alice.network,
        targets: vec![alice.targets[0], bob.targets[0]],
        keys,
        recoveries: records,
    };
    merged
        .verify()
        .context("combined SaplingOS export failed native verification")?;
    Ok(merged)
}

fn main() -> Result<()> {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    ensure!(
        args.len() == 4,
        "usage: merge-bundles ALICE-BUNDLE.json BOB-BUNDLE.json INDEPENDENT-TERMS.json COMBINED.json"
    );
    let alice_path = PathBuf::from(&args[0]);
    let bob_path = PathBuf::from(&args[1]);
    let terms_path = PathBuf::from(&args[2]);
    let output_path = PathBuf::from(&args[3]);
    ensure!(
        alice_path != bob_path
            && output_path != alice_path
            && output_path != bob_path
            && output_path != terms_path,
        "source, terms and destination paths must be different"
    );
    let terms: Terms = serde_json::from_reader(
        File::open(&terms_path).context("opening independently attested payout terms")?,
    )
    .context("decoding independently attested payout terms")?;
    ensure!(
        terms.targets.len() == 2
            && terms.targets.iter().all(|target| target.beneficiaries.len() == 1)
            && terms.targets[0].beneficiaries[0].holder
                != terms.targets[1].beneficiaries[0].holder,
        "two independent recovery terms, each naming one different holder, are required"
    );
    let alice = read_bundle(&alice_path)?;
    let bob = read_bundle(&bob_path)?;
    let merged = combine(alice, bob)?;
    let checked = audit_bundle(&merged, &terms)
        .context("merged signed recovery claims do not match independently agreed payouts")?;
    let expected_principal = terms.targets.iter().try_fold(0u64, |sum, target| {
        sum.checked_add(target.beneficiaries[0].sats)
            .context("independent participant total overflows")
    })?;
    ensure!(
        checked.total_protected_sats == expected_principal,
        "merged recovery principal differs from independent participant rights"
    );

    // Sensitive saved recovery documents are written only to new files.
    // Restrict local access on Unix, and never overwrite a prior recovery.
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(&output_path)
        .context("creating private merged recovery file (must not already exist)")?;
    serde_json::to_writer_pretty(&mut file, &merged)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    println!(
        "saved two independently verified SaplingOS recovery positions: {} sats",
        checked.total_protected_sats
    );
    Ok(())
}
