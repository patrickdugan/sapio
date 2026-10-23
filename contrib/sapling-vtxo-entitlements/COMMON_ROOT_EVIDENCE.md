# Genuine common-root recovery: regtest evidence

This records the first passing run of
`sapio_real_common_anchor_two_holder_recovery` against pinned, really
running SaplingOS, Sapio TEE (local-dev), Ark server and Bitcoin Core
fixtures. It establishes that fixture's behaviour under its regtest
assumptions. It is not a general security proof.

## Passing receipt

| Item | Value |
| --- | --- |
| Commit (PR head) | `18f68029d5802aa0a0a243c22c6c8b00ed6e9d99` |
| Commit Actions built | `8591bf9b18cb89ed6ca44b5a9096e3b99ba6e165`, the PR merge of `bf64b0c` and `18f6802`, with the same tree (`8a6cafef…`) as `18f6802` |
| Workflow run | [39927925655](https://github.com/patrickdugan/sapio/actions/runs/39927925655) |
| Artifact | `saplingos-real-common-root-regtest-proof`, [id 12492156148](https://github.com/patrickdugan/sapio/actions/runs/39927925655/artifacts/12492156148), 2,860 bytes, `sha256:1bed69fe898c5253c94562c2dcea5def24831c324e1867e60595602e646dc052`, expires 2026-11-22 |
| Pins | SaplingOS `b45e5ef7`, sapio_tee `f083bdbd`, Bark `626c9b24`, hold `af0055b1`, Bitcoin Core 31.0, Core Lightning 26.06.7 |

Downloading Actions artifacts needs a signed-in GitHub account. The same
`public-regtest-proof.json` is also published as three `public-regtest-proof
n/3` notice annotations on the job, which the unauthenticated REST API
serves (`GET /repos/patrickdugan/sapio/check-runs/120328785917/annotations`).

## What the run checked

Every item below is an assertion in the test or in
`scripts/write_public_proof.py`, and failing it fails the run.

- **One genuine funded root.** A native sender boards one 120,000-sat VTXO
  (chain anchor `b124c9ef…d646:0`, 120,000 sats on chain). Two native
  arkoor transfers, each co-signed live by the Sapio TEE and Ark server,
  give Alice 60,000 sats and Bob 40,000 sats in distinct program VTXOs.
  Both report the same chain anchor. Both exports carry the same two
  signed ancestors (`da9ff080…`, `099bc863…`). The selected 100,000 sats
  are no more than the anchor's value. The sender's other 20,000 sats are
  outside the selected claims.
- **Independent terms.** Each target pins its outpoint, program ID,
  signer root and the holder's own wallet key U. U is derived from the
  holder's seed and matched to the live VTXO key, before either export is
  requested. The beneficiary scripts come from two separate Bitcoin Core
  descriptor wallets.
- **Frozen signed evidence.** The terms and both signed exports are hashed
  into a manifest before shutdown. The manifest's own bytes are pinned
  (SHA-256 `f840efc3…300d`), and both are re-checked after shutdown,
  after recovery, before the audit and after the final spends. The
  adversarial guard test, run first in the same pinned build, rejects an
  altered Alice export, an altered Bob export, altered terms, a forged
  manifest, and a re-serialised manifest that parses to the same JSON.
- **Shutdown before publication.** Alice's, Bob's, the sponsor's and the
  sender's SDK daemons stop, then the TEE, then captaind. Sapio ports
  8000 and 8367 then refuse connections. None of the eight saved
  transactions is on chain at the recorded shutdown height 112, and
  every one confirms above it (heights 113–142).
- **Native offline recovery with exact bytes.** Fresh SDK processes run
  `recover_program_bundle` on each saved export, Alice first and then Bob,
  respecting native CSV maturity. For each saved ancestor and claim, the
  confirmed Bitcoin Core transaction equals the saved transaction
  byte for byte, witnesses included. Alice's claim is `201a6970…c66c`
  (wtxid `411639a9…2824`) and Bob's is `50b48ddb…5ea5` (wtxid
  `8d4cf84a…c275`). Bob's claim was absent until Bob's own recovery ran.
- **External fee sponsorship.** Each of the eight transactions confirmed
  beside exactly one mined P2A child. Every child's external input traces
  back to the sponsor wallet's only pre-shutdown UTXO, `5851b36f…9710:1`,
  through earlier fee children's change. The sponsor has its own seed and
  no VTXOs, and paid 18,464 sats in total. No fee came from a beneficiary
  output or an Ark ancestor.
- **Strict audit.** The standalone merger and auditor (`--two-holder`,
  6 confirmations) accept the exports against the terms: 100,000 sats
  protected, non-conflicting paths, two distinct unspent payouts.
- **Two distinct holder redemptions.** Each descriptor wallet signs its
  own PSBT, spending only its payout (`201a6970…:0` and `50b48ddb…:0`).
  The spends are `94c0c142…7e3a` (59,780 sats paid, 220 fee) and
  `9ad1f160…e1ce` (39,780 paid, 220 fee). Both are mined, each input has
  a witness, and the frozen evidence is unchanged afterwards.

## Trust assumptions

- Disposable regtest with one Bitcoin Core node, which every verifier
  trusts for chain state. No reorgs, fee competition, mempool pinning or
  relay policy differences between nodes are exercised.
- The Sapio signer is the **local-dev** TEE: an ephemeral key with no
  Nitro measurement or attestation. Its signer root is pinned from the
  running instance, not from an external attestation.
- The terms, the holder wallets, the sponsor and the shutdown record are
  all produced by the same test process. Their independence is in key
  material, wallets and data flow, not in separate organisations or
  machines. The shutdown ordering is recorded by that process; captaind's
  own ports are not probed, only the Sapio ports.
- The services are stopped, not malicious. The Ark operator never tries
  to publish a conflicting state, front-run an ancestor, or race the
  claims.

## Not established

- The **separately boarded** two-holder scenario
  (`sapio_real_two_holder_offline_recovery`) and the single joint-output
  unilateral exit are different properties. Neither was run here.
- Recovery when the operator or another VTXO holder acts adversarially:
  conflicting spends of shared ancestors, competing CPFP, or a timelock
  race.
- Recovery of the sender's 20,000-sat remainder.
- Behaviour on signet or mainnet, under real fee pressure, or with a
  production (attested) Sapio signer.

## Failures fixed to reach this run

Every failure was classified from public annotations, because job logs
require sign-in:

1. **Dependency bootstrap** (earlier, PR #3/#4): `utoipa-swagger-ui`
   launched host `curl` inside the Nix shell. The archive is now
   prefetched outside Nix.
2. **Fixture startup** (run 39907061360): the pinned dev shell's Nix
   `LD_LIBRARY_PATH` made Ubuntu's `initdb` load Nix glibc
   (`GLIBC_ABI_DT_X86_64_PLT` not found). Host-linked PostgreSQL and Core
   Lightning now run through clean-loader `exec` wrappers.
3. **Fixture startup** (run 39914816584): pinned captaind requires
   Bitcoin Core 31 or later (`MIN_BITCOIND_VERSION`). The bootstrap now
   pins 31.0, with its digest checked against Guix attestations.
4. **Test harness** (run 39920629437): the holders' Core wallets made the
   fixture node's default-wallet RPCs fail with "Multiple wallets are
   loaded". They now stay unloaded except while signing.
5. **Agreement check** (run 39925992435), after the first complete native
   recovery: the terms pinned the aggregate VTXO key instead of the
   holder key U. The auditor stays strict, and the test now pins U.

No signed transaction bytes, cryptographic checks or pins were relaxed,
and no synthetic payment replaces a native claim.
