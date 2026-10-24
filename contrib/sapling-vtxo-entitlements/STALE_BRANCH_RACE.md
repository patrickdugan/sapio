# Shared-root adversarial race: previously signed sender exit

**Status:** experimental actual-service negative control, targeting
`research/sapling-proof-freeze-qa-2026-10-23`. A clean CI run is required
before making a claim about what happened on regtest.

## Question

Alice receives 60,000 sats and Bob receives 40,000 sats by native, signed
SaplingOS arkoor transfers descending from the same 120,000-sat chain anchor.
They each preserve a complete signed program recovery bundle. Can an earlier
holder cause the shared on-chain branch to lose, leaving Bob with an apparently
complete offline signature but no spendable Bitcoin?

This test deliberately gives a **former owner** an alternative, previously
signed program recovery from *before* the transfers. It models a stale former
holder capable of publishing retained signed Bitcoin transactions after a
handoff, potentially with operator assistance. It does **not** grant an
arbitrary Ark operator an ability to sign a fresh conflicting state.

## Live setup

1. Launch a pinned Sapio local-dev TEE, Ark server, Bitcoin Core regtest and
   three independently seeded SDK wallets. The sponsor has regular Bitcoin
   inputs but no Ark VTXOs. Alice/Bob also have independent Bitcoin Core
   descriptor wallets.
2. Board a 120,000-sat **Sapio program** VTXO to the sender. Export and verify
   its complete, signed 120,000-sat recovery **before** either transfer.
3. Via the actual TEE/Ark, send 60,000 to Alice and 40,000 to Bob. Verify both
   live balances, the common economic funding root, and both independently
   agreed recipient scripts. Freeze all three signed exports and terms into a
   SHA-256 manifest whose bytes are separately retained.
4. Shut down the owner SDKs, Sapio TEE, and Ark, preserving the manifest and
   confirming no signed honest recovery ancestor is on chain.
5. Publish the prior sender's *exact saved* recovery via the same native
   fresh-process SDK flow and P2A fee sponsor as the successful baseline test.
   Demand Bitcoin Core confirmations after the shutdown height.
6. Identify the genuine spent-outpoint intersection between the confirmed
   stale branch and Alice/Bob's **different** saved signed ancestor bytes. A
   shared transaction alone is insufficient to pass this check.
7. Demand that both newer signed claims remain absent, reject a positive
   two-holder chain audit, and produce a private capture.
8. Independently derive all conflicted inputs, roles, txids and wtxids from
   the frozen original exports. Publish only the sanitized loss receipt.

## Reproduce

With the prerequisites and pinned revisions listed in
[README.md](README.md):

```sh
python3 -m unittest discover \
  -s contrib/sapling-vtxo-entitlements/scripts \
  -p 'test_*public_proof.py' -v

SAPLING_TWO_HOLDER_CAPTURE_DIR=/private/stale-race \
  bash contrib/sapling-vtxo-entitlements/scripts/run_real_two_holder.sh \
  sapio_real_stale_sender_recovery_race
```

The actual-service GitHub workflow also runs the original common-root and
separate-root positive controls. The standalone negative-control test has a
distinct capture directory and `stale-branch-race.json` output. Never upload
raw bundles, terms, seeds or test service logs as public CI artifacts.

## What outcomes mean

- **Stale branch wins:** The old fully signed sender claim confirms while both
  new holder claims remain unconfirmed. The independent 2-holder verifier
  refuses to report them as recovered. This is a measured failure of the
  property "each current holder survives any valid older conflicting spend."
- **Stale branch is refused or blocked:** Record the actual reason and whether
  it failed from wallet policy, relay policy, timelock, consensus, or protocol
  signatures. This run cannot claim a successful adversarial spend.
- **No signed-input conflict:** The fixture must fail. An unrelated payment
  or a rejected unsigned mutation gives no evidence about Bob's entitlement.
- **Both holder claims confirm:** The alleged old-branch attack was defeated
  or the scenario did not construct a genuine conflict; examine the full
  on-chain ancestry and fail the loss receipt.

This tests **a stale sender with preserved prior signatures**, including any
operator signatures already present in that branch. The next variants should
test fresh malicious operator-authored conflicting states, cross-node relay,
RBF/CPFP fee competition, reorgs, expiry races, and the true joint-output
LayerTree/SaplingOS composition. Every result is specific to one pinned,
single-node disposable regtest with a local-dev un-attested signer.
