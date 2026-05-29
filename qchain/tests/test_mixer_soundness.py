"""M10 Phase 2 — Soundness tests for the mixer attack surface.

Phase 1 proved the chain plumbing works end-to-end (deposit → withdraw
→ chain replay). Phase 2 proves the mixer-specific attack classes are
actually defeated, not just that the happy path runs.

The mixer reuses m86_air. The soundness of that AIR (M8.6 Gap B
nullifier binding, M8.8-A1 Gap A value conservation, M8.11 Phase 2
change-output forgery) carries over automatically — these tests
verify that the carryover actually happens at the mixer surface,
plus the mixer-specific attack classes:

  1. Cross-tree replay: STARK-anon proof submitted as mixer withdrawal
  2. Cross-tree replay: mixer withdrawal proof submitted as STARK-anon
  3. Tampered nullifier rejected (mirrors M8.6 attack at mixer surface)
  4. Mixer→STARK boundary preserves value (no inflation/destruction)
  5. Forged proof in block bypassing admission caught by is_valid() replay
  6. Tampered mixer_root post-construction rejected

Phase 2 does NOT cover:
  * Network propagation (Phase 3)
  * `withdraw_amount` admin-label tampering — the field was removed
    entirely in the binding-hardening pass that followed M10. The
    denomination is now hidden inside `output_leaf`, which IS FS-bound
    via the m86_air proof. See HARDENING-WITHDRAW-AMOUNT-README.md.
"""

from __future__ import annotations

import time

import pytest

from qchain.chain.anon_stark_tx import (
    STARKAnonTransaction, create_stark_anon_tx,
)
from qchain.chain.blockchain import Blockchain
from qchain.chain.mixer_tx import (
    MIXER_DENOMINATIONS,
    MixerDepositTransaction,
    MixerWithdrawTransaction,
    create_mixer_deposit_tx,
    create_mixer_withdraw_tx,
)
from qchain.chain.shield_tx import ShieldTransaction
from qchain.chain.wallet import Wallet
from qchain.crypto.anon_stark import STARKNote


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fund_wallet(chain: Blockchain, wallet: Wallet, target: float) -> None:
    while chain.balance_of(wallet.address) < target:
        chain.mine_pending(wallet.address)


def _chain_with_mixer_deposit(denomination: int = 100) -> tuple[Blockchain, STARKNote]:
    """Build a chain with one mixer deposit, then mine MIXER_WITHDRAWAL_DELAY
    more blocks so the deposit is anchorable for a withdrawal.
    Returns (chain, deposit_note)."""
    from qchain.chain.mixer_tx import MIXER_WITHDRAWAL_DELAY
    chain = Blockchain()
    depositor = Wallet()
    _fund_wallet(chain, depositor, target=denomination + 50)
    note = STARKNote.random(value=denomination)
    deposit = create_mixer_deposit_tx(depositor, denomination, note)
    chain.submit_mixer_deposit(deposit)
    chain.mine_pending("proposer")
    # M-timing: anchor the deposit (wait DELAY blocks)
    for _ in range(MIXER_WITHDRAWAL_DELAY):
        chain.mine_pending("proposer")
    return chain, note


def _build_withdraw_against_anchor(
    chain: Blockchain,
    note: STARKNote,
    leaf_idx: int,
    output_note: STARKNote,
):
    """Build a mixer withdrawal against chain's latest valid anchor."""
    anchor_idx = chain.latest_valid_mixer_anchor()
    anchored_tree = chain.historical_mixer_tree_for_block(anchor_idx)
    return create_mixer_withdraw_tx(
        note=note,
        leaf_idx=leaf_idx,
        mixer_tree=anchored_tree,
        output_note=output_note,
        anchor_block_index=anchor_idx,
    )


def _chain_with_stark_shield(value: int = 100) -> tuple[Blockchain, STARKNote, Wallet]:
    """Build a chain with one shielded note (via ShieldTransaction, the M8.7-D
    path). Mines MIXER_WITHDRAWAL_DELAY extra blocks so any cross-tree-replay
    test can also use anchor_block_index=0 (genesis empty-mixer-root) without
    tripping the timing-defense check.

    Returns (chain, shielded_note, depositor)."""
    from qchain.chain.mixer_tx import MIXER_WITHDRAWAL_DELAY
    chain = Blockchain()
    depositor = Wallet()
    _fund_wallet(chain, depositor, target=value + 50)
    note = STARKNote.random(value=value)
    shtx = ShieldTransaction(
        sender="", leaf=note.leaf(), amount=float(value),
        timestamp=time.time(),
        nonce=int(time.time() * 1e6),
    )
    shtx.sign(depositor.keypair)
    chain.submit_shield(shtx)
    chain.mine_pending("proposer")
    # M-timing: extra blocks so anchor=0 passes the age check
    for _ in range(MIXER_WITHDRAWAL_DELAY):
        chain.mine_pending("proposer")
    return chain, note, depositor


# ---------------------------------------------------------------------------
# Attack 1: Cross-tree replay (STARK-anon proof → mixer withdrawal)
# ---------------------------------------------------------------------------
#
# An attacker has a valid STARK-anon-spend proof from the STARK pool.
# They package the proof's bytes as a MixerWithdrawTransaction claiming
# the proof attests against the mixer tree. The chain must reject —
# the proof's bound root is the STARK pool root, not the mixer root.

def test_m10_phase2_stark_proof_rejected_as_mixer_withdrawal():
    """A genuine STARK-anon-spend proof is not a valid mixer withdrawal.
    The FS-bound merkle_root is the STARK pool's, not the mixer's.
    """
    chain, note, _ = _chain_with_stark_shield(value=100)

    # Build an honest STARK-anon spend
    stx = create_stark_anon_tx(
        note, leaf_idx=0, tree=chain.stark_anon_tree,
        unshield_recipient="attacker", unshield_amount=100, fee=0,
    )

    # Repackage the proof as a mixer withdrawal, claiming the STARK
    # pool's root is the mixer root. (In a real attack the malicious
    # peer would also need this to coincide with the mixer's actual
    # root — it doesn't, because the mixer is empty here.)
    # M-timing: also need a valid-shape anchor_block_index. We use
    # genesis (block 0) which is the empty mixer-root state. The
    # attack still fails because stx.merkle_root != empty mixer root.
    fake_withdrawal = MixerWithdrawTransaction(
        mixer_root=stx.merkle_root,          # STARK pool's root, not mixer's
        nullifier=stx.nullifier,
        output_leaf=stx.output_leaf,
        proof=stx.proof,
        anchor_block_index=0,                # genesis empty-mixer-root
    )

    # Submit must reject — the chain's mixer_root_history[0] is the
    # empty-mixer root, which differs from stx.merkle_root.
    # The new (M-timing) error path catches it via the anchor-match check.
    # Also: anchor_block_index=0 against a chain of height ≥ DELAY is
    # old enough to pass the timing-defense check, so we exercise the
    # root-mismatch path specifically.
    with pytest.raises(ValueError, match="mixer_root doesn't match"):
        chain.submit_mixer_withdraw(fake_withdrawal)


# ---------------------------------------------------------------------------
# Attack 2: Cross-tree replay (mixer withdrawal proof → STARK-anon spend)
# ---------------------------------------------------------------------------
#
# Symmetric: an attacker has a valid mixer withdrawal proof. They try
# to use it as a STARK-anon transaction. The chain must reject — the
# proof's bound root is the mixer's, not the STARK pool's.

def test_m10_phase2_mixer_proof_rejected_as_stark_spend():
    """A genuine mixer withdrawal proof is not a valid STARK-anon spend.
    The FS-bound merkle_root is the mixer's, not the STARK pool's.
    """
    chain, mixer_note = _chain_with_mixer_deposit(denomination=100)

    # Build an honest mixer withdrawal against the latest valid anchor
    output_note = STARKNote(sk=11, randomness=22, value=100)
    mwtx = _build_withdraw_against_anchor(chain, mixer_note, 0, output_note)

    # Repackage the proof as a STARK-anon spend, claiming the mixer
    # root is the STARK pool root.
    fake_spend = STARKAnonTransaction(
        merkle_root=mwtx.mixer_root,         # mixer's root, not STARK pool's
        nullifier=mwtx.nullifier,
        unshield_recipient="attacker",
        unshield_amount=0,                   # match the mixer's unshield=0 from prove
        fee=0,
        output_leaf=mwtx.output_leaf,
        proof=mwtx.proof,
    )

    # submit_stark_anon checks against stark_anon_tree's root, which is empty
    with pytest.raises(ValueError):
        chain.submit_stark_anon(fake_spend)


# ---------------------------------------------------------------------------
# Attack 3: Tampered nullifier on mixer withdrawal
# ---------------------------------------------------------------------------
#
# The M8.6 Gap B attack class at the mixer surface. The proof binds
# the nullifier via Fiat-Shamir; changing it post-construction breaks
# the FS transcript.

def test_m10_phase2_tampered_mixer_nullifier_rejected():
    """Post-construction nullifier tampering caught by FS cross-check."""
    chain, mixer_note = _chain_with_mixer_deposit(denomination=100)

    output_note = STARKNote(sk=11, randomness=22, value=100)
    mwtx = _build_withdraw_against_anchor(chain, mixer_note, 0, output_note)

    # Tamper the nullifier to a different (random) digest
    fake_null = tuple(((x + 1) % (1 << 64)) for x in mwtx.nullifier)
    mwtx.nullifier = fake_null  # type: ignore[assignment]

    with pytest.raises(ValueError, match="STARK proof failed to verify"):
        chain.submit_mixer_withdraw(mwtx)


# ---------------------------------------------------------------------------
# Attack 4: Inflation/destruction at the mixer → STARK boundary
# ---------------------------------------------------------------------------
#
# An attacker deposits at one denomination but tries to construct a
# withdrawal whose output_note has a different value. The AIR's
# value-conservation constraint catches this — v_in == 0 + 0 + v_out
# forces v_out to equal the deposit's denomination.
#
# create_mixer_withdraw_tx itself enforces this (defensive); the AIR
# enforces it cryptographically. This test exercises the helper's
# rejection because the helper is the legitimate construction path.

def test_m10_phase2_inflation_at_mixer_boundary_rejected():
    """Trying to mint value across the mixer→STARK boundary fails."""
    chain, mixer_note = _chain_with_mixer_deposit(denomination=100)

    # Try to construct a withdrawal where the output is worth 1000
    inflation_note = STARKNote(sk=11, randomness=22, value=1000)

    with pytest.raises(ValueError, match="must equal deposit denomination"):
        create_mixer_withdraw_tx(
            mixer_note, leaf_idx=0,
            mixer_tree=chain.mixer_tree, output_note=inflation_note,
        )


def test_m10_phase2_destruction_at_mixer_boundary_rejected():
    """Symmetric: can't quietly destroy value either."""
    chain, mixer_note = _chain_with_mixer_deposit(denomination=100)

    destruction_note = STARKNote(sk=11, randomness=22, value=10)

    with pytest.raises(ValueError, match="must equal deposit denomination"):
        create_mixer_withdraw_tx(
            mixer_note, leaf_idx=0,
            mixer_tree=chain.mixer_tree, output_note=destruction_note,
        )


# ---------------------------------------------------------------------------
# Attack 5: Forged proof in a directly-mined block bypassing admission
# ---------------------------------------------------------------------------
#
# A malicious miner mines a block containing a forged mixer withdrawal,
# bypassing the submit_mixer_withdraw admission check. Honest peers
# running is_valid() on the resulting chain must reject — the M8.10
# pattern (re-verify on replay) extends to mixer transactions.

def test_m10_phase2_forged_proof_in_block_caught_by_is_valid():
    """A malicious miner who inserts a tampered withdrawal directly into a
    block (bypassing admission) is caught by is_valid() chain replay.
    """
    chain, mixer_note = _chain_with_mixer_deposit(denomination=100)

    # Construct an honest withdrawal against the latest valid anchor
    output_note = STARKNote(sk=11, randomness=22, value=100)
    mwtx = _build_withdraw_against_anchor(chain, mixer_note, 0, output_note)

    # Tamper the output_leaf — this would be rejected at admission,
    # but a malicious miner can put it in a block directly.
    fake_output = STARKNote(sk=999, randomness=999, value=100)
    mwtx.output_leaf = fake_output.leaf()

    # Manually mine a block containing the tampered withdrawal.
    # Don't go through submit_mixer_withdraw (which would catch it).
    chain.mixer_withdraw_mempool.append(mwtx)
    chain.mine_pending("malicious-miner")

    # The honest chain replay must reject
    assert not chain.is_valid(), (
        "is_valid() must reject a chain containing a forged mixer "
        "withdrawal whose output_leaf doesn't match the proof's FS-bound "
        "public input"
    )


# ---------------------------------------------------------------------------
# Attack 6: Tampered mixer_root in transit (stale-root variant)
# ---------------------------------------------------------------------------
#
# A withdrawal carries the mixer_root the proof was generated against.
# If a malicious peer changes that field to "patch" a stale-root
# rejection, the FS cross-check still fails because the proof's
# internal bound root doesn't match.

def test_m10_phase2_tampered_mixer_root_rejected():
    """Changing mixer_root post-construction breaks the anchor-match
    check at admission. M-timing: the chain keeps a record of which
    root the anchor block had; any deviation is caught immediately.
    """
    chain, mixer_note = _chain_with_mixer_deposit(denomination=100)

    output_note = STARKNote(sk=11, randomness=22, value=100)
    mwtx = _build_withdraw_against_anchor(chain, mixer_note, 0, output_note)

    # Capture the legitimate root for restoration if needed
    real_root = mwtx.mixer_root

    # Tamper: change root to a syntactically valid but semantically wrong digest
    tampered_root = tuple(((x + 7) % (1 << 64)) for x in real_root)
    mwtx.mixer_root = tampered_root  # type: ignore[assignment]

    # M-timing: anchor-match check fires immediately (mixer_root doesn't
    # match mixer_root_history[anchor_block_index])
    with pytest.raises(ValueError, match="mixer_root doesn't match"):
        chain.submit_mixer_withdraw(mwtx)

    # Restore for cleanliness
    mwtx.mixer_root = real_root
