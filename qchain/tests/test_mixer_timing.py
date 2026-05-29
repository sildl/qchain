"""Tests specific to the mixer timing-attack defense (T13 mitigation).

The defense layers two checks at chain admission:
  1. **Anchor age**: anchor_block_index must be <= current_height - DELAY.
     Catches an attacker trying to anchor against the freshest mixer
     state (which would defeat the timing-defense purpose).
  2. **Anchor root match**: mwtx.mixer_root must equal
     mixer_root_history[anchor_block_index]. Catches an attacker who
     tries to anchor against a valid old block but supplies a tampered
     root (e.g., the current root, hoping to bypass the age check).

These tests exercise BOTH checks in isolation. Honest end-to-end paths
are covered in test_mixer.py and test_audit_followup.py.

The chain-layer checks fire BEFORE proof verification, so most of
these tests can use a sham proof (saving ~30 seconds of STARK time per
test). One test exercises the full honest flow as a control.
"""

from __future__ import annotations

import pytest

from qchain.chain.blockchain import Blockchain
from qchain.chain.mixer_tx import (
    MIXER_WITHDRAWAL_DELAY,
    MixerWithdrawTransaction,
    create_mixer_deposit_tx,
    create_mixer_withdraw_tx,
)
from qchain.chain.wallet import Wallet
from qchain.crypto.anon_stark import STARKNote


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _chain_with_a_deposit(denomination: int = 100) -> tuple[Blockchain, STARKNote, int]:
    """Build a chain with one mixer deposit and mine DELAY blocks more.

    Returns (chain, note, deposit_block_index). The deposit's leaf is
    at mixer_tree index 0; the deposit block index is recorded so
    callers can construct sham withdrawals anchored at various ages.
    """
    chain = Blockchain()
    w = Wallet()
    while chain.balance_of(w.address) < 150:
        chain.mine_pending(w.address)
    note = STARKNote.random(value=denomination)
    deposit = create_mixer_deposit_tx(w, denomination, note)
    chain.submit_mixer_deposit(deposit)
    chain.mine_pending("proposer")
    deposit_block = chain.height
    # Mine DELAY more blocks so a withdrawal anchored at deposit_block
    # is exactly at the age limit. Tests that want a "too recent"
    # anchor can use deposit_block; tests that want a "just barely
    # valid" anchor can also use deposit_block (since after DELAY
    # additional blocks, deposit_block is exactly DELAY behind current
    # height).
    for _ in range(MIXER_WITHDRAWAL_DELAY):
        chain.mine_pending("proposer")
    return chain, note, deposit_block


def _sham_withdrawal(
    mixer_root,
    nullifier=(1, 2, 3, 4),
    output_leaf=(5, 6, 7, 8),
    anchor_block_index: int = 0,
) -> MixerWithdrawTransaction:
    """Build a syntactically-valid-but-cryptographically-fake withdrawal.

    Used to exercise chain-level admission checks that fire BEFORE the
    proof verification step. Useful for testing the anchor-age and
    anchor-root checks without spending ~30s on real STARK proving.
    """
    return MixerWithdrawTransaction(
        mixer_root=mixer_root,
        nullifier=nullifier,
        output_leaf=output_leaf,
        proof=b"sham proof that would never STARK-verify",
        anchor_block_index=anchor_block_index,
    )


# ---------------------------------------------------------------------------
# 1. Anchor too recent — the headline timing-defense test
# ---------------------------------------------------------------------------

def test_timing_anchor_at_current_height_rejected():
    """An anchor pointing to the current chain head is age 0, which is
    < DELAY. Reject with the 'anchor too recent' message.
    """
    chain, _note, _deposit_block = _chain_with_a_deposit()
    current = chain.height
    sham = _sham_withdrawal(
        mixer_root=chain.mixer_root_history[current],
        anchor_block_index=current,
    )
    with pytest.raises(ValueError, match="anchor too recent"):
        chain.submit_mixer_withdraw(sham)


def test_timing_anchor_one_block_behind_rejected():
    """An anchor 1 block behind is also too recent (age 1 < DELAY=5)."""
    chain, _note, _deposit_block = _chain_with_a_deposit()
    one_back = chain.height - 1
    sham = _sham_withdrawal(
        mixer_root=chain.mixer_root_history[one_back],
        anchor_block_index=one_back,
    )
    with pytest.raises(ValueError, match="anchor too recent"):
        chain.submit_mixer_withdraw(sham)


def test_timing_anchor_at_exactly_delay_boundary_passes_age_check():
    """An anchor exactly DELAY blocks old passes the age check.

    The proof check still fails (sham proof), but the error message
    is the proof-failure one, NOT the timing-defense one. Confirms
    the boundary is inclusive (>= DELAY, not > DELAY).
    """
    chain, _note, _deposit_block = _chain_with_a_deposit()
    boundary = chain.height - MIXER_WITHDRAWAL_DELAY
    assert boundary >= 0, "test setup: chain too short"
    sham = _sham_withdrawal(
        mixer_root=chain.mixer_root_history[boundary],
        anchor_block_index=boundary,
    )
    # Should NOT raise "anchor too recent"; should hit proof verification
    # which fails with a different message.
    with pytest.raises(ValueError) as exc_info:
        chain.submit_mixer_withdraw(sham)
    assert "anchor too recent" not in str(exc_info.value), (
        f"boundary anchor should pass age check; got: {exc_info.value}"
    )


# ---------------------------------------------------------------------------
# 2. Anchor root tampering — caught by anchor-match check
# ---------------------------------------------------------------------------

def test_timing_anchor_root_tampered_rejected():
    """An attacker picks a valid old anchor block but supplies a
    tampered mixer_root (e.g., the current root). The anchor-match
    check catches this before proof verification.
    """
    chain, _note, deposit_block = _chain_with_a_deposit()
    # Pick a valid old anchor: anchor_block = deposit_block exists,
    # current_height - deposit_block == DELAY, so age check passes.
    # Tamper the mixer_root to the CURRENT root (which doesn't match
    # the history at deposit_block — even by a single hash, since
    # mining DELAY empty blocks doesn't change mixer state, but a
    # forged attacker would tamper to something different).
    bogus_root = (999, 999, 999, 999)
    sham = _sham_withdrawal(
        mixer_root=bogus_root,
        anchor_block_index=deposit_block,
    )
    with pytest.raises(ValueError, match="mixer_root doesn't match"):
        chain.submit_mixer_withdraw(sham)


def test_timing_anchor_in_the_future_rejected():
    """An anchor_block_index beyond the current height is nonsense —
    that block hasn't been mined yet. Reject."""
    chain, _note, _deposit_block = _chain_with_a_deposit()
    future = chain.height + 1
    sham = _sham_withdrawal(
        mixer_root=(0, 0, 0, 0),
        anchor_block_index=future,
    )
    with pytest.raises(ValueError, match="in the future"):
        chain.submit_mixer_withdraw(sham)


def test_timing_anchor_negative_rejected():
    """Defensive: negative anchor_block_index is invalid input."""
    chain, _note, _deposit_block = _chain_with_a_deposit()
    sham = _sham_withdrawal(
        mixer_root=(0, 0, 0, 0),
        anchor_block_index=-1,
    )
    with pytest.raises(ValueError, match="non-negative"):
        chain.submit_mixer_withdraw(sham)


# ---------------------------------------------------------------------------
# 3. Honest end-to-end — control test that the defense allows honest flow
# ---------------------------------------------------------------------------

def test_timing_honest_withdrawal_at_oldest_valid_anchor_succeeds():
    """Full real proof at the oldest possible anchor (the deposit's
    own block). This is the AT-LIMIT honest case. End-to-end real
    STARK to confirm the defense doesn't block honest flow at the
    boundary.

    This is the only test in this file that runs a real STARK
    proof; the rest use sham proofs to test chain-layer checks
    in isolation.
    """
    chain, note, deposit_block = _chain_with_a_deposit(denomination=100)
    # The deposit's own block is exactly DELAY behind current height.
    anchor_idx = chain.latest_valid_mixer_anchor()
    assert anchor_idx == deposit_block, (
        f"test setup: latest_valid_anchor should equal deposit_block "
        f"({deposit_block}); got {anchor_idx}"
    )
    anchored_tree = chain.historical_mixer_tree_for_block(anchor_idx)
    output_note = STARKNote.random(value=100)
    mwtx = create_mixer_withdraw_tx(
        note=note, leaf_idx=0,
        mixer_tree=anchored_tree, output_note=output_note,
        anchor_block_index=anchor_idx,
    )
    chain.submit_mixer_withdraw(mwtx)
    chain.mine_pending("proposer")
    assert chain.is_valid(), "honest at-limit anchor withdrawal must validate"


# ---------------------------------------------------------------------------
# 4. is_valid replay enforces the same checks
# ---------------------------------------------------------------------------

def test_timing_forged_too_recent_anchor_in_block_caught_by_is_valid():
    """A malicious miner who inserts a withdrawal with a too-recent
    anchor directly into a block (bypassing submit_mixer_withdraw)
    is caught by is_valid() chain replay.

    Mirrors the M8.10 + M10-Phase-2 pattern: admission and replay
    must enforce the same invariants. A miner who can mine blocks
    locally can bypass submit_mixer_withdraw, but honest peers
    running is_valid() reject the chain.
    """
    chain, note, _deposit_block = _chain_with_a_deposit(denomination=100)
    # Build an honest proof against the current head (anchor too recent)
    # by using the current mixer_tree directly and a current-height anchor.
    current_height = chain.height
    too_recent_anchor = current_height  # age = 0
    output_note = STARKNote.random(value=100)
    # We use the real tree to make the proof actually verify; the
    # admission check would catch this, so we bypass it.
    mwtx = create_mixer_withdraw_tx(
        note=note, leaf_idx=0,
        mixer_tree=chain.mixer_tree, output_note=output_note,
        anchor_block_index=too_recent_anchor,
    )
    # Bypass admission, inject directly into the mempool, mine.
    chain.mixer_withdraw_mempool.append(mwtx)
    chain.mine_pending("malicious-miner")
    # is_valid() must reject — chain replay enforces the age check.
    assert not chain.is_valid(), (
        "is_valid must reject chains containing withdrawals with "
        "too-recent anchors"
    )
