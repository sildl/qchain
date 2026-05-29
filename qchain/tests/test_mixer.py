"""M10 Phase 1 — Mixer layer integration tests.

The mixer hides the link between a depositor (publicly identified) and
their later anonymous use of funds. These tests prove the chain
plumbing actually works end-to-end: deposits land in the mixer pool,
withdrawals consume nullifiers and credit the STARK pool, replay
catches tampering.

Phase 1 scope: chain-level mechanics only. No network tests (Phase 4),
no soundness adversarials beyond the basic tamper-rejection (Phase 2),
no dashboard UX. The AIR itself (m86_air) is reused unchanged — M10
introduces no new cryptography.
"""

from __future__ import annotations

import time

import pytest

from qchain.chain.blockchain import Blockchain
from qchain.chain.mixer_tx import (
    MIXER_DENOMINATIONS,
    MixerDepositTransaction,
    MixerWithdrawTransaction,
    create_mixer_deposit_tx,
    create_mixer_withdraw_tx,
)
from qchain.chain.wallet import Wallet
from qchain.crypto.anon_stark import STARKNote


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fund_wallet(chain: Blockchain, wallet: Wallet, target: float) -> None:
    """Mine until the wallet has at least `target` balance."""
    while chain.balance_of(wallet.address) < target:
        chain.mine_pending(wallet.address)


def _make_deposited_note(
    chain: Blockchain, denomination: int = 100,
) -> tuple[STARKNote, Wallet]:
    """Fund a wallet, deposit a fresh note into the mixer at the given
    denomination, mine the block, then mine MIXER_WITHDRAWAL_DELAY more
    blocks so the deposit is anchorable for a withdrawal.
    Returns (note, depositor)."""
    from qchain.chain.mixer_tx import MIXER_WITHDRAWAL_DELAY
    depositor = Wallet()
    _fund_wallet(chain, depositor, target=denomination + 50)  # cushion for fees
    note = STARKNote.random(value=denomination)
    deposit = create_mixer_deposit_tx(depositor, denomination, note)
    chain.submit_mixer_deposit(deposit)
    chain.mine_pending("proposer")
    # M-timing: mine more blocks so the deposit is at least DELAY blocks
    # behind, allowing the test to build a withdrawal proof against it.
    for _ in range(MIXER_WITHDRAWAL_DELAY):
        chain.mine_pending("proposer")
    return note, depositor


def _build_withdraw(
    chain: Blockchain,
    note: STARKNote,
    leaf_idx: int,
    output_note: STARKNote,
) -> "MixerWithdrawTransaction":
    """Build a mixer withdrawal against the latest valid anchor.

    Assumes the chain is at least MIXER_WITHDRAWAL_DELAY blocks past
    the deposit (use _make_deposited_note which guarantees this).
    """
    anchor_idx = chain.latest_valid_mixer_anchor()
    anchored_tree = chain.historical_mixer_tree_for_block(anchor_idx)
    return create_mixer_withdraw_tx(
        note=note,
        leaf_idx=leaf_idx,
        mixer_tree=anchored_tree,
        output_note=output_note,
        anchor_block_index=anchor_idx,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_m10_honest_deposit_appears_in_mixer_tree():
    """A signed deposit at an allowed denomination lands in mixer_tree
    after mining. The depositor is debited the amount.
    """
    chain = Blockchain()
    depositor = Wallet()
    _fund_wallet(chain, depositor, target=150)
    pre_balance = chain.balance_of(depositor.address)
    pre_mixer_size = chain.mixer_tree._next_idx

    note = STARKNote.random(value=100)
    deposit = create_mixer_deposit_tx(depositor, 100, note)
    chain.submit_mixer_deposit(deposit)
    chain.mine_pending("proposer")

    # Mixer pool grew by 1
    assert chain.mixer_tree._next_idx == pre_mixer_size + 1, \
        "mixer pool must grow by one leaf after honest deposit"
    # The leaf at the new index is the note's commitment
    assert chain.mixer_tree._layers[0][pre_mixer_size] == note.leaf(), \
        "appended leaf must equal note.leaf()"
    # Depositor was debited exactly 100
    assert chain.balance_of(depositor.address) == pre_balance - 100, \
        "depositor must be debited the deposit amount"
    # Chain replays cleanly
    assert chain.is_valid(), "honest mixer-deposit chain must validate"


def test_m10_honest_withdrawal_credits_stark_pool_and_validates():
    """A real withdrawal consumes the mixer nullifier and appends an
    output_leaf to the STARK pool. The whole chain validates via
    is_valid() — Phase 3-style chain replay including mixer state.
    """
    chain = Blockchain()
    note, _depositor = _make_deposited_note(chain, denomination=100)
    pre_stark_size = chain.stark_anon_tree._next_idx
    pre_mixer_nullifiers = len(chain.mixer_nullifiers)

    # Withdraw: the spender designates a new note that will land in the STARK pool
    output_note = STARKNote(sk=42, randomness=43, value=100)
    withdraw = _build_withdraw(chain, note, 0, output_note)
    chain.submit_mixer_withdraw(withdraw)
    chain.mine_pending("proposer")

    # Mixer nullifier recorded
    assert len(chain.mixer_nullifiers) == pre_mixer_nullifiers + 1
    assert note.nullifier() in chain.mixer_nullifiers
    # STARK pool grew by the output_leaf
    assert chain.stark_anon_tree._next_idx == pre_stark_size + 1
    assert chain.stark_anon_tree._layers[0][pre_stark_size] == output_note.leaf()
    # Chain replays cleanly (the moment of truth)
    assert chain.is_valid(), \
        "honest mixer deposit + withdrawal chain must validate"


def test_m10_tampered_output_leaf_rejected_at_submission():
    """If a withdrawal's output_leaf is changed post-construction, the
    proof's Fiat-Shamir cross-check fails. Mirrors M8.11 Phase 4's
    tamper test but for the mixer withdrawal path.
    """
    chain = Blockchain()
    note, _depositor = _make_deposited_note(chain, denomination=100)

    output_note = STARKNote(sk=42, randomness=43, value=100)
    withdraw = _build_withdraw(chain, note, 0, output_note)

    # Tamper output_leaf to a different (still-valid-looking) value
    bad_note = STARKNote(sk=99999, randomness=99999, value=100)
    withdraw.output_leaf = bad_note.leaf()

    with pytest.raises(ValueError, match="STARK proof failed to verify"):
        chain.submit_mixer_withdraw(withdraw)


def test_m10_double_withdraw_rejected_by_mixer_nullifier_set():
    """The same mixer note can't be withdrawn twice — the second attempt
    is caught by the mixer nullifier set, exactly the same defense
    STARK-anon double-spend uses for the main pool.
    """
    chain = Blockchain()
    note, _depositor = _make_deposited_note(chain, denomination=100)

    # First withdrawal (honest)
    out1 = STARKNote(sk=1, randomness=2, value=100)
    w1 = _build_withdraw(chain, note, 0, out1)
    chain.submit_mixer_withdraw(w1)
    chain.mine_pending("proposer")

    # Second withdrawal with the same input note — should be rejected.
    # Note: this rebuilds a fresh proof but uses the SAME (sk, r, v),
    # which produces the same nullifier.
    out2 = STARKNote(sk=3, randomness=4, value=100)
    w2 = _build_withdraw(chain, note, 0, out2)
    with pytest.raises(ValueError, match="mixer nullifier already seen"):
        chain.submit_mixer_withdraw(w2)


def test_m10_mismatched_mixer_root_rejected():
    """A withdrawal proof attests against a specific anchored mixer root.
    If the withdrawal's `mixer_root` field is tampered to differ from
    what the chain has on record at the declared anchor block, the
    chain rejects at admission.

    M-timing version: we tamper `mixer_root` post-construction. The
    chain's `mixer_root_history[anchor_block_index]` is fixed, so any
    tampering is caught by the anchor-match check.
    """
    chain = Blockchain()
    note, _depositor = _make_deposited_note(chain, denomination=100)

    # Build a valid withdrawal
    out = STARKNote(sk=42, randomness=43, value=100)
    withdraw = _build_withdraw(chain, note, 0, out)

    # Tamper the mixer_root field to something the chain doesn't recognize
    withdraw.mixer_root = (0, 0, 0, 0)

    # Submitting must be rejected by the anchor-match check
    with pytest.raises(ValueError, match="mixer_root doesn't match"):
        chain.submit_mixer_withdraw(withdraw)


def test_m10_wrong_denomination_at_submit_rejected():
    """Only deposits at allowed denominations are admitted. Catches a
    malicious or buggy depositor trying to deposit an arbitrary amount.
    """
    chain = Blockchain()
    depositor = Wallet()
    _fund_wallet(chain, depositor, target=200)

    # 50 is NOT in MIXER_DENOMINATIONS = (1, 10, 100, 1000)
    assert 50 not in MIXER_DENOMINATIONS

    note = STARKNote.random(value=50)
    # create_mixer_deposit_tx itself rejects this
    with pytest.raises(ValueError, match="denomination 50 not in allowed"):
        create_mixer_deposit_tx(depositor, 50, note)

    # If a malicious caller bypassed the helper and constructed the tx
    # directly with a bad amount, submit_mixer_deposit also rejects.
    bad_deposit = MixerDepositTransaction(
        leaf=note.leaf(), amount=50,
        timestamp=time.time(),
        nonce=int(time.time() * 1e6),
    )
    bad_deposit.sign(depositor.keypair)
    with pytest.raises(ValueError, match="not in allowed denominations"):
        chain.submit_mixer_deposit(bad_deposit)
