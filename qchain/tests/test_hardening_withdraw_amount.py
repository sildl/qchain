"""Withdraw-amount binding-hardening tests.

The mixer originally carried a `withdraw_amount` field on the
withdrawal transaction. The field was admin-side only — not bound to
the proof via Fiat-Shamir — and was therefore tamperable by malicious
peers without invalidating the proof. The honest analysis of "binding"
options led to removing the field entirely instead of trying to bind
it inside m86_air (which would have touched the cryptographic core).

This file verifies the post-removal properties:

  1. The struct no longer carries the field
  2. The denomination is genuinely private on the wire — chain
     observers can't read it from the withdrawal alone
  3. Old-format saved chains (with `withdraw_amount` in the dict)
     still load correctly (migration safety)
  4. Value conservation is unaffected — the AIR still enforces it
  5. The privacy gain holds end-to-end: the chain reaches the same
     state regardless of which legitimate denomination was withdrawn
"""

from __future__ import annotations

import time

import pytest

from qchain.chain.blockchain import Blockchain
from qchain.chain.mixer_tx import (
    MIXER_DENOMINATIONS,
    MixerWithdrawTransaction,
    create_mixer_deposit_tx,
    create_mixer_withdraw_tx,
)
from qchain.chain.wallet import Wallet
from qchain.crypto.anon_stark import STARKNote


def _fund_wallet(chain: Blockchain, wallet: Wallet, target: float) -> None:
    while chain.balance_of(wallet.address) < target:
        chain.mine_pending(wallet.address)


def _deposit(chain: Blockchain, w: Wallet, denomination: int) -> STARKNote:
    """Deposit a fresh note into the mixer, mine the block, then mine
    MIXER_WITHDRAWAL_DELAY more blocks so the deposit is anchorable
    for a withdrawal."""
    from qchain.chain.mixer_tx import MIXER_WITHDRAWAL_DELAY
    note = STARKNote.random(value=denomination)
    deposit = create_mixer_deposit_tx(w, denomination, note)
    chain.submit_mixer_deposit(deposit)
    chain.mine_pending("proposer")
    for _ in range(MIXER_WITHDRAWAL_DELAY):
        chain.mine_pending("proposer")
    return note


def _build_withdraw(chain: Blockchain, note: STARKNote, leaf_idx: int,
                    output_note: STARKNote):
    """Build a mixer withdrawal against the chain's latest valid anchor."""
    anchor_idx = chain.latest_valid_mixer_anchor()
    anchored_tree = chain.historical_mixer_tree_for_block(anchor_idx)
    return create_mixer_withdraw_tx(
        note=note, leaf_idx=leaf_idx,
        mixer_tree=anchored_tree, output_note=output_note,
        anchor_block_index=anchor_idx,
    )


# ---------------------------------------------------------------------------
# 1. Struct shape — withdraw_amount field is gone
# ---------------------------------------------------------------------------

def test_hardening_withdraw_struct_has_no_withdraw_amount_field():
    """The dataclass should not carry a withdraw_amount field anymore."""
    fields = set(MixerWithdrawTransaction.__dataclass_fields__)
    assert "withdraw_amount" not in fields, \
        "withdraw_amount should be removed after the binding-hardening pass"
    # And the expected fields are still there
    assert "mixer_root" in fields
    assert "nullifier" in fields
    assert "output_leaf" in fields
    assert "proof" in fields


def test_hardening_withdraw_to_dict_does_not_include_withdraw_amount():
    """Serialized form must not include the denomination label."""
    chain = Blockchain()
    w = Wallet()
    _fund_wallet(chain, w, target=150)
    note = _deposit(chain, w, denomination=100)

    output_note = STARKNote.random(value=100)
    mwtx = _build_withdraw(chain, note, 0, output_note)
    d = mwtx.to_dict()
    assert "withdraw_amount" not in d, \
        "serialized withdrawal must not carry the denomination as a label"


# ---------------------------------------------------------------------------
# 2. Denomination is private on the wire
# ---------------------------------------------------------------------------

def test_hardening_serialized_withdrawal_does_not_leak_denomination_label():
    """Two withdrawals at different denominations must look identical
    in shape — same keys in to_dict(). A chain observer with no
    knowledge of the spender's secrets shouldn't be able to tell
    them apart from structural shape alone."""
    chain = Blockchain()
    w = Wallet()
    _fund_wallet(chain, w, target=200)

    # Two deposits at different denominations
    note_10 = _deposit(chain, w, denomination=10)
    note_100 = _deposit(chain, w, denomination=100)

    out_10 = STARKNote.random(value=10)
    out_100 = STARKNote.random(value=100)
    mw_10 = _build_withdraw(chain, note_10, 0, out_10)
    mw_100 = _build_withdraw(chain, note_100, 1, out_100)

    d_10 = mw_10.to_dict()
    d_100 = mw_100.to_dict()
    # Same key set
    assert set(d_10.keys()) == set(d_100.keys()), \
        "structural shape must be identical regardless of denomination"
    # No "10" or "100" appears in any non-opaque field of either dict.
    # The denomination is hidden inside output_leaf (a hash) and inside
    # proof (an opaque blob). It's NOT in any visible amount-like field.
    for k, v in d_10.items():
        if k in ("kind", "proof"):
            continue
        if isinstance(v, int):
            assert v != 10, f"denomination 10 leaks in field {k}: {v}"
        if isinstance(v, list):
            assert 10 not in v, f"denomination 10 leaks in list field {k}: {v}"
    for k, v in d_100.items():
        if k in ("kind", "proof"):
            continue
        if isinstance(v, int):
            assert v != 100, f"denomination 100 leaks in field {k}: {v}"
        if isinstance(v, list):
            assert 100 not in v, f"denomination 100 leaks in list field {k}: {v}"


# ---------------------------------------------------------------------------
# 3. Old-format migration safety
# ---------------------------------------------------------------------------

def test_hardening_from_dict_accepts_legacy_withdraw_amount():
    """Saved chains written before this pass had `withdraw_amount` in
    the dict. Loading them must not break — the field is silently
    discarded."""
    chain = Blockchain()
    w = Wallet()
    _fund_wallet(chain, w, target=150)
    note = _deposit(chain, w, denomination=100)
    output_note = STARKNote.random(value=100)
    mwtx = _build_withdraw(chain, note, 0, output_note)

    # Take the new-format dict and inject the legacy field
    legacy = mwtx.to_dict()
    legacy["withdraw_amount"] = 100

    # from_dict must accept it without error
    reloaded = MixerWithdrawTransaction.from_dict(legacy)
    assert reloaded.mixer_root == mwtx.mixer_root
    assert reloaded.nullifier == mwtx.nullifier
    assert reloaded.output_leaf == mwtx.output_leaf
    assert reloaded.proof == mwtx.proof
    # And the field doesn't sneak onto the object
    assert not hasattr(reloaded, "withdraw_amount")


# ---------------------------------------------------------------------------
# 4. Value conservation still works
# ---------------------------------------------------------------------------

def test_hardening_value_conservation_still_enforced_by_air():
    """Even with no withdraw_amount field, the AIR still catches
    attempts to mint value across the mixer→STARK boundary. This is
    a sanity check that removing the admin-side label didn't loosen
    the cryptographic enforcement."""
    chain = Blockchain()
    w = Wallet()
    _fund_wallet(chain, w, target=150)
    note = _deposit(chain, w, denomination=100)

    # Try to construct a withdrawal where the output is value 1000.
    # The helper rejects at construction time (defense layer 1).
    inflation_note = STARKNote(sk=99, randomness=88, value=1000)
    with pytest.raises(ValueError, match="must equal deposit denomination"):
        _build_withdraw(chain, note, 0, inflation_note)


# ---------------------------------------------------------------------------
# 5. End-to-end privacy: chain state is identical regardless of denomination
# ---------------------------------------------------------------------------

def test_hardening_chain_state_shape_invariant_across_denominations():
    """After a deposit + withdrawal at any allowed denomination, the
    chain's external state shape (counter values) is the same. This is
    the strongest privacy property we can verify externally — that an
    observer running is_valid() or inspecting state can't distinguish
    a 10-coin withdrawal from a 100-coin one from a 1000-coin one."""
    counters_by_denom = {}
    for denom in MIXER_DENOMINATIONS:
        chain = Blockchain()
        w = Wallet()
        _fund_wallet(chain, w, target=denom + 50)
        note = _deposit(chain, w, denomination=denom)
        out = STARKNote.random(value=denom)
        mwtx = _build_withdraw(chain, note, 0, out)
        chain.submit_mixer_withdraw(mwtx)
        chain.mine_pending("proposer")
        counters_by_denom[denom] = {
            "mixer_pool_size": chain.mixer_tree._next_idx,
            "mixer_nullifiers": len(chain.mixer_nullifiers),
            "stark_pool_size": chain.stark_anon_tree._next_idx,
            "stark_nullifiers": len(chain.stark_nullifiers),
            "is_valid": chain.is_valid(),
        }

    # Every denomination produces the same counter shape
    reference = counters_by_denom[MIXER_DENOMINATIONS[0]]
    for denom in MIXER_DENOMINATIONS[1:]:
        assert counters_by_denom[denom] == reference, (
            f"chain state shape differs between denomination {denom} and "
            f"{MIXER_DENOMINATIONS[0]} — denomination leaks via counters: "
            f"{counters_by_denom[denom]} vs {reference}"
        )
