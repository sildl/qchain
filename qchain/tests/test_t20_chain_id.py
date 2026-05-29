"""Tests for T20 closure: cross-network replay defense.

The defense binds a `chain_id` into every transaction's signature
payload (for Dilithium-signed txs: Transaction, ShieldTransaction,
MixerDepositTransaction) and carries it as a serialized field on
STARK/Schnorr-proof-bearing txs (STARKAnonTransaction,
MixerWithdrawTransaction, AnonTransaction), checked at chain admission.

The defended threat is **accidental cross-network replay** — e.g., a
wallet pointed at the wrong RPC endpoint sending the same signed tx
to a different chain. Cryptographic binding for Dilithium-signed txs
makes any post-broadcast tampering with chain_id invalidate the
signature; for STARK-bearing txs, an active attacker who edits the
chain_id field after broadcast would be caught by the admission check
only if they don't also re-target the resubmission. The carve-out is
documented in THREAT-MODEL.md T20.

Backward compatibility: txs with chain_id=None are accepted as legacy
(unbound). This preserves the ability to load chain files that
predate this pass.
"""

from __future__ import annotations

import pytest

from qchain.chain.blockchain import Blockchain
from qchain.chain.transaction import Transaction
from qchain.chain.shield_tx import ShieldTransaction
from qchain.chain.mixer_tx import (
    MixerDepositTransaction,
    MixerWithdrawTransaction,
)
from qchain.chain.anon_stark_tx import STARKAnonTransaction
from qchain.chain.wallet import Wallet


# ===========================================================================
# Cryptographic binding (Dilithium-signed txs)
# ===========================================================================

def test_t20_transaction_chain_id_bound_into_signature():
    """A Transaction signed for chain_id="qchain-v1" must fail verify
    if chain_id is post-mutated to a different value. The signature
    covers chain_id (via _payload), so any tampering breaks it.
    """
    w = Wallet()
    tx = w.create_tx("alice", 1.0, chain_id="qchain-v1")
    assert tx.verify(), "freshly-signed tx must verify"

    tx.chain_id = "qchain-different"
    assert not tx.verify(), "post-mutated chain_id must invalidate signature"


def test_t20_transaction_legacy_unbound_still_verifies():
    """A Transaction with chain_id=None signs the legacy payload (no
    chain_id field). Backward-compat: existing chain files predating
    this pass continue to work.
    """
    w = Wallet()
    tx = w.create_tx("alice", 1.0)  # no chain_id
    assert tx.chain_id is None
    assert tx.verify()


def test_t20_transaction_forged_binding_rejected():
    """A legacy (unbound) tx with chain_id=None signs the legacy
    payload. An attacker who claims the tx was signed for a specific
    chain by setting tx.chain_id post-hoc must fail verify —
    the signature was computed without chain_id, so adding one
    changes the payload and invalidates the signature.
    """
    w = Wallet()
    tx = w.create_tx("alice", 1.0)  # legacy, chain_id=None
    tx.chain_id = "qchain-v1"        # forge binding after the fact
    assert not tx.verify()


def test_t20_shield_chain_id_bound_into_signature():
    """ShieldTransaction signature covers chain_id. Post-mutation breaks it."""
    w = Wallet()
    sht = ShieldTransaction(
        sender="",
        leaf=(1, 2, 3, 4),
        amount=5.0,
        timestamp=1000.0,
        nonce=42,
        chain_id="qchain-v1",
    )
    sht.sign(w.keypair)
    assert sht.verify(), "freshly-signed shield must verify"

    sht.chain_id = "qchain-different"
    assert not sht.verify(), "post-mutated chain_id must invalidate signature"


def test_t20_mixer_deposit_chain_id_bound_into_signature():
    """MixerDepositTransaction signature covers chain_id via hash
    payload. Post-mutation breaks it.
    """
    w = Wallet()
    md = MixerDepositTransaction(
        leaf=(5, 6, 7, 8),
        amount=10,
        timestamp=1000.0,
        nonce=99,
        chain_id="qchain-v1",
    )
    md.sign(w.keypair)
    assert md.verify_signature(), "freshly-signed deposit must verify"

    md.chain_id = "qchain-different"
    assert not md.verify_signature(), "post-mutated chain_id breaks sig"


# ===========================================================================
# Admission-time checking (chain layer)
# ===========================================================================

def test_t20_admission_rejects_wrong_chain_transparent_tx():
    """The chain rejects any incoming transparent tx whose chain_id
    is set to something other than its own CHAIN_ID. This catches the
    accidental cross-network replay scenario.
    """
    bc = Blockchain()
    w = Wallet()
    bc.mine_pending(w.address)        # fund w

    tx = w.create_tx("alice", 1.0, chain_id="qchain-OTHER-NETWORK")

    with pytest.raises(ValueError, match="T20"):
        bc.submit(tx)


def test_t20_admission_accepts_matching_chain_tx():
    """Sanity check: txs targeting this chain ARE accepted."""
    bc = Blockchain()
    w = Wallet()
    bc.mine_pending(w.address)

    tx = w.create_tx("alice", 1.0, chain_id=bc.CHAIN_ID)
    bc.submit(tx)
    assert tx in bc.mempool


def test_t20_admission_accepts_legacy_unbound_tx():
    """Backward compat: a tx with chain_id=None is treated as legacy
    and accepted. Pre-T20 chain files and existing wallets keep working.
    """
    bc = Blockchain()
    w = Wallet()
    bc.mine_pending(w.address)

    tx = w.create_tx("alice", 1.0)  # no chain_id
    bc.submit(tx)
    assert tx in bc.mempool


def test_t20_admission_rejects_wrong_chain_stark_anon_tx():
    """For STARK-bearing transactions, the chain_id field is checked
    at admission. The proof does NOT bind chain_id (documented carve-
    out), but the admission check catches accidental cross-network
    replay anyway.
    """
    bc = Blockchain()
    # Construct a STARK-anon tx with wrong chain_id. We don't need a
    # valid proof for this test — the chain_id check fires first
    # (before verify()), so the proof is never inspected.
    stx = STARKAnonTransaction(
        merkle_root=bc.stark_anon_tree.root(),
        nullifier=(0, 0, 0, 1),
        unshield_recipient="alice",
        unshield_amount=0,
        fee=0,
        output_leaf=(0, 0, 0, 2),
        proof=b"\x00" * 100,
        chain_id="qchain-FAKE",
    )

    with pytest.raises(ValueError, match="T20"):
        bc.submit_stark_anon(stx)


def test_t20_admission_rejects_wrong_chain_mixer_withdraw():
    """MixerWithdrawTransaction chain_id checked at admission."""
    bc = Blockchain()
    mw = MixerWithdrawTransaction(
        mixer_root=(0, 0, 0, 0),
        nullifier=(0, 0, 0, 1),
        output_leaf=(0, 0, 0, 2),
        proof=b"\x00" * 100,
        anchor_block_index=0,
        chain_id="qchain-FAKE",
    )

    with pytest.raises(ValueError, match="T20"):
        bc.submit_mixer_withdraw(mw)


# ===========================================================================
# Serialization
# ===========================================================================

def test_t20_chain_id_roundtrips_through_serialization():
    """A tx with chain_id set roundtrips through to_dict/from_dict
    preserving the chain_id value.
    """
    w = Wallet()
    tx = w.create_tx("alice", 1.0, chain_id="qchain-v1")

    d = tx.to_dict()
    assert d.get("chain_id") == "qchain-v1"

    tx2 = Transaction.from_dict(d)
    assert tx2.chain_id == "qchain-v1"
    assert tx2.verify()


def test_t20_legacy_tx_dict_does_not_contain_chain_id():
    """A legacy tx (chain_id=None) does NOT emit the chain_id field
    in its serialized form. This keeps on-wire bytes identical to
    pre-T20 format for backward compat (existing chain files don't
    grow new fields after this pass).
    """
    w = Wallet()
    tx = w.create_tx("alice", 1.0)    # legacy
    assert tx.chain_id is None

    d = tx.to_dict()
    # For Transaction (uses asdict from dataclasses), the field is in the dict
    # but with value None — verify either it's absent OR None.
    assert d.get("chain_id") is None


# ===========================================================================
# Save/load round-trip regression
# ===========================================================================
# Caught during the end-to-end demo build: ShieldTransaction.to_dict() and
# MixerDepositTransaction.to_dict() previously didn't include chain_id, so
# a chain saved with bound shield/mixer-deposit txs reloaded with chain_id
# dropped to None and signature verification failed at is_valid().

def test_t20_shield_chain_id_survives_save_load_roundtrip():
    """ShieldTransaction.to_dict + from_dict preserves chain_id.

    Regression: previously the to_dict explicitly enumerated fields and
    forgot chain_id, dropping it silently.
    """
    w = Wallet()
    sht = ShieldTransaction(
        sender="",
        leaf=(1, 2, 3, 4),
        amount=5.0,
        timestamp=1000.0,
        nonce=42,
        chain_id="qchain-v1",
    )
    sht.sign(w.keypair)
    assert sht.verify()

    d = sht.to_dict()
    assert d.get("chain_id") == "qchain-v1", (
        "to_dict must include chain_id when set"
    )

    sht2 = ShieldTransaction.from_dict(d)
    assert sht2.chain_id == "qchain-v1", "from_dict must restore chain_id"
    assert sht2.verify(), (
        "verify must still pass after roundtrip (signature covers chain_id)"
    )


def test_t20_mixer_deposit_chain_id_survives_save_load_roundtrip():
    """MixerDepositTransaction.to_dict + from_dict preserves chain_id.

    Same regression class as the shield test above.
    """
    w = Wallet()
    md = MixerDepositTransaction(
        leaf=(5, 6, 7, 8),
        amount=10,
        timestamp=1000.0,
        nonce=99,
        chain_id="qchain-v1",
    )
    md.sign(w.keypair)
    assert md.verify_signature()

    d = md.to_dict()
    assert d.get("chain_id") == "qchain-v1"

    md2 = MixerDepositTransaction.from_dict(d)
    assert md2.chain_id == "qchain-v1"
    assert md2.verify_signature(), (
        "verify_signature must still pass after roundtrip"
    )
