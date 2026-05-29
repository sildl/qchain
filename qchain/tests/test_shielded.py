"""Tests for milestone 3: shielded transactions. Run with:
    python -m qchain.tests.test_shielded
"""

import dataclasses
import secrets

from qchain.chain.shielded import (
    ShieldedOutput,
    ShieldedPool,
    ShieldedTransaction,
    apply_shielded_tx,
    verify_shielded_tx,
)
from qchain.crypto import dilithium
from qchain.crypto.zk import (
    SpendAuthorization,
    new_shielded_note,
    prove_spend,
    verify_spend,
)


def _setup_pool_with_alice_note(value: int = 100):
    """Helper: create a pool, give Alice a fresh note in it."""
    pool = ShieldedPool()
    alice = dilithium.generate_keypair()
    note = new_shielded_note(value=value, recipient_pk=alice.public_key)
    idx = pool.add_output(
        ShieldedOutput(leaf_commitment=note.leaf(), value_commit=note.value_commit())
    )
    return pool, alice, note, idx


def test_honest_shielded_spend_succeeds():
    pool, alice, note, idx = _setup_pool_with_alice_note(value=100)
    mp = pool.tree.proof(idx)
    auth = prove_spend(note, alice.secret_key, alice.public_key, mp)
    ok = verify_spend(auth, pool.root, pool.seen_nullifiers)
    assert ok
    print("  ✓ Honest spend authorization verifies")


def test_double_spend_blocked():
    pool, alice, note, idx = _setup_pool_with_alice_note()
    mp = pool.tree.proof(idx)
    auth = prove_spend(note, alice.secret_key, alice.public_key, mp)
    pool.mark_nullifier(auth.statement.nullifier)
    assert not verify_spend(auth, pool.root, pool.seen_nullifiers)
    print("  ✓ Double-spend is blocked by the nullifier set")


def test_wrong_owner_cannot_spend():
    """Bob has no note in the pool; he can't spend Alice's."""
    pool, alice, note, idx = _setup_pool_with_alice_note()
    bob = dilithium.generate_keypair()
    mp = pool.tree.proof(idx)
    try:
        # prove_spend should refuse because Bob's pubkey isn't the recipient
        prove_spend(note, bob.secret_key, bob.public_key, mp)
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    print("  ✓ Wrong-owner spend rejected at proving time")


def test_forged_pubkey_cannot_spend():
    """Even if Bob manually constructs an auth, the leaf binding fails."""
    pool, alice, note, idx = _setup_pool_with_alice_note()
    bob = dilithium.generate_keypair()
    mp = pool.tree.proof(idx)
    # Honest auth, but we swap in Bob's pubkey and re-sign
    honest = prove_spend(note, alice.secret_key, alice.public_key, mp)
    forged = SpendAuthorization(
        statement=honest.statement,
        spender_pubkey=bob.public_key,
        signature=dilithium.sign(bob.secret_key, honest.statement.digest()),
        note_id=honest.note_id,
        note_randomness=honest.note_randomness,
    )
    assert not verify_spend(forged, pool.root, pool.seen_nullifiers)
    print("  ✓ Forged-pubkey spend rejected (leaf-binding check)")


def test_shield_transparent_to_shielded():
    """Transparent coins flow INTO the shielded pool."""
    pool = ShieldedPool()
    alice = dilithium.generate_keypair()
    note = new_shielded_note(value=50, recipient_pk=alice.public_key)

    tx = ShieldedTransaction(
        inputs=[],
        outputs=[ShieldedOutput(note.leaf(), note.value_commit())],
        shield_in=50,
        unshield_in_address="",
        unshield_out=0,
        fee=0,
        timestamp=0,
        balance_blinding=secrets.token_bytes(32),
    )
    ok, reason = verify_shielded_tx(
        tx, pool, revealed_input_values=[], revealed_output_values=[50]
    )
    assert ok, reason
    apply_shielded_tx(tx, pool)
    assert pool.tree.size == 1
    print("  ✓ Transparent → shielded (shield) works")


def test_unshield_shielded_to_transparent():
    """Alice spends her shielded note and gets transparent coins."""
    pool, alice, note, idx = _setup_pool_with_alice_note(value=80)
    mp = pool.tree.proof(idx)
    auth = prove_spend(note, alice.secret_key, alice.public_key, mp)

    tx = ShieldedTransaction(
        inputs=[auth],
        outputs=[],
        shield_in=0,
        unshield_in_address="alice_transparent_addr",
        unshield_out=78,
        fee=2,
        timestamp=0,
        balance_blinding=secrets.token_bytes(32),
    )
    ok, reason = verify_shielded_tx(
        tx, pool, revealed_input_values=[80], revealed_output_values=[]
    )
    assert ok, reason
    apply_shielded_tx(tx, pool)
    # After applying, the nullifier is recorded so a re-spend would fail
    assert auth.statement.nullifier in pool.seen_nullifiers
    print("  ✓ Shielded → transparent (unshield) works")


def test_internal_shielded_transfer():
    """Alice spends her note, creating a new note for Bob (still shielded)."""
    pool, alice, note, idx = _setup_pool_with_alice_note(value=100)
    bob = dilithium.generate_keypair()
    mp = pool.tree.proof(idx)
    auth = prove_spend(note, alice.secret_key, alice.public_key, mp)

    # Bob's incoming note (Alice creates it for him with his pubkey)
    bob_note = new_shielded_note(value=98, recipient_pk=bob.public_key)

    tx = ShieldedTransaction(
        inputs=[auth],
        outputs=[ShieldedOutput(bob_note.leaf(), bob_note.value_commit())],
        shield_in=0,
        unshield_in_address="",
        unshield_out=0,
        fee=2,
        timestamp=0,
        balance_blinding=secrets.token_bytes(32),
    )
    ok, reason = verify_shielded_tx(
        tx, pool, revealed_input_values=[100], revealed_output_values=[98]
    )
    assert ok, reason
    apply_shielded_tx(tx, pool)
    print("  ✓ Shielded → shielded internal transfer works")


def test_value_imbalance_rejected():
    """Try to mint coins by claiming more output value than input."""
    pool, alice, note, idx = _setup_pool_with_alice_note(value=10)
    bob_pk = dilithium.generate_keypair().public_key
    mp = pool.tree.proof(idx)
    auth = prove_spend(note, alice.secret_key, alice.public_key, mp)

    inflated_note = new_shielded_note(value=10_000_000, recipient_pk=bob_pk)
    tx = ShieldedTransaction(
        inputs=[auth],
        outputs=[ShieldedOutput(inflated_note.leaf(), inflated_note.value_commit())],
        shield_in=0,
        unshield_in_address="",
        unshield_out=0,
        fee=0,
        timestamp=0,
        balance_blinding=secrets.token_bytes(32),
    )
    ok, reason = verify_shielded_tx(
        tx, pool, revealed_input_values=[10], revealed_output_values=[10_000_000]
    )
    assert not ok
    assert "value mismatch" in reason
    print(f"  ✓ Value-conservation breach rejected: {reason}")


def test_replay_in_same_tx_rejected():
    """Same input note can't be spent twice in one transaction."""
    pool, alice, note, idx = _setup_pool_with_alice_note(value=50)
    mp = pool.tree.proof(idx)
    a1 = prove_spend(note, alice.secret_key, alice.public_key, mp)
    a2 = prove_spend(note, alice.secret_key, alice.public_key, mp)
    assert a1.statement.nullifier == a2.statement.nullifier  # deterministic

    tx = ShieldedTransaction(
        inputs=[a1, a2],
        outputs=[],
        shield_in=0,
        unshield_in_address="alice",
        unshield_out=100,
        fee=0,
        timestamp=0,
        balance_blinding=secrets.token_bytes(32),
    )
    ok, reason = verify_shielded_tx(
        tx, pool, revealed_input_values=[50, 50], revealed_output_values=[]
    )
    assert not ok
    assert "duplicate" in reason
    print("  ✓ Duplicate-nullifier-within-tx is caught")


def test_stale_root_rejected():
    """An input that references an old Merkle root must fail."""
    pool, alice, note, idx = _setup_pool_with_alice_note(value=20)
    mp_old = pool.tree.proof(idx)
    auth = prove_spend(note, alice.secret_key, alice.public_key, mp_old)

    # Modify the pool: add another commitment, changing the root
    extra = new_shielded_note(7, dilithium.generate_keypair().public_key)
    pool.add_output(ShieldedOutput(extra.leaf(), extra.value_commit()))

    tx = ShieldedTransaction(
        inputs=[auth],
        outputs=[],
        shield_in=0,
        unshield_in_address="alice",
        unshield_out=20,
        fee=0,
        timestamp=0,
        balance_blinding=secrets.token_bytes(32),
    )
    ok, reason = verify_shielded_tx(
        tx, pool, revealed_input_values=[20], revealed_output_values=[]
    )
    assert not ok
    assert "stale" in reason
    print(f"  ✓ Stale-root spend rejected: {reason}")


if __name__ == "__main__":
    print("Running milestone 3 tests (shielded transactions)...\n")
    test_honest_shielded_spend_succeeds()
    test_double_spend_blocked()
    test_wrong_owner_cannot_spend()
    test_forged_pubkey_cannot_spend()
    test_shield_transparent_to_shielded()
    test_unshield_shielded_to_transparent()
    test_internal_shielded_transfer()
    test_value_imbalance_rejected()
    test_replay_in_same_tx_rejected()
    test_stale_root_rejected()
    print("\nAll milestone 3 tests passed ✓")
