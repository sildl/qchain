"""M8.5 — STARK-anonymous transaction tests.

The critical tests are the adversarial ones: a spender who doesn't know
a valid (sk, leaf, path) for the current pool root must NOT be able to
get a transaction past `submit_stark_anon`. Equally critical: double-spend
must be prevented by the nullifier set.

Also tests coexistence with M4 anon transactions in the same chain.
"""

from __future__ import annotations

import os

import pytest

from qchain.chain.anon_stark_tx import STARKAnonTransaction, create_stark_anon_tx
from qchain.chain.blockchain import Blockchain
from qchain.crypto.anon_stark import (
    ANONYMITY_SET_SIZE, MERKLE_DEPTH, STARKAnonTree, STARKNote, bytes_to_digest,
    digest_to_bytes,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def fresh_chain_with_pool(num_notes: int = 5) -> tuple[Blockchain, list[STARKNote], list[int]]:
    """Build a chain with `num_notes` notes shielded into the STARK pool.

    Returns (chain, notes_in_order, indices_in_order).
    """
    chain = Blockchain()
    notes: list[STARKNote] = []
    indices: list[int] = []
    for i in range(num_notes):
        n = STARKNote.random(value=100 + i)
        idx = chain.shield_to_stark_pool(n.leaf())
        notes.append(n)
        indices.append(idx)
    return chain, notes, indices


# ---------------------------------------------------------------------------
# Note / nullifier basics
# ---------------------------------------------------------------------------

def test_note_leaf_is_deterministic():
    n = STARKNote(sk=1, randomness=2, value=3)
    assert n.leaf() == n.leaf()

def test_note_leaf_distinguishes_value():
    n1 = STARKNote(sk=1, randomness=2, value=3)
    n2 = STARKNote(sk=1, randomness=2, value=4)
    assert n1.leaf() != n2.leaf()

def test_nullifier_is_deterministic():
    n = STARKNote(sk=1, randomness=2, value=3)
    assert n.nullifier() == n.nullifier()

def test_nullifier_differs_from_leaf():
    """Domain separation: H(sk, r, v) should not equal H(sk+1, r, v)."""
    n = STARKNote(sk=1, randomness=2, value=3)
    assert n.leaf() != n.nullifier()

def test_different_notes_have_different_nullifiers():
    n1 = STARKNote(sk=1, randomness=2, value=3)
    n2 = STARKNote(sk=2, randomness=2, value=3)
    assert n1.nullifier() != n2.nullifier()


# ---------------------------------------------------------------------------
# Tree basics
# ---------------------------------------------------------------------------

def test_tree_starts_with_empty_root_independent_of_state():
    t1 = STARKAnonTree()
    t2 = STARKAnonTree()
    assert t1.root() == t2.root()

def test_tree_root_changes_after_append():
    t = STARKAnonTree()
    r0 = t.root()
    t.append(STARKNote.random(100).leaf())
    r1 = t.root()
    assert r0 != r1

def test_tree_capacity_enforced():
    t = STARKAnonTree()
    for _ in range(ANONYMITY_SET_SIZE):
        t.append(STARKNote.random(1).leaf())
    with pytest.raises(ValueError, match="tree full"):
        t.append(STARKNote.random(1).leaf())

def test_auth_path_length():
    t = STARKAnonTree()
    t.append(STARKNote.random(100).leaf())
    path = t.auth_path(0)
    assert len(path) == MERKLE_DEPTH


# ---------------------------------------------------------------------------
# Bytes round-trip
# ---------------------------------------------------------------------------

def test_digest_bytes_roundtrip():
    d = (1, 2, 3, 18446744069414584320)
    assert bytes_to_digest(digest_to_bytes(d)) == d


# ---------------------------------------------------------------------------
# Honest spend end-to-end
# ---------------------------------------------------------------------------

def test_honest_spend_verifies_and_lands_in_block():
    chain, notes, idxs = fresh_chain_with_pool(3)
    spender_note = notes[1]  # value = 101 (from fresh_chain_with_pool)
    spender_idx = idxs[1]

    # M8.8-A1: unshield_amount + fee must equal note.value (101).
    # Split it as 100 unshield + 1 fee.
    stx = create_stark_anon_tx(
        spender_note,
        spender_idx,
        chain.stark_anon_tree,
        unshield_recipient="alice",
        unshield_amount=100,
        fee=1,
    )
    chain.submit_stark_anon(stx)
    assert len(chain.stark_anon_mempool) == 1

    block = chain.mine_pending(miner_address="proposer1")
    assert len(block.stark_anon_transactions) == 1

    # Mempool cleared, nullifier marked
    assert chain.stark_anon_mempool == []
    assert stx.nullifier in chain.stark_nullifiers

    # Alice received the unshielded value (100)
    assert chain.balance_of("alice") == 100

    # Proposer received block reward + fee (10 + 1 = 11)
    assert chain.balance_of("proposer1") == 11.0


# ---------------------------------------------------------------------------
# Adversarial cases
# ---------------------------------------------------------------------------

def test_rejects_spend_with_stale_root():
    """A tx built against an old root must fail once new leaves are added."""
    chain, notes, idxs = fresh_chain_with_pool(2)
    # Build a tx against the current state (notes[0].value = 100, fully unshielded)
    stx = create_stark_anon_tx(
        notes[0], idxs[0], chain.stark_anon_tree,
        "alice", unshield_amount=100, fee=0,
    )
    # NOW add another note — this changes the root
    chain.shield_to_stark_pool(STARKNote.random(50).leaf())
    # The old tx is now stale
    with pytest.raises(ValueError, match="stale|invalid"):
        chain.submit_stark_anon(stx)

def test_rejects_double_spend():
    chain, notes, idxs = fresh_chain_with_pool(2)
    stx1 = create_stark_anon_tx(
        notes[0], idxs[0], chain.stark_anon_tree,
        "alice", unshield_amount=100, fee=0,
    )
    chain.submit_stark_anon(stx1)
    chain.mine_pending("proposer")

    # The spender tries to spend the same note again (against the SAME root,
    # which still matches because the tree didn't grow on the spend).
    stx2 = create_stark_anon_tx(
        notes[0], idxs[0], chain.stark_anon_tree,
        "bob", unshield_amount=100, fee=0,
    )
    with pytest.raises(ValueError, match="double-spend|invalid"):
        chain.submit_stark_anon(stx2)

def test_rejects_mempool_double_spend():
    """Two pending txs with the same nullifier must conflict."""
    chain, notes, idxs = fresh_chain_with_pool(2)
    stx1 = create_stark_anon_tx(
        notes[0], idxs[0], chain.stark_anon_tree,
        "alice", unshield_amount=100, fee=0,
    )
    stx2 = create_stark_anon_tx(
        notes[0], idxs[0], chain.stark_anon_tree,
        "bob", unshield_amount=100, fee=0,
    )
    chain.submit_stark_anon(stx1)
    with pytest.raises(ValueError, match="nullifier conflicts"):
        chain.submit_stark_anon(stx2)

def test_rejects_tampered_proof():
    chain, notes, idxs = fresh_chain_with_pool(2)
    stx = create_stark_anon_tx(
        notes[0], idxs[0], chain.stark_anon_tree,
        "alice", unshield_amount=100, fee=0,
    )
    # Flip a byte in the middle of the proof
    p = bytearray(stx.proof)
    p[len(p) // 2] ^= 0xFF
    stx.proof = bytes(p)
    with pytest.raises(ValueError, match="invalid|STARK"):
        chain.submit_stark_anon(stx)

def test_m86_closes_gap_b_swapped_nullifier_rejected():
    """M8.6 closes the M8.5 nullifier-binding gap.

    With M8.5 (M8.3-FULL STARK), the STARK proved Merkle membership but
    did NOT bind the nullifier to the leaf being spent. An attacker who
    knew a valid (sk, r, v, path) could spend the same note multiple
    times by varying the nullifier.

    M8.6 extends the AIR to also prove `nullifier = H(sk+1, r, v)` in
    the SAME proof. The verifier is given the nullifier as a public
    input and only accepts proofs where the claimed nullifier matches
    the one computed inside the proof.

    This test demonstrates the closure: a tampered nullifier is now
    rejected.
    """
    chain, notes, idxs = fresh_chain_with_pool(2)
    stx = create_stark_anon_tx(
        notes[0], idxs[0], chain.stark_anon_tree,
        "alice", unshield_amount=100, fee=0,
    )
    # Substitute a nullifier from a different note (this was the M8.5 gap)
    attacker_note = STARKNote.random(100)
    stx.nullifier = attacker_note.nullifier()
    # M8.6 now rejects this — the proof's bound nullifier doesn't match.
    with pytest.raises(ValueError, match="STARK proof failed to verify"):
        chain.submit_stark_anon(stx)


def test_m88_a1_closes_gap_a_tampered_unshield_amount_rejected():
    """M8.8-A1 Phase 3 closes Gap A (value conservation).

    Before this milestone: a malicious spender could shield a note worth 10
    and broadcast a transaction claiming to unshield 1_000_000. The STARK
    only proved Merkle membership and nullifier binding — it didn't bind
    the declared amount to the leaf's actual value.

    After M8.8-A1: the proof's public inputs include (unshield_amount, fee),
    bound to the proof via Fiat-Shamir. The chain's submit_stark_anon
    re-verifies with the tx's declared amount; if it doesn't match what
    the proof was generated for, verification fails.

    Cross-check: build an honest tx for 100 unshield, tamper the
    unshield_amount to 50, and confirm the chain rejects it.
    """
    chain, notes, idxs = fresh_chain_with_pool(2)
    stx = create_stark_anon_tx(
        notes[0], idxs[0], chain.stark_anon_tree,
        "alice", unshield_amount=100, fee=0,
    )
    # Tamper: claim only 50 went to Alice instead of 100. (The remaining 50
    # would, if accepted, be unaccounted-for value extraction.)
    stx.unshield_amount = 50
    # Phase 3: the FS-bound public inputs no longer match the proof
    with pytest.raises(ValueError, match="STARK proof failed to verify"):
        chain.submit_stark_anon(stx)


def test_m88_a1_value_conservation_blocks_overspend_at_construction():
    """Symmetric: cannot construct a STARK tx claiming MORE than note's value.

    This is the bread-and-butter Gap A attack: leaf worth 10, claim to
    unshield 1_000_000. The trace builder's witness-consistency assertion
    fires, raising ValueError before any proof is even generated.
    """
    chain, notes, idxs = fresh_chain_with_pool(2)
    # notes[0].value = 100; try to spend it as if it were worth 1,000,000
    with pytest.raises(ValueError, match="value conservation"):
        create_stark_anon_tx(
            notes[0], idxs[0], chain.stark_anon_tree,
            "alice", unshield_amount=1_000_000, fee=0,
        )


def test_m88_a1_u64_overflow_rejected_at_construction():
    """Phase 3 field-wrap defense: amounts whose u64 sum overflows are
    rejected by create_stark_anon_tx BEFORE the AIR sees them. The AIR
    works in Goldilocks field arithmetic and can't distinguish a u64-
    overflowing sum from a small value (see Phase 2's
    field_wrap_attack_documented_as_chain_layer_concern test).
    """
    chain, notes, idxs = fresh_chain_with_pool(2)
    with pytest.raises(ValueError, match="overflows u64"):
        create_stark_anon_tx(
            notes[0], idxs[0], chain.stark_anon_tree,
            "alice",
            unshield_amount=(1 << 63),
            fee=(1 << 63),  # sum = 2^64, overflows
        )


def test_rejects_negative_amounts():
    chain, notes, idxs = fresh_chain_with_pool(2)
    stx = create_stark_anon_tx(
        notes[0], idxs[0], chain.stark_anon_tree,
        "alice", unshield_amount=100, fee=0,
    )
    stx.unshield_amount = -5
    with pytest.raises(ValueError, match="negative"):
        chain.submit_stark_anon(stx)

def test_rejects_empty_recipient():
    chain, notes, idxs = fresh_chain_with_pool(2)
    stx = create_stark_anon_tx(
        notes[0], idxs[0], chain.stark_anon_tree,
        "alice", unshield_amount=100, fee=0,
    )
    stx.unshield_recipient = ""
    with pytest.raises(ValueError, match="empty recipient"):
        chain.submit_stark_anon(stx)


# ---------------------------------------------------------------------------
# Coexistence with M4 Schnorr-based anon
# ---------------------------------------------------------------------------

def test_m4_and_m85_can_coexist_in_same_chain():
    """An M4 anon transaction and an M8.5 stark-anon transaction in the
    SAME block, the chain validates both."""
    import secrets as _secrets
    from ecdsa import SECP256k1, SigningKey
    from qchain.crypto.anon import new_anon_note
    from qchain.crypto.schnorr import _compress_point
    from qchain.chain.anon_tx import AnonOutput, AnonTransaction, compute_net_blinding

    chain, notes, idxs = fresh_chain_with_pool(2)

    # --- M8.5 STARK transaction (notes[0].value = 100; split 99 unshield + 1 fee) ---
    stx = create_stark_anon_tx(
        notes[0], idxs[0], chain.stark_anon_tree,
        "alice", unshield_amount=99, fee=1,
    )
    chain.submit_stark_anon(stx)

    # --- M4 Schnorr transaction: shield_in 50 to a fresh note ---
    sk_obj = SigningKey.generate(curve=SECP256k1)
    pk_bytes = _compress_point(sk_obj.get_verifying_key().pubkey.point)
    out_note = new_anon_note(value=49, recipient_pk=pk_bytes)
    net_b = compute_net_blinding(
        input_blindings=[],
        output_blindings=[out_note.value_blinding],
    )
    atx = AnonTransaction(
        inputs=[],
        outputs=[AnonOutput.from_note(out_note)],
        shield_in=50,
        unshield_out=0,
        unshield_recipient="",
        fee=1,
        net_blinding=net_b,
    )
    chain.submit_anon(atx)

    # --- Mine block ---
    block = chain.mine_pending("proposer")
    assert len(block.anon_transactions) == 1
    assert len(block.stark_anon_transactions) == 1

    # Alice got unshield from STARK (99); proposer got block reward + fees (1+1=2)
    assert chain.balance_of("alice") == 99
    assert chain.balance_of("proposer") == 12.0  # 10 reward + 1 stark fee + 1 m4 fee


# ---------------------------------------------------------------------------
# Block hash backward-compatibility
# ---------------------------------------------------------------------------

def test_block_without_stark_txs_has_same_hash_shape_as_before_m85():
    """A block with no stark_anon_transactions should not include the
    stark_anon_tx_root field in its hash payload."""
    chain = Blockchain()
    block = chain.mine_pending("p1")
    # The hash payload must be identical to what milestone 7 would produce
    # for an otherwise-identical block. We check by ensuring that adding
    # an empty stark_anon_transactions list to from_dict round-trips.
    d = block.to_dict()
    assert d["stark_anon_transactions"] == []
    from qchain.chain.block import Block
    block2 = Block.from_dict(d)
    assert block2.hash() == block.hash()


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def test_stark_tx_to_dict_from_dict_roundtrip():
    chain, notes, idxs = fresh_chain_with_pool(2)
    # notes[0].value = 100; split as 98 unshield + 2 fee
    stx = create_stark_anon_tx(
        notes[0], idxs[0], chain.stark_anon_tree,
        "alice", unshield_amount=98, fee=2,
    )
    d = stx.to_dict()
    assert d["kind"] == "stark_anon"
    stx2 = STARKAnonTransaction.from_dict(d)
    assert stx2.merkle_root == stx.merkle_root
    assert stx2.nullifier == stx.nullifier
    assert stx2.unshield_recipient == stx.unshield_recipient
    assert stx2.unshield_amount == stx.unshield_amount
    assert stx2.fee == stx.fee
    assert stx2.proof == stx.proof
    assert stx2.txid() == stx.txid()


# ---------------------------------------------------------------------------
# M8.10 — STARK proof re-verification during chain replay (is_valid)
# ---------------------------------------------------------------------------
#
# Before M8.10, `is_valid()` re-verified signatures and M4 anon txs but
# trusted submit_stark_anon's admission-time check for STARK proofs.
# That left a gap: a malicious miner could include a forged proof in a
# block directly (bypassing their own admission check), and a fresh
# validator replaying the chain wouldn't catch it. M8.10 closes the gap.

def _build_chain_with_stark_txs(num_shields: int = 2) -> Blockchain:
    """Build a chain containing real STARK shield + spend transactions.

    Goes through the real on-chain path: shields are signed
    ShieldTransactions, mined into blocks, and only THEN spent by
    STARK-anon txs. This is the only path is_valid() can replay
    successfully (M8.10 requires shield history to reconstruct the
    pool root).

    Returns a Blockchain with:
      - Block 1: contains `num_shields` real ShieldTransactions
      - Block 2: contains one STARK-anon spend of notes[0] in full
    """
    from qchain.chain.shield_tx import ShieldTransaction
    from qchain.chain.wallet import Wallet
    import time as _time

    chain = Blockchain()

    # Fund a depositor with enough coins for all shields
    depositor = Wallet()
    needed = sum(100 + i for i in range(num_shields))
    while chain.balance_of(depositor.address) < needed:
        chain.mine_pending(depositor.address)

    # Create notes and corresponding signed shield txs
    notes = []
    for i in range(num_shields):
        n = STARKNote.random(value=100 + i)
        shtx = ShieldTransaction(
            sender="", leaf=n.leaf(), amount=float(100 + i),
            timestamp=_time.time(),
            nonce=int(_time.time() * 1e6) + i,
        )
        shtx.sign(depositor.keypair)
        chain.submit_shield(shtx)
        notes.append(n)
    chain.mine_pending("proposer")  # mine all shields into one block

    # Now spend notes[0] in full (value=100)
    stx = create_stark_anon_tx(
        notes[0], leaf_idx=0, tree=chain.stark_anon_tree,
        unshield_recipient="alice", unshield_amount=100, fee=0,
    )
    chain.submit_stark_anon(stx)
    chain.mine_pending("proposer")
    return chain


def test_m810_honest_stark_chain_validates():
    """The positive case: a chain with real STARK txs passes is_valid()
    after M8.10 added re-verification. If this fails, the new replay
    code path is broken or doesn't actually run the STARK verifier.
    """
    chain = _build_chain_with_stark_txs()
    # Sanity: chain actually has STARK txs
    has_stark = any(b.stark_anon_transactions for b in chain.blocks)
    assert has_stark, "test setup didn't produce a STARK tx"
    # The actual M8.10 check
    assert chain.is_valid(), "honest STARK-containing chain should validate"


def test_m810_tampered_stark_proof_in_historical_block_detected():
    """A forged proof in a sealed block is caught by chain replay.
    Before M8.10 this was a real attack surface — a malicious miner
    could include a bogus proof and only adversarial peers would
    catch it; honest peers running is_valid would pass the chain.
    """
    chain = _build_chain_with_stark_txs()
    # Find the block with the STARK tx (it's the last one we mined)
    stark_block = next(b for b in chain.blocks if b.stark_anon_transactions)
    stx = stark_block.stark_anon_transactions[0]
    # Flip a byte in the middle of the proof
    p = bytearray(stx.proof)
    p[len(p) // 2] ^= 0xFF
    stx.proof = bytes(p)
    # M8.10 must now reject the chain
    assert not chain.is_valid(), \
        "Tampered STARK proof in a historical block must be detected by is_valid()"


def test_m810_tampered_stark_amount_in_historical_block_detected():
    """Phase 3 closes Gap A at submit time. M8.10 closes it during
    replay too: a tx whose declared amount no longer matches its
    Fiat-Shamir-bound proof is rejected.
    """
    chain = _build_chain_with_stark_txs()
    stark_block = next(b for b in chain.blocks if b.stark_anon_transactions)
    stx = stark_block.stark_anon_transactions[0]
    stx.unshield_amount = 42  # tamper the declared amount
    assert not chain.is_valid(), \
        "Tampered unshield_amount in a historical STARK tx must be detected"


def test_m810_stark_tx_against_wrong_root_detected():
    """A STARK tx whose merkle_root doesn't match the chain's actual
    pool state at that block must be rejected. This tests the replay
    logic itself — the proof might be cryptographically valid for
    some OTHER root, but not for the chain's root at this point.

    We construct this by taking a tx built against root R, then
    SWAPPING the order of shields and the STARK tx in the block so
    the tx ends up referencing a stale root.
    """
    chain = _build_chain_with_stark_txs()
    # The chain currently looks like: [genesis, block_with_2_shields,
    # block_with_spend]. Let's manually splice an extra shield into the
    # spend block AFTER the STARK tx was generated, in a position that
    # would have changed the root the STARK was generated against.
    #
    # Simpler approach: tamper the STARK tx's `merkle_root` field directly.
    # That's exactly what the cross-check is supposed to catch — the
    # proof's FS transcript bound the root, so changing it after the fact
    # makes verify fail.
    stark_block = next(b for b in chain.blocks if b.stark_anon_transactions)
    stx = stark_block.stark_anon_transactions[0]
    # Set a deterministic-but-wrong root (all zeros)
    stx.merkle_root = (0, 0, 0, 0)
    assert not chain.is_valid(), \
        "STARK tx with mismatched merkle_root must be detected during replay"




# ---------------------------------------------------------------------------
# M8.11 — Partial-spend with change-output integration tests
# ---------------------------------------------------------------------------
#
# Phase 3 made create_stark_anon_tx accept partial amounts with an optional
# change_note. The chain now appends the output_leaf to the STARK pool on
# every spend (real change OR dummy for full spends — Sapling pattern).
#
# These tests prove the partial-spend path actually works end-to-end through
# the chain (not just at the AIR level, which Phase 2 covers).
#
# They use the M8.10-era `_build_chain_with_stark_txs` style — going through
# real ShieldTransactions mined into blocks — because that's the only path
# is_valid() can replay successfully.

def _build_partial_spend_chain(
    shield_value: int = 100,
    change_value: int = 35,
    unshield_amount: int = 60,
    fee: int = 5,
) -> tuple[Blockchain, STARKNote, STARKNote]:
    """Build a chain with one shielded note, then partially spend it.
    Returns (chain, original_note, change_note_used).
    Caller asserts whatever they need to.
    """
    from qchain.chain.shield_tx import ShieldTransaction
    from qchain.chain.wallet import Wallet
    import time as _time

    assert unshield_amount + fee + change_value == shield_value, \
        "test setup error: amounts don't sum to shield_value"

    chain = Blockchain()

    # Fund a depositor enough to shield
    depositor = Wallet()
    while chain.balance_of(depositor.address) < shield_value:
        chain.mine_pending(depositor.address)

    # Shield one note via real ShieldTransaction
    note = STARKNote.random(value=shield_value)
    shtx = ShieldTransaction(
        sender="", leaf=note.leaf(), amount=float(shield_value),
        timestamp=_time.time(),
        nonce=int(_time.time() * 1e6),
    )
    shtx.sign(depositor.keypair)
    chain.submit_shield(shtx)
    chain.mine_pending("proposer")

    # Now partial-spend the note: shield_value → unshield + fee + change
    change_note = STARKNote(sk=12345, randomness=67890, value=change_value)
    stx = create_stark_anon_tx(
        note, leaf_idx=0, tree=chain.stark_anon_tree,
        unshield_recipient="alice",
        unshield_amount=unshield_amount,
        fee=fee,
        change_note=change_note,
    )
    chain.submit_stark_anon(stx)
    chain.mine_pending("proposer")

    return chain, note, change_note


def test_m811_partial_spend_produces_change_note():
    """A partial spend leaves a new shielded note in the pool.
    Before M8.11, every spend consumed the entire leaf value.
    """
    chain, _note, change_note = _build_partial_spend_chain()

    # The pool should contain at least the original note + the change note
    assert chain.stark_anon_tree._next_idx >= 2, \
        "pool must contain the original shielded note + the change note"

    # The change note's hash should be the most recently appended leaf
    last_idx = chain.stark_anon_tree._next_idx - 1
    last_leaf = chain.stark_anon_tree._layers[0][last_idx]
    assert last_leaf == change_note.leaf(), \
        "last appended leaf must be the change note's hash"

    # Alice received 60 from the unshield
    assert chain.balance_of("alice") == 60.0
    # And the chain validates (the moment of truth — M8.10 replay)
    assert chain.is_valid(), \
        "honest partial-spend chain must validate through is_valid()"


def test_m811_change_note_can_be_spent_later():
    """The change note from a partial spend can be spent in a follow-up tx.
    Proves the wallet/index bookkeeping round-trips through the chain.
    """
    chain, _note, change_note = _build_partial_spend_chain(
        shield_value=100, change_value=35, unshield_amount=60, fee=5,
    )

    # Find the change_note's leaf index in the pool
    change_leaf = change_note.leaf()
    num_real_leaves = chain.stark_anon_tree._next_idx
    change_idx = None
    for i in range(num_real_leaves):
        if chain.stark_anon_tree._layers[0][i] == change_leaf:
            change_idx = i
            break
    assert change_idx is not None, "change note must be findable in the pool"

    # Spend the change note: 35 → 30 unshield + 0 fee + 5 second change
    second_change = STARKNote(sk=11111, randomness=22222, value=5)
    stx2 = create_stark_anon_tx(
        change_note, change_idx, chain.stark_anon_tree,
        "bob", 30, 0, change_note=second_change,
    )
    chain.submit_stark_anon(stx2)
    chain.mine_pending("proposer")

    # Both nullifiers recorded
    assert change_note.nullifier() in chain.stark_nullifiers, \
        "the change note's nullifier must be marked spent"
    assert chain.balance_of("alice") == 60.0
    assert chain.balance_of("bob") == 30.0
    assert chain.is_valid(), \
        "chain with two sequential partial spends must validate"


def test_m811_partial_spend_with_mismatched_value_rejected():
    """unshield + fee + change_value must equal note.value.
    Catches the most obvious foot-gun at construction time.
    """
    chain, notes, idxs = fresh_chain_with_pool(1)
    # notes[0].value == 100; try to spend 60 + 5 + 20 (= 85 ≠ 100)
    wrong_change = STARKNote(sk=1, randomness=2, value=20)
    with pytest.raises(ValueError, match="value conservation"):
        create_stark_anon_tx(
            notes[0], idxs[0], chain.stark_anon_tree,
            "alice", 60, 5, change_note=wrong_change,
        )


def test_m811_full_spend_still_works_with_default_change():
    """Backward-compat: omitting change_note auto-generates a dummy
    (full spend with value=0 change). Proves we didn't break the
    common case.
    """
    from qchain.chain.shield_tx import ShieldTransaction
    from qchain.chain.wallet import Wallet
    import time as _time

    chain = Blockchain()
    depositor = Wallet()
    while chain.balance_of(depositor.address) < 100:
        chain.mine_pending(depositor.address)

    note = STARKNote.random(value=100)
    shtx = ShieldTransaction(
        sender="", leaf=note.leaf(), amount=100.0,
        timestamp=_time.time(),
        nonce=int(_time.time() * 1e6),
    )
    shtx.sign(depositor.keypair)
    chain.submit_shield(shtx)
    chain.mine_pending("proposer")

    pool_size_before = chain.stark_anon_tree._next_idx

    # No change_note argument — should default to dummy
    stx = create_stark_anon_tx(
        note, leaf_idx=0, tree=chain.stark_anon_tree,
        unshield_recipient="alice", unshield_amount=100, fee=0,
    )
    chain.submit_stark_anon(stx)
    chain.mine_pending("proposer")

    # Even a "full spend" appends a dummy leaf — Sapling pattern
    pool_size_after = chain.stark_anon_tree._next_idx
    assert pool_size_after == pool_size_before + 1, \
        "even full spends must append a (dummy) output_leaf to the pool"

    assert chain.balance_of("alice") == 100.0
    assert chain.is_valid()
