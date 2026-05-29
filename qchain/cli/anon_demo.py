"""Demo for milestone 4: full sender anonymity.

The killer demo: Alice has two notes. She spends both. An observer sees
the two spends but CANNOT tell they came from the same wallet — the
on-chain data is completely unlinkable.

Run with: python -m qchain.cli.anon_demo
"""

import secrets

from qchain.crypto.anon import (
    new_anon_note,
    prove_anon_spend,
    verify_anon_spend,
)
from qchain.crypto.merkle import MerkleTree
from qchain.crypto.schnorr import generate_keypair


def short(b: bytes) -> str:
    return b.hex()[:16] + "…"


def main():
    print("=" * 72)
    print("QChain Milestone 4 — Full-Anonymity Shielded Spends (Schnorr ZK)")
    print("=" * 72)

    # ----- Setup ---------------------------------------------------------
    alice = generate_keypair()
    bob = generate_keypair()
    carol = generate_keypair()  # decoy participant
    print(f"\nAlice's PK (long-term): {short(alice.pk)}")
    print(f"Bob's PK   (long-term): {short(bob.pk)}")
    print(f"Carol's PK (decoy):     {short(carol.pk)}")

    # Build a pool with several notes, two of which are Alice's
    pool = MerkleTree()
    print(f"\n--- Pool setup: 5 notes total, 2 of them Alice's ---")

    # Add some decoy notes first
    decoy1 = new_anon_note(value=50, recipient_pk=carol.pk)
    pool.append(decoy1.leaf())
    decoy2 = new_anon_note(value=25, recipient_pk=bob.pk)
    pool.append(decoy2.leaf())

    # Alice's two notes
    alice_note_a = new_anon_note(value=80, recipient_pk=alice.pk)
    idx_a = pool.append(alice_note_a.leaf())
    print(f"Alice's note A added (index {idx_a}, value 80)")

    decoy3 = new_anon_note(value=10, recipient_pk=carol.pk)
    pool.append(decoy3.leaf())

    alice_note_b = new_anon_note(value=42, recipient_pk=alice.pk)
    idx_b = pool.append(alice_note_b.leaf())
    print(f"Alice's note B added (index {idx_b}, value 42)")

    print(f"\nMerkle root after setup: {short(pool.root())}")
    print(f"Pool size: {pool.size}")

    # ----- Alice spends both notes --------------------------------------
    print(f"\n--- Alice spends both her notes ---")

    proof_a = prove_anon_spend(alice_note_a, alice.sk, pool.proof(idx_a))
    proof_b = prove_anon_spend(alice_note_b, alice.sk, pool.proof(idx_b))

    # Both verify
    ok_a, _ = verify_anon_spend(proof_a, pool.root(), set())
    ok_b, _ = verify_anon_spend(proof_b, pool.root(), set())
    print(f"  Spend A verifies: {ok_a}")
    print(f"  Spend B verifies: {ok_b}")

    # ----- The unlinkability demonstration -------------------------------
    print(f"\n--- What an observer sees from each spend ---\n")

    def show_public_data(label: str, p) -> None:
        s = p.statement
        print(f"{label}:")
        print(f"  nullifier:       {short(s.nullifier)}")
        print(f"  leaf spent:      {short(s.leaf_commitment)}")
        print(f"  value commit:    {short(s.value_commit_bytes)}")
        print(f"  pubkey commit:   {short(s.pubkey_commit_bytes)}   ← randomized per spend!")
        print(f"  schnorr R:       {short(p.schnorr.R)}")
        print(f"  schnorr s_x:     {p.schnorr.s_x.to_bytes(32, 'big').hex()[:16]}…")
        print(f"  note_id:         {short(s.note_id)}")
        print()

    show_public_data("Spend A", proof_a)
    show_public_data("Spend B", proof_b)

    # ----- The proof that they're unlinkable ----------------------------
    print("--- Unlinkability check ---")
    print(f"  Alice's true PK appears in spend A? {alice.pk in proof_a.statement.pubkey_commit_bytes}")
    print(f"  Alice's true PK appears in spend B? {alice.pk in proof_b.statement.pubkey_commit_bytes}")
    print(f"  Spend A's pubkey commit == Spend B's pubkey commit? "
          f"{proof_a.statement.pubkey_commit_bytes == proof_b.statement.pubkey_commit_bytes}")
    print(f"  Spend A's nullifier == Spend B's nullifier?       "
          f"{proof_a.statement.nullifier == proof_b.statement.nullifier}")

    print()
    print("To an observer, these two spends look as unrelated as if they")
    print("were performed by two different wallets. Yet they're both Alice.")

    # ----- Verify by simulation: random ordering still works ------------
    print(f"\n--- Stress test: 10 spends from 10 different wallets, randomly ordered ---")
    fresh_pool = MerkleTree()
    parties = []
    notes = []
    indices = []
    for i in range(10):
        kp = generate_keypair()
        note = new_anon_note(value=10 + i, recipient_pk=kp.pk)
        idx = fresh_pool.append(note.leaf())
        parties.append(kp)
        notes.append(note)
        indices.append(idx)

    proofs = []
    for kp, note, idx in zip(parties, notes, indices):
        proofs.append(prove_anon_spend(note, kp.sk, fresh_pool.proof(idx)))

    # Verify them in shuffled order
    import random
    random.shuffle(proofs)
    seen = set()
    for p in proofs:
        ok, reason = verify_anon_spend(p, fresh_pool.root(), seen)
        assert ok, reason
        seen.add(p.statement.nullifier)
    print(f"  All 10 spends verified in randomized order ✓")

    # ----- Summary -------------------------------------------------------
    print("\n" + "=" * 72)
    print("WHAT THIS BUYS YOU")
    print("=" * 72)
    print("Privacy properties achieved:")
    print("  • Note values are committed (Pedersen), not stored on chain.")
    print("  • Note recipients are committed, not stored on chain.")
    print("  • Spender's long-term pubkey is HIDDEN (Schnorr proof of knowledge).")
    print("  • Two spends by the same party are UNLINKABLE (fresh randomization).")
    print("  • Double-spending is detected via deterministic nullifiers.")
    print()
    print("Honest limitations:")
    print("  • Which leaf was spent is visible (a real SNARK would hide this).")
    print("  • The shielded layer is NOT post-quantum safe (Schnorr on secp256k1).")
    print("    The transparent transaction layer (milestone 1) remains PQ.")
    print("  • Full post-quantum anonymity would need lattice-based ZK or STARKs,")
    print("    which is beyond what this learning project implements.")
    print()
    print("What this IS:")
    print("  • Textbook Schnorr signatures of knowledge over secp256k1.")
    print("  • Standard Pedersen commitments.")
    print("  • Fiat-Shamir transform, properly bound to the full statement.")
    print("  • Real, sound cryptography — not invented constructions.")


if __name__ == "__main__":
    main()
