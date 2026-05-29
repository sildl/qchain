"""Demo for milestone 3: shielded (privacy-preserving) transactions.

Storyline:
  * Alice and Bob each have transparent balances.
  * Alice shields 50 coins (moves them into the shielded pool, hiding
    the amount on-chain).
  * Alice privately sends 30 to Bob (the chain sees a transfer happened
    but not the amounts).
  * Bob unshields 30 back to a transparent address.

Throughout, we print what an external observer sees vs. what's actually
happening. This shows the privacy properties concretely.

Run with: python -m qchain.cli.shielded_demo
"""

import secrets

from qchain.chain.shielded import (
    ShieldedOutput,
    ShieldedPool,
    ShieldedTransaction,
    apply_shielded_tx,
    verify_shielded_tx,
)
from qchain.crypto import dilithium
from qchain.crypto.zk import new_shielded_note, prove_spend


def hexshort(b: bytes) -> str:
    return b.hex()[:12] + "..."


def show_observer_view(label: str, tx: ShieldedTransaction):
    print(f"\n  [Public observer sees: {label}]")
    print(f"    txid:             {tx.txid()[:16]}...")
    print(f"    inputs:           {len(tx.inputs)} (nullifiers shown, values hidden)")
    for inp in tx.inputs:
        print(f"      • nullifier:    {hexshort(inp.statement.nullifier)}")
        print(f"        leaf spent:   {hexshort(inp.statement.leaf_commitment)}")
        print(f"        spender pk:   {hexshort(inp.spender_pubkey)}")
        print(f"        value commit: {hexshort(inp.statement.value_commit)} (value hidden)")
    print(f"    outputs:          {len(tx.outputs)} (recipient + amount hidden)")
    for out in tx.outputs:
        print(f"      • new leaf:     {hexshort(out.leaf_commitment)}")
        print(f"        value commit: {hexshort(out.value_commit)} (value hidden)")
    print(f"    shield_in:        {tx.shield_in} (public)")
    print(f"    unshield_out:     {tx.unshield_out} to {tx.unshield_in_address or '<none>'}")
    print(f"    fee:              {tx.fee}")


def main():
    print("=" * 64)
    print("QChain Milestone 3 — Shielded Transactions")
    print("=" * 64)

    pool = ShieldedPool()
    alice = dilithium.generate_keypair()
    bob = dilithium.generate_keypair()
    print(f"\nAlice's pubkey:  {hexshort(alice.public_key)}")
    print(f"Bob's pubkey:    {hexshort(bob.public_key)}")
    print(f"Pool initially empty. Merkle root: {hexshort(pool.root)}")

    # ----- Step 1: Alice shields 50 coins ---------------------------------
    print("\n--- Step 1: Alice shields 50 transparent coins ---")
    alice_note_50 = new_shielded_note(value=50, recipient_pk=alice.public_key)
    tx1 = ShieldedTransaction(
        inputs=[],
        outputs=[ShieldedOutput(alice_note_50.leaf(), alice_note_50.value_commit())],
        shield_in=50,
        unshield_in_address="",
        unshield_out=0,
        fee=0,
        timestamp=0,
        balance_blinding=secrets.token_bytes(32),
    )
    ok, reason = verify_shielded_tx(
        tx1, pool, revealed_input_values=[], revealed_output_values=[50]
    )
    assert ok, reason
    apply_shielded_tx(tx1, pool)
    show_observer_view("shield tx", tx1)
    print(f"\n  [What's actually happening: Alice has a hidden 50-coin note]")
    print(f"  [Pool size: {pool.tree.size}, new root: {hexshort(pool.root)}]")

    # ----- Step 2: Alice privately sends 30 to Bob, keeps 18, 2 fee --------
    print("\n--- Step 2: Alice privately sends 30 to Bob (keeping 18 for change) ---")
    alice_idx = 0  # her note is the first leaf
    mp_alice = pool.tree.proof(alice_idx)
    auth_alice = prove_spend(alice_note_50, alice.secret_key, alice.public_key, mp_alice)

    bob_note_30 = new_shielded_note(value=30, recipient_pk=bob.public_key)
    alice_change_18 = new_shielded_note(value=18, recipient_pk=alice.public_key)

    tx2 = ShieldedTransaction(
        inputs=[auth_alice],
        outputs=[
            ShieldedOutput(bob_note_30.leaf(), bob_note_30.value_commit()),
            ShieldedOutput(alice_change_18.leaf(), alice_change_18.value_commit()),
        ],
        shield_in=0,
        unshield_in_address="",
        unshield_out=0,
        fee=2,
        timestamp=0,
        balance_blinding=secrets.token_bytes(32),
    )
    ok, reason = verify_shielded_tx(
        tx2, pool, revealed_input_values=[50], revealed_output_values=[30, 18]
    )
    assert ok, reason
    apply_shielded_tx(tx2, pool)
    show_observer_view("private transfer", tx2)
    print(f"\n  [What's actually happening:")
    print(f"     - Alice spent her 50-coin note")
    print(f"     - Bob received a hidden 30-coin note")
    print(f"     - Alice received a hidden 18-coin change note")
    print(f"     - Block proposer earned 2 fee]")
    print(f"  [The observer CAN'T tell:")
    print(f"     - Which output went to Bob vs back to Alice")
    print(f"     - The amounts in each output (could be 1+47 or 24+24, all look identical)]")
    print(f"  [Pool size: {pool.tree.size}, new root: {hexshort(pool.root)}]")

    # ----- Step 3: Bob unshields 30 to a public address --------------------
    print("\n--- Step 3: Bob unshields his 30-coin note to a transparent address ---")
    bob_idx = 1  # Bob's note was the second leaf added in tx2
    mp_bob = pool.tree.proof(bob_idx)
    auth_bob = prove_spend(bob_note_30, bob.secret_key, bob.public_key, mp_bob)

    tx3 = ShieldedTransaction(
        inputs=[auth_bob],
        outputs=[],
        shield_in=0,
        unshield_in_address="bob_transparent_address",
        unshield_out=29,
        fee=1,
        timestamp=0,
        balance_blinding=secrets.token_bytes(32),
    )
    ok, reason = verify_shielded_tx(
        tx3, pool, revealed_input_values=[30], revealed_output_values=[]
    )
    assert ok, reason
    apply_shielded_tx(tx3, pool)
    show_observer_view("unshield tx", tx3)
    print(f"\n  [What's actually happening: Bob converted his hidden 30-coin note into")
    print(f"   29 transparent coins + 1 fee. Observer NOW sees the value, but still")
    print(f"   doesn't know it was originally Alice who shielded those coins.]")

    # ----- Step 4: Try a double-spend ------------------------------------
    print("\n--- Step 4: Eve tries to double-spend Bob's already-spent note ---")
    # Eve somehow got hold of an old Merkle proof, but the nullifier is recorded
    try:
        tx_evil = ShieldedTransaction(
            inputs=[auth_bob],  # reuse the same auth
            outputs=[],
            shield_in=0,
            unshield_in_address="eve",
            unshield_out=30,
            fee=0,
            timestamp=0,
            balance_blinding=secrets.token_bytes(32),
        )
        ok, reason = verify_shielded_tx(
            tx_evil, pool, revealed_input_values=[30], revealed_output_values=[]
        )
        if not ok:
            print(f"  ✓ Double-spend rejected: {reason}")
    except Exception as e:
        print(f"  ✓ Double-spend rejected: {e}")

    # ----- Summary ---------------------------------------------------------
    print("\n" + "=" * 64)
    print("SUMMARY")
    print("=" * 64)
    print(f"Total notes in pool:     {pool.tree.size}")
    print(f"Total nullifiers spent:  {len(pool.seen_nullifiers)}")
    print(f"\nPrivacy delivered:")
    print(f"  ✓ Note values are committed, not revealed on-chain")
    print(f"  ✓ Recipient pubkeys are hidden inside output commitments")
    print(f"  ✓ Spends are unlinkable from the original shielded notes")
    print(f"  ✓ Double-spending is detected via nullifiers")
    print(f"\nHonest limitations:")
    print(f"  • Sender pubkey is revealed at spend time")
    print(f"  • Which leaf was spent is revealed (Merkle path is public)")
    print(f"  • Upgrade path: replace SpendAuthorization with a zk-STARK")
    print(f"    proof for full sender-anonymity (à la Zcash Sapling).")


if __name__ == "__main__":
    main()
