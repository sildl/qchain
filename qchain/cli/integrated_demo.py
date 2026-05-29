"""Milestone 5 integrated demo: one blockchain handling transparent AND
anonymous transactions, with quantum-random PoS proposer selection.

Run with: python -m qchain.cli.integrated_demo
"""

from qchain.chain.anon_tx import AnonOutput, AnonTransaction, compute_net_blinding
from qchain.chain.blockchain import Blockchain
from qchain.chain.proposer import Validator
from qchain.chain.wallet import Wallet
from qchain.crypto.anon import new_anon_note, prove_anon_spend
from qchain.crypto.schnorr import generate_keypair
from qchain.quantum.qrng import QRNG


def short(b) -> str:
    if isinstance(b, bytes):
        return b.hex()[:14] + "…"
    return str(b)[:14] + "…"


def summary(bc: Blockchain) -> None:
    print(f"\n  ── chain state ──")
    print(f"  height:          {bc.height}")
    print(f"  anon pool size:  {bc.anon_tree.size}")
    print(f"  nullifiers used: {len(bc.nullifiers)}")
    print(f"  chain valid:     {bc.is_valid()}")


def main():
    print("=" * 72)
    print("QChain Milestone 5 — Integrated Chain")
    print("Transparent + Anonymous transactions in the same blocks")
    print("=" * 72)

    bc = Blockchain()

    # --- Set up parties ---------------------------------------------------
    miner_w = Wallet()
    alice_w = Wallet()             # alice's transparent wallet
    alice_anon = generate_keypair()  # alice's anon keypair
    bob_anon = generate_keypair()    # bob's anon keypair

    validators = [Validator(address=miner_w.address, stake=1.0)]
    qrng = QRNG(num_qubits=4, shots=32, prefer_hardware=False)

    print(f"\nMiner addr:    {miner_w.address}")
    print(f"Alice transparent addr: {alice_w.address}")
    print(f"Alice anon pk: {short(alice_anon.pk)}")
    print(f"Bob anon pk:   {short(bob_anon.pk)}")

    # ====================================================================
    # Block 1: Bootstrap — miner earns reward
    # ====================================================================
    print("\n" + "─" * 72)
    print("Block 1: bootstrap (PoS, miner-only)")
    bc.propose_pending(validators, qrng)
    print(f"  miner balance: {bc.balance_of(miner_w.address)}")

    # ====================================================================
    # Block 2: Mixed — transparent tx + anon shield
    # ====================================================================
    print("\n" + "─" * 72)
    print("Block 2: MIXED")
    print("  • transparent: miner pays Alice 5 coins")
    print("  • anonymous:   Alice shields 3 coins into her anon pool")

    # Transparent tx: miner → alice
    tx_t = Wallet(miner_w.keypair).create_tx(alice_w.address, amount=5.0)
    bc.submit(tx_t)

    # Anon tx: Alice shields 3 transparent coins. The "transparent
    # source" is Alice's own funds — in a real chain Alice would pair
    # this with a transparent tx burning 3 from her own balance, but
    # for this demo we just emit the shield_in alongside.
    alice_first_note = new_anon_note(value=3, recipient_pk=alice_anon.pk)
    bc.submit_anon(AnonTransaction(
        inputs=[],
        outputs=[AnonOutput.from_note(alice_first_note)],
        shield_in=3,
        unshield_out=0,
        unshield_recipient="",
        fee=0,
        net_blinding=compute_net_blinding(
            [], [alice_first_note.value_blinding]
        ),
    ))

    block = bc.propose_pending(validators, qrng)
    print(f"\n  block {block.index}:")
    print(f"    transparent txs: {len(block.transactions)}")
    print(f"    anon txs:        {len(block.anon_transactions)}")
    print(f"    proposer:        {block.proposer.split('|')[0][:20]}…")
    summary(bc)

    # ====================================================================
    # Block 3: Pure anon — Alice privately sends to Bob
    # ====================================================================
    print("\n" + "─" * 72)
    print("Block 3: PURE ANON — Alice sends 2 anonymously to Bob")
    print("  Alice spends her 3-coin anon note, sends 2 to Bob, keeps 1 change")

    spend = prove_anon_spend(
        alice_first_note, alice_anon.sk, bc.anon_tree.proof(0)
    )
    bob_note = new_anon_note(value=2, recipient_pk=bob_anon.pk)
    change = new_anon_note(value=1, recipient_pk=alice_anon.pk)

    bc.submit_anon(AnonTransaction(
        inputs=[spend],
        outputs=[AnonOutput.from_note(bob_note), AnonOutput.from_note(change)],
        shield_in=0,
        unshield_out=0,
        unshield_recipient="",
        fee=0,
        net_blinding=compute_net_blinding(
            [alice_first_note.value_blinding],
            [bob_note.value_blinding, change.value_blinding],
        ),
    ))

    block = bc.propose_pending(validators, qrng)
    print(f"\n  what the world sees about Alice's private transfer:")
    atx = block.anon_transactions[0]
    inp = atx.inputs[0]
    print(f"    nullifier:    {short(inp.statement.nullifier)}")
    print(f"    pubkey commit: {short(inp.statement.pubkey_commit_bytes)}  "
          "← unlinkable to Alice's long-term pk")
    print(f"    output 1 leaf: {short(atx.outputs[0].leaf_commitment)}  ← could be Bob or change")
    print(f"    output 2 leaf: {short(atx.outputs[1].leaf_commitment)}  ← could be Bob or change")
    print(f"    public flow:  shield={atx.shield_in} unshield={atx.unshield_out} fee={atx.fee}")
    summary(bc)

    # ====================================================================
    # Block 4: Bob unshields
    # ====================================================================
    print("\n" + "─" * 72)
    print("Block 4: Bob unshields his 2-coin anon note")

    bob_idx = 1  # bob_note was added 2nd in block 3
    bob_spend = prove_anon_spend(bob_note, bob_anon.sk, bc.anon_tree.proof(bob_idx))
    bc.submit_anon(AnonTransaction(
        inputs=[bob_spend],
        outputs=[],
        shield_in=0,
        unshield_out=2,
        unshield_recipient="bob_transparent_addr",
        fee=0,
        net_blinding=compute_net_blinding([bob_note.value_blinding], []),
    ))
    bc.propose_pending(validators, qrng)
    print(f"  bob_transparent_addr balance: {bc.balance_of('bob_transparent_addr')}")
    summary(bc)

    # ====================================================================
    # Final state
    # ====================================================================
    print("\n" + "=" * 72)
    print("FINAL CHAIN STATE")
    print("=" * 72)
    print(f"Blocks:                  {bc.height}")
    print(f"Anon pool size:          {bc.anon_tree.size}")
    print(f"Anon spends to date:     {len(bc.nullifiers)}")
    print(f"Miner balance:           {bc.balance_of(miner_w.address)}")
    print(f"Alice transparent bal:   {bc.balance_of(alice_w.address)}")
    print(f"Bob transparent bal:     {bc.balance_of('bob_transparent_addr')}")
    print(f"Chain valid:             {bc.is_valid()}")

    print("\nFour different transaction kinds coexisted in this chain:")
    print("  • Transparent coinbase rewards (PoS-via-QRNG proposer selection)")
    print("  • Transparent transfers (miner → Alice)")
    print("  • Anon shield (Alice: transparent → anon pool)")
    print("  • Anon private transfer (Alice → Bob, fully hidden)")
    print("  • Anon unshield (Bob: anon pool → transparent)")
    print("\nAll validated by a single `is_valid()` call that replays both")
    print("the transparent ledger AND the anon pool from genesis.")


if __name__ == "__main__":
    main()
