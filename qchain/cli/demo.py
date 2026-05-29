"""Demo: spin up Alice and Bob, transfer coins, watch the chain grow.

Run with: python -m qchain.cli.demo
"""

from qchain.chain.blockchain import Blockchain
from qchain.chain.wallet import Wallet


def main():
    print("=" * 60)
    print("QChain Milestone 1 — Post-Quantum Blockchain Demo")
    print("=" * 60)

    bc = Blockchain()
    alice = Wallet()
    bob = Wallet()
    miner = Wallet()

    print(f"\nAlice's address:  {alice.address}")
    print(f"Bob's address:    {bob.address}")
    print(f"Miner's address:  {miner.address}")
    print(f"\nDilithium public key size: {len(alice.keypair.public_key)} bytes")
    print(f"Dilithium secret key size: {len(alice.keypair.secret_key)} bytes")

    print("\n--- Mining block 1 (no transactions, miner earns reward) ---")
    block = bc.mine_pending(miner.address)
    print(f"Block 1 hash: {block.hash()[:20]}...")
    print(f"Miner balance: {bc.balance_of(miner.address)}")

    print("\n--- Mining block 2 (miner earns another reward) ---")
    bc.mine_pending(miner.address)
    print(f"Miner balance: {bc.balance_of(miner.address)}")

    print("\n--- Miner sends 7 coins to Alice ---")
    tx1 = Wallet(miner.keypair).create_tx(recipient=alice.address, amount=7.0)
    print(f"Signature size: {len(tx1.signature)} chars (base64)")
    bc.submit(tx1)
    bc.mine_pending(miner.address)
    print(f"Miner balance: {bc.balance_of(miner.address)}")
    print(f"Alice balance: {bc.balance_of(alice.address)}")

    print("\n--- Alice sends 2 coins to Bob ---")
    tx2 = alice.create_tx(recipient=bob.address, amount=2.0)
    bc.submit(tx2)
    bc.mine_pending(miner.address)
    print(f"Alice balance: {bc.balance_of(alice.address)}")
    print(f"Bob balance:   {bc.balance_of(bob.address)}")

    print("\n--- Final chain state ---")
    print(f"Height: {bc.height}")
    print(f"Total blocks: {len(bc.blocks)}")
    print(f"Chain valid: {bc.is_valid()}")

    print("\n--- Tampering test ---")
    print("Trying to change Bob's balance by editing block 3...")
    original = bc.blocks[3].transactions[1].amount
    bc.blocks[3].transactions[1].amount = 1000.0
    print(f"Chain valid after tampering: {bc.is_valid()}")
    bc.blocks[3].transactions[1].amount = original  # restore
    print(f"Chain valid after restoring: {bc.is_valid()}")

    print("\n" + "=" * 60)
    print("Done. Every signature above was post-quantum (Dilithium / ML-DSA-65).")
    print("Shor's algorithm cannot forge these even with a large quantum computer.")
    print("=" * 60)


if __name__ == "__main__":
    main()
