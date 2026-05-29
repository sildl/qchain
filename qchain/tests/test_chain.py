"""End-to-end tests for milestone 1. Run with: python -m qchain.tests.test_chain"""

from qchain.chain.blockchain import Blockchain
from qchain.chain.transaction import Transaction
from qchain.chain.wallet import Wallet
from qchain.crypto import dilithium


def test_keypair_roundtrip():
    kp = dilithium.generate_keypair()
    msg = b"hello quantum-resistant world"
    sig = dilithium.sign(kp.secret_key, msg)
    assert dilithium.verify(kp.public_key, msg, sig)
    assert not dilithium.verify(kp.public_key, b"different message", sig)
    print("  ✓ Dilithium sign/verify works")


def test_tampered_signature_fails():
    kp = dilithium.generate_keypair()
    sig = dilithium.sign(kp.secret_key, b"pay alice 100")
    # Flip a bit in the signature
    tampered = bytes([sig[0] ^ 0x01]) + sig[1:]
    assert not dilithium.verify(kp.public_key, b"pay alice 100", tampered)
    print("  ✓ Tampered signatures are rejected")


def test_transaction_signs_and_verifies():
    alice = Wallet()
    tx = alice.create_tx(recipient="bob_address", amount=5.0)
    assert tx.verify()
    assert tx.sender == alice.address
    print("  ✓ Transaction signs and verifies")


def test_transaction_cannot_be_forged():
    """An attacker can't take Alice's tx and change the recipient."""
    alice = Wallet()
    tx = alice.create_tx(recipient="bob_address", amount=5.0)
    tx.recipient = "attacker_address"  # tamper
    assert not tx.verify()
    print("  ✓ Tampered transactions are rejected")


def test_blockchain_mines_and_validates():
    bc = Blockchain()
    miner = Wallet()

    # Mine an empty block — miner gets the reward
    bc.mine_pending(miner.address)
    assert bc.balance_of(miner.address) == 10.0
    assert bc.is_valid()
    print("  ✓ Block mined, miner got reward, chain valid")

    # Miner sends 3 coins to a new wallet
    bob = Wallet()
    tx = Wallet(miner.keypair).create_tx(recipient=bob.address, amount=3.0)
    bc.submit(tx)
    bc.mine_pending(miner.address)

    # Miner: started with 10, spent 3, got another 10 reward = 17
    assert bc.balance_of(miner.address) == 17.0
    assert bc.balance_of(bob.address) == 3.0
    assert bc.is_valid()
    print("  ✓ Transfer works, balances correct")


def test_insufficient_balance_rejected():
    bc = Blockchain()
    alice = Wallet()
    try:
        tx = alice.create_tx(recipient="bob", amount=100.0)
        bc.submit(tx)
        assert False, "should have raised"
    except ValueError as e:
        assert "insufficient" in str(e)
    print("  ✓ Overspending is rejected")


def test_chain_tampering_detected():
    bc = Blockchain()
    miner = Wallet()
    bc.mine_pending(miner.address)
    bc.mine_pending(miner.address)
    assert bc.is_valid()

    # Tamper: change the amount in block 1's coinbase
    bc.blocks[1].transactions[0].amount = 9999.0
    assert not bc.is_valid()
    print("  ✓ Chain tampering is detected")


if __name__ == "__main__":
    print("Running milestone 1 tests...\n")
    test_keypair_roundtrip()
    test_tampered_signature_fails()
    test_transaction_signs_and_verifies()
    test_transaction_cannot_be_forged()
    test_blockchain_mines_and_validates()
    test_insufficient_balance_rejected()
    test_chain_tampering_detected()
    print("\nAll tests passed ✓")
