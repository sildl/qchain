"""End-to-end tests for milestone 2: QRNG + PoS. Run with:
    python -m qchain.tests.test_quantum
"""

from qchain.chain.blockchain import Blockchain
from qchain.chain.proposer import Validator, select_proposer, stake_distribution
from qchain.chain.wallet import Wallet
from qchain.quantum.qrng import QRNG, Source


# Use simulator path everywhere — fast and deterministic enough for CI.
def make_qrng() -> QRNG:
    return QRNG(num_qubits=8, shots=256, prefer_hardware=False)


def test_qrng_returns_requested_size():
    q = make_qrng()
    bits = q.random_bits(100)
    assert len(bits) == 100
    assert set(bits) <= {"0", "1"}
    print("  ✓ QRNG returns the requested number of bits")


def test_qrng_distribution_is_balanced():
    """A fair quantum coin should give ~50% ones over many bits."""
    q = make_qrng()
    bits = q.random_bits(10000)
    ones = bits.count("1")
    # With 10k bits the standard deviation is ~50, so ±200 is very loose
    assert 4800 <= ones <= 5200, f"got {ones} ones, expected ~5000"
    print(f"  ✓ QRNG bits look balanced ({ones}/10000 ones)")


def test_qrng_randbelow_is_in_range():
    q = make_qrng()
    for _ in range(50):
        x = q.randbelow(13)
        assert 0 <= x < 13
    print("  ✓ randbelow stays within bounds")


def test_qrng_falls_back_to_classical():
    """If we pretend Qiskit Aer isn't available, classical should still work."""
    import qchain.quantum.qrng as qrng_mod

    # Temporarily break the simulator path
    original = qrng_mod._from_simulator
    qrng_mod._from_simulator = lambda *a, **kw: None
    try:
        q = QRNG(num_qubits=4, shots=8, prefer_hardware=False)
        bits = q.random_bits(64)
        assert len(bits) == 64
        assert q.last_source == Source.CLASSICAL
    finally:
        qrng_mod._from_simulator = original
    print("  ✓ QRNG falls back to classical when quantum paths fail")


def test_proposer_selection_respects_stake():
    """Validator with 9x the stake should win roughly 9x as often."""
    q = make_qrng()
    validators = [
        Validator(address="alice", stake=10.0),
        Validator(address="bob", stake=90.0),
    ]
    counts = stake_distribution(validators, samples=2000, q=q) if False else None
    counts = stake_distribution(validators, samples=2000, qrng=q)
    # Bob should win roughly 90% — anywhere from 80% to 95% is fine
    bob_share = counts["bob"] / 2000
    assert 0.80 <= bob_share <= 0.95, f"bob share {bob_share}"
    print(f"  ✓ Stake-weighted selection works (bob {counts['bob']}/2000)")


def test_proposer_selection_single_validator():
    q = make_qrng()
    only = [Validator(address="solo", stake=1.0)]
    for _ in range(5):
        assert select_proposer(only, q).address == "solo"
    print("  ✓ Single validator is always chosen")


def test_pos_block_production():
    """Build a chain using PoS proposer selection instead of PoW."""
    bc = Blockchain()
    q = make_qrng()
    alice = Wallet()
    bob = Wallet()

    validators = [
        Validator(address=alice.address, stake=50.0),
        Validator(address=bob.address, stake=50.0),
    ]

    # Produce 3 blocks
    for _ in range(3):
        bc.propose_pending(validators, q)

    assert bc.height == 3
    assert bc.is_valid()

    # Total coins issued: 3 blocks × 10 reward = 30
    total = bc.balance_of(alice.address) + bc.balance_of(bob.address)
    assert total == 30.0
    print(f"  ✓ PoS produced 3 blocks (alice={bc.balance_of(alice.address)}, bob={bc.balance_of(bob.address)})")


def test_pos_block_records_qrng_source():
    bc = Blockchain()
    q = make_qrng()
    val = [Validator(address=Wallet().address, stake=1.0)]
    block = bc.propose_pending(val, q)
    assert "|qrng=" in block.proposer
    print(f"  ✓ Block records QRNG source: {block.proposer.split('|')[1]}")


def test_pos_chain_validates():
    bc = Blockchain()
    q = make_qrng()
    validators = [Validator(address=Wallet().address, stake=1.0) for _ in range(3)]
    for _ in range(5):
        bc.propose_pending(validators, q)
    assert bc.is_valid()

    # Tamper with a PoS block — chain should still detect it
    bc.blocks[2].transactions[0].amount = 9999.0
    assert not bc.is_valid()
    print("  ✓ PoS chain still detects tampering")


if __name__ == "__main__":
    print("Running milestone 2 tests (QRNG + PoS)...\n")
    test_qrng_returns_requested_size()
    test_qrng_distribution_is_balanced()
    test_qrng_randbelow_is_in_range()
    test_qrng_falls_back_to_classical()
    test_proposer_selection_single_validator()
    test_proposer_selection_respects_stake()
    test_pos_block_production()
    test_pos_block_records_qrng_source()
    test_pos_chain_validates()
    print("\nAll milestone 2 tests passed ✓")
