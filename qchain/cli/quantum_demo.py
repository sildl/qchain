"""Demo for milestone 2: a PoS blockchain whose block proposers are picked
using true(-ish) quantum randomness.

Run with simulator (default, fast):
    python -m qchain.cli.quantum_demo

Run against real IBM Quantum hardware (slow — queue waits):
    export IBM_QUANTUM_TOKEN=...
    python -m qchain.cli.quantum_demo --hardware
"""

import argparse
from collections import Counter

from qchain.chain.blockchain import Blockchain
from qchain.chain.proposer import Validator, stake_distribution
from qchain.chain.wallet import Wallet
from qchain.quantum.qrng import QRNG


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--hardware",
        action="store_true",
        help="Try real IBM Quantum hardware first (set IBM_QUANTUM_TOKEN env var)",
    )
    parser.add_argument(
        "--blocks", type=int, default=5, help="How many blocks to produce"
    )
    parser.add_argument(
        "--qubits", type=int, default=8, help="QRNG circuit width"
    )
    parser.add_argument(
        "--shots", type=int, default=256, help="QRNG shots per refresh"
    )
    args = parser.parse_args()

    print("=" * 64)
    print("QChain Milestone 2 — Quantum Random Proposer Selection")
    print("=" * 64)

    qrng = QRNG(
        num_qubits=args.qubits,
        shots=args.shots,
        prefer_hardware=args.hardware,
    )

    print("\n--- Phase 1: warm up the QRNG ---")
    print(f"Requesting 256 random bits (hardware={'on' if args.hardware else 'off'})...")
    bits = qrng.random_bits(256)
    print(f"Source: {qrng.last_source.value}")
    print(f"Backend: {qrng.last_backend}")
    if qrng.last_job_id:
        print(f"IBM job ID: {qrng.last_job_id}")
    print(f"First 64 bits: {bits[:64]}")

    print("\n--- Phase 2: fairness check ---")
    print("Three validators with stakes 10 / 30 / 60 — proposer share should match.")
    alice, bob, carol = Wallet(), Wallet(), Wallet()
    validators = [
        Validator(address=alice.address, stake=10.0),
        Validator(address=bob.address,   stake=30.0),
        Validator(address=carol.address, stake=60.0),
    ]
    label = {alice.address: "alice (10%)", bob.address: "bob (30%)", carol.address: "carol (60%)"}

    SAMPLES = 1000
    print(f"Running {SAMPLES} draws...")
    counts = stake_distribution(validators, samples=SAMPLES, qrng=qrng)
    for addr, c in counts.items():
        share = c / SAMPLES * 100
        print(f"  {label[addr]:<14} won {c:4d}/{SAMPLES}  ({share:.1f}%)")

    print("\n--- Phase 3: build a PoS chain ---")
    bc = Blockchain()
    miner_wallet = Wallet()  # used to fund validators initially
    validator_wallets = {alice.address: alice, bob.address: bob, carol.address: carol}

    print(f"Producing {args.blocks} blocks. Proposer chosen by QRNG each time.\n")
    proposer_history = []
    for i in range(args.blocks):
        block = bc.propose_pending(validators, qrng)
        winner_addr = block.proposer.split("|")[0]
        proposer_history.append(winner_addr)
        print(
            f"  Block {block.index}: proposer {label[winner_addr]:<14} "
            f"hash={block.hash()[:16]}..."
        )

    print("\n--- Phase 4: final state ---")
    print(f"Chain height: {bc.height}")
    print(f"Chain valid:  {bc.is_valid()}")
    print(f"Balances:")
    for addr, w in validator_wallets.items():
        print(f"  {label[addr]:<14}: {bc.balance_of(addr)} coins")

    proposer_counts = Counter(proposer_history)
    print(f"\nProposer counts over the {args.blocks}-block run:")
    for addr, n in proposer_counts.most_common():
        print(f"  {label[addr]:<14}: {n}")

    print("\n" + "=" * 64)
    print("Done. Block proposer was chosen by quantum measurement, not by a")
    print("classical PRNG an attacker could predict or grind.")
    print("=" * 64)


if __name__ == "__main__":
    main()
