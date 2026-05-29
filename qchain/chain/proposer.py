"""
Stake-weighted block proposer selection using quantum randomness.

In milestone 1 we used proof-of-work to decide who got to mine the next
block: whoever hashed fastest. In a proof-of-stake chain, the next proposer
is instead selected at random, weighted by how many coins each validator
has staked.

The fairness of that "random" selection is critical — if an attacker can
predict the random seed, they can grind transactions to bias the outcome
in their favor. Using quantum randomness as the seed source makes the
outcome unpredictable even in principle, because the bits come from
fundamentally non-deterministic quantum measurements rather than a
classical algorithm an attacker could simulate.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from qchain.quantum.qrng import QRNG


@dataclass
class Validator:
    address: str
    stake: float


def select_proposer(
    validators: List[Validator],
    qrng: QRNG,
) -> Validator:
    """Pick a validator at random with probability proportional to stake.

    This is the "weighted random sampling" problem. We use the inverse-CDF
    method: place each validator on a number line in a slot of width
    proportional to their stake, draw a uniform random point on the total
    line, return whoever owns the slot it lands in.

    Example with stakes [10, 20, 30]:
        slots: [0..10) [10..30) [30..60)
        point = qrng.randbelow(60)
        if point in [10..30): pick the second validator
    """
    if not validators:
        raise ValueError("no validators")
    total = sum(v.stake for v in validators)
    if total <= 0:
        raise ValueError("total stake must be positive")

    # QRNG gives us integers; scale stakes to integers for an exact draw.
    # Multiply by a precision factor so fractional stakes still work.
    SCALE = 10_000
    scaled = [int(v.stake * SCALE) for v in validators]
    total_scaled = sum(scaled)

    point = qrng.randbelow(total_scaled)

    running = 0
    for v, weight in zip(validators, scaled):
        running += weight
        if point < running:
            return v

    # Floating-point edge case — shouldn't happen since we use integers,
    # but return the last validator as a safe fallback.
    return validators[-1]


def stake_distribution(
    validators: List[Validator], samples: int, qrng: QRNG
) -> Dict[str, int]:
    """How many times each validator gets selected in `samples` draws.

    Useful for verifying fairness: the resulting counts should be roughly
    proportional to each validator's stake. Used by the demo script.
    """
    counts: Dict[str, int] = {v.address: 0 for v in validators}
    for _ in range(samples):
        winner = select_proposer(validators, qrng)
        counts[winner.address] += 1
    return counts
