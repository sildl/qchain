"""Independent Python implementation of Rescue-Prime 64/256's round function.

Used by m86_reference for differential testing: we re-execute each
round inside the m86 AIR's trace independently, then compare against
the Rust trace builder. Disagreement between this Python
implementation and the Rust one (Winterfell's `Rp64_256::apply_round`)
would indicate either:
  (a) a bug in this Python implementation, OR
  (b) a bug in Winterfell's Rust implementation, OR
  (c) a bug in the trace builder.

Independence note: the round constants are EXTRACTED from
Winterfell's source code, not derived from a separate spec. So this
implementation isn't fully independent of Winterfell — it's
TEXTUALLY independent (different language, different code path,
different at-runtime values) but shares Winterfell as the original
source of constants. Catching a bug in Winterfell's constants would
require a Phase 3 cross-reference against a different implementation
(e.g., Polygon Miden's). What this DOES catch:

  * Trace-builder bugs in round ordering, off-by-one in round counter
  * Trace-builder bugs in the per-round MDS/ARK application
  * Mismatch between the trace builder and the published Rescue-Prime
    algorithm (the Python implementation is straight from the
    Rescue-Prime spec; the Rust implementation in Winterfell may
    have optimizations whose correctness is non-obvious)
  * Cross-checks the AIR's transition constraints would have to enforce

Algorithm (Rescue-XLIX round, from Szepieniec et al. 2020):
  1. S-box layer 1: state[i] = state[i]^ALPHA (= state[i]^7 for Goldilocks)
  2. MDS layer: state = MDS @ state
  3. Add round constants: state += ARK1[round]
  4. S-box layer 2: state[i] = state[i]^INV_ALPHA
  5. MDS layer: state = MDS @ state
  6. Add round constants: state += ARK2[round]

All operations are in Goldilocks F_p where p = 2^64 - 2^32 + 1.
"""

from __future__ import annotations

from typing import List, Tuple

from qchain.crypto._rescue_constants import (
    ALPHA, ARK1, ARK2, INV_ALPHA, MDS, NUM_ROUNDS, P, STATE_WIDTH,
)


# ---------------------------------------------------------------------------
# Field arithmetic in Goldilocks F_p
# ---------------------------------------------------------------------------

def add_mod(a: int, b: int) -> int:
    return (a + b) % P


def mul_mod(a: int, b: int) -> int:
    return (a * b) % P


def pow_mod(a: int, e: int) -> int:
    return pow(a, e, P)


# ---------------------------------------------------------------------------
# Rescue-XLIX round
# ---------------------------------------------------------------------------

def apply_sbox(state: List[int]) -> List[int]:
    """Forward S-box: state[i] = state[i]^ALPHA."""
    return [pow_mod(x, ALPHA) for x in state]


def apply_inv_sbox(state: List[int]) -> List[int]:
    """Inverse S-box: state[i] = state[i]^INV_ALPHA.

    Winterfell uses a specific addition-chain optimization for this; we
    just use Python's built-in modular exponentiation since this is
    reference-implementation code, not performance code.
    """
    return [pow_mod(x, INV_ALPHA) for x in state]


def apply_mds(state: List[int]) -> List[int]:
    """Linear layer: state = MDS @ state."""
    out = [0] * STATE_WIDTH
    for i in range(STATE_WIDTH):
        acc = 0
        for j in range(STATE_WIDTH):
            acc = add_mod(acc, mul_mod(MDS[i][j], state[j]))
        out[i] = acc
    return out


def add_round_constants(state: List[int], ark_row: Tuple[int, ...]) -> List[int]:
    """Add per-round constants."""
    return [add_mod(state[i], ark_row[i]) for i in range(STATE_WIDTH)]


def apply_round(state: List[int], round_idx: int) -> List[int]:
    """One full Rescue-XLIX round at the given round index (0..NUM_ROUNDS-1).

    This MUST produce identical output to Winterfell's
    Rp64_256::apply_round(state, round_idx) for any 12-element state.
    Drift between this and Winterfell is a finding.
    """
    assert 0 <= round_idx < NUM_ROUNDS, f"round {round_idx} out of range [0..{NUM_ROUNDS-1}]"
    assert len(state) == STATE_WIDTH
    # First half: S-box (forward) → MDS → +ARK1
    state = apply_sbox(state)
    state = apply_mds(state)
    state = add_round_constants(state, ARK1[round_idx])
    # Second half: S-box (inverse) → MDS → +ARK2
    state = apply_inv_sbox(state)
    state = apply_mds(state)
    state = add_round_constants(state, ARK2[round_idx])
    return state


def apply_all_rounds(initial_state: List[int]) -> List[List[int]]:
    """Run all 7 rounds from `initial_state`, returning the full row sequence.

    Returns 8 rows (the initial state + 7 post-round states), matching
    the trace's per-block layout where row 0 is the initial state and
    rows 1..7 are the post-round states.
    """
    assert len(initial_state) == STATE_WIDTH
    rows = [list(initial_state)]
    state = list(initial_state)
    for r in range(NUM_ROUNDS):
        state = apply_round(state, r)
        rows.append(list(state))
    return rows
