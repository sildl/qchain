"""m86 AIR reference and trace-inspection helpers for differential testing.

This module provides an independent Python implementation of:
  1. The native m86 computation (leaf, root, nullifier, output_leaf from witness)
  2. Structural invariants the AIR's trace MUST satisfy
  3. Helpers to inspect a trace built by the Rust prover

It does NOT reimplement:
  * The Rescue-Prime permutation rounds (we'd be reimplementing 150 lines of
    polynomial arithmetic; the gain over using the Rust impl is marginal
    while the risk of subtly-wrong reimplementation is high)
  * The Winterfell prover/verifier (out of scope; trusted dependency)

What this module IS useful for: catching the class of bugs where the Rust
trace builder produces a trace whose semantic content disagrees with what
we believe the AIR is proving. If we built a trace claiming root=R, but
the trace's last-Merkle-block output isn't actually R, that's a bug the
AIR's boundary constraint should catch — but if both the trace builder and
the constraint evaluation share a misconception, the bug slides through.

This module catches that class.

Use:
    from qchain.crypto.m86_reference import (
        compute_expected, inspect_trace_boundaries,
        validate_trace_structural_invariants,
    )

    exp = compute_expected(sk, r, v, path, sk_out, r_out, v_out)
    # exp.leaf, exp.root, exp.nullifier, exp.output_leaf — what AIR should prove

    trace = q.build_m86_trace_for_inspection(sk, r, v, path, ua, f, sko, ro, vo)
    obs = inspect_trace_boundaries(trace)
    # obs.leaf, obs.root, obs.nullifier, obs.output_leaf — what trace claims

    assert exp == obs   # if not, BUG
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

import qstark_py as q


# ---------------------------------------------------------------------------
# Trace layout constants (mirror m86_air.rs)
# ---------------------------------------------------------------------------

_WIDTH, _LENGTH, _ACTIVE_ROWS, _NUM_BLOCKS, _ROWS_PER_BLOCK = q.m86_trace_dims()
_MERKLE_DEPTH = q.m86_merkle_depth()

# Column offsets — these MUST match m86_air.rs constants
COL_STATE_START = 0
COL_STATE_END = 12          # state[0..12], 12 elements
COL_DIR = 12
COL_SIB_START = 13
COL_SIB_END = 17            # sib[0..4]
COL_SK = 17
COL_R = 18
COL_V = 19
COL_BIT_START = 20
COL_BIT_END = 84            # 64 bits
NUM_VALUE_BITS = 64
COL_SK_OUT = 84
COL_R_OUT = 85
COL_V_OUT = 86
COL_BIT_OUT_START = 87
COL_BIT_OUT_END = 151       # 64 bits

# Block indices
LEAF_BLOCK = 0
FIRST_MERKLE_BLOCK = 1
LAST_MERKLE_BLOCK = _MERKLE_DEPTH       # inclusive
NULLIFIER_BLOCK = _MERKLE_DEPTH + 1
OUTPUT_LEAF_BLOCK = _MERKLE_DEPTH + 2   # = _NUM_BLOCKS - 1

# Important row positions (state[4..8] holds the block's output digest)
ROOT_ROW = (_MERKLE_DEPTH + 1) * _ROWS_PER_BLOCK - 1
NULLIFIER_LAST_ROW = (NULLIFIER_BLOCK + 1) * _ROWS_PER_BLOCK - 1
OUTPUT_LEAF_LAST_ROW = (OUTPUT_LEAF_BLOCK + 1) * _ROWS_PER_BLOCK - 1
LEAF_LAST_ROW = _ROWS_PER_BLOCK - 1     # row 7


# ---------------------------------------------------------------------------
# Expected values (the "native reference")
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class M86Expected:
    """What the AIR's public inputs MUST be for a given witness.

    Computed independently from the trace builder using only the
    hash primitives. If the trace built from the same witness
    disagrees with these, the trace builder is broken.
    """
    leaf: Tuple[int, int, int, int]
    root: Tuple[int, int, int, int]
    nullifier: Tuple[int, int, int, int]
    output_leaf: Tuple[int, int, int, int]


def compute_expected(
    sk: int, r: int, v: int,
    path: List[Tuple[Tuple[int, int, int, int], bool]],
    sk_out: int, r_out: int, v_out: int,
) -> M86Expected:
    """Compute what root, nullifier, leaf, output_leaf SHOULD be for this witness.

    Uses ONLY the hash primitives (hash_leaf, hash_inner) exposed by
    qstark_py — NOT the trace builder. So this is genuinely
    independent of the m86_air implementation.

    The native rules per m86_native.rs:compute_reference:
      leaf       = hash_leaf(sk, r, v)
      walk       = leaf; for (sib, is_right) in path: walk = merge(...)
      root       = walk
      nullifier  = hash_leaf(sk + 1, r, v)
    Plus output_leaf which is just hash_leaf(sk_out, r_out, v_out).
    """
    assert len(path) == _MERKLE_DEPTH, \
        f"path must have {_MERKLE_DEPTH} elements, got {len(path)}"
    leaf = q.hash_leaf(sk, r, v)
    walk = leaf
    for sibling, is_right in path:
        if is_right:
            walk = q.hash_inner(sibling, walk)
        else:
            walk = q.hash_inner(walk, sibling)
    root = walk
    # Goldilocks: sk+1 must be canonical
    P = q.field_modulus()
    nullifier = q.hash_leaf((sk + 1) % P, r, v)
    output_leaf = q.hash_leaf(sk_out, r_out, v_out)
    return M86Expected(leaf=leaf, root=root, nullifier=nullifier, output_leaf=output_leaf)


# ---------------------------------------------------------------------------
# Trace inspection
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class M86TraceObservation:
    """What the trace's boundary cells actually contain.

    These are the same cells the AIR's get_assertions() pins to
    public inputs. If observation == expected, the trace's boundary
    behaviour matches the native computation.
    """
    leaf: Tuple[int, int, int, int]      # state[4..8] at row LEAF_LAST_ROW
    root: Tuple[int, int, int, int]      # state[4..8] at row ROOT_ROW
    nullifier: Tuple[int, int, int, int] # state[4..8] at row NULLIFIER_LAST_ROW
    output_leaf: Tuple[int, int, int, int] # state[4..8] at row OUTPUT_LEAF_LAST_ROW


def _read_digest_at(trace: List[List[int]], row: int) -> Tuple[int, int, int, int]:
    """state[4..8] at the given row is a 4-element digest."""
    return (trace[row][4], trace[row][5], trace[row][6], trace[row][7])


def inspect_trace_boundaries(trace: List[List[int]]) -> M86TraceObservation:
    """Read the boundary-constraint cells from a trace.

    These are the EXACT cells the AIR pins to public inputs via
    get_assertions(). If a tampered trace got past the AIR somehow,
    the public inputs the verifier sees would equal these cell values.
    """
    return M86TraceObservation(
        leaf=_read_digest_at(trace, LEAF_LAST_ROW),
        root=_read_digest_at(trace, ROOT_ROW),
        nullifier=_read_digest_at(trace, NULLIFIER_LAST_ROW),
        output_leaf=_read_digest_at(trace, OUTPUT_LEAF_LAST_ROW),
    )


# ---------------------------------------------------------------------------
# Structural invariants
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class InvariantViolation:
    """One specific way the trace violates an AIR invariant."""
    invariant: str
    detail: str


def validate_trace_structural_invariants(
    trace: List[List[int]],
    expected_sk: int,
    expected_r: int,
    expected_v: int,
    expected_sk_out: int,
    expected_r_out: int,
    expected_v_out: int,
    expected_dir_bits: List[bool],
    expected_siblings: List[Tuple[int, int, int, int]],
) -> List[InvariantViolation]:
    """Check structural invariants the AIR claims about its trace.

    Returns an empty list if all invariants hold; otherwise a list of
    violations. We check things that DON'T require reimplementing the
    Rescue-Prime rounds — instead, they verify witness-column constancy,
    direction-bit booleanity, bit-decomposition correctness, and
    block-boundary digest continuity.

    Specifically:

    INV-1: sk, r, v columns are constant across all active rows
    INV-2: sk_out, r_out, v_out columns are constant across all active rows
    INV-3: dir column is boolean (0 or 1) on every active row
    INV-4: dir column is constant within each Merkle block
    INV-5: sib columns are constant within each Merkle block
    INV-6: bit-decomposition columns are boolean on every active row
    INV-7: bit decomposition at row 0 matches v in cols COL_V (sum of b[i]*2^i)
    INV-8: bit-out decomposition at row 0 matches v_out
    INV-9: bit columns are constant across all active rows (the witness columns)
    INV-10: bit_out columns are constant across all active rows
    INV-11: cols COL_SK, COL_R, COL_V match expected (we know what should be there)
    INV-12: cols COL_SK_OUT, COL_R_OUT, COL_V_OUT match expected
    INV-13: cols COL_DIR matches expected_dir_bits per Merkle block
    INV-14: cols COL_SIB_START..END matches expected_siblings per Merkle block
    INV-15: block-boundary continuity — state[4..8] at row 7 (leaf digest)
            equals row 8's state[4..8] OR state[8..12] depending on dir bit
            (for the first Merkle block's first row)
    INV-16: row-0 state capacity has correct preimage-init shape:
            state[0]=3, state[1..4]=0, state[4..7]=(sk, r, v), state[7..]=0
    INV-17: padding rows (>= ACTIVE_ROWS) are exact copies of the last active row

    The Rescue-Prime ROUND CORRECTNESS is NOT checked — that's the
    one thing we genuinely trust to Rust because reimplementing it
    in Python would itself be a major source of bugs.
    """
    violations: List[InvariantViolation] = []

    def v(inv: str, detail: str) -> None:
        violations.append(InvariantViolation(invariant=inv, detail=detail))

    P = q.field_modulus()

    # INV-1 + INV-11
    for row_idx in range(_ACTIVE_ROWS):
        if trace[row_idx][COL_SK] != expected_sk:
            v("INV-1/INV-11", f"col SK at row {row_idx}: {trace[row_idx][COL_SK]} != {expected_sk}")
            break
    for row_idx in range(_ACTIVE_ROWS):
        if trace[row_idx][COL_R] != expected_r:
            v("INV-1/INV-11", f"col R at row {row_idx}: {trace[row_idx][COL_R]} != {expected_r}")
            break
    for row_idx in range(_ACTIVE_ROWS):
        if trace[row_idx][COL_V] != expected_v:
            v("INV-1/INV-11", f"col V at row {row_idx}: {trace[row_idx][COL_V]} != {expected_v}")
            break

    # INV-2 + INV-12
    for row_idx in range(_ACTIVE_ROWS):
        if trace[row_idx][COL_SK_OUT] != expected_sk_out:
            v("INV-2/INV-12", f"col SK_OUT at row {row_idx}: {trace[row_idx][COL_SK_OUT]} != {expected_sk_out}")
            break
    for row_idx in range(_ACTIVE_ROWS):
        if trace[row_idx][COL_R_OUT] != expected_r_out:
            v("INV-2/INV-12", f"col R_OUT at row {row_idx}: {trace[row_idx][COL_R_OUT]} != {expected_r_out}")
            break
    for row_idx in range(_ACTIVE_ROWS):
        if trace[row_idx][COL_V_OUT] != expected_v_out:
            v("INV-2/INV-12", f"col V_OUT at row {row_idx}: {trace[row_idx][COL_V_OUT]} != {expected_v_out}")
            break

    # INV-3: dir boolean
    for row_idx in range(_ACTIVE_ROWS):
        d = trace[row_idx][COL_DIR]
        if d not in (0, 1):
            v("INV-3", f"dir at row {row_idx} = {d}, not boolean")
            break

    # INV-4: dir constant within each Merkle block
    for block_idx in range(FIRST_MERKLE_BLOCK, LAST_MERKLE_BLOCK + 1):
        start = block_idx * _ROWS_PER_BLOCK
        ref = trace[start][COL_DIR]
        for row_idx in range(start, start + _ROWS_PER_BLOCK):
            if trace[row_idx][COL_DIR] != ref:
                v("INV-4", f"dir not constant in block {block_idx} (row {row_idx} differs)")
                break

    # INV-5: sib constant within each Merkle block
    for block_idx in range(FIRST_MERKLE_BLOCK, LAST_MERKLE_BLOCK + 1):
        start = block_idx * _ROWS_PER_BLOCK
        ref = tuple(trace[start][COL_SIB_START:COL_SIB_END])
        for row_idx in range(start, start + _ROWS_PER_BLOCK):
            obs = tuple(trace[row_idx][COL_SIB_START:COL_SIB_END])
            if obs != ref:
                v("INV-5", f"sib not constant in block {block_idx} (row {row_idx} differs)")
                break

    # INV-13: dir matches expected per Merkle block
    for level in range(_MERKLE_DEPTH):
        block_idx = level + 1
        start = block_idx * _ROWS_PER_BLOCK
        observed = trace[start][COL_DIR]
        exp = 1 if expected_dir_bits[level] else 0
        if observed != exp:
            v("INV-13", f"dir at block {block_idx} (level {level}) = {observed}, expected {exp}")

    # INV-14: sib matches expected per Merkle block
    for level in range(_MERKLE_DEPTH):
        block_idx = level + 1
        start = block_idx * _ROWS_PER_BLOCK
        observed = tuple(trace[start][COL_SIB_START:COL_SIB_END])
        exp = expected_siblings[level]
        if observed != exp:
            v("INV-14", f"sib at block {block_idx} (level {level}) = {observed}, expected {exp}")

    # INV-6: bit columns boolean
    for row_idx in range(_ACTIVE_ROWS):
        for b in range(NUM_VALUE_BITS):
            bit = trace[row_idx][COL_BIT_START + b]
            if bit not in (0, 1):
                v("INV-6", f"bit[{b}] at row {row_idx} = {bit}, not boolean")
                break
        else:
            continue
        break

    # INV-6 (out side)
    for row_idx in range(_ACTIVE_ROWS):
        for b in range(NUM_VALUE_BITS):
            bit = trace[row_idx][COL_BIT_OUT_START + b]
            if bit not in (0, 1):
                v("INV-6", f"bit_out[{b}] at row {row_idx} = {bit}, not boolean")
                break
        else:
            continue
        break

    # INV-7: bit decomposition at row 0 matches v
    reconstructed_v = sum(
        trace[0][COL_BIT_START + b] * (1 << b) for b in range(NUM_VALUE_BITS)
    )
    if reconstructed_v != expected_v:
        v("INV-7", f"reconstructed v from bits = {reconstructed_v}, expected {expected_v}")

    # INV-8: bit_out decomposition at row 0 matches v_out
    reconstructed_v_out = sum(
        trace[0][COL_BIT_OUT_START + b] * (1 << b) for b in range(NUM_VALUE_BITS)
    )
    if reconstructed_v_out != expected_v_out:
        v("INV-8", f"reconstructed v_out from bits = {reconstructed_v_out}, expected {expected_v_out}")

    # INV-9 + INV-10: bit columns constant across active trace
    for b in range(NUM_VALUE_BITS):
        ref = trace[0][COL_BIT_START + b]
        for row_idx in range(1, _ACTIVE_ROWS):
            if trace[row_idx][COL_BIT_START + b] != ref:
                v("INV-9", f"bit[{b}] not constant (row {row_idx} differs from row 0)")
                break

    for b in range(NUM_VALUE_BITS):
        ref = trace[0][COL_BIT_OUT_START + b]
        for row_idx in range(1, _ACTIVE_ROWS):
            if trace[row_idx][COL_BIT_OUT_START + b] != ref:
                v("INV-10", f"bit_out[{b}] not constant (row {row_idx} differs from row 0)")
                break

    # INV-16: row 0 state has preimage-init shape
    # state[0]=3 (length=3 for 3-element preimage), state[1..4]=0
    if trace[0][0] != 3:
        v("INV-16", f"row 0 state[0] = {trace[0][0]}, expected 3 (preimage length)")
    for i in range(1, 4):
        if trace[0][i] != 0:
            v("INV-16", f"row 0 state[{i}] = {trace[0][i]}, expected 0 (capacity init)")
    # state[4..7] should be (sk, r, v)
    if trace[0][4] != expected_sk:
        v("INV-16", f"row 0 state[4] (sk slot) = {trace[0][4]}, expected sk={expected_sk}")
    if trace[0][5] != expected_r:
        v("INV-16", f"row 0 state[5] (r slot) = {trace[0][5]}, expected r={expected_r}")
    if trace[0][6] != expected_v:
        v("INV-16", f"row 0 state[6] (v slot) = {trace[0][6]}, expected v={expected_v}")
    for i in range(7, 12):
        if trace[0][i] != 0:
            v("INV-16", f"row 0 state[{i}] = {trace[0][i]}, expected 0 (rate-init)")

    # INV-17: padding rows (>= _ACTIVE_ROWS) are exact copies of last active row
    if _ACTIVE_ROWS < _LENGTH:
        last_active = trace[_ACTIVE_ROWS - 1]
        for row_idx in range(_ACTIVE_ROWS, _LENGTH):
            if trace[row_idx] != last_active:
                # Find first differing column for diagnostics
                for col_idx in range(_WIDTH):
                    if trace[row_idx][col_idx] != last_active[col_idx]:
                        v("INV-17",
                          f"padding row {row_idx} differs from last active row at col {col_idx}")
                        break
                break

    return violations


# ---------------------------------------------------------------------------
# Phase 2: Independent round-function re-execution (the strongest check)
# ---------------------------------------------------------------------------

def validate_trace_round_function(trace: List[List[int]]) -> List[InvariantViolation]:
    """Re-execute every Rescue-Prime round on every active block in Python
    and verify the trace's state columns match.

    This is the **strongest** soundness check we do in Phase 2. For
    each of the 23 active hash blocks (1 leaf + 20 Merkle + 1
    nullifier + 1 output_leaf), we:
      1. Read row `block * 8` (row 0 of the block) from the trace's
         state columns (0..12) — this is the "initial state" of the
         block
      2. Run apply_round 7 times in Python starting from that state
      3. Compare each post-round state against the trace's state
         columns at rows `block * 8 + 1` through `block * 8 + 7`

    If ANY row in ANY block disagrees, that's a Phase-2 finding:
    either the trace builder is not actually computing Rescue-Prime
    rounds correctly, or our Python implementation of the round
    function disagrees with Winterfell's. (The earlier `apply_round`
    spot-check via `hash_leaf` should have caught the second case.)

    Notes on scope:
      * The CHECK uses the state columns (0..12) only. The witness
        columns (12..151) are not re-derived here — they're checked
        by validate_trace_structural_invariants.
      * Padding rows (>= ACTIVE_ROWS) are NOT round-checked because
        they're exact copies of the last active row by INV-17.
    """
    from qchain.crypto.rescue_prime_ref import apply_round, STATE_WIDTH as _SW

    violations: List[InvariantViolation] = []

    def report(detail: str) -> None:
        violations.append(InvariantViolation(invariant="ROUND-FN", detail=detail))

    assert _SW == COL_STATE_END - COL_STATE_START, \
        f"state width mismatch: rescue={_SW}, m86={COL_STATE_END - COL_STATE_START}"

    for block_idx in range(_NUM_BLOCKS):
        block_start_row = block_idx * _ROWS_PER_BLOCK
        # Read the block's initial state (row 0 of block) from state cols
        state = list(trace[block_start_row][COL_STATE_START:COL_STATE_END])
        # Re-execute each round and check the matching post-round trace row
        for round_idx in range(_ROWS_PER_BLOCK - 1):
            expected = apply_round(state, round_idx)
            row_idx = block_start_row + round_idx + 1
            observed = list(trace[row_idx][COL_STATE_START:COL_STATE_END])
            if expected != observed:
                # Identify the FIRST differing column for diagnostics
                for col in range(_SW):
                    if expected[col] != observed[col]:
                        report(
                            f"block {block_idx} round {round_idx}: "
                            f"row {row_idx} state[{col}] = {observed[col]}, "
                            f"expected {expected[col]} from Python apply_round"
                        )
                        break
                else:
                    report(
                        f"block {block_idx} round {round_idx}: "
                        f"row {row_idx} state differs from Python apply_round"
                    )
                # Stop after first mismatch in this block — subsequent rows
                # would be confusing diagnostics
                break
            state = expected

    return violations


def validate_trace_block_boundaries(trace: List[List[int]]) -> List[InvariantViolation]:
    """Check that each block's last-row digest (state[4..8] at row 7) is
    used correctly as input to the next block.

    Specifically:
      * Leaf block (0): output state[4..8] at row 7 → enters Merkle block 1
      * Merkle block N (1..MERKLE_DEPTH): output → input of Merkle block N+1
        (placed in state[4..8] if dir=0, state[8..12] if dir=1)
      * Last Merkle block (MERKLE_DEPTH): output IS the root (no successor input)
      * Nullifier block (MERKLE_DEPTH+1): preimage-init from (sk+1, r, v),
        independent of previous block
      * Output leaf block (MERKLE_DEPTH+2): preimage-init from
        (sk_out, r_out, v_out), independent of previous block

    The CRITICAL claim being checked here: the Merkle path is genuinely
    chained, not freely-floating. If the trace builder accidentally
    used (say) zero as input to block 2 instead of block 1's output,
    that would slip past INV-1..INV-17 but be caught here.

    NOTE: this is currently a subset check — we don't enforce that
    the nullifier block's row 0 is preimage-init from (sk+1, r, v)
    here because INV-16 checks preimage-init for block 0 already.
    Extending to all preimage blocks is straightforward future work.
    """
    violations: List[InvariantViolation] = []

    def report(detail: str) -> None:
        violations.append(InvariantViolation(invariant="BLOCK-BOUNDARY", detail=detail))

    # Leaf block output → Merkle block 1 input
    leaf_output = tuple(trace[LEAF_LAST_ROW][4:8])  # state[4..8]
    # Merkle block 1 starts at row 8. Its initial state is state[4..12].
    # Direction bit at row 8 tells us if leaf_output is "current" (left)
    # or the sibling is "left".
    block1_start = _ROWS_PER_BLOCK  # row 8
    dir_bit = trace[block1_start][COL_DIR]
    sibling = tuple(trace[block1_start][COL_SIB_START:COL_SIB_END])
    # State at row 8 should be [8, 0, 0, 0, left, right] where:
    #   if dir==0: left=leaf_output, right=sibling
    #   if dir==1: left=sibling, right=leaf_output
    expected_left = sibling if dir_bit == 1 else leaf_output
    expected_right = leaf_output if dir_bit == 1 else sibling
    observed_left = tuple(trace[block1_start][4:8])
    observed_right = tuple(trace[block1_start][8:12])
    if observed_left != expected_left:
        report(
            f"Merkle block 1 (row {block1_start}) input state[4..8]: "
            f"observed {observed_left}, expected {expected_left} "
            f"(dir={dir_bit}, leaf_output={leaf_output}, sibling={sibling})"
        )
    if observed_right != expected_right:
        report(
            f"Merkle block 1 (row {block1_start}) input state[8..12]: "
            f"observed {observed_right}, expected {expected_right}"
        )
    # capacity check: state[0]=8 (length=8 for 8-element merge preimage)
    if trace[block1_start][0] != 8:
        report(f"Merkle block 1 row {block1_start} state[0] = {trace[block1_start][0]}, expected 8")

    # Chain through all Merkle blocks
    for block_idx in range(FIRST_MERKLE_BLOCK, LAST_MERKLE_BLOCK):
        # Block N's output (last-row state[4..8]) feeds block N+1's input
        block_last_row = (block_idx + 1) * _ROWS_PER_BLOCK - 1
        block_output = tuple(trace[block_last_row][4:8])
        next_start = (block_idx + 1) * _ROWS_PER_BLOCK
        next_dir = trace[next_start][COL_DIR]
        next_sib = tuple(trace[next_start][COL_SIB_START:COL_SIB_END])
        expected_left = next_sib if next_dir == 1 else block_output
        expected_right = block_output if next_dir == 1 else next_sib
        observed_left = tuple(trace[next_start][4:8])
        observed_right = tuple(trace[next_start][8:12])
        if observed_left != expected_left:
            report(
                f"Merkle chain broken at block {block_idx}→{block_idx+1}: "
                f"row {next_start} state[4..8] = {observed_left}, "
                f"expected {expected_left} (dir={next_dir})"
            )
        if observed_right != expected_right:
            report(
                f"Merkle chain broken at block {block_idx}→{block_idx+1}: "
                f"row {next_start} state[8..12] = {observed_right}, "
                f"expected {expected_right}"
            )

    # Nullifier block: preimage init for (sk+1, r, v)
    null_start = NULLIFIER_BLOCK * _ROWS_PER_BLOCK
    if trace[null_start][0] != 3:
        report(f"nullifier block row {null_start} state[0] = {trace[null_start][0]}, expected 3 (preimage)")
    sk = trace[null_start][COL_SK]
    r = trace[null_start][COL_R]
    v = trace[null_start][COL_V]
    expected_sk_plus_1 = (sk + 1) % q.field_modulus()
    if trace[null_start][4] != expected_sk_plus_1:
        report(
            f"nullifier block row {null_start} state[4] = {trace[null_start][4]}, "
            f"expected sk+1 = {expected_sk_plus_1}"
        )
    if trace[null_start][5] != r:
        report(f"nullifier block row {null_start} state[5] = {trace[null_start][5]}, expected r = {r}")
    if trace[null_start][6] != v:
        report(f"nullifier block row {null_start} state[6] = {trace[null_start][6]}, expected v = {v}")

    # Output leaf block: preimage init for (sk_out, r_out, v_out)
    out_start = OUTPUT_LEAF_BLOCK * _ROWS_PER_BLOCK
    if trace[out_start][0] != 3:
        report(f"output block row {out_start} state[0] = {trace[out_start][0]}, expected 3 (preimage)")
    sk_out = trace[out_start][COL_SK_OUT]
    r_out = trace[out_start][COL_R_OUT]
    v_out = trace[out_start][COL_V_OUT]
    if trace[out_start][4] != sk_out:
        report(f"output block row {out_start} state[4] = {trace[out_start][4]}, expected sk_out = {sk_out}")
    if trace[out_start][5] != r_out:
        report(f"output block row {out_start} state[5] = {trace[out_start][5]}, expected r_out = {r_out}")
    if trace[out_start][6] != v_out:
        report(f"output block row {out_start} state[6] = {trace[out_start][6]}, expected v_out = {v_out}")

    return violations
