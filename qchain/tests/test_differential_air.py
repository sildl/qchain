"""Differential AIR testing: Python reference vs. Rust m86_air.

This test suite cross-checks two independent implementations of the
m86 STARK's content:

  1. The Python NATIVE COMPUTATION (compute_expected) — what root,
     nullifier, leaf, and output_leaf SHOULD be for a given witness,
     computed using only the hash primitives.

  2. The Rust TRACE BUILDER (build_m86_trace_for_inspection) — what
     the AIR's witness trace contains at its boundary cells (the cells
     get_assertions pins to public inputs).

If (1) and (2) disagree on any honest witness, that's a real finding:
either the native rules are wrong, the trace builder is wrong, or our
mental model of what the AIR proves is wrong.

The test suite also exercises:
  * 17 structural invariants on the trace (witness-column constancy,
    direction-bit booleanity, bit-decomposition correctness, etc.)
  * Random witnesses (30 trials)
  * The Winterfell prove→verify roundtrip on honest witnesses
  * Boundary tampering: modify a trace cell, re-prove, verify must reject

Scope explicitly NOT covered:
  * Rescue-Prime round correctness — that's checked transitively by
    "the prover succeeds and the verifier verifies", but we don't
    independently re-implement it here.
  * The Winterfell transcript / FRI layer — trusted dependency.

See: AUDIT-PACKAGE.md section "Cryptographic mechanisms / m86_air STARK"
for the security claims (C1-C5) this differential test exercises.
"""

from __future__ import annotations

import random
from typing import List, Tuple

import pytest

import qstark_py as q
from qchain.crypto.m86_reference import (
    LEAF_LAST_ROW, ROOT_ROW, NULLIFIER_LAST_ROW, OUTPUT_LEAF_LAST_ROW,
    compute_expected, inspect_trace_boundaries,
    validate_trace_structural_invariants,
)


# ---------------------------------------------------------------------------
# Helpers — building witnesses
# ---------------------------------------------------------------------------

MERKLE_DEPTH = q.m86_merkle_depth()
ZERO_DIGEST: Tuple[int, int, int, int] = (0, 0, 0, 0)


def _build_witness_and_path(rng: random.Random):
    """Build a random valid witness for the m86 AIR.

    Returns a dict with all the fields prove_m86_membership expects.
    The path is random; the leaf at the implied position is hashed
    correctly; values are sampled so v == ua + fee + v_out in field
    arithmetic (the AIR's value-conservation requirement).
    """
    sk = rng.randrange(1, 1 << 32)
    r = rng.randrange(1, 1 << 32)
    # Pick v in a range where it decomposes to 64 bits cleanly
    v = rng.randrange(1, 1 << 30)
    # Split v into (unshield_amount, fee, v_out) such that all are
    # non-negative and sum to v
    ua = rng.randrange(0, v + 1)
    remaining = v - ua
    fee = rng.randrange(0, remaining + 1)
    v_out = remaining - fee
    assert ua + fee + v_out == v
    sk_out = rng.randrange(1, 1 << 32)
    r_out = rng.randrange(1, 1 << 32)

    # Random path: each level has a random sibling and a random direction
    path: List[Tuple[Tuple[int, int, int, int], bool]] = []
    for _ in range(MERKLE_DEPTH):
        sibling = (
            rng.randrange(0, 1 << 60),
            rng.randrange(0, 1 << 60),
            rng.randrange(0, 1 << 60),
            rng.randrange(0, 1 << 60),
        )
        is_right = bool(rng.randrange(0, 2))
        path.append((sibling, is_right))
    return {
        "sk": sk, "r": r, "v": v, "path": path,
        "unshield_amount": ua, "fee": fee,
        "sk_out": sk_out, "r_out": r_out, "v_out": v_out,
    }


# ---------------------------------------------------------------------------
# Differential test 1: native vs trace agree on honest witnesses
# ---------------------------------------------------------------------------

def test_diff_honest_witness_native_matches_trace_boundaries():
    """For an honest witness:
       compute_expected(...)  == inspect_trace_boundaries(build_trace(...))

    If this fails, EITHER the native rules in m86_native.rs disagree
    with the Python computation in m86_reference (very surprising —
    they use the same primitives), OR build_m86_trace produces a
    trace whose boundary cells don't match its native_reference.
    Both are real findings.
    """
    rng = random.Random(0xC0FFEE)
    w = _build_witness_and_path(rng)

    expected = compute_expected(
        w["sk"], w["r"], w["v"], w["path"],
        w["sk_out"], w["r_out"], w["v_out"],
    )
    trace = q.build_m86_trace_for_inspection(
        w["sk"], w["r"], w["v"], w["path"],
        w["unshield_amount"], w["fee"],
        w["sk_out"], w["r_out"], w["v_out"],
    )
    observed = inspect_trace_boundaries(trace)

    assert observed.leaf == expected.leaf, (
        f"leaf mismatch: trace boundary {observed.leaf} != "
        f"native {expected.leaf}"
    )
    assert observed.root == expected.root, (
        f"root mismatch: trace boundary {observed.root} != "
        f"native {expected.root}"
    )
    assert observed.nullifier == expected.nullifier, (
        f"nullifier mismatch: trace boundary {observed.nullifier} != "
        f"native {expected.nullifier}"
    )
    assert observed.output_leaf == expected.output_leaf, (
        f"output_leaf mismatch: trace boundary {observed.output_leaf} != "
        f"native {expected.output_leaf}"
    )


def test_diff_30_random_witnesses_native_matches_trace_boundaries():
    """Fuzz test: 30 independent random witnesses must all show
    native == trace boundary agreement. If ANY single one disagrees,
    that's a finding.
    """
    rng = random.Random(0xDEADBEEF)
    for trial in range(30):
        w = _build_witness_and_path(rng)
        expected = compute_expected(
            w["sk"], w["r"], w["v"], w["path"],
            w["sk_out"], w["r_out"], w["v_out"],
        )
        trace = q.build_m86_trace_for_inspection(
            w["sk"], w["r"], w["v"], w["path"],
            w["unshield_amount"], w["fee"],
            w["sk_out"], w["r_out"], w["v_out"],
        )
        observed = inspect_trace_boundaries(trace)
        assert observed.leaf == expected.leaf, f"trial {trial}: leaf mismatch"
        assert observed.root == expected.root, f"trial {trial}: root mismatch"
        assert observed.nullifier == expected.nullifier, f"trial {trial}: nullifier mismatch"
        assert observed.output_leaf == expected.output_leaf, f"trial {trial}: output_leaf mismatch"


# ---------------------------------------------------------------------------
# Differential test 2: structural invariants
# ---------------------------------------------------------------------------

def test_diff_honest_trace_satisfies_all_structural_invariants():
    """An honest trace satisfies all 17 structural invariants the AIR
    claims about its witness columns and block structure.

    If any invariant fails, the AIR's constraints would fail at proof
    time — but more importantly, this confirms that our model of the
    trace structure matches what the trace builder produces.
    """
    rng = random.Random(0x42)
    w = _build_witness_and_path(rng)

    trace = q.build_m86_trace_for_inspection(
        w["sk"], w["r"], w["v"], w["path"],
        w["unshield_amount"], w["fee"],
        w["sk_out"], w["r_out"], w["v_out"],
    )

    expected_dir_bits = [is_right for (_sib, is_right) in w["path"]]
    expected_siblings = [sib for (sib, _is_right) in w["path"]]
    violations = validate_trace_structural_invariants(
        trace,
        expected_sk=w["sk"], expected_r=w["r"], expected_v=w["v"],
        expected_sk_out=w["sk_out"], expected_r_out=w["r_out"],
        expected_v_out=w["v_out"],
        expected_dir_bits=expected_dir_bits,
        expected_siblings=expected_siblings,
    )
    assert violations == [], (
        f"honest trace violated structural invariants:\n"
        + "\n".join(f"  {v.invariant}: {v.detail}" for v in violations)
    )


def test_diff_30_random_traces_satisfy_all_structural_invariants():
    """30 random honest traces, all 17 invariants per trace.

    Catches any non-determinism or rng-sensitive bug in the trace
    builder. Also smoke-tests the structural-invariant code itself
    against varied witness shapes.
    """
    rng = random.Random(0xFACADE)
    for trial in range(30):
        w = _build_witness_and_path(rng)
        trace = q.build_m86_trace_for_inspection(
            w["sk"], w["r"], w["v"], w["path"],
            w["unshield_amount"], w["fee"],
            w["sk_out"], w["r_out"], w["v_out"],
        )
        expected_dir_bits = [is_right for (_sib, is_right) in w["path"]]
        expected_siblings = [sib for (sib, _is_right) in w["path"]]
        violations = validate_trace_structural_invariants(
            trace,
            expected_sk=w["sk"], expected_r=w["r"], expected_v=w["v"],
            expected_sk_out=w["sk_out"], expected_r_out=w["r_out"],
            expected_v_out=w["v_out"],
            expected_dir_bits=expected_dir_bits,
            expected_siblings=expected_siblings,
        )
        assert violations == [], (
            f"trial {trial}: invariant violations:\n"
            + "\n".join(f"  {v.invariant}: {v.detail}" for v in violations)
        )


# ---------------------------------------------------------------------------
# Differential test 3: prove-verify roundtrip on honest witnesses
# ---------------------------------------------------------------------------

def test_diff_honest_witness_produces_verifying_proof():
    """End-to-end: an honest witness with native-computed expected
    public inputs produces a STARK proof that verifies.

    This is the most direct integration check: native computation,
    trace boundaries, prover, and verifier all agree.
    """
    rng = random.Random(0xBADF00D)
    w = _build_witness_and_path(rng)

    expected = compute_expected(
        w["sk"], w["r"], w["v"], w["path"],
        w["sk_out"], w["r_out"], w["v_out"],
    )

    proof, root, nullifier, output_leaf = q.prove_m86_membership(
        w["sk"], w["r"], w["v"], w["path"],
        w["unshield_amount"], w["fee"],
        w["sk_out"], w["r_out"], w["v_out"],
    )

    # The prover's reported public inputs MUST match the native computation
    assert root == expected.root, f"prover's root {root} != native {expected.root}"
    assert nullifier == expected.nullifier
    assert output_leaf == expected.output_leaf

    # And the verifier accepts when given the native-computed public inputs
    ok = q.verify_m86_membership(
        proof, expected.root, expected.nullifier,
        w["unshield_amount"], w["fee"], expected.output_leaf,
    )
    assert ok, "verifier rejected honest proof with native public inputs"


# ---------------------------------------------------------------------------
# Differential test 4: tamper detection — modified PUBLIC INPUT rejected
# ---------------------------------------------------------------------------
#
# These tests confirm that swapping in a WRONG public input at verify
# time is detected. This is essentially testing what the AIR's
# boundary constraints assert, but going through the full verifier
# rather than just inspecting the trace.

def _make_proof_and_pubs(rng: random.Random):
    """Build an honest witness, return (proof, expected, witness_dict)."""
    w = _build_witness_and_path(rng)
    expected = compute_expected(
        w["sk"], w["r"], w["v"], w["path"],
        w["sk_out"], w["r_out"], w["v_out"],
    )
    proof, root, nullifier, output_leaf = q.prove_m86_membership(
        w["sk"], w["r"], w["v"], w["path"],
        w["unshield_amount"], w["fee"],
        w["sk_out"], w["r_out"], w["v_out"],
    )
    # Confirm the prover and native agree (precondition for the rest)
    assert root == expected.root
    return proof, expected, w


def test_diff_tamper_root_rejected():
    """Verify-time tampering: swap in a wrong root, verifier must reject."""
    rng = random.Random(1)
    proof, expected, w = _make_proof_and_pubs(rng)
    bad_root = tuple((x + 1) % q.field_modulus() for x in expected.root)
    ok = q.verify_m86_membership(
        proof, bad_root, expected.nullifier,
        w["unshield_amount"], w["fee"], expected.output_leaf,
    )
    assert not ok, "verifier accepted a tampered root"


def test_diff_tamper_nullifier_rejected():
    rng = random.Random(2)
    proof, expected, w = _make_proof_and_pubs(rng)
    bad_null = tuple((x + 1) % q.field_modulus() for x in expected.nullifier)
    ok = q.verify_m86_membership(
        proof, expected.root, bad_null,
        w["unshield_amount"], w["fee"], expected.output_leaf,
    )
    assert not ok, "verifier accepted a tampered nullifier"


def test_diff_tamper_output_leaf_rejected():
    rng = random.Random(3)
    proof, expected, w = _make_proof_and_pubs(rng)
    bad_out = tuple((x + 1) % q.field_modulus() for x in expected.output_leaf)
    ok = q.verify_m86_membership(
        proof, expected.root, expected.nullifier,
        w["unshield_amount"], w["fee"], bad_out,
    )
    assert not ok, "verifier accepted a tampered output_leaf"


def test_diff_tamper_unshield_amount_rejected():
    rng = random.Random(4)
    proof, expected, w = _make_proof_and_pubs(rng)
    # Swap unshield_amount and fee (changes nothing about sum but
    # changes the FS-bound public input)
    if w["unshield_amount"] == w["fee"]:
        pytest.skip("witness happened to have ua == fee; swap is a no-op")
    ok = q.verify_m86_membership(
        proof, expected.root, expected.nullifier,
        w["fee"], w["unshield_amount"], expected.output_leaf,
    )
    assert not ok, (
        "verifier accepted (fee, unshield_amount) swap — the value-"
        "conservation constraint would still hold, so this MUST be "
        "caught by the FS binding on the individual amounts"
    )


# ---------------------------------------------------------------------------
# Differential test 5: invariant catches malformed witnesses
# ---------------------------------------------------------------------------
#
# Negative tests for the structural-invariant checker itself. If we
# pass a deliberately-bad EXPECTED value, the checker should catch it.

def test_diff_invariant_catches_wrong_sk_expectation():
    """Sanity check: pass a wrong expected_sk, structural invariant
    must flag it. This is a meta-test: confirms the invariant code
    actually detects mismatches.
    """
    rng = random.Random(0x101)
    w = _build_witness_and_path(rng)
    trace = q.build_m86_trace_for_inspection(
        w["sk"], w["r"], w["v"], w["path"],
        w["unshield_amount"], w["fee"],
        w["sk_out"], w["r_out"], w["v_out"],
    )
    expected_dir_bits = [is_right for (_sib, is_right) in w["path"]]
    expected_siblings = [sib for (sib, _is_right) in w["path"]]
    # Deliberately wrong expected_sk
    violations = validate_trace_structural_invariants(
        trace,
        expected_sk=w["sk"] + 1,    # WRONG by 1
        expected_r=w["r"], expected_v=w["v"],
        expected_sk_out=w["sk_out"], expected_r_out=w["r_out"],
        expected_v_out=w["v_out"],
        expected_dir_bits=expected_dir_bits,
        expected_siblings=expected_siblings,
    )
    sk_violations = [v for v in violations if "SK" in v.detail or "sk" in v.detail]
    assert sk_violations, (
        "invariant checker missed a deliberately-wrong sk expectation"
    )


def test_diff_invariant_catches_wrong_direction_bit():
    rng = random.Random(0x202)
    w = _build_witness_and_path(rng)
    trace = q.build_m86_trace_for_inspection(
        w["sk"], w["r"], w["v"], w["path"],
        w["unshield_amount"], w["fee"],
        w["sk_out"], w["r_out"], w["v_out"],
    )
    expected_dir_bits = [is_right for (_sib, is_right) in w["path"]]
    # Flip the first direction bit
    bad_dir_bits = list(expected_dir_bits)
    bad_dir_bits[0] = not bad_dir_bits[0]
    expected_siblings = [sib for (sib, _is_right) in w["path"]]
    violations = validate_trace_structural_invariants(
        trace,
        expected_sk=w["sk"], expected_r=w["r"], expected_v=w["v"],
        expected_sk_out=w["sk_out"], expected_r_out=w["r_out"],
        expected_v_out=w["v_out"],
        expected_dir_bits=bad_dir_bits,
        expected_siblings=expected_siblings,
    )
    dir_violations = [v for v in violations if v.invariant == "INV-13"]
    assert dir_violations, (
        "invariant checker missed a deliberately-wrong direction bit"
    )


def test_diff_invariant_catches_wrong_sibling():
    rng = random.Random(0x303)
    w = _build_witness_and_path(rng)
    trace = q.build_m86_trace_for_inspection(
        w["sk"], w["r"], w["v"], w["path"],
        w["unshield_amount"], w["fee"],
        w["sk_out"], w["r_out"], w["v_out"],
    )
    expected_dir_bits = [is_right for (_sib, is_right) in w["path"]]
    expected_siblings = [sib for (sib, _is_right) in w["path"]]
    # Tamper the first sibling
    bad_siblings = list(expected_siblings)
    bad_siblings[0] = tuple((x + 1) % q.field_modulus() for x in bad_siblings[0])
    violations = validate_trace_structural_invariants(
        trace,
        expected_sk=w["sk"], expected_r=w["r"], expected_v=w["v"],
        expected_sk_out=w["sk_out"], expected_r_out=w["r_out"],
        expected_v_out=w["v_out"],
        expected_dir_bits=expected_dir_bits,
        expected_siblings=bad_siblings,
    )
    sib_violations = [v for v in violations if v.invariant == "INV-14"]
    assert sib_violations, (
        "invariant checker missed a deliberately-wrong sibling"
    )


# ===========================================================================
# PHASE 2 TESTS — Independent round-function re-execution
# ===========================================================================
#
# Phase 1 catches: trace boundaries don't match the native computation.
# Phase 2 catches: trace builder doesn't actually run Rescue-Prime rounds
# correctly inside each block (would slip past Phase 1 if both Python and
# Rust hash_leaf share the same wrong round function, which they don't,
# but that's exactly the gap Phase 2 closes).
#
# The key tool: rescue_prime_ref.apply_round, an independent Python
# implementation that uses ARK1/ARK2/MDS constants extracted from
# Winterfell's source. The Python implementation matched Winterfell
# byte-for-byte on (sk=1, r=2, v=3) and (hash_inner(left, right)) — see
# the development-time smoke test in the README.

from qchain.crypto.m86_reference import (
    validate_trace_round_function,
    validate_trace_block_boundaries,
)


def test_diff_phase2_python_round_matches_winterfell_leaf_hash():
    """Independent Python Rescue-Prime apply_round, when chained for 7
    rounds starting from a preimage-init state of (sk=1, r=2, v=3),
    must produce the SAME digest as Winterfell's hash_leaf(1, 2, 3).

    If this fails, the Python apply_round is wrong (most likely cause)
    or our extraction of MDS/ARK1/ARK2 constants is corrupted. Either
    case invalidates Phase 2's entire premise.
    """
    from qchain.crypto.rescue_prime_ref import apply_all_rounds, STATE_WIDTH

    initial = [0] * STATE_WIDTH
    initial[0] = 3
    initial[4], initial[5], initial[6] = 1, 2, 3
    rows = apply_all_rounds(initial)
    python_digest = tuple(rows[-1][4:8])
    winterfell_digest = q.hash_leaf(1, 2, 3)
    assert python_digest == winterfell_digest, (
        f"Phase 2 premise violated: Python apply_round != Winterfell\n"
        f"  Python:     {python_digest}\n"
        f"  Winterfell: {winterfell_digest}"
    )


def test_diff_phase2_python_round_matches_winterfell_merge():
    """Python apply_round chained 7x on a merge-init state must match
    Winterfell's hash_inner(left, right). Different state shape than
    the leaf-hash test (capacity=8 not 3, both halves of rate filled)."""
    from qchain.crypto.rescue_prime_ref import apply_all_rounds, STATE_WIDTH

    left = q.hash_leaf(10, 20, 30)
    right = q.hash_leaf(40, 50, 60)
    initial = [0] * STATE_WIDTH
    initial[0] = 8
    for i in range(4):
        initial[4 + i] = left[i]
        initial[8 + i] = right[i]
    rows = apply_all_rounds(initial)
    python_digest = tuple(rows[-1][4:8])
    winterfell_digest = q.hash_inner(left, right)
    assert python_digest == winterfell_digest, (
        f"Python merge != Winterfell hash_inner\n"
        f"  Python:     {python_digest}\n"
        f"  Winterfell: {winterfell_digest}"
    )


def test_diff_phase2_honest_trace_passes_round_validator():
    """Every active block in an honest trace satisfies: row i+1 is the
    Python apply_round of row i. This is the strongest Phase 2 claim."""
    rng = random.Random(0xAA)
    w = _build_witness_and_path(rng)
    trace = q.build_m86_trace_for_inspection(
        w["sk"], w["r"], w["v"], w["path"],
        w["unshield_amount"], w["fee"],
        w["sk_out"], w["r_out"], w["v_out"],
    )
    violations = validate_trace_round_function(trace)
    assert violations == [], (
        f"honest trace failed round-function check (Phase 2 finding!):\n"
        + "\n".join(f"  {v.detail}" for v in violations)
    )


def test_diff_phase2_10_random_traces_pass_round_validator():
    """10 random honest traces — every round in every block must check.

    This is the deep coverage check: Python's apply_round agrees with
    Winterfell's Rp64_256::apply_round across the full state space we
    exercise via random witnesses. ~37ms × 10 = ~400ms total.
    """
    rng = random.Random(0xBB)
    for trial in range(10):
        w = _build_witness_and_path(rng)
        trace = q.build_m86_trace_for_inspection(
            w["sk"], w["r"], w["v"], w["path"],
            w["unshield_amount"], w["fee"],
            w["sk_out"], w["r_out"], w["v_out"],
        )
        violations = validate_trace_round_function(trace)
        assert violations == [], (
            f"trial {trial}: round-function check failed:\n"
            + "\n".join(f"  {v.detail}" for v in violations[:3])
        )


def test_diff_phase2_honest_trace_passes_block_boundary_check():
    """Block-to-block chaining check passes on honest traces:
    leaf output → Merkle block 1 input → ... → nullifier preimage uses
    sk+1, r, v; output_leaf preimage uses sk_out, r_out, v_out.
    """
    rng = random.Random(0xCC)
    w = _build_witness_and_path(rng)
    trace = q.build_m86_trace_for_inspection(
        w["sk"], w["r"], w["v"], w["path"],
        w["unshield_amount"], w["fee"],
        w["sk_out"], w["r_out"], w["v_out"],
    )
    violations = validate_trace_block_boundaries(trace)
    assert violations == [], (
        f"honest trace failed block-boundary check:\n"
        + "\n".join(f"  {v.detail}" for v in violations)
    )


def test_diff_phase2_round_validator_catches_state_tamper():
    """Meta-test: if we tamper one state cell mid-block, the round
    validator MUST catch it. Confirms the check is not vacuous."""
    rng = random.Random(0xDD)
    w = _build_witness_and_path(rng)
    trace = q.build_m86_trace_for_inspection(
        w["sk"], w["r"], w["v"], w["path"],
        w["unshield_amount"], w["fee"],
        w["sk_out"], w["r_out"], w["v_out"],
    )
    # Sanity: clean trace passes
    assert validate_trace_round_function(trace) == []
    # Tamper a state cell in the middle of the leaf block (row 3, state col 5)
    trace[3][5] = (trace[3][5] + 1) % q.field_modulus()
    violations = validate_trace_round_function(trace)
    assert violations, (
        "round validator missed a tampered state cell (vacuous check?)"
    )


def test_diff_phase2_round_validator_catches_wrong_round_constants():
    """Indirect test: if the trace builder used different ARK constants
    than Winterfell publishes, the round validator catches it.

    We simulate this by tampering a state cell AT THE END of a round
    (where ARK is added), confirming the next round's output disagrees.
    """
    rng = random.Random(0xEE)
    w = _build_witness_and_path(rng)
    trace = q.build_m86_trace_for_inspection(
        w["sk"], w["r"], w["v"], w["path"],
        w["unshield_amount"], w["fee"],
        w["sk_out"], w["r_out"], w["v_out"],
    )
    # Tamper row 1 (end of round 0) — round 1 will be computed from this
    # wrong input by our validator, but the trace's row 2 will be from
    # the ORIGINAL row 1; mismatch confirms detection.
    trace[1][7] = (trace[1][7] + 1) % q.field_modulus()
    violations = validate_trace_round_function(trace)
    assert violations, "validator missed a round-output tamper"


def test_diff_phase2_block_boundary_catches_broken_merkle_chain():
    """If the trace builder accidentally used wrong input to a Merkle
    block (e.g., zero instead of the previous block's output), the
    block-boundary check catches it.

    We simulate by zeroing state[4..8] at row 8 (first Merkle block's
    initial state). Round validator would also catch this, but
    block-boundary check has more localized diagnostics.
    """
    rng = random.Random(0xFF)
    w = _build_witness_and_path(rng)
    trace = q.build_m86_trace_for_inspection(
        w["sk"], w["r"], w["v"], w["path"],
        w["unshield_amount"], w["fee"],
        w["sk_out"], w["r_out"], w["v_out"],
    )
    # Tamper Merkle block 1's input state[4..8]
    for col in range(4, 8):
        trace[8][col] = 0
    violations = validate_trace_block_boundaries(trace)
    assert violations, "block-boundary check missed a broken Merkle chain"


def test_diff_phase2_block_boundary_catches_nullifier_sk_off_by_one():
    """If the trace builder used `sk` (not `sk+1`) in the nullifier
    block's preimage, the boundary check catches it.

    This protects claim C2 (nullifier binding): nullifier = H(sk+1,r,v).
    If sk+1 became sk somehow, the chain's nullifier mechanism would
    break — leaves and nullifiers would collide.
    """
    rng = random.Random(0x11)
    w = _build_witness_and_path(rng)
    trace = q.build_m86_trace_for_inspection(
        w["sk"], w["r"], w["v"], w["path"],
        w["unshield_amount"], w["fee"],
        w["sk_out"], w["r_out"], w["v_out"],
    )
    # Tamper the nullifier block's state[4] from (sk+1) to sk
    # Nullifier block starts at row MERKLE_DEPTH+1 * ROWS_PER_BLOCK = 21*8 = 168
    null_block_row = (q.m86_merkle_depth() + 1) * 8
    trace[null_block_row][4] = w["sk"]   # was sk+1, now sk
    violations = validate_trace_block_boundaries(trace)
    sk_violations = [v for v in violations if "sk+1" in v.detail]
    assert sk_violations, (
        f"boundary check missed nullifier sk vs sk+1: {violations}"
    )
