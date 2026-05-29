//! M8.2: Rescue-Prime hash AIR.
//!
//! Proves: "I know `x` such that `Rp64_256(x) = y`" where `Rp64_256` is
//! Winterfell's customized Rescue-Prime hash (used by Polygon Miden).
//!
//! ## Architecture
//!
//! Our trace is a 12-column table (one column per state element) with 8 rows.
//! - Row 0 = initial sponge state with the preimage in the rate
//! - Row 1 = state after round 0
//! - ...
//! - Row 7 = state after round 6 (the final state)
//! - The digest is rows[7][4..8]
//!
//! ## The transition constraint
//!
//! Rescue-XLIX one round is:
//!
//! ```text
//! A = sbox(S)              (componentwise S^7)
//! B = MDS * A
//! C = B + ARK1[round]
//! D = inv_sbox(C)          (componentwise C^(1/7))
//! E = MDS * D
//! S' = E + ARK2[round]
//! ```
//!
//! The naive AIR would require modeling `inv_sbox` as a polynomial — but that
//! would be degree 1/7 (impossible) or require 72 trace rows (expensive).
//! The standard trick: rearrange to eliminate `inv_sbox`:
//!
//! ```text
//! E = S' - ARK2[round]
//! D = INV_MDS * E
//! C = D^7         (inverting the inv_sbox)
//! C = B + ARK1[round]
//! B = C - ARK1[round]
//! B = MDS * A
//! A = S^7
//! ```
//!
//! Combining: `(INV_MDS * (S' - ARK2[round]))^7 == MDS * S^7 + ARK1[round]`
//!
//! This is a degree-7 polynomial constraint. We assert it componentwise (12
//! equations per transition). Winterfell's default config supports degree-7
//! constraints without field extension.

use winter_crypto::hashers::Rp64_256;
use winter_math::fields::f64::BaseElement;
use winter_math::FieldElement;

pub const STATE_WIDTH: usize = 12;
pub const NUM_ROUNDS: usize = 7;
pub const RATE_WIDTH: usize = 8;
pub const RATE_START: usize = 4;
pub const DIGEST_START: usize = 4;
pub const DIGEST_SIZE: usize = 4;

// Trace must be a power of 2. We need NUM_ROUNDS+1 = 8 state-rows. Exactly fits.
pub const TRACE_LEN: usize = 8;

/// Compute the initial sponge state for a single-block message of length `n`.
///
/// Matches `Rp64_256::hash_elements` for inputs that fit in one absorption
/// block (≤8 elements after the implicit length prefix). For M8.2 we restrict
/// preimages to this case; multi-block absorption is straightforward to add.
pub fn initial_state(preimage: &[BaseElement]) -> [BaseElement; STATE_WIDTH] {
    assert!(preimage.len() <= RATE_WIDTH, "preimage too long for single block");
    let mut state = [BaseElement::ZERO; STATE_WIDTH];
    // Winterfell's convention: number of elements goes in capacity slot 0
    // (NOT slot 3 — I was wrong earlier; let me verify against Rp64_256 in tests).
    // The exact convention is verified by the test
    // `hash_air_matches_rp64_256_for_one_element`.
    state[0] = BaseElement::new(preimage.len() as u64);
    for (i, &elt) in preimage.iter().enumerate() {
        state[RATE_START + i] = elt;
    }
    state
}

/// Build the full execution trace: 12 columns, 8 rows of state.
///
/// Computed by calling `Rp64_256::apply_round` directly — this is the
/// reference. Our AIR's transition constraint must agree with this.
pub fn build_trace(preimage: &[BaseElement]) -> Vec<[BaseElement; STATE_WIDTH]> {
    let mut state = initial_state(preimage);
    let mut rows = Vec::with_capacity(TRACE_LEN);
    rows.push(state);
    for round in 0..NUM_ROUNDS {
        Rp64_256::apply_round(&mut state, round);
        rows.push(state);
    }
    assert_eq!(rows.len(), TRACE_LEN);
    rows
}

/// Extract the digest from a completed trace.
pub fn digest_from_trace(rows: &[[BaseElement; STATE_WIDTH]]) -> [BaseElement; DIGEST_SIZE] {
    let last = rows.last().expect("non-empty trace");
    let mut digest = [BaseElement::ZERO; DIGEST_SIZE];
    for i in 0..DIGEST_SIZE {
        digest[i] = last[DIGEST_START + i];
    }
    digest
}

/// MDS multiplication, mirroring Winterfell's `mds_multiply` but operating
/// on a copy. Used for trace generation and (compile-time-friendly) for the
/// AIR's transition constraint evaluation.
pub fn mds_multiply(state: &[BaseElement; STATE_WIDTH]) -> [BaseElement; STATE_WIDTH] {
    let mut result = [BaseElement::ZERO; STATE_WIDTH];
    for i in 0..STATE_WIDTH {
        for j in 0..STATE_WIDTH {
            result[i] += Rp64_256::MDS[i][j] * state[j];
        }
    }
    result
}

/// INV_MDS multiplication: computes y = INV_MDS * x.
pub fn inv_mds_multiply(state: &[BaseElement; STATE_WIDTH]) -> [BaseElement; STATE_WIDTH] {
    let mut result = [BaseElement::ZERO; STATE_WIDTH];
    for i in 0..STATE_WIDTH {
        for j in 0..STATE_WIDTH {
            result[i] += Rp64_256::INV_MDS[i][j] * state[j];
        }
    }
    result
}

/// Componentwise S-box: x -> x^7.
pub fn apply_sbox(state: &mut [BaseElement; STATE_WIDTH]) {
    for s in state.iter_mut() {
        let s2 = s.square();
        let s4 = s2.square();
        *s = s4 * s2 * *s; // x^7 = x^4 * x^2 * x
    }
}

/// Verify our constraint equation matches the reference round.
///
/// Checks that for any state S and round r, the equation
///   `(INV_MDS * (apply_round(S, r) - ARK2[r]))^7 == MDS * S^7 + ARK1[r]`
/// holds componentwise. This is the constraint our AIR will enforce.
pub fn check_constraint_equation(s: &[BaseElement; STATE_WIDTH], round: usize) -> bool {
    let mut s_next = *s;
    Rp64_256::apply_round(&mut s_next, round);

    // RHS: MDS * S^7 + ARK1[round]
    let mut s_sbox = *s;
    apply_sbox(&mut s_sbox);
    let mds_s7 = mds_multiply(&s_sbox);
    let mut rhs = mds_s7;
    for i in 0..STATE_WIDTH {
        rhs[i] += Rp64_256::ARK1[round][i];
    }

    // LHS: (INV_MDS * (S' - ARK2[round]))^7
    let mut s_next_minus_ark2 = s_next;
    for i in 0..STATE_WIDTH {
        s_next_minus_ark2[i] -= Rp64_256::ARK2[round][i];
    }
    let mut d = inv_mds_multiply(&s_next_minus_ark2);
    apply_sbox(&mut d);

    d == rhs
}
