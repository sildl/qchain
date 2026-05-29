//! Python bindings for the qstark zk-STARK proof system.
//!
//! Exposes:
//!   * `hash_leaf(sk, r, value) -> tuple[int,int,int,int]`
//!   * `hash_inner(left, right) -> tuple[int,int,int,int]`
//!   * `prove_preimage(x) -> tuple[bytes, tuple[int,int,int,int]]`
//!   * `verify_preimage(proof, digest) -> bool`
//!   * `prove_membership(leaf, path) -> tuple[bytes, tuple[int,int,int,int]]`
//!   * `verify_membership(proof, root) -> bool`
//!
//! Field elements are passed as Python ints in [0, p) where
//! `p = 2^64 - 2^32 + 1` (the Goldilocks prime). Digests are tuples of 4 ints.

use pyo3::exceptions::{PyValueError, PyRuntimeError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyTuple};

use qstark::hash_air::anon_full::{
    prove_full_membership, verify_full_membership,
    FullMembershipInputs, FullMembershipWitness, MERKLE_DEPTH,
};
use qstark::hash_air::m86_air::{
    build_m86_trace, prove_m86, verify_m86, M86Inputs, M86Witness, M86_WIDTH,
};
use qstark::hash_air::m86_native::{M86_MERKLE_DEPTH, M86_TRACE_LEN, M86_ACTIVE_ROWS,
                                    M86_NUM_BLOCKS, ROWS_PER_BLOCK};
use qstark::hash_air::merkle::{hash_inner as native_hash_inner, hash_leaf as native_hash_leaf,
                               Digest4};
use qstark::hash_air::{prove_preimage as native_prove_preimage,
                       verify_preimage as native_verify_preimage, HashInputs};
use winter_math::fields::f64::BaseElement;
use winter_math::{FieldElement, StarkField};

// ---------------------------------------------------------------------------
// Type conversion helpers
// ---------------------------------------------------------------------------

/// Convert a Python int to a Goldilocks BaseElement, validating range.
fn py_int_to_field(x: u64) -> PyResult<BaseElement> {
    // BaseElement::new(x) automatically reduces mod p, but if x is greater
    // than p we'd silently change the value. Reject inputs that aren't
    // already canonical (in [0, p)).
    let modulus = BaseElement::MODULUS;
    if x >= modulus {
        return Err(PyValueError::new_err(format!(
            "field element {} is >= modulus {} ({})",
            x, modulus, "Goldilocks p = 2^64 - 2^32 + 1"
        )));
    }
    Ok(BaseElement::new(x))
}

/// Convert a digest tuple (4 ints) into Digest4.
fn tuple_to_digest(t: &PyTuple) -> PyResult<Digest4> {
    if t.len() != 4 {
        return Err(PyValueError::new_err(format!(
            "digest must be a tuple of 4 elements, got {}", t.len()
        )));
    }
    let mut d = [BaseElement::ZERO; 4];
    for i in 0..4 {
        let v: u64 = t.get_item(i)?.extract()?;
        d[i] = py_int_to_field(v)?;
    }
    Ok(d)
}

/// Convert a Digest4 to a Python int tuple.
fn digest_to_tuple(py: Python<'_>, d: Digest4) -> PyObject {
    PyTuple::new(py, d.iter().map(|x| x.as_int())).into()
}

// ---------------------------------------------------------------------------
// Hash helpers (callable from Python)
// ---------------------------------------------------------------------------

/// Hash a (sk, r, value) triple into a 4-element leaf digest.
///
/// Returns a tuple of 4 ints, each in [0, p).
#[pyfunction]
fn hash_leaf(py: Python<'_>, sk: u64, r: u64, value: u64) -> PyResult<PyObject> {
    let sk_f = py_int_to_field(sk)?;
    let r_f = py_int_to_field(r)?;
    let v_f = py_int_to_field(value)?;
    let d = native_hash_leaf(sk_f, r_f, v_f);
    Ok(digest_to_tuple(py, d))
}

/// Compute parent = Rp64_256::merge(left, right) for Merkle tree composition.
#[pyfunction]
fn hash_inner(py: Python<'_>, left: &PyTuple, right: &PyTuple) -> PyResult<PyObject> {
    let l = tuple_to_digest(left)?;
    let r = tuple_to_digest(right)?;
    Ok(digest_to_tuple(py, native_hash_inner(l, r)))
}

// ---------------------------------------------------------------------------
// M8.2: Preimage STARK
// ---------------------------------------------------------------------------

/// Prove "I know x such that Rp64_256(x) = y".
///
/// Returns (proof_bytes, y) where y is a 4-tuple. The verifier sees only y
/// and the proof bytes; the preimage x stays hidden.
#[pyfunction]
fn prove_preimage(py: Python<'_>, x: u64) -> PyResult<PyObject> {
    let preimage = py_int_to_field(x)?;
    let (bytes, pub_inputs) = native_prove_preimage(preimage)
        .map_err(|e| PyRuntimeError::new_err(format!("prove failed: {}", e)))?;
    let proof_obj: PyObject = PyBytes::new(py, &bytes).into();
    let digest_obj = digest_to_tuple(py, pub_inputs.digest);
    Ok(PyTuple::new(py, [proof_obj, digest_obj]).into())
}

/// Verify a preimage proof. Returns True if it verifies, False otherwise.
#[pyfunction]
fn verify_preimage(proof: &[u8], digest: &PyTuple) -> PyResult<bool> {
    let d = tuple_to_digest(digest)?;
    let inputs = HashInputs { digest: d };
    Ok(native_verify_preimage(proof, inputs).is_ok())
}

// ---------------------------------------------------------------------------
// M8.3 FULL: Multi-level Merkle membership STARK
// ---------------------------------------------------------------------------

/// Prove "I know (leaf, path) such that walking from leaf along path reaches root".
///
/// Arguments:
///   leaf:  digest tuple (4 ints)
///   path:  list of (sibling_tuple, direction_bit_bool) pairs of length MERKLE_DEPTH=4
///
/// Returns (proof_bytes, root_tuple).
#[pyfunction]
fn prove_membership(
    py: Python<'_>,
    leaf: &PyTuple,
    path: Vec<(&PyTuple, bool)>,
) -> PyResult<PyObject> {
    let leaf_d = tuple_to_digest(leaf)?;
    if path.len() != MERKLE_DEPTH {
        return Err(PyValueError::new_err(format!(
            "path must have {} elements (one per Merkle level), got {}",
            MERKLE_DEPTH, path.len()
        )));
    }
    let mut native_path = Vec::with_capacity(MERKLE_DEPTH);
    for (sib_tuple, is_right) in path {
        let sib_d = tuple_to_digest(sib_tuple)?;
        native_path.push((sib_d, is_right));
    }
    let witness = FullMembershipWitness { leaf: leaf_d, path: native_path };
    let (bytes, pub_inputs) = prove_full_membership(witness)
        .map_err(|e| PyRuntimeError::new_err(format!("prove failed: {}", e)))?;
    let proof_obj: PyObject = PyBytes::new(py, &bytes).into();
    let root_obj = digest_to_tuple(py, pub_inputs.root);
    Ok(PyTuple::new(py, [proof_obj, root_obj]).into())
}

/// Verify a Merkle membership proof.
#[pyfunction]
fn verify_membership(proof: &[u8], root: &PyTuple) -> PyResult<bool> {
    let r = tuple_to_digest(root)?;
    let inputs = FullMembershipInputs { root: r };
    Ok(verify_full_membership(proof, inputs).is_ok())
}

// ---------------------------------------------------------------------------
// M8.6: Nullifier-bound membership STARK
// ---------------------------------------------------------------------------

/// Prove M8.6: "I know (sk, r, v, path) such that:
///   1. leaf = Rp64_256(sk, r, v) is in the Merkle tree at root R, and
///   2. nullifier = Rp64_256(sk+1, r, v)."
///
/// Arguments:
///   sk:    field element (witness)
///   r:     field element (witness)
///   v:     field element (witness)
///   path:  list of (sibling_tuple, direction_bit_bool) pairs of length
///          MERKLE_DEPTH=4
///
/// Prove M8.6 (+ M8.8-A1 Gap A + M8.11 partial-spend) nullifier-bound membership.
///
/// Witness: (sk, r, v, path, unshield_amount, fee, sk_out, r_out, v_out)
/// Public:  (root, nullifier, unshield_amount, fee, output_leaf)
///
/// M8.11 invariants the prover must satisfy (build_m86_trace asserts):
///   - v.as_int() == unshield_amount + fee + v_out  (field arithmetic)
///   - v < 2^64 (canonical u64)
///   - v_out < 2^64 (canonical u64)
///
/// For a full-spend (no change), pass v_out=0 and random (sk_out, r_out).
/// A dummy output_leaf H(sk_out, r_out, 0) gets added to the pool, making
/// full spends indistinguishable from partial spends with tiny change values.
/// (Same design pattern as Zcash Sapling's dummy outputs.)
///
/// Returns (proof_bytes, root_tuple, nullifier_tuple, output_leaf_tuple).
/// The caller already knows unshield_amount, fee, and the v_out/sk_out/r_out
/// they passed in, so we don't return those.
#[pyfunction]
fn prove_m86_membership(
    py: Python<'_>,
    sk: u64,
    r: u64,
    v: u64,
    path: Vec<(&PyTuple, bool)>,
    unshield_amount: u64,
    fee: u64,
    sk_out: u64,
    r_out: u64,
    v_out: u64,
) -> PyResult<PyObject> {
    let sk_f = py_int_to_field(sk)?;
    let r_f = py_int_to_field(r)?;
    let v_f = py_int_to_field(v)?;
    let sk_out_f = py_int_to_field(sk_out)?;
    let r_out_f = py_int_to_field(r_out)?;
    let v_out_f = py_int_to_field(v_out)?;
    if path.len() != M86_MERKLE_DEPTH {
        return Err(PyValueError::new_err(format!(
            "path must have {} elements (one per Merkle level), got {}",
            M86_MERKLE_DEPTH, path.len()
        )));
    }
    // M8.11: cheap pre-check of the three-way value-conservation invariant.
    // build_m86_trace would assert this anyway; we surface a clean ValueError
    // instead of a Rust panic for Python callers.
    let expected_sum_field = py_int_to_field(unshield_amount)?
        + py_int_to_field(fee)?
        + v_out_f;
    if expected_sum_field != v_f {
        return Err(PyValueError::new_err(format!(
            "witness inconsistency: v ({}) != unshield_amount ({}) + fee ({}) + v_out ({}) \
             in field arithmetic",
            v, unshield_amount, fee, v_out
        )));
    }
    let mut native_path = Vec::with_capacity(M86_MERKLE_DEPTH);
    for (sib_tuple, is_right) in path {
        let sib_d = tuple_to_digest(sib_tuple)?;
        native_path.push((sib_d, is_right));
    }
    let witness = M86Witness {
        sk: sk_f, r: r_f, v: v_f, path: native_path,
        unshield_amount, fee,
        sk_out: sk_out_f, r_out: r_out_f, v_out: v_out_f,
    };
    let (bytes, pub_inputs) = prove_m86(witness)
        .map_err(|e| PyRuntimeError::new_err(format!("prove failed: {}", e)))?;
    let proof_obj: PyObject = PyBytes::new(py, &bytes).into();
    let root_obj = digest_to_tuple(py, pub_inputs.root);
    let null_obj = digest_to_tuple(py, pub_inputs.nullifier);
    let out_obj = digest_to_tuple(py, pub_inputs.output_leaf);
    Ok(PyTuple::new(py, [proof_obj, root_obj, null_obj, out_obj]).into())
}

/// Verify an M8.6 + M8.8-A1 + M8.11 nullifier-bound membership proof.
///
/// All five public inputs (root, nullifier, unshield_amount, fee, output_leaf)
/// are bound to the proof via Fiat-Shamir. Tampering with any of them — even
/// a swap of (amount, fee) preserving the sum — invalidates the proof.
#[pyfunction]
fn verify_m86_membership(
    proof: &[u8],
    root: &PyTuple,
    nullifier: &PyTuple,
    unshield_amount: u64,
    fee: u64,
    output_leaf: &PyTuple,
) -> PyResult<bool> {
    let r = tuple_to_digest(root)?;
    let n = tuple_to_digest(nullifier)?;
    let ol = tuple_to_digest(output_leaf)?;
    let inputs = M86Inputs {
        root: r, nullifier: n,
        unshield_amount, fee,
        output_leaf: ol,
    };
    Ok(verify_m86(proof, inputs).is_ok())
}

// ---------------------------------------------------------------------------
// Constants exposed to Python
// ---------------------------------------------------------------------------

/// Goldilocks prime modulus: 2^64 - 2^32 + 1.
#[pyfunction]
fn field_modulus() -> u64 {
    BaseElement::MODULUS
}

/// Merkle depth used by `prove_membership` / `verify_membership` (M8.3).
#[pyfunction]
fn merkle_depth() -> usize {
    MERKLE_DEPTH
}

/// Merkle depth used by `prove_m86_membership` / `verify_m86_membership` (M8.5/M8.6).
/// This is the value QChain's STARK-anon code should consult.
#[pyfunction]
fn m86_merkle_depth() -> usize {
    M86_MERKLE_DEPTH
}

/// Trace dimensions for the m86 AIR. Returns (width, length, active_rows, num_blocks, rows_per_block).
/// Used by differential-testing code to know what shape of trace to expect.
#[pyfunction]
fn m86_trace_dims() -> (usize, usize, usize, usize, usize) {
    (M86_WIDTH, M86_TRACE_LEN, M86_ACTIVE_ROWS, M86_NUM_BLOCKS, ROWS_PER_BLOCK)
}

/// Build the m86 trace from a witness and return it as a 2D list
/// (rows × columns) of Python ints.
///
/// This is for differential-testing only. Calling code can:
///   * Compare specific cells against independently-computed expected values
///   * Tamper with cells and re-prove to confirm tampered proofs are rejected
///   * Inspect block boundaries and constraint regions
///
/// The witness is structured identically to prove_m86_membership's inputs:
/// (sk, r, v, path, unshield_amount, fee, sk_out, r_out, v_out).
#[pyfunction]
fn build_m86_trace_for_inspection(
    py: Python<'_>,
    sk: u64,
    r: u64,
    v: u64,
    path: Vec<(&PyTuple, bool)>,
    unshield_amount: u64,
    fee: u64,
    sk_out: u64,
    r_out: u64,
    v_out: u64,
) -> PyResult<PyObject> {
    let sk_f = py_int_to_field(sk)?;
    let r_f = py_int_to_field(r)?;
    let v_f = py_int_to_field(v)?;
    let sk_out_f = py_int_to_field(sk_out)?;
    let r_out_f = py_int_to_field(r_out)?;
    let v_out_f = py_int_to_field(v_out)?;
    if path.len() != M86_MERKLE_DEPTH {
        return Err(PyValueError::new_err(format!(
            "path must have {} elements, got {}", M86_MERKLE_DEPTH, path.len()
        )));
    }
    let expected_sum_field = py_int_to_field(unshield_amount)?
        + py_int_to_field(fee)?
        + v_out_f;
    if expected_sum_field != v_f {
        return Err(PyValueError::new_err(format!(
            "witness inconsistency: v ({}) != unshield_amount ({}) + fee ({}) + v_out ({})",
            v, unshield_amount, fee, v_out
        )));
    }
    let mut native_path = Vec::with_capacity(M86_MERKLE_DEPTH);
    for (sib_tuple, is_right) in path {
        let sib_d = tuple_to_digest(sib_tuple)?;
        native_path.push((sib_d, is_right));
    }
    let witness = M86Witness {
        sk: sk_f, r: r_f, v: v_f, path: native_path,
        unshield_amount, fee,
        sk_out: sk_out_f, r_out: r_out_f, v_out: v_out_f,
    };
    // Build the trace via the same path the prover uses
    let trace = build_m86_trace(&witness);
    // M86_TRACE_LEN and M86_WIDTH are the known dimensions; trace's
    // inherent `get(col, step)` and `width()` give us cell access without
    // needing the Trace trait.
    let length = M86_TRACE_LEN;
    let width = trace.width();
    // Convert to a Python list of lists: rows × cols
    let outer = pyo3::types::PyList::empty(py);
    for row_idx in 0..length {
        let row_list = pyo3::types::PyList::empty(py);
        for col_idx in 0..width {
            let val: BaseElement = trace.get(col_idx, row_idx);
            row_list.append(val.as_int())?;
        }
        outer.append(row_list)?;
    }
    Ok(outer.into())
}

// ---------------------------------------------------------------------------
// Module definition
// ---------------------------------------------------------------------------

#[pymodule]
fn qstark_py(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hash_leaf, m)?)?;
    m.add_function(wrap_pyfunction!(hash_inner, m)?)?;
    m.add_function(wrap_pyfunction!(prove_preimage, m)?)?;
    m.add_function(wrap_pyfunction!(verify_preimage, m)?)?;
    m.add_function(wrap_pyfunction!(prove_membership, m)?)?;
    m.add_function(wrap_pyfunction!(verify_membership, m)?)?;
    m.add_function(wrap_pyfunction!(prove_m86_membership, m)?)?;
    m.add_function(wrap_pyfunction!(verify_m86_membership, m)?)?;
    m.add_function(wrap_pyfunction!(field_modulus, m)?)?;
    m.add_function(wrap_pyfunction!(merkle_depth, m)?)?;
    m.add_function(wrap_pyfunction!(m86_merkle_depth, m)?)?;
    m.add_function(wrap_pyfunction!(m86_trace_dims, m)?)?;
    m.add_function(wrap_pyfunction!(build_m86_trace_for_inspection, m)?)?;
    Ok(())
}
