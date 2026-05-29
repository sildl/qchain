# qstark — Real zk-STARKs in Rust

A continuation of [QChain](../qchain) (milestones 1–7). The goal of qstark
is to replace milestone 4's Schnorr-based anonymity with a real, sound
zk-STARK proof system using `winterfell`.

## Milestones

| Status | Milestone | What it proves |
|--------|-----------|---------------|
| ✅ M8.1 | Fibonacci AIR | toolchain works end-to-end |
| ✅ M8.2 | Rescue-Prime hash AIR | "I know x such that Rp64_256(x) = y" |
| ✅ M8.3a | Single-level Merkle membership | "I know `left` such that merge(left, public_right) = root" |
| ✅ **M8.3 FULL** | **Multi-level Merkle membership** | **"I know (leaf, path, dir_bits) for a depth-4 Merkle tree with root R"** |
| ⬜ M8.4 | Python ↔ Rust FFI + integration | replace QChain M4's Schnorr layer |

## M8.3 FULL: what we have

A real, sound, zero-knowledge STARK proving multi-level Merkle membership.
The prover proves they know a leaf + path + direction bits for a depth-4
Merkle tree with a public root. **Everything except the root is hidden in the
witness.**

**Numbers** (release build, single core, depth 4):
- Proving: ~2.8 ms
- Proof size: ~28,400 bytes
- Verifying: ~319 µs

**11 dedicated M8.3-full tests, all green:**
- Happy paths (all 16 positions in a sub-tree)
- 8 adversarial: wrong root, garbage root, root of different leaf, tampered
  witness with wrong sibling, tampered with wrong direction, tampered proof,
  truncated proof, empty proof
- 30 random byte-flips: all rejected
- Anonymity demonstration: two different leaves with two different roots,
  each proof reveals nothing about its witness

## The construction

The AIR is the heart of this milestone. Here's how it actually works:

**Trace layout** (17 columns × 64 rows):
- Columns 0..12: Rescue-Prime state (12 elements)
- Column 12: direction bit for the current hash block
- Columns 13..17: sibling digest for the current hash block

**Periodic columns:**
- 24 columns for ARK1 + ARK2 round constants (period 8)
- `is_boundary`: 1 only at the last row of each 8-row hash block (period 8)
- `is_active`: 1 on rows 0..30, 0 on rows 31..63 (gates off the transition
  out of the last active row, and all padding)

**Four constraint groups:**

1. **Hash round** (12 constraints, base degree 7 + 2 periodic cycles):
   ```
   active_round * ((INV_MDS * (next - ARK2))^7 - MDS * curr^7 - ARK1) = 0
   ```
   Active on within-block transitions; gates off at boundaries.

2. **Block boundary** (12 constraints, base degree 2 + 2 cycles):
   ```
   active_boundary * (next - swap_target(prev_output, sib_next, dir_next)) = 0
   ```
   where `swap_target` selects `(prev_output, sib)` if dir=0 or `(sib, prev_output)`
   if dir=1. Active only at rows 7→8, 15→16, 23→24.

3. **Direction bit binary** (1 constraint):
   ```
   is_active * dir * (dir - 1) = 0
   ```

4. **Witness-static** (5 constraints):
   ```
   active_round * (next[dir/sib_i] - curr[dir/sib_i]) = 0
   ```
   Forces dir/sib columns to stay constant within a hash block.

## How I got this working (and almost didn't)

The first attempt failed with "constraint evaluations over the out-of-domain
frame are inconsistent." This is a Winterfell verifier error meaning the
prover's claimed constraint evaluations didn't match the constraint
polynomial degree.

**Two real bugs I had to find:**

1. **Misdeclared constraint degrees.** I wrote
   `TransitionConstraintDegree::new(8)` for the hash-round constraint, but
   the correct API is `with_cycles(7, vec![cycle_full, cycle_8])` — telling
   Winterfell that the base degree (over trace columns) is 7, AND there are
   two periodic columns multiplying in. Winterfell uses this to size the
   LDE correctly.

2. **Direction bit and sibling read from wrong row.** I was reading dir/sib
   from the `curr` block (the one ENDING at the boundary), but they should
   come from the `next` block (the one STARTING). They describe how the
   *next* hash block's input is constructed from the previous output.

I caught both bugs by writing a diagnostic test that natively evaluated
every constraint at every row and listed all violations. This is the
right way to debug STARKs — don't trust the abstract error message,
manually verify each constraint expression against a known-honest trace.

## Scope: what M8.3 does and doesn't do

**What it does:**
- Real, sound, zero-knowledge STARK for depth-4 Merkle membership
- Production hash (Rp64_256, same as Polygon Miden)
- 11 adversarial tests including witness-forgery cases — all pass
- Scales to greater depth by changing one constant (MERKLE_DEPTH) and
  adjusting trace length

**What it explicitly doesn't do:**
- The current depth is 4 → anonymity set of 16. Production wants 20+.
  Scaling to depth 8 requires changing FULL_TRACE_LEN=128 and verifying
  the constraint cycles still divide correctly. Should be a one-line
  change but I didn't test it.
- No nullifier in this proof. A real anonymous spend proof also commits
  to a nullifier (so the chain can detect double-spend). This would
  require an additional hash block in the same trace, easy to add.
- No leaf computation in the proof. We assume the prover has a precomputed
  `leaf` digest. A real proof would start from `(sk, r, value)` and hash
  to `leaf` in the trace. Also easy to add — another hash block.
- 50-bit conjectured security (not 128). The 64-row trace is too small
  for full security. Same as M8.2: real systems batch many proofs into
  longer traces.

## Run

```bash
cargo run --release       # demo of M8.1 + M8.2 + M8.3 (single + full)
cargo test --release      # 65 tests across all milestones
```

## What's next (M8.4)

Python ↔ Rust FFI via PyO3 so QChain can call these STARKs from its
existing Python code. The full membership proof is the one that actually
replaces M4's Schnorr scaffolding with a true zk-STARK.
