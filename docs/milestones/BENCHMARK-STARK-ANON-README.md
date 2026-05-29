# Benchmark — STARK-anon proving pipeline

## What this is

A one-time evidence-of-understanding benchmark for the STARK-anon
proving pipeline. The goal is to demonstrate that the project has
measured the proving pipeline at a phase level and knows where time
goes — not to claim performance is competitive, and not to motivate
optimization work (which the project's [anti-roadmap](../../ROADMAP.md)
explicitly declines).

## Where to look

- [`bench_stark_anon.py`](../../qchain/benchmarks/bench_stark_anon.py)
  — the runnable benchmark script (~360 lines, fully commented)
- [`bench_stark_anon.txt`](../../qchain/benchmarks/bench_stark_anon.txt)
  — the formatted summary table from one run
- [`bench_stark_anon.json`](../../qchain/benchmarks/bench_stark_anon.json)
  — raw measurements (every iteration, every phase) for reproducibility

To reproduce on your own hardware:

```bash
cd qchain-repo
python -m qchain.benchmarks.bench_stark_anon
```

Optional flags: `--iterations N`, `--warmup N`, `--decoys N`, `--output-dir PATH`.

## What's measured

For each STARK-anon proof (spending a note in the depth-20 sparse
Merkle pool, anonymity set 1,048,576), five phases are timed:

| # | Phase | Where | What it does |
|---|-------|-------|--------------|
| 1 | `setup` | Python | Input validation, value-conservation check, full-spend dummy generation |
| 2 | `auth_path` | Python | Build the depth-20 Merkle authentication path from the tree |
| 3 | `stark_prove` | Rust (FFI) | One call to `qstark_py.prove_m86_membership` — internally: trace builder → Winterfell AIR prove → FRI commit/query → serialize |
| 4 | `python_checks` | Python | Three post-proof consistency checks (root, nullifier, output_leaf) |
| 5 | `verify` | Rust (FFI) | One call to `qstark_py.verify_m86_membership` |

Phases 1, 2, and 4 are Python; phases 3 and 5 are single FFI calls
into the qstark crate. We do not break down phase 3 further — that
would require modifying Rust code to return internal sub-timings,
which is out of scope for an evidence benchmark.

## Headline result

The Rust STARK prove call dominates the total time by roughly
**98%**. Everything else is rounding error.

| Phase | Mean (ms) | % of total |
|-------|----------:|-----------:|
| setup | 0.002 | 0.01% |
| auth_path | 0.018 | 0.06% |
| **stark_prove** | **32.76** | **97.75%** |
| python_checks | 0.039 | 0.12% |
| verify | 0.695 | 2.07% |
| **TOTAL** | **33.52** | 100% |

Standard deviation of the total is 0.54 ms (~1.6% of mean) — the
measurements are stable.

Other numbers from the same run:

- Proof size: **96,602 bytes** (~94 KiB), constant across runs
- Verification: **~0.7 ms** (~50× faster than proving)
- All 20 measured iterations produced verifying proofs

## Where time goes — interpretation

The headline result is that the **Winterfell-driven STARK prover is
the bottleneck**. Everything the Python side does — input validation,
Merkle path construction, post-proof sanity checks — together accounts
for less than 0.2% of the total time. Verification is also small at
~2%, which is the expected prover/verifier asymmetry for STARKs.

Within the Rust prove call, the standard breakdown for a Winterfell
AIR of this shape would be approximately:

| Sub-phase (not measured here) | Typical fraction of `stark_prove` |
|---|---|
| Trace construction (round-by-round Rescue-Prime execution over the depth-20 auth path) | ~5–10% |
| AIR constraint composition polynomial | ~10–20% |
| FRI commit phase (Merkle-committing the LDE) | ~40–60% |
| FRI query phase (proof openings) | ~10–20% |
| Serialization | ~1–5% |

These fractions are typical for Winterfell-based AIRs at small scale
and are intended as context, not measurements. The benchmark in this
directory does not produce these sub-phase numbers; obtaining them
would require modifying Rust code to instrument internal Winterfell
boundaries.

## What "the bottleneck" means in context

For a reviewer asking "what would optimization target": the answer is
the Winterfell STARK prover. Specifically, FRI commit/query phases
typically dominate within Winterfell, and those are functions of the
trace length, blowup factor, and FRI parameters chosen by the AIR
design.

Concretely, optimization paths that exist in the literature include:

- **Smaller trace** (the M86 AIR uses 17 columns × 64 rows; a more
  compact AIR could go to ~12 × 64 with some constraint restructuring)
- **Tighter FRI parameters** (lower blowup factor at the cost of
  conjectured soundness margin; not appropriate for a research demo)
- **GPU prover** (Winterfell has no GPU backend; alternative crates do)
- **Recursive proof aggregation** (one outer STARK verifying many
  inner STARKs; significant additional cryptographic surface)

**None of these are pursued by this project.** The optimization story
is recorded here for completeness, not as a roadmap.

## Tree population does not affect proving time

A natural concern is whether a larger anonymity set increases proving
cost. It does not, by design:

| Decoys in tree | Tree population | Proving time |
|---:|---:|---:|
| 0 | 1 note | ~33 ms |
| 100 | 101 notes | ~33 ms |
| 1,000 | 1,001 notes | ~33 ms |

The AIR works on the **authentication path** (always 20 elements at
depth 20), not the full tree. Adding decoys to the tree adds insert-
time work to `tree.append()` (Merkle hash recomputation up the
spine), but no per-proof work. The anonymity set can grow to its
full 1,048,576 capacity without affecting prover time.

Tree insertion itself was not measured here; it's a one-time per-deposit
cost paid at insert time, separate from the per-spend cost the
benchmark measures.

## Methodology

- **Timer:** `time.perf_counter()` — monotonic, fractional seconds,
  highest resolution available on the platform.
- **Warmup:** 3 iterations run and recorded but excluded from the
  statistical summary. First iteration includes Python import / JIT /
  cache warmup overhead; subsequent warmups stabilize. Honest reporting
  keeps warmup measurements in the JSON for inspection.
- **Sample size:** 20 measured iterations. With the observed standard
  deviation (~1.6% of mean), this gives a tight estimate. More
  iterations don't materially change the conclusions.
- **Tree population:** 1,001 notes (500 decoys before the target, 500
  after) by default. Configurable via `--decoys`.
- **Hardware:** not pinned by the script; the script reports
  `platform.platform()`, machine, and processor in its output so a
  reader can interpret the numbers in context.
- **The benchmark script does NOT cherry-pick.** It reports mean,
  median, standard deviation, min, and max for every phase. All raw
  measurements are written to JSON. A reader can verify the
  distribution shape themselves.

## Reproducibility

The benchmark is deterministic in structure: every iteration runs the
same operations on the same tree. The proving randomness comes from
the Winterfell prover's internal Fiat-Shamir, which is deterministic
given the inputs — but each iteration uses the same inputs, so each
iteration produces the same proof bytes. (Verification is over the
same proof; the test that `verify_ok` is True every iteration is
checked.)

Timing variance comes from OS scheduling, CPU frequency scaling, and
memory cache effects — not from cryptographic randomness.

## Honest scope

What this benchmark is:

- A measurement, not a comparison
- A snapshot, not a tracked metric
- Evidence that we understand where time goes
- Reproducible on any machine with the qstark_py wheel installed

What this benchmark is not:

- **A regression test.** The project has no performance budget. If
  future code changes alter proving time by 2× or 0.5×, the benchmark
  is still informative but the project will not treat it as a failure.
- **An optimization motivation.** The findings (prover dominates;
  Winterfell is the bottleneck) are well known in the STARK literature.
  Documenting them is honest practice, not a call to action.
- **A claim that QChain is fast.** It is not, intentionally. The AIR
  was hand-rolled for clarity over performance.
- **Representative of STARK proving in general.** The M86 AIR is small
  (17 × 64 trace, 4 constraint groups). Bigger circuits (e.g., a
  recursive verifier, a large state machine) would scale differently.
- **A claim about hardware portability.** Numbers vary by CPU,
  OS, and memory configuration. Reproduce on your own hardware to
  get numbers relevant to your context.

## Why this benchmark exists in the repo at all

The project's stated identity is "prefer correctness over performance,
prefer clarity over scalability." Performance work is explicitly in
the anti-roadmap.

A natural question from an external reviewer is: *"if performance is
not a goal, do you know what your performance is?"* This benchmark
answers that question honestly. Measuring without optimizing is a
coherent position — and the measurement itself is small evidence of
discipline (we measure rather than guess; we report variance rather
than cherry-pick; we know the bottleneck and choose not to chase it).

If your reading of the project is "they didn't bother to measure, so
they don't really know what they have," this benchmark addresses that
reading directly. If your reading is "this needs to be 10× faster
before it's serious," this benchmark won't satisfy you — but neither
will any future pass on this project, because that's not what this
project is for.

## When this benchmark would be re-run

- If the AIR design changes substantively (new constraint, larger trace)
- If Winterfell ships a major version change
- After an external audit, if the audit finds anything affecting
  performance
- Never as a CI regression test
