"""Benchmark: STARK-anon proving pipeline phase breakdown.

# What this measures

For one STARK-anon proof (spending a note in the depth-20 sparse Merkle
pool, anonymity set 1,048,576), we time five phases:

  1. setup            — Python-side input validation, value-conservation
                         check, full-spend dummy generation
  2. auth_path        — building the Merkle authentication path from the
                         tree (Python; O(depth))
  3. stark_prove      — single Rust call (qstark_py::prove_m86_membership)
                         which internally runs: trace builder → Winterfell
                         AIR prove → FRI commit/query → serialize
  4. python_checks    — Python-side post-proof sanity checks (root/nullifier/
                         output_leaf consistency)
  5. verify           — Rust verifier (qstark_py::verify_m86_membership)

Phases 1, 2, 4 are Python; phases 3 and 5 are single FFI calls into the
Rust qstark crate. We do not break down phase 3 further — that would
require modifying Rust code to return internal timings, which is out of
scope for an evidence-of-understanding benchmark.

# What this does not measure

* Memory (RSS / peak allocations) — would require psutil + finer tooling
* Multi-proof batching — current AIR is single-proof
* Verification under adversarial inputs — soundness tests cover that, not
  this benchmark
* End-to-end transaction submission, including network gossip and mining

# Methodology

* Tree population: configurable (default 1,000 decoy notes + 1 target);
  tree population should not significantly affect timings since the AIR
  works on the auth path (always 20 elements), not the full tree
* Warmup iterations: run but reported separately (first run includes
  Python import overhead, JIT / cache warmup); discarded for the
  statistical summary
* Measured iterations: configurable (default 20)
* Hardware: not pinned by the script; report the host system in the
  output so a reader can interpret the numbers
* Timer: `time.perf_counter()` (monotonic, fractional seconds, highest
  resolution available)

# Output

Writes two files:
* `bench_stark_anon.json` — raw measurements (every iteration, every phase)
* `bench_stark_anon.txt` — formatted summary table

Stdout shows progress and the final summary.

# To reproduce

    cd qchain-repo
    python -m qchain.benchmarks.bench_stark_anon
    python -m qchain.benchmarks.bench_stark_anon --iterations 50 --decoys 10000

# Honest scope

This is a one-time evidence-of-understanding benchmark. It demonstrates
that the project has measured the proving pipeline at a phase level and
knows where time goes. It is NOT:

* A regression-tracking CI benchmark (the project has no perf budget)
* An optimization target (the anti-roadmap declines this work)
* A claim that QChain is fast (it isn't, intentionally)
* A representative benchmark for STARK proving in general (the AIR is
  small; bigger circuits scale differently)

The expected finding — that the Rust STARK prove call dominates the
total time — is intentional. We make this finding visible rather than
buried so a reviewer can ask "what would optimization target?" and get
the answer: the Winterfell prover, which is out of scope.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import List, Optional

# Project imports
from qchain.crypto.anon_stark import STARKNote, STARKAnonTree
import qstark_py as q


@dataclass
class PhaseTimings:
    """Times for one proof, in milliseconds."""
    iteration: int
    is_warmup: bool
    setup_ms: float
    auth_path_ms: float
    stark_prove_ms: float
    python_checks_ms: float
    verify_ms: float
    proof_size_bytes: int
    verify_ok: bool

    @property
    def total_ms(self) -> float:
        return (self.setup_ms + self.auth_path_ms + self.stark_prove_ms
                + self.python_checks_ms + self.verify_ms)


@dataclass
class BenchmarkConfig:
    iterations: int = 20
    warmup: int = 3
    decoys_before: int = 500
    decoys_after: int = 500
    output_dir: str = "."


@dataclass
class BenchmarkResult:
    config: dict
    host_info: dict
    timings: List[dict] = field(default_factory=list)
    summary: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# One proof, fully instrumented
# ---------------------------------------------------------------------------

def time_one_proof(tree: STARKAnonTree, target_note: STARKNote,
                   target_idx: int, iteration: int, is_warmup: bool) -> PhaseTimings:
    """Run one STARK-anon proof end-to-end and time each phase.

    Mirrors the create_stark_anon_tx pipeline. We don't actually
    construct the STARKAnonTransaction object; we just exercise the
    work it does, in the same order, with the same arguments.
    """
    # --- Phase 1: setup ---
    t0 = time.perf_counter()
    unshield_amount = int(target_note.value)
    fee = 0
    change_sk, change_r, change_v = 0, 0, 0    # full-spend dummy
    total = unshield_amount + fee + change_v
    if total != int(target_note.value):
        raise RuntimeError("value conservation precondition failed")
    if total >= (1 << 64):
        raise RuntimeError("overflow precondition failed")
    t1 = time.perf_counter()

    # --- Phase 2: auth_path ---
    path = tree.auth_path(target_idx)
    t2 = time.perf_counter()

    # --- Phase 3: stark_prove (one Rust call) ---
    proof, claimed_root, claimed_nullifier, claimed_output_leaf = q.prove_m86_membership(
        target_note.sk, target_note.randomness, target_note.value, path,
        unshield_amount, fee,
        change_sk, change_r, change_v,
    )
    t3 = time.perf_counter()

    # --- Phase 4: python_checks ---
    # Match create_stark_anon_tx's three sanity checks
    if claimed_root != tree.root():
        raise RuntimeError("root mismatch")
    if claimed_nullifier != target_note.nullifier():
        raise RuntimeError("nullifier mismatch")
    expected_output_leaf = STARKNote(sk=change_sk, randomness=change_r,
                                     value=change_v).leaf()
    if claimed_output_leaf != expected_output_leaf:
        raise RuntimeError("output_leaf mismatch")
    t4 = time.perf_counter()

    # --- Phase 5: verify ---
    ok = q.verify_m86_membership(proof, claimed_root, claimed_nullifier,
                                  unshield_amount, fee, claimed_output_leaf)
    t5 = time.perf_counter()

    return PhaseTimings(
        iteration=iteration,
        is_warmup=is_warmup,
        setup_ms=(t1 - t0) * 1000.0,
        auth_path_ms=(t2 - t1) * 1000.0,
        stark_prove_ms=(t3 - t2) * 1000.0,
        python_checks_ms=(t4 - t3) * 1000.0,
        verify_ms=(t5 - t4) * 1000.0,
        proof_size_bytes=len(proof),
        verify_ok=ok,
    )


# ---------------------------------------------------------------------------
# Setup: build a populated tree with the target note at a known position
# ---------------------------------------------------------------------------

def build_populated_tree(config: BenchmarkConfig):
    """Populate a tree with decoys + target note + more decoys.

    Returns (tree, target_note, target_idx).

    Tree population shouldn't affect per-proof time (AIR works on the
    20-element auth path), but we use a non-trivial population to make
    the benchmark realistic.
    """
    tree = STARKAnonTree()
    for i in range(config.decoys_before):
        tree.append(STARKNote.random(value=i + 1).leaf())
    target_note = STARKNote.random(value=1000)
    target_idx = tree.append(target_note.leaf())
    for i in range(config.decoys_after):
        tree.append(STARKNote.random(value=99999 + i).leaf())
    return tree, target_note, target_idx


# ---------------------------------------------------------------------------
# Summary statistics
# ---------------------------------------------------------------------------

def summarize_phase(values: List[float], name: str) -> dict:
    if not values:
        return {"name": name, "n": 0}
    return {
        "name": name,
        "n": len(values),
        "mean_ms": statistics.mean(values),
        "median_ms": statistics.median(values),
        "stdev_ms": statistics.stdev(values) if len(values) > 1 else 0.0,
        "min_ms": min(values),
        "max_ms": max(values),
    }


def summarize(timings: List[PhaseTimings]) -> dict:
    measured = [t for t in timings if not t.is_warmup]
    if not measured:
        return {"error": "no measured iterations"}

    phases = {
        "setup": [t.setup_ms for t in measured],
        "auth_path": [t.auth_path_ms for t in measured],
        "stark_prove": [t.stark_prove_ms for t in measured],
        "python_checks": [t.python_checks_ms for t in measured],
        "verify": [t.verify_ms for t in measured],
    }

    summaries = {name: summarize_phase(vals, name) for name, vals in phases.items()}
    totals = [t.total_ms for t in measured]
    summaries["TOTAL"] = summarize_phase(totals, "TOTAL")

    # Percentage breakdown of mean total
    mean_total = summaries["TOTAL"]["mean_ms"]
    breakdown = {}
    for name in ["setup", "auth_path", "stark_prove", "python_checks", "verify"]:
        breakdown[name] = (summaries[name]["mean_ms"] / mean_total) * 100.0

    proof_sizes = [t.proof_size_bytes for t in measured]
    return {
        "phases": summaries,
        "percentage_breakdown_of_mean_total": breakdown,
        "proof_size_bytes": {
            "min": min(proof_sizes),
            "max": max(proof_sizes),
            "mean": statistics.mean(proof_sizes),
        },
        "all_verify_ok": all(t.verify_ok for t in measured),
    }


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def format_summary_table(summary: dict, config: BenchmarkConfig,
                          host_info: dict) -> str:
    """Format a human-readable summary table."""
    lines = []
    lines.append("=" * 78)
    lines.append("STARK-anon proving pipeline benchmark")
    lines.append("=" * 78)
    lines.append("")
    lines.append("Configuration:")
    lines.append(f"  Measured iterations: {config.iterations}")
    lines.append(f"  Warmup iterations:   {config.warmup} (excluded from stats)")
    lines.append(f"  Tree population:     {config.decoys_before + 1 + config.decoys_after:>5} notes")
    lines.append(f"    decoys before:     {config.decoys_before}")
    lines.append(f"    target note:       1 (at position {config.decoys_before})")
    lines.append(f"    decoys after:      {config.decoys_after}")
    lines.append(f"  Anonymity set:       1,048,576 (depth-20 sparse Merkle)")
    lines.append("")
    lines.append("Host:")
    for k, v in host_info.items():
        lines.append(f"  {k:18}: {v}")
    lines.append("")
    if "error" in summary:
        lines.append(f"ERROR: {summary['error']}")
        return "\n".join(lines)

    lines.append("Per-phase timings (milliseconds):")
    lines.append("")
    header = f"  {'Phase':<18} {'mean':>10} {'median':>10} {'stdev':>10} {'min':>10} {'max':>10}"
    lines.append(header)
    lines.append(f"  {'-'*18:<18} {'-'*10:>10} {'-'*10:>10} {'-'*10:>10} {'-'*10:>10} {'-'*10:>10}")
    for name in ["setup", "auth_path", "stark_prove", "python_checks", "verify", "TOTAL"]:
        p = summary["phases"][name]
        if name == "TOTAL":
            lines.append(f"  {'-'*18:<18} {'-'*10:>10} {'-'*10:>10} {'-'*10:>10} {'-'*10:>10} {'-'*10:>10}")
        lines.append(
            f"  {p['name']:<18} {p['mean_ms']:>10.3f} {p['median_ms']:>10.3f} "
            f"{p['stdev_ms']:>10.3f} {p['min_ms']:>10.3f} {p['max_ms']:>10.3f}"
        )

    lines.append("")
    lines.append("Percentage of mean total per phase:")
    lines.append("")
    for name in ["setup", "auth_path", "stark_prove", "python_checks", "verify"]:
        pct = summary["percentage_breakdown_of_mean_total"][name]
        bar_len = int(pct / 2)   # 1 char per 2%
        bar = "█" * bar_len
        lines.append(f"  {name:<18} {pct:>6.2f}%  {bar}")

    lines.append("")
    ps = summary["proof_size_bytes"]
    lines.append(f"Proof size: {ps['min']} – {ps['max']} bytes "
                  f"(mean {ps['mean']:.0f}, ~{ps['mean']/1024:.1f} KiB)")
    lines.append(f"All verifications OK: {summary['all_verify_ok']}")
    lines.append("")
    lines.append("Bottleneck: see the phase with the largest %-of-total figure.")
    lines.append("=" * 78)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--iterations", type=int, default=20,
                         help="Number of measured iterations (default 20)")
    parser.add_argument("--warmup", type=int, default=3,
                         help="Number of warmup iterations (default 3, "
                              "excluded from statistics)")
    parser.add_argument("--decoys", type=int, default=1000,
                         help="Number of decoy notes in the tree (default 1000); "
                              "half before the target, half after")
    parser.add_argument("--output-dir", type=str, default=".",
                         help="Where to write bench_stark_anon.json/.txt "
                              "(default: current directory)")
    args = parser.parse_args()

    config = BenchmarkConfig(
        iterations=args.iterations,
        warmup=args.warmup,
        decoys_before=args.decoys // 2,
        decoys_after=args.decoys - (args.decoys // 2),
        output_dir=args.output_dir,
    )

    host_info = {
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor() or "unknown",
        "qstark_py_module": str(Path(q.__file__).resolve()),
        "merkle_depth": q.m86_merkle_depth(),
        "field_modulus": q.field_modulus(),
    }

    print("Building populated tree...")
    t0 = time.perf_counter()
    tree, target_note, target_idx = build_populated_tree(config)
    t1 = time.perf_counter()
    print(f"  tree population took {(t1-t0):.2f} s "
          f"({config.decoys_before + 1 + config.decoys_after} notes)")
    print(f"  target note at idx {target_idx}")

    timings: List[PhaseTimings] = []

    print(f"\nWarmup ({config.warmup} iterations, excluded from stats):")
    for i in range(config.warmup):
        t = time_one_proof(tree, target_note, target_idx, i, is_warmup=True)
        timings.append(t)
        print(f"  warmup {i+1}: total {t.total_ms:7.1f} ms "
              f"(prove {t.stark_prove_ms:6.1f} ms, verify {t.verify_ms:5.2f} ms)")

    print(f"\nMeasured ({config.iterations} iterations):")
    for i in range(config.iterations):
        t = time_one_proof(tree, target_note, target_idx, i, is_warmup=False)
        timings.append(t)
        print(f"  iter {i+1:>3}: total {t.total_ms:7.1f} ms "
              f"(prove {t.stark_prove_ms:6.1f} ms, verify {t.verify_ms:5.2f} ms)")

    print("\nSummarizing...")
    summary = summarize(timings)

    # Write JSON (raw measurements + summary)
    result = BenchmarkResult(
        config=asdict(config),
        host_info=host_info,
        timings=[asdict(t) for t in timings],
        summary=summary,
    )
    output_dir = Path(config.output_dir)
    output_dir.mkdir(exist_ok=True)
    json_path = output_dir / "bench_stark_anon.json"
    json_path.write_text(json.dumps(asdict(result), indent=2))
    print(f"  raw measurements: {json_path}")

    # Write text summary
    txt = format_summary_table(summary, config, host_info)
    txt_path = output_dir / "bench_stark_anon.txt"
    txt_path.write_text(txt)
    print(f"  summary table:    {txt_path}")
    print()
    print(txt)
    return 0


if __name__ == "__main__":
    sys.exit(main())
