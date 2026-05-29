"""
Quantum Random Number Generator.

Uses IBM Quantum hardware to generate true random bits from quantum
measurement. The physics: a qubit prepared in the |+> state (via Hadamard)
collapses to |0> or |1> with exactly 50% probability when measured. This
randomness comes from the laws of quantum mechanics, not a deterministic
algorithm — fundamentally different from classical pseudo-random generators.

Three backends in order of preference:
  1. Real IBM Quantum hardware  — true quantum randomness, slow (queue)
  2. Local AerSimulator          — pseudo-random but uses the real circuit
  3. Python secrets module       — classical CSPRNG fallback if nothing else works

The blockchain treats QRNG as a periodic *seed refresh*, not a per-block call,
because hardware queue times are unpredictable. Each call pulls a large batch
of bits and caches them.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from enum import Enum
from typing import Optional

# NOTE: Qiskit is imported LAZILY inside _hadamard_circuit() and the
# backend functions, NOT at module level. Qiskit takes 5-10 seconds to
# import and uses 300-500MB of RAM. Since blockchain.py imports this
# module at the top level, an eager import would penalize every node
# startup — even nodes that never use QRNG (e.g., PoW-only miners).
# Lazy import means the cost is paid only when QRNG is first invoked.


class Source(str, Enum):
    """Where a batch of random bits came from. Logged for auditability."""
    HARDWARE = "ibm_quantum_hardware"
    SIMULATOR = "qiskit_aer_simulator"
    CLASSICAL = "classical_secrets_fallback"


@dataclass
class RandomBatch:
    """A batch of random bits plus metadata about how they were generated."""
    bits: str            # string of '0'/'1' characters
    source: Source
    backend_name: str    # which IBM device, or "aer_simulator", or "secrets"
    job_id: Optional[str] = None  # IBM job id, for audit

    def as_int(self) -> int:
        return int(self.bits, 2)

    def as_bytes(self) -> bytes:
        # Pad to a multiple of 8 bits so we can pack into bytes cleanly
        padded = self.bits.ljust((len(self.bits) + 7) // 8 * 8, "0")
        return int(padded, 2).to_bytes(len(padded) // 8, "big")


# ---------------------------------------------------------------------------
# Circuit construction
# ---------------------------------------------------------------------------

def _hadamard_circuit(num_qubits: int):
    """Build a QRNG circuit: a Hadamard on each qubit followed by measurement.

    After the Hadamards, each qubit is in (|0> + |1>) / sqrt(2). Measurement
    then collapses each qubit to |0> or |1> with 50/50 probability, completely
    independently. With N qubits and S shots we get N*S random bits.
    """
    from qiskit import QuantumCircuit
    qc = QuantumCircuit(num_qubits, num_qubits)
    for q in range(num_qubits):
        qc.h(q)
    qc.measure(range(num_qubits), range(num_qubits))
    return qc


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------

def _from_hardware(
    num_qubits: int, shots: int, timeout_seconds: int
) -> Optional[RandomBatch]:
    """Submit the QRNG circuit to a real IBM Quantum processor.

    Returns None on any failure so the caller can fall back. We catch broadly
    on purpose — auth failures, queue timeouts, network errors should all
    degrade gracefully rather than crash the blockchain.
    """
    token = os.environ.get("IBM_QUANTUM_TOKEN") or os.environ.get("QISKIT_IBM_TOKEN")
    if not token:
        return None

    try:
        from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2

        # `ibm_quantum_platform` is the current channel (the old `ibm_quantum`
        # channel was sunset in 2025). The user's instance CRN can be passed
        # via QISKIT_IBM_INSTANCE; if absent the service picks the default.
        service = QiskitRuntimeService(
            channel="ibm_quantum_platform",
            token=token,
            instance=os.environ.get("QISKIT_IBM_INSTANCE"),
        )
        backend = service.least_busy(
            operational=True, simulator=False, min_num_qubits=num_qubits
        )

        qc = _hadamard_circuit(num_qubits)
        from qiskit.transpiler.preset_passmanagers import generate_preset_pass_manager
        pm = generate_preset_pass_manager(backend=backend, optimization_level=1)
        isa_circuit = pm.run(qc)

        sampler = SamplerV2(mode=backend)
        job = sampler.run([isa_circuit], shots=shots)
        job_id = job.job_id()
        result = job.result(timeout=timeout_seconds)

        # SamplerV2 returns bitstrings via the classical register named "c"
        # (default name). get_bitstrings() returns one string per shot.
        bitstrings = result[0].data.c.get_bitstrings()
        bits = "".join(bitstrings)

        return RandomBatch(
            bits=bits,
            source=Source.HARDWARE,
            backend_name=backend.name,
            job_id=job_id,
        )
    except Exception as e:
        # We deliberately swallow the error — the caller will fall back.
        # In production you'd log this somewhere visible.
        print(f"[QRNG] hardware path failed: {type(e).__name__}: {e}")
        return None


def _from_simulator(num_qubits: int, shots: int) -> Optional[RandomBatch]:
    """Run the QRNG circuit on a local Aer simulator.

    The simulator's randomness is itself classical (Mersenne Twister under
    the hood), so this isn't *true* quantum randomness — but it exercises
    the same circuit and is useful for testing and as a middle fallback.
    """
    try:
        from qiskit_aer import AerSimulator

        backend = AerSimulator()
        qc = _hadamard_circuit(num_qubits)
        from qiskit.transpiler.preset_passmanagers import generate_preset_pass_manager
        pm = generate_preset_pass_manager(backend=backend, optimization_level=1)
        isa_circuit = pm.run(qc)

        # Aer's BackendV2 interface accepts circuits directly via run().
        job = backend.run(isa_circuit, shots=shots)
        counts = job.result().get_counts()

        # `counts` is a dict {bitstring: count}. We need the raw per-shot
        # bitstrings; reconstruct them by expanding the counts.
        bits_parts = []
        for bitstring, count in counts.items():
            bits_parts.append(bitstring * count)
        bits = "".join(bits_parts)

        return RandomBatch(
            bits=bits,
            source=Source.SIMULATOR,
            backend_name="aer_simulator",
        )
    except Exception as e:
        print(f"[QRNG] simulator path failed: {type(e).__name__}: {e}")
        return None


def _from_classical(num_bits: int) -> RandomBatch:
    """Classical CSPRNG fallback. Always succeeds."""
    n = secrets.randbits(num_bits)
    bits = bin(n)[2:].zfill(num_bits)
    return RandomBatch(
        bits=bits,
        source=Source.CLASSICAL,
        backend_name="secrets",
    )


# ---------------------------------------------------------------------------
# Public API + cache
# ---------------------------------------------------------------------------

class QRNG:
    """Caching front-end to the quantum random number generator.

    Pulls a big batch of bits from the best available source, then hands them
    out to callers a few at a time. Refreshes the cache when it runs low.

    Args:
        num_qubits: width of the quantum circuit. More qubits per shot is
            more efficient but needs a backend with at least that many qubits.
        shots:      how many times to repeat the measurement per refresh.
            num_qubits * shots bits per refresh.
        prefer_hardware: if False, skip hardware entirely (useful for tests).
        timeout_seconds: how long to wait for an IBM job before falling back.
    """

    def __init__(
        self,
        num_qubits: int = 8,
        shots: int = 128,
        prefer_hardware: bool = True,
        timeout_seconds: int = 120,
    ) -> None:
        self.num_qubits = num_qubits
        self.shots = shots
        self.prefer_hardware = prefer_hardware
        self.timeout_seconds = timeout_seconds
        self._cache: str = ""
        self._last_source: Optional[Source] = None
        self._last_backend: Optional[str] = None
        self._last_job_id: Optional[str] = None

    # ---- internal ---------------------------------------------------------

    def _refresh(self) -> None:
        """Pull a fresh batch from the best available source."""
        batch: Optional[RandomBatch] = None

        if self.prefer_hardware:
            batch = _from_hardware(self.num_qubits, self.shots, self.timeout_seconds)
        if batch is None:
            batch = _from_simulator(self.num_qubits, self.shots)
        if batch is None:
            batch = _from_classical(self.num_qubits * self.shots)

        self._cache += batch.bits
        self._last_source = batch.source
        self._last_backend = batch.backend_name
        self._last_job_id = batch.job_id

    def _take(self, n_bits: int) -> str:
        while len(self._cache) < n_bits:
            self._refresh()
        out, self._cache = self._cache[:n_bits], self._cache[n_bits:]
        return out

    # ---- public -----------------------------------------------------------

    def random_bits(self, n: int) -> str:
        """Return n random bits as a '01' string."""
        return self._take(n)

    def random_int(self, n_bits: int = 256) -> int:
        """Return a random integer with `n_bits` of entropy."""
        return int(self._take(n_bits), 2)

    def random_bytes(self, n: int) -> bytes:
        """Return n random bytes."""
        bits = self._take(n * 8)
        return int(bits, 2).to_bytes(n, "big")

    def randbelow(self, upper: int) -> int:
        """Return a uniform random integer in [0, upper).

        Uses rejection sampling so the result is unbiased (the obvious
        `random_int % upper` is slightly biased unless upper is a power of 2).
        """
        if upper <= 0:
            raise ValueError("upper must be positive")
        n_bits = (upper - 1).bit_length()
        while True:
            candidate = self.random_int(n_bits)
            if candidate < upper:
                return candidate

    # ---- introspection ---------------------------------------------------

    @property
    def last_source(self) -> Optional[Source]:
        return self._last_source

    @property
    def last_backend(self) -> Optional[str]:
        return self._last_backend

    @property
    def last_job_id(self) -> Optional[str]:
        return self._last_job_id

    def status(self) -> dict:
        return {
            "cache_bits_available": len(self._cache),
            "last_source": self._last_source.value if self._last_source else None,
            "last_backend": self._last_backend,
            "last_job_id": self._last_job_id,
        }
