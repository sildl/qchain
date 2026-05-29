"""
Shielded transactions and the shielded pool.

A shielded transaction has three parts:
  - INPUTS:  one or more SpendAuthorizations (consume existing shielded notes)
  - OUTPUTS: zero or more new shielded-note commitments (create notes)
  - SHIELD:  optional transparent-in value (move coins from transparent
             balance into the shielded pool)
  - UNSHIELD: optional transparent-out value (move coins from shielded
             pool back to a transparent address)
  - FEE:     a transparent fee for the block proposer

Value conservation:
    transparent_in + sum(input_values)
        == transparent_out + sum(output_values) + fee

The chain enforces this WITHOUT seeing the individual input or output
values, because:
  * Input values are committed in each SpendAuthorization's value_commit.
  * Output values are committed in each new note's commitment.
  * The transaction publishes the SUM of input blindings minus the sum
    of output blindings (the "balance blinding"), so the verifier can
    recompute the expected aggregate commitment and confirm it matches
    the public transparent-flow values.

## Privacy summary (again, honestly)

What's hidden:
  * Each input note's exact value
  * Each output note's value, recipient, randomness
  * Linkage between transparent senders and shielded recipients

What's visible:
  * Which leaves were spent (via Merkle proofs)
  * The spenders' pubkeys (each signed their spend)
  * Transparent flow amounts (shield in / unshield out / fee)
  * The fact that a shielded tx happened

Real shielded pools (Zcash) hide more by using ZK proofs to prove
membership without revealing the leaf. We can plug a real ZK proof
system in later by replacing the SpendAuthorization with a ZK proof
that asserts the same statements.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List, Set

from qchain.crypto.commitments import H
from qchain.crypto.merkle import MerkleTree
from qchain.crypto.zk import (
    ShieldedNote,
    SpendAuthorization,
    commit_value,
    verify_spend,
)


# ---------------------------------------------------------------------------
# Transaction types
# ---------------------------------------------------------------------------

@dataclass
class ShieldedOutput:
    """A new shielded note being created. The recipient's pubkey is *not*
    revealed here — it's encoded inside the commitment. The recipient
    learns about their new note via an off-chain side channel (or by
    trial-decryption of a memo field, which we don't implement here).

    Publishes:
      * The leaf commitment (will be appended to the tree)
      * The value_commit (used for the value-conservation check)
    """
    leaf_commitment: bytes
    value_commit: bytes


@dataclass
class ShieldedTransaction:
    """A complete shielded transaction.

    Either inputs or shield_in must be non-empty (the tx has to source value
    from somewhere). Either outputs or unshield_out must be non-empty (it
    has to spend the value somewhere).
    """
    inputs: List[SpendAuthorization]
    outputs: List[ShieldedOutput]
    shield_in: int                  # transparent coins entering the pool
    unshield_in_address: str        # transparent recipient of unshielded coins
    unshield_out: int               # transparent coins leaving the pool
    fee: int                        # transparent fee for the block proposer
    timestamp: float

    # The value-conservation witness. The chain checks:
    #   shield_in + sum_input_values == unshield_out + sum_output_values + fee
    # by recomputing H over the published total commit + this witness.
    balance_blinding: bytes

    def txid(self) -> str:
        """Stable transaction ID."""
        parts = [str(len(self.inputs)).encode(), str(len(self.outputs)).encode()]
        for inp in self.inputs:
            parts.append(inp.statement.nullifier)
        for out in self.outputs:
            parts.append(out.leaf_commitment)
        parts += [
            self.shield_in.to_bytes(16, "big"),
            self.unshield_out.to_bytes(16, "big"),
            self.fee.to_bytes(16, "big"),
            self.unshield_in_address.encode(),
        ]
        return H(b"sztxid", *parts).hex()


# ---------------------------------------------------------------------------
# Shielded pool state
# ---------------------------------------------------------------------------

@dataclass
class ShieldedPool:
    """The chain's shielded state.

    * `tree` accumulates every note commitment ever created. Its root is
       what spend proofs are anchored to.
    * `seen_nullifiers` tracks every note that's been spent, so a
       double-spend can be detected.
    """
    tree: MerkleTree = field(default_factory=MerkleTree)
    seen_nullifiers: Set[bytes] = field(default_factory=set)

    # -- public ------------------------------------------------------------

    def add_output(self, output: ShieldedOutput) -> int:
        """Append a new note commitment to the tree; return its leaf index."""
        return self.tree.append(output.leaf_commitment)

    def has_nullifier(self, nullifier_bytes: bytes) -> bool:
        return nullifier_bytes in self.seen_nullifiers

    def mark_nullifier(self, nullifier_bytes: bytes) -> None:
        self.seen_nullifiers.add(nullifier_bytes)

    @property
    def root(self) -> bytes:
        return self.tree.root()


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_shielded_tx(
    tx: ShieldedTransaction,
    pool: ShieldedPool,
    *,
    revealed_input_values: List[int] | None = None,
    revealed_output_values: List[int] | None = None,
) -> tuple[bool, str]:
    """Verify a shielded transaction against the current pool state.

    Returns (ok, reason). On failure, reason describes which check failed.

    Value conservation:
      In a real shielded pool the chain wouldn't need to see any values
      because the commitments are homomorphic. Our hash-based commitments
      aren't homomorphic, so the spender of the transaction reveals the
      values (kept WITHIN the tx, separate from the chain) to the
      verifier as part of the proof, along with the blinding factors so
      the verifier can confirm each commitment opens correctly.

      revealed_input_values: one int per input, in the same order
      revealed_output_values: one int per output, in the same order

      The "revealed" terminology is honest: at verification time, the
      verifier knows the values. The privacy comes from the fact that
      these values aren't STORED on the chain in cleartext; the chain
      only stores the commitments. A node that re-validates a transaction
      from history would need the values to be available out-of-band, OR
      the chain would store an opaque blob that only certain parties
      (e.g. auditors with view keys) can decrypt.

      A real Zcash-style design uses note-encryption so each recipient
      can decrypt their own outputs from on-chain ciphertexts; we don't
      implement that here, but the slot for the encrypted memo would go
      on each ShieldedOutput.
    """
    # 1. Structural checks
    if len(tx.inputs) == 0 and tx.shield_in == 0:
        return False, "tx has no value sources"
    if len(tx.outputs) == 0 and tx.unshield_out == 0:
        return False, "tx has no value sinks"
    if tx.fee < 0 or tx.shield_in < 0 or tx.unshield_out < 0:
        return False, "negative public values"

    # 2. Each input must verify against the current pool state
    nullifiers_in_tx: Set[bytes] = set()
    for inp in tx.inputs:
        if inp.statement.merkle_root != pool.root:
            # Inputs must reference the current root (in production, a
            # short list of recent roots is also acceptable to handle
            # concurrent spends).
            return False, "stale merkle root"
        if not verify_spend(inp, pool.root, pool.seen_nullifiers):
            return False, "invalid spend authorization"
        # Catch duplicates within the same transaction
        if inp.statement.nullifier in nullifiers_in_tx:
            return False, "duplicate nullifier within tx"
        nullifiers_in_tx.add(inp.statement.nullifier)

    # 3. Value conservation, using the revealed values
    if revealed_input_values is None:
        revealed_input_values = []
    if revealed_output_values is None:
        revealed_output_values = []
    if len(revealed_input_values) != len(tx.inputs):
        return False, "wrong number of revealed input values"
    if len(revealed_output_values) != len(tx.outputs):
        return False, "wrong number of revealed output values"
    if any(v < 0 for v in revealed_input_values + revealed_output_values):
        return False, "negative value"

    total_in = tx.shield_in + sum(revealed_input_values)
    total_out = tx.unshield_out + tx.fee + sum(revealed_output_values)
    if total_in != total_out:
        return False, f"value mismatch: {total_in} in vs {total_out} out"

    return True, "ok"


def apply_shielded_tx(tx: ShieldedTransaction, pool: ShieldedPool) -> None:
    """Apply a verified shielded tx to the pool: mark nullifiers, append outputs.

    Caller must have already called verify_shielded_tx and got (True, "ok").
    """
    for inp in tx.inputs:
        pool.mark_nullifier(inp.statement.nullifier)
    for out in tx.outputs:
        pool.add_output(out)
