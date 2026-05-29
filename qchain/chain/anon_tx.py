"""
Anonymous transactions for inclusion in blocks.

An AnonTransaction is the on-chain wire format for milestone-4 anonymous
spends. It bundles:

  * INPUTS:  zero or more AnonSpendProofs (each spends one shielded note)
  * OUTPUTS: zero or more new anonymous note commitments
  * SHIELD_IN:  transparent coins moving INTO the anonymous pool
  * UNSHIELD_OUT: transparent coins moving OUT, plus a transparent recipient
  * FEE:     transparent fee paid to the block proposer

Value conservation (enforced on every block apply):
    shield_in + Σ input_values  ==  unshield_out + Σ output_values + fee

Because input/output values are hidden in Pedersen commitments, we
exploit the additive homomorphism: the chain checks that the sum of
input value commitments minus the sum of output value commitments
equals a Pedersen commitment to (unshield_out + fee - shield_in)
under the spender's published net blinding. This way the chain enforces
balance without seeing individual values.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import List, Optional, Set

from ecdsa.ellipticcurve import Point

from qchain.crypto.anon import (
    AnonNote,
    AnonSpendProof,
    verify_anon_spend,
)
from qchain.crypto.merkle import MerkleTree
from qchain.crypto.schnorr import (
    G, H, N,
    _compress_point,
    _decompress_point,
    pedersen_commit,
)


# ---------------------------------------------------------------------------
# AnonOutput: a new shielded note's on-chain footprint
# ---------------------------------------------------------------------------

@dataclass
class AnonOutput:
    """A new anonymous note being created.

    On chain we publish:
      * The leaf commitment (gets appended to the Merkle tree)
      * The value commitment as a compressed EC point

    The recipient learns about their new note via an off-chain channel
    (in real Zcash, the sender encrypts the note to the recipient and
    posts the ciphertext on chain; we omit that for simplicity).
    """
    leaf_commitment: bytes
    value_commit_bytes: bytes      # compressed EC point

    @classmethod
    def from_note(cls, note: AnonNote) -> "AnonOutput":
        return cls(
            leaf_commitment=note.leaf(),
            value_commit_bytes=_compress_point(note.value_commit()),
        )


# ---------------------------------------------------------------------------
# AnonTransaction
# ---------------------------------------------------------------------------

@dataclass
class AnonTransaction:
    """An anonymous transaction.

    Use sparingly — these are expensive to verify (each input requires a
    Schnorr verification + a Merkle proof check).

    Value conservation is checked using:
      net_blinding = Σ input_blindings - Σ output_blindings
    which the spender publishes. The chain confirms:
      (Σ input_value_commits - Σ output_value_commits)
        == commit(net_value, net_blinding)
    where net_value = unshield_out + fee - shield_in is public.
    """
    inputs: List[AnonSpendProof]
    outputs: List[AnonOutput]
    shield_in: int                  # transparent → anon (public)
    unshield_out: int               # anon → transparent (public)
    unshield_recipient: str         # transparent address receiving unshield_out
    fee: int
    net_blinding: int               # Σ in - Σ out, mod N (revealed by spender)
    timestamp: float = field(default_factory=time.time)

    # T20 closure: identifies the chain this tx targets. NOT bound into the
    # Schnorr proof's digest (that would invalidate any in-flight proofs).
    # Checked at chain admission only. Same carve-out as STARK txs:
    # defends against accidental cross-network replay; active attackers
    # modifying this field after broadcast are not caught.
    chain_id: Optional[str] = None

    # -----------------------------------------------------------------
    # Identity & equality
    # -----------------------------------------------------------------

    def txid(self) -> str:
        """Stable transaction id. Same content -> same id."""
        h = hashlib.sha256()
        h.update(b"anon-tx-v1")
        h.update(len(self.inputs).to_bytes(4, "big"))
        for inp in self.inputs:
            h.update(inp.statement.nullifier)
        h.update(len(self.outputs).to_bytes(4, "big"))
        for out in self.outputs:
            h.update(out.leaf_commitment)
        h.update(self.shield_in.to_bytes(16, "big"))
        h.update(self.unshield_out.to_bytes(16, "big"))
        h.update(self.unshield_recipient.encode())
        h.update(self.fee.to_bytes(16, "big"))
        return h.hexdigest()

    # -----------------------------------------------------------------
    # Verification
    # -----------------------------------------------------------------

    def verify(
        self,
        anon_tree_root: bytes,
        seen_nullifiers: Set[bytes],
    ) -> tuple[bool, str]:
        """Verify the transaction against the current anon-pool state.

        Returns (ok, reason). On failure, reason describes which check
        broke. This is intentionally verbose so chain-replay debugging
        is tractable.
        """
        # 1. Structural sanity
        if len(self.inputs) == 0 and self.shield_in == 0:
            return False, "no value sources (need inputs or shield_in)"
        if len(self.outputs) == 0 and self.unshield_out == 0:
            return False, "no value sinks (need outputs or unshield_out)"
        if self.shield_in < 0 or self.unshield_out < 0 or self.fee < 0:
            return False, "negative public value"

        # 2. Each input must verify against the current Merkle root and
        #    not already be spent.
        nullifiers_in_tx: Set[bytes] = set()
        for inp in self.inputs:
            ok, reason = verify_anon_spend(inp, anon_tree_root, seen_nullifiers)
            if not ok:
                return False, f"input failed: {reason}"
            if inp.statement.nullifier in nullifiers_in_tx:
                return False, "duplicate nullifier within tx"
            nullifiers_in_tx.add(inp.statement.nullifier)

        # 3. Value conservation via Pedersen homomorphism.
        #    Let:
        #       VC_in  = Σ commit(v_i, b_i^in)   for each input
        #       VC_out = Σ commit(w_j, b_j^out)  for each output
        #       net_pub = unshield_out + fee - shield_in
        #    Then VC_in - VC_out should equal commit(net_pub, net_blinding)
        #    if the spender computed everything correctly.
        try:
            sum_in: Optional[Point] = None
            for inp in self.inputs:
                pt = _decompress_point(inp.statement.value_commit_bytes)
                sum_in = pt if sum_in is None else sum_in + pt
            sum_out: Optional[Point] = None
            for out in self.outputs:
                pt = _decompress_point(out.value_commit_bytes)
                sum_out = pt if sum_out is None else sum_out + pt
        except ValueError as e:
            return False, f"bad commitment encoding: {e}"

        # If no inputs and no outputs, just check transparent flow
        # (shouldn't happen given step 1, but defensive)
        net_value = (self.unshield_out + self.fee - self.shield_in) % N
        expected_diff = pedersen_commit(net_value, self.net_blinding)

        # Compute sum_in - sum_out. If one side is None, treat as identity.
        # The point at infinity is the identity element; ecdsa represents
        # it as INFINITY.
        if sum_in is None:
            # No inputs — value flow is shield_in → outputs + unshield_out + fee
            # Then sum_out must equal commit(shield_in - unshield_out - fee, net_blinding)
            # Algebraically equivalent to -expected_diff. Use that.
            lhs = sum_out
            rhs = -expected_diff
        elif sum_out is None:
            lhs = sum_in
            rhs = expected_diff
        else:
            lhs = sum_in + (-sum_out)
            rhs = expected_diff

        if lhs != rhs:
            return False, "value conservation failed (Pedersen sums mismatch)"

        return True, "ok"

    # -----------------------------------------------------------------
    # Serialization (lightweight — for blocks + persistence)
    # -----------------------------------------------------------------

    def to_dict(self) -> dict:
        d = {
            "_type": "anon",
            "inputs": [
                {
                    "nullifier": inp.statement.nullifier.hex(),
                    "leaf": inp.statement.leaf_commitment.hex(),
                    "merkle_root": inp.statement.merkle_root.hex(),
                    "value_commit": inp.statement.value_commit_bytes.hex(),
                    "pubkey_commit": inp.statement.pubkey_commit_bytes.hex(),
                    "note_id": inp.statement.note_id.hex(),
                    "merkle_path": [s.hex() for s in inp.statement.leaf_merkle_proof.siblings],
                    "leaf_index": inp.statement.leaf_merkle_proof.index,
                    "schnorr_R": inp.schnorr.R.hex(),
                    "schnorr_sx": inp.schnorr.s_x,
                    "schnorr_sh": inp.schnorr.s_h,
                }
                for inp in self.inputs
            ],
            "outputs": [
                {
                    "leaf": out.leaf_commitment.hex(),
                    "value_commit": out.value_commit_bytes.hex(),
                }
                for out in self.outputs
            ],
            "shield_in": self.shield_in,
            "unshield_out": self.unshield_out,
            "unshield_recipient": self.unshield_recipient,
            "fee": self.fee,
            "net_blinding": self.net_blinding,
            "timestamp": self.timestamp,
        }
        # T20: emit chain_id only if set (legacy bytes unchanged)
        if self.chain_id is not None:
            d["chain_id"] = self.chain_id
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "AnonTransaction":
        """Reconstruct an AnonTransaction from a dict (e.g. JSON from network)."""
        from qchain.crypto.anon import AnonSpendProof, AnonSpendStatement
        from qchain.crypto.merkle import MerkleProof
        from qchain.crypto.schnorr import SchnorrProof

        inputs: List[AnonSpendProof] = []
        for inp_d in d["inputs"]:
            null = bytes.fromhex(inp_d["nullifier"])
            leaf = bytes.fromhex(inp_d["leaf"])
            root = bytes.fromhex(inp_d["merkle_root"])
            siblings = [bytes.fromhex(s) for s in inp_d["merkle_path"]]
            mp = MerkleProof(
                leaf=leaf,
                index=inp_d["leaf_index"],
                siblings=siblings,
                root=root,
            )
            stmt = AnonSpendStatement(
                merkle_root=root,
                nullifier=null,
                leaf_commitment=leaf,
                value_commit_bytes=bytes.fromhex(inp_d["value_commit"]),
                pubkey_commit_bytes=bytes.fromhex(inp_d["pubkey_commit"]),
                note_id=bytes.fromhex(inp_d["note_id"]),
                leaf_merkle_proof=mp,
            )
            schnorr = SchnorrProof(
                R=bytes.fromhex(inp_d["schnorr_R"]),
                s_x=inp_d["schnorr_sx"],
                s_h=inp_d["schnorr_sh"],
            )
            inputs.append(AnonSpendProof(statement=stmt, schnorr=schnorr))

        outputs = [
            AnonOutput(
                leaf_commitment=bytes.fromhex(out_d["leaf"]),
                value_commit_bytes=bytes.fromhex(out_d["value_commit"]),
            )
            for out_d in d["outputs"]
        ]

        return cls(
            inputs=inputs,
            outputs=outputs,
            shield_in=d["shield_in"],
            unshield_out=d["unshield_out"],
            unshield_recipient=d["unshield_recipient"],
            fee=d["fee"],
            net_blinding=d["net_blinding"],
            timestamp=d.get("timestamp", 0.0),
            chain_id=d.get("chain_id"),    # T20: None if absent (legacy)
        )


# ---------------------------------------------------------------------------
# Helper: build a transaction with correct net_blinding
# ---------------------------------------------------------------------------

def compute_net_blinding(
    input_blindings: List[int],
    output_blindings: List[int],
) -> int:
    """net_blinding = Σ input - Σ output, mod N.

    The spender computes this from their own knowledge of all blindings,
    revealing it on chain so the verifier can check value conservation
    without learning any individual value.
    """
    acc = 0
    for b in input_blindings:
        acc = (acc + b) % N
    for b in output_blindings:
        acc = (acc - b) % N
    return acc
