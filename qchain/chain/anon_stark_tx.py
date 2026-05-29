"""M8.5 — STARK-anon transaction wire format.

A STARKAnonTransaction is the on-chain footprint for a single anonymous
spend backed by a zk-STARK proof. Compared to M4's AnonTransaction, this is
simpler in capability but stronger in anonymity:

  * One nullifier (one input note) per tx
  * One transparent recipient + amount
  * No new shielded outputs
  * No Pedersen value commitments

What's public:
  * the Merkle root the proof was made against
  * the nullifier (so chain rejects double-spend)
  * the unshield recipient (transparent address)
  * the unshield amount + fee
  * the STARK proof bytes

What's hidden:
  * which leaf in the pool was spent
  * the spender's secret key, randomness, value
  * the Merkle path siblings

## Soundness summary

* The STARK proves "I know (leaf, path) such that walking from leaf using
  path reaches the public root." This binds the spend to a leaf in the
  current pool.
* The nullifier is a deterministic function of the secret key; spending the
  same note twice produces the same nullifier, and the chain rejects it.
* The unshield amount and recipient are public; the chain updates
  transparent balances using them.

## What this DOESN'T prove (honest scope)

* Value conservation. M8.5 trusts the spender's declared unshield amount.
  A spender could publish unshield_out=1000 while their actual note was
  worth 100; the STARK proof doesn't constrain this. M4 used Pedersen
  commitments to enforce conservation; M8.5 doesn't. Production zk-STARKs
  for shielded payments embed value-conservation constraints in the AIR
  itself (i.e. the proof would also assert "note value = unshield_out + fee").
  This is real M8.6+ work.
* The connection between the nullifier and the leaf. M8.5's nullifier
  scheme uses the same secret key as the leaf commitment, so an attacker
  cannot mint a nullifier without knowing the sk. But the STARK doesn't
  cryptographically *prove* this binding — it just relies on the note
  owner constructing both correctly. A production system would prove
  inside the STARK that nullifier and leaf share a sk.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Optional, Set

import qstark_py as q

from qchain.crypto.anon_stark import (
    Digest, STARKNote, bytes_to_digest, digest_to_bytes,
    MERKLE_DEPTH,
)


@dataclass
class STARKAnonTransaction:
    """A STARK-anonymous transaction.

    M8.11 Phase 3: now supports partial spends with a change output. The
    spender's STARK proof attests that
      v_in == unshield_amount + fee + v_out
    where v_out is the value of a NEW shielded note H(sk_out, r_out, v_out)
    that the chain appends to the STARK pool when this tx is mined.
    The spender keeps (sk_out, r_out, v_out) privately and can spend it later.

    For full spends (no change), the spender passes v_out=0 with random
    (sk_out, r_out), producing a dummy output_leaf that makes full spends
    indistinguishable from partial spends with tiny change values.
    Same pattern as Zcash Sapling's dummy outputs.
    """

    # Public inputs to the STARK
    merkle_root: Digest           # the pool root the proof attests against

    # Other public fields
    nullifier: Digest             # spent-note nullifier (rejects double-spend)
    unshield_recipient: str       # transparent address receiving unshield_out
    unshield_amount: int          # transparent value
    fee: int                       # transparent fee to proposer

    # M8.11: new output (change) note hash that gets appended to STARK pool
    # when this tx is mined. H(sk_out, r_out, v_out) — spender retains the
    # secrets to spend the change later.
    output_leaf: Digest

    # The STARK proof bytes
    proof: bytes

    timestamp: float = field(default_factory=time.time)

    # T20 closure: identifies the chain this tx targets. NOT bound to the
    # STARK proof (that would require modifying the AIR). Checked at chain
    # admission only. Defends against ACCIDENTAL cross-network replay; an
    # active attacker modifying this field after broadcast wouldn't be
    # caught by this check (proof itself doesn't bind it). See
    # THREAT-MODEL.md T20 for the documented carve-out.
    chain_id: Optional[str] = None

    # -----------------------------------------------------------------
    # Identity / serialization
    # -----------------------------------------------------------------

    def txid(self) -> str:
        """Stable transaction ID: SHA-256 of canonical encoding."""
        h = hashlib.sha256()
        h.update(b"STARKAnonTx")
        h.update(digest_to_bytes(self.merkle_root))
        h.update(digest_to_bytes(self.nullifier))
        h.update(self.unshield_recipient.encode())
        h.update(self.unshield_amount.to_bytes(8, "big", signed=False))
        h.update(self.fee.to_bytes(8, "big", signed=False))
        h.update(digest_to_bytes(self.output_leaf))  # M8.11
        h.update(self.proof)
        return h.hexdigest()

    def to_dict(self) -> dict:
        d = {
            "kind": "stark_anon",
            "merkle_root": list(self.merkle_root),
            "nullifier": list(self.nullifier),
            "unshield_recipient": self.unshield_recipient,
            "unshield_amount": self.unshield_amount,
            "fee": self.fee,
            "output_leaf": list(self.output_leaf),  # M8.11
            "proof": self.proof.hex(),
            "timestamp": self.timestamp,
        }
        # T20: only emit chain_id if set, keeping legacy payloads bit-for-bit
        # identical for backward compat with pre-T20 chain files.
        if self.chain_id is not None:
            d["chain_id"] = self.chain_id
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "STARKAnonTransaction":
        return cls(
            merkle_root=tuple(d["merkle_root"]),       # type: ignore[arg-type]
            nullifier=tuple(d["nullifier"]),           # type: ignore[arg-type]
            unshield_recipient=d["unshield_recipient"],
            unshield_amount=d["unshield_amount"],
            fee=d["fee"],
            output_leaf=tuple(d["output_leaf"]),       # type: ignore[arg-type]  M8.11
            proof=bytes.fromhex(d["proof"]),
            timestamp=d.get("timestamp", time.time()),
            chain_id=d.get("chain_id"),                # T20: None if missing (legacy)
        )

    # -----------------------------------------------------------------
    # Verification
    # -----------------------------------------------------------------

    def verify(
        self,
        current_root: Digest,
        seen_nullifiers: Set[Digest],
    ) -> tuple[bool, str]:
        """Verify this transaction against the current pool state.

        Returns (ok, reason). On failure, reason describes which check broke.
        """
        # 1. Structural sanity
        if self.unshield_amount < 0:
            return False, "negative unshield amount"
        if self.fee < 0:
            return False, "negative fee"
        if not self.unshield_recipient:
            return False, "empty recipient"

        # 2. The Merkle root in the tx must match the current pool root.
        #    (For finality: a tx is valid only against the root that was
        #     current when it was constructed. If the pool has grown since,
        #     the spender must re-prove against the new root.)
        if self.merkle_root != current_root:
            return False, (f"stale Merkle root: tx attests to "
                          f"{self.merkle_root[0]}... but current is "
                          f"{current_root[0]}...")

        # 3. Nullifier must not already be spent.
        if self.nullifier in seen_nullifiers:
            return False, "nullifier already seen (double-spend)"

        # 4. The STARK proof must verify against the claimed root, nullifier,
        #    declared amount/fee, AND the output_leaf (M8.11). The proof's
        #    Fiat-Shamir transcript binds all five public inputs; if the tx
        #    body declares different values than what the proof was generated
        #    for, FS challenges won't match and verification fails.
        try:
            ok = q.verify_m86_membership(
                self.proof, self.merkle_root, self.nullifier,
                self.unshield_amount, self.fee,
                self.output_leaf,
            )
        except Exception as e:
            return False, f"STARK verification raised: {type(e).__name__}: {e}"
        if not ok:
            return False, "STARK proof failed to verify"

        return True, "ok"


# ---------------------------------------------------------------------------
# Tx construction helper
# ---------------------------------------------------------------------------

def create_stark_anon_tx(
    note: STARKNote,
    leaf_idx: int,
    tree,                              # STARKAnonTree
    unshield_recipient: str,
    unshield_amount: int,
    fee: int = 0,
    change_note: Optional[STARKNote] = None,
) -> STARKAnonTransaction:
    """Build a STARK-anon transaction spending `note` at `leaf_idx`.

    The caller (the note owner) must know:
      * the note's preimage (sk, randomness, value)
      * the note's position in the tree
      * the current pool root and authentication path

    M8.11 partial-spend invariants:
      * unshield_amount + fee + change_value == note.value
        (value conservation; the AIR rejects with witness-inconsistency otherwise)
      * unshield_amount + fee + change_value must not overflow u64 (field-wrap defense)

    `change_note` is the spender's new shielded note (the change output).
      * For partial spends: caller provides a STARKNote with their chosen
        secrets and the change value. They retain it to spend later.
      * For full spends with no real change: pass None; this function
        generates a dummy STARKNote with random (sk_out, r_out) and
        value=0, so the chain still appends an indistinguishable leaf.
        Same pattern as Zcash Sapling's dummy outputs.

    Returns a ready-to-broadcast STARKAnonTransaction.
    The spender's `change_note` (if real) must be tracked separately by
    the wallet — the chain only sees its hash.
    """
    if unshield_amount < 0:
        raise ValueError("unshield_amount must be non-negative")
    if fee < 0:
        raise ValueError("fee must be non-negative")

    # M8.11: full-spend pattern when no change note provided
    if change_note is None:
        change_note = STARKNote.random(value=0)
    if change_note.value < 0:
        raise ValueError("change_note value must be non-negative")

    total = unshield_amount + fee + change_note.value

    # M8.8-A1 Phase 3 + M8.11: u64-overflow defense.
    if total >= (1 << 64):
        raise ValueError(
            f"unshield_amount + fee + change_value ({total}) overflows u64 — "
            "rejected to prevent field-wrap attack"
        )
    # M8.11: three-way value conservation. The AIR will reject with
    # witness-inconsistency if this fails; we surface a clearer error here.
    if total != int(note.value):
        raise ValueError(
            f"value conservation: note.value ({int(note.value)}) != "
            f"unshield_amount ({unshield_amount}) + fee ({fee}) + "
            f"change_value ({change_note.value})"
        )

    # Verify the note actually sits at leaf_idx (defensive)
    expected_leaf = note.leaf()
    actual_leaf = tree._layers[0][leaf_idx]
    if actual_leaf != expected_leaf:
        raise ValueError(
            f"note's leaf doesn't match tree position {leaf_idx}: "
            f"note.leaf()={expected_leaf[0]}... vs tree={actual_leaf[0]}..."
        )

    # Build the auth path and generate the M8.6 + M8.8-A1 + M8.11 STARK proof.
    # The proof binds:
    #   - nullifier to (sk, r, v) (M8.6 / Gap B)
    #   - v to (unshield_amount + fee + v_out) via bit decomposition (M8.8-A1 + M8.11)
    #   - output_leaf to H(sk_out, r_out, v_out) (M8.11 partial-spend)
    path = tree.auth_path(leaf_idx)
    proof, claimed_root, claimed_nullifier, claimed_output_leaf = q.prove_m86_membership(
        note.sk, note.randomness, note.value, path,
        unshield_amount, fee,
        change_note.sk, change_note.randomness, change_note.value,
    )

    # Sanity: the STARK's computed root should match the tree's current root
    if claimed_root != tree.root():
        raise RuntimeError(
            "STARK computed root doesn't match tree root — "
            "tree may have changed during proof construction"
        )
    # Sanity: the STARK's computed nullifier should match note.nullifier()
    note_nullifier = note.nullifier()
    if claimed_nullifier != note_nullifier:
        raise RuntimeError(
            "STARK computed nullifier doesn't match note.nullifier() — "
            "check that the nullifier scheme in the chain matches "
            "what the STARK enforces (H(sk+1, r, v))"
        )
    # Sanity: the STARK's computed output_leaf should match change_note.leaf()
    expected_output_leaf = change_note.leaf()
    if claimed_output_leaf != expected_output_leaf:
        raise RuntimeError(
            "STARK computed output_leaf doesn't match change_note.leaf() — "
            "check that the leaf-hash scheme matches what the STARK enforces"
        )

    return STARKAnonTransaction(
        merkle_root=tree.root(),
        nullifier=claimed_nullifier,
        unshield_recipient=unshield_recipient,
        unshield_amount=unshield_amount,
        fee=fee,
        output_leaf=claimed_output_leaf,
        proof=proof,
    )
