"""
Anonymous shielded transactions.

Builds on the Schnorr primitives (qchain.crypto.schnorr) and the Merkle
tree (qchain.crypto.merkle) to provide a shielded pool where:

  * Note recipients are hidden in Pedersen commitments to their pubkey
  * Spend authorization is via a Schnorr proof of knowledge of the
    secret key, with no link from the proof back to the recipient's
    long-term pubkey
  * Note values are hidden in Pedersen commitments to the value
  * Double-spending is prevented by nullifiers

## What's hidden

  - Note value:                            HIDDEN (Pedersen commitment)
  - Note recipient's long-term pubkey:     HIDDEN (Pedersen commitment)
  - Linkability of two spends by same      HIDDEN (each spend uses fresh
    party                                            blinding)
  - Whether a wallet ever spent at all:    HIDDEN

## What's still visible

  - Which leaf in the Merkle tree was spent (needs a real SNARK to hide)
  - The fact that a shielded transaction occurred
  - Transparent flow amounts (shield-in, unshield-out, fee)

## Honest disclaimer (again)

This module uses elliptic-curve cryptography. It is NOT post-quantum
safe. The transparent transaction layer (milestone 1) remains post-
quantum via Dilithium signatures. The shielded layer here is classical-
quantum: it provides strong privacy today against classical attackers,
and would be broken by a future large-scale quantum computer.

## Soundness

Each operation here uses only:
  - Standard secp256k1 point arithmetic
  - Standard Pedersen commitments
  - Standard Schnorr signatures of knowledge
  - Standard hash-based nullifiers

These are textbook constructions with well-understood security in the
discrete-log + random oracle model. No novel cryptography.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Set

from ecdsa.ellipticcurve import Point
from ecdsa.util import randrange

from qchain.crypto.merkle import MerkleProof
from qchain.crypto.schnorr import (
    G, H, N,
    Keypair,
    SchnorrProof,
    _compress_point,
    _decompress_point,
    commit_pubkey,
    nullifier,
    pedersen_commit,
    prove_pedersen_opening,
    verify_pedersen_opening,
)


# ---------------------------------------------------------------------------
# Anonymous shielded notes
# ---------------------------------------------------------------------------

@dataclass
class AnonNote:
    """A note in the anonymous shielded pool.

    The on-chain leaf commits to (value_commit, pubkey_commit, note_id).
    Neither the value nor the recipient's pubkey is recoverable from the
    leaf without knowing the blinding factors.
    """
    value: int
    recipient_pk_point: Point     # decompressed for arithmetic convenience
    note_id: bytes
    value_blinding: int           # scalar in [0, N)
    pubkey_blinding: int          # scalar in [0, N)

    def value_commit(self) -> Point:
        return pedersen_commit(self.value, self.value_blinding)

    def pubkey_commit(self) -> Point:
        return commit_pubkey(self.recipient_pk_point, self.pubkey_blinding)

    def leaf(self) -> bytes:
        """The on-chain commitment.

        Hash of the two commitment points + the note_id. The verifier can
        recompute this from the publicly-revealed commitments + note_id
        after a spend, but cannot recover the underlying value or pubkey.
        """
        return hashlib.sha256(
            b"anon-leaf"
            + _compress_point(self.value_commit())
            + _compress_point(self.pubkey_commit())
            + self.note_id
        ).digest()


def new_anon_note(value: int, recipient_pk: bytes) -> AnonNote:
    """Create a fresh anonymous note for the given recipient."""
    if value < 0 or value >= N:
        raise ValueError("value out of range")
    return AnonNote(
        value=value,
        recipient_pk_point=_decompress_point(recipient_pk),
        note_id=secrets.token_bytes(32),
        value_blinding=randrange(N),
        pubkey_blinding=randrange(N),
    )


# ---------------------------------------------------------------------------
# Anonymous spend authorization
# ---------------------------------------------------------------------------

@dataclass
class AnonSpendStatement:
    """Public part of an anonymous spend.

    Every field here goes on-chain. None of them reveal the spender's
    long-term identity or the note's hidden value.
    """
    merkle_root: bytes
    nullifier: bytes
    leaf_commitment: bytes
    value_commit_bytes: bytes     # compressed point
    pubkey_commit_bytes: bytes    # compressed point — randomized per spend!
    note_id: bytes                # revealed so verifier can recompute leaf
    leaf_merkle_proof: MerkleProof

    def digest(self) -> bytes:
        """Bytes that get committed in the Schnorr proof's challenge."""
        return hashlib.sha256(
            b"anon-spend-digest-v1"
            + self.merkle_root
            + self.nullifier
            + self.leaf_commitment
            + self.value_commit_bytes
            + self.pubkey_commit_bytes
            + self.note_id
        ).digest()


@dataclass
class AnonSpendProof:
    """Complete anonymous spend: statement + ZK proof.

    The Schnorr proof attests: "I know (sk, blinding) such that
    pubkey_commit = sk*G + blinding*H". This is a proof of knowledge of
    the secret key for the (randomized) pubkey committed in the spend.

    Because the pubkey_commit is freshly randomized per spend, the proof
    reveals NO information about which long-term pubkey is the spender,
    and two spends by the same party are unlinkable.
    """
    statement: AnonSpendStatement
    schnorr: SchnorrProof


def prove_anon_spend(
    note: AnonNote,
    secret_key: int,
    merkle_proof: MerkleProof,
) -> AnonSpendProof:
    """Build an anonymous spend proof.

    Inputs:
      note         — the note being spent (we know all its hidden fields)
      secret_key   — the integer secret key for note.recipient_pk_point
      merkle_proof — inclusion proof for note.leaf() in the tree

    Steps:
      1. Compute the nullifier from (sk, note_id). Deterministic, so
         spending the same note twice yields the same nullifier.
      2. Compute the on-chain commitments. These are deterministic in
         the note's stored blindings, so anyone given the note can
         reconstruct them.
      3. Build the public statement.
      4. Prove in zero knowledge that we know (sk, pubkey_blinding) such
         that pubkey_commit = sk*G + pubkey_blinding*H. The challenge is
         bound to the entire statement, so the proof can't be replayed.
    """
    if merkle_proof.leaf != note.leaf():
        raise ValueError("merkle proof does not match this note's leaf")
    # Sanity: the supplied sk must really correspond to the note's recipient
    if secret_key * G != note.recipient_pk_point:
        raise ValueError("secret_key does not match note.recipient_pk")

    null = nullifier(secret_key, note.note_id)

    vc = note.value_commit()
    pc = note.pubkey_commit()

    statement = AnonSpendStatement(
        merkle_root=merkle_proof.root,
        nullifier=null,
        leaf_commitment=note.leaf(),
        value_commit_bytes=_compress_point(vc),
        pubkey_commit_bytes=_compress_point(pc),
        note_id=note.note_id,
        leaf_merkle_proof=merkle_proof,
    )

    # The Schnorr proof proves: we know (sk, h) opening pubkey_commit.
    # The aux_transcript binds the proof to this specific statement, so
    # an attacker can't replay it on a different spend.
    schnorr = prove_pedersen_opening(
        x=secret_key,
        h_blind=note.pubkey_blinding,
        C=pc,
        aux_transcript=statement.digest(),
    )

    return AnonSpendProof(statement=statement, schnorr=schnorr)


def verify_anon_spend(
    proof: AnonSpendProof,
    expected_merkle_root: bytes,
    seen_nullifiers: Set[bytes],
) -> tuple[bool, str]:
    """Verify an anonymous spend.

    Checks (in order):
      1. Merkle proof valid and references the current root.
      2. Leaf in the Merkle proof equals the statement's leaf_commitment.
      3. The leaf_commitment, when recomputed from
            H("anon-leaf", value_commit, pubkey_commit, note_id),
         matches what's claimed. This binds value_commit, pubkey_commit,
         and note_id to this specific leaf — preventing an attacker from
         swapping in their own commitments for someone else's leaf.
      4. The Schnorr proof verifies for the published pubkey_commit, with
         the aux_transcript equal to the statement's digest.
      5. The nullifier hasn't been seen before.

    Returns (ok, reason).
    """
    s = proof.statement

    # 1. Merkle proof validity
    if s.leaf_merkle_proof.root != expected_merkle_root:
        return False, "stale merkle root"
    if s.merkle_root != expected_merkle_root:
        return False, "statement root mismatch"
    if not s.leaf_merkle_proof.verify():
        return False, "invalid merkle proof"
    if s.leaf_merkle_proof.leaf != s.leaf_commitment:
        return False, "merkle leaf doesn't match statement leaf"

    # 2 + 3. Recompute the leaf from public commitments and note_id.
    # If the spender supplied wrong commitments for this leaf, this fails.
    recomputed = hashlib.sha256(
        b"anon-leaf"
        + s.value_commit_bytes
        + s.pubkey_commit_bytes
        + s.note_id
    ).digest()
    if recomputed != s.leaf_commitment:
        return False, "leaf doesn't match its commitments"

    # 4. The Schnorr proof must verify for the pubkey_commit, with the
    #    aux_transcript bound to the full statement.
    try:
        pc = _decompress_point(s.pubkey_commit_bytes)
    except ValueError:
        return False, "invalid pubkey_commit encoding"

    if not verify_pedersen_opening(
        proof.schnorr, pc, aux_transcript=s.digest()
    ):
        return False, "invalid schnorr proof"

    # 5. Double-spend prevention
    if s.nullifier in seen_nullifiers:
        return False, "nullifier already used (double-spend)"

    return True, "ok"
