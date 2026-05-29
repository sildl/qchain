"""
Cryptographic primitives for the shielded transaction layer.

Everything here is hash-based, which makes it post-quantum safe — Grover's
algorithm gives a quadratic speedup on hash preimage search, but doubling
the output size (which SHA-256 already provides) restores the security
margin. Unlike elliptic-curve cryptography, hash functions don't fall to
Shor's algorithm.

The constructions:

  Commitment   : commit(value, recipient_pk, randomness) = H("note" || ...)
                 Hiding: without the randomness, the value is unknowable.
                 Binding: cannot find a different (v, pk, r) hashing to the
                          same commitment without breaking SHA-256.

  Nullifier    : nullify(secret_key, note_id) = H("null" || sk || note_id)
                 One-way: cannot recover sk or note_id from the nullifier.
                 Unlinkable: cannot link a nullifier back to its commitment
                            without knowing sk.

  Fiat-Shamir  : turn an interactive sigma-protocol challenge into a
                 deterministic hash of the prover's commitments. Standard
                 trick for making interactive proofs non-interactive.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Domain-separated hashing
# ---------------------------------------------------------------------------
# Every hash use gets a unique tag (e.g. b"note", b"null", b"chal") so that
# a hash output for one purpose can't be confused with one for another.
# Production systems do exactly this; without it, weird cross-protocol
# attacks become possible.

def H(tag: bytes, *parts: bytes) -> bytes:
    """Domain-separated SHA-256."""
    h = hashlib.sha256()
    h.update(len(tag).to_bytes(2, "big"))
    h.update(tag)
    for p in parts:
        h.update(len(p).to_bytes(4, "big"))
        h.update(p)
    return h.digest()


# ---------------------------------------------------------------------------
# Notes and commitments
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Note:
    """A spendable unit of shielded value.

    Conceptually like a banknote in a sealed envelope: only the recipient
    can open it. Sent to a recipient address, holds a value, has random
    blinding so identical (value, recipient) notes still hash differently.

    All fields are private to the recipient. Only the *commitment* derived
    from these fields ever appears on-chain.
    """
    value: int                # amount in smallest units
    recipient_pk: bytes       # recipient's Dilithium public key
    randomness: bytes         # 32 random bytes — blinds the commitment
    note_id: bytes            # 32 random bytes — used for the nullifier

    def commitment(self) -> bytes:
        """The note's on-chain identifier. Hides the value and recipient."""
        return H(
            b"note",
            self.value.to_bytes(16, "big"),
            self.recipient_pk,
            self.randomness,
            self.note_id,
        )


def new_note(value: int, recipient_pk: bytes) -> Note:
    """Create a fresh note with cryptographically random blinding."""
    if value < 0:
        raise ValueError("note value cannot be negative")
    return Note(
        value=value,
        recipient_pk=recipient_pk,
        randomness=secrets.token_bytes(32),
        note_id=secrets.token_bytes(32),
    )


# ---------------------------------------------------------------------------
# Nullifiers
# ---------------------------------------------------------------------------

def nullifier(secret_key: bytes, note_id: bytes) -> bytes:
    """The public spend-marker for a note.

    Published when the note is spent. The chain rejects any nullifier
    that's been seen before — that's how double-spending is prevented in
    the shielded pool.

    Critically, the nullifier is computed from the *secret* key, not the
    public key. This means:
      1. Only the note's owner can compute it (anyone watching the chain
         sees the nullifier but can't link it to a specific commitment).
      2. It's deterministic: spending the same note twice produces the
         same nullifier, which the chain detects.
    """
    return H(b"null", secret_key, note_id)


# ---------------------------------------------------------------------------
# Fiat-Shamir transcripts
# ---------------------------------------------------------------------------
# A sigma protocol normally goes: prover sends commitment, verifier sends a
# random challenge, prover sends response. Fiat-Shamir replaces the verifier
# with a hash function: the challenge is hash(commitment), which the prover
# can't influence after fixing the commitment. This makes the proof
# non-interactive (one message, no back-and-forth) but otherwise as sound.

class Transcript:
    """Builds a Fiat-Shamir challenge from labelled prover messages.

    Using a transcript object (instead of just hashing concatenated bytes)
    prevents a class of attacks where reordering messages collides
    challenges. Each `append` is domain-separated by its label.
    """

    def __init__(self, protocol_name: bytes) -> None:
        self._state = hashlib.sha256()
        self._state.update(len(protocol_name).to_bytes(2, "big"))
        self._state.update(protocol_name)

    def append(self, label: bytes, data: bytes) -> "Transcript":
        self._state.update(len(label).to_bytes(2, "big"))
        self._state.update(label)
        self._state.update(len(data).to_bytes(4, "big"))
        self._state.update(data)
        return self

    def challenge(self, label: bytes, n_bytes: int = 32) -> bytes:
        # Branch the state so we can keep appending after extracting a
        # challenge — important when a proof needs multiple challenges.
        branch = self._state.copy()
        branch.update(b"\x00challenge")
        branch.update(len(label).to_bytes(2, "big"))
        branch.update(label)
        out = b""
        counter = 0
        while len(out) < n_bytes:
            h = branch.copy()
            h.update(counter.to_bytes(4, "big"))
            out += h.digest()
            counter += 1
        return out[:n_bytes]
