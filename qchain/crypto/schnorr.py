"""
Schnorr signature of knowledge over secp256k1.

This is a **standard, well-known** zero-knowledge proof construction. It
proves "I know the discrete logarithm x of a point P = x*G" without
revealing x. The math is identical to the proofs used inside Bitcoin's
BIP-340 (taproot), Monero ring signatures, and countless academic
constructions.

## What it proves and why we can trust it

A Schnorr proof of knowledge has three formal security properties, each
proven in the cryptographic literature under standard assumptions:

  1. COMPLETENESS — honest provers always convince honest verifiers.
  2. SPECIAL SOUNDNESS — if two accepting transcripts share the same
     commitment but differ in challenge, you can extract the witness.
     This implies a cheating prover succeeds with probability at most
     1/|challenge_space| ≈ 2^-256.
  3. HONEST-VERIFIER ZERO KNOWLEDGE — the transcript distribution is
     simulatable from public inputs alone, so no information about x
     leaks. With Fiat-Shamir (modeled as a random oracle), this extends
     to malicious verifiers.

The construction is decades old, has been peer-reviewed and deployed
billions of times, and the implementation here uses the well-tested
`ecdsa` library's primitives for the actual point arithmetic. I'm not
inventing crypto; I'm composing standard pieces.

## What's hidden vs. revealed in a spend

For a shielded spend, the prover knows:
  * x  : the secret key
  * P  : the public key, P = x*G  (= the recipient inside the note)
  * The note's value, randomness, note_id
  * The Merkle inclusion proof for the note's leaf

We use a *commitment-to-pubkey* trick: instead of revealing P at spend
time (which would link this spend to anyone who saw P used elsewhere),
the prover publishes a fresh randomized commitment to P:
        C_pk = P + h*H
where h is fresh randomness per spend and H is a second generator with
unknown discrete log relative to G. The prover then proves in zero
knowledge that they know (x, h) such that
        C_pk = x*G + h*H
AND that C_pk corresponds to the recipient_pk inside the spent note.

This is a *Pedersen commitment* to the pubkey + a *Schnorr proof of
opening*. Standard textbook construction.

## What's hidden after this upgrade

Public on-chain data per spend:
  * The nullifier (same as before — prevents double-spend)
  * A randomized commitment to the spender's pubkey
  * The Merkle path to the spent leaf (= the leaf index is visible)
  * A Schnorr zero-knowledge proof
  * The value commitment

What an observer can NO LONGER tell:
  * Who the spender is (their actual pubkey)
  * Whether two spends are by the same party
  * Whether a particular wallet ever spent at all

What is still visible:
  * Which leaf in the Merkle tree was spent

## Post-quantum disclaimer

Schnorr signatures and Pedersen commitments rely on the hardness of the
discrete logarithm problem in elliptic-curve groups. Shor's algorithm
breaks DLog in polynomial time on a sufficiently large quantum computer.

This means: an attacker with a quantum computer of ~2300 logical qubits
could derive any wallet's secret key from its public commitment, break
the spend authorization, and forge transactions. As of the model's
knowledge cutoff such machines do not exist, but they may within
decades.

A post-quantum equivalent (lattice-based ZK proofs, e.g. STARKs over
prime fields using hash-based commitments only) is an active research
area; deploying one correctly is beyond what this learning project can
do. The post-quantum transparent transactions (milestone 1) remain
post-quantum safe; only the shielded layer is now classical-quantum.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Optional, Tuple

from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point, PointJacobi
from ecdsa.util import randrange

# ---------------------------------------------------------------------------
# Curve setup
# ---------------------------------------------------------------------------

_CURVE = SECP256k1
G = _CURVE.generator              # primary generator
N = _CURVE.order                  # group order (prime)


def _nothing_up_my_sleeve_H() -> Point:
    """A second generator H with unknown DLog relative to G.

    For Pedersen commitments we need two generators where nobody knows the
    discrete log of one with respect to the other. The standard "nothing
    up my sleeve" technique: hash a fixed string to a point. Anyone can
    reproduce H and verify there's no backdoor.

    We use a try-and-increment approach: hash "qchain-H||counter" until
    we get a value that's a valid x-coordinate on the curve.
    """
    # secp256k1 prime
    p = _CURVE.curve.p()
    counter = 0
    while True:
        h = hashlib.sha256(f"qchain-H-generator-v1-{counter}".encode()).digest()
        x = int.from_bytes(h, "big") % p
        # secp256k1: y^2 = x^3 + 7 mod p
        rhs = (pow(x, 3, p) + 7) % p
        # try to compute square root: rhs^((p+1)/4) since p ≡ 3 mod 4
        y = pow(rhs, (p + 1) // 4, p)
        if (y * y) % p == rhs:
            point = Point(_CURVE.curve, x, y, N)
            return point
        counter += 1


H = _nothing_up_my_sleeve_H()


# ---------------------------------------------------------------------------
# Key generation and Pedersen commitments
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Keypair:
    """An EC keypair on secp256k1. NOT post-quantum safe — see module docstring."""
    sk: int                       # scalar in [1, N-1]
    pk: bytes                     # compressed point: 33 bytes

    def pk_point(self) -> Point:
        return _decompress_point(self.pk)

    def address(self) -> str:
        """Short hex address for compatibility with the existing chain."""
        return hashlib.sha256(self.pk).hexdigest()[:40]


def generate_keypair() -> Keypair:
    sk = randrange(N)
    pk_point = sk * G
    return Keypair(sk=sk, pk=_compress_point(pk_point))


def _compress_point(p: Point) -> bytes:
    """Standard SEC1 compressed point format: 33 bytes."""
    x = int(p.x())
    y = int(p.y())
    prefix = b"\x02" if y % 2 == 0 else b"\x03"
    return prefix + x.to_bytes(32, "big")


def _decompress_point(data: bytes) -> Point:
    if len(data) != 33 or data[0] not in (2, 3):
        raise ValueError("invalid compressed point")
    prime = _CURVE.curve.p()
    x = int.from_bytes(data[1:], "big")
    rhs = (pow(x, 3, prime) + 7) % prime
    y = pow(rhs, (prime + 1) // 4, prime)
    if (y * y) % prime != rhs:
        raise ValueError("not a curve point")
    if (y % 2 == 0) != (data[0] == 2):
        y = prime - y
    return Point(_CURVE.curve, x, y, N)


def pedersen_commit(value: int, blinding: int) -> Point:
    """Pedersen commitment to an integer: C = value*G + blinding*H.

    Properties:
      * Hiding: with uniform blinding in [0, N), C reveals nothing about value.
      * Binding: finding (v', b') such that v*G + b*H = v'*G + b'*H requires
        computing dlog_G(H), which is infeasible.
      * Additively homomorphic: commit(v1, b1) + commit(v2, b2)
                              = commit(v1+v2, b1+b2). Used for value
        conservation across multiple inputs/outputs.
    """
    if value < 0 or value >= N:
        raise ValueError("value out of range")
    return value * G + blinding * H


def commit_pubkey(pk_point: Point, blinding: int) -> Point:
    """Randomize a pubkey for one-shot use: C_pk = pk + blinding*H.

    The verifier sees C_pk but cannot link it to pk unless they know the
    blinding. Same blinding on the same pk yields the same C_pk, so use a
    fresh blinding per spend.
    """
    return pk_point + blinding * H


# ---------------------------------------------------------------------------
# Schnorr signature of knowledge
# ---------------------------------------------------------------------------

@dataclass
class SchnorrProof:
    """Non-interactive Schnorr proof of knowledge of (x, h) such that
    C = x*G + h*H.

    Encoded as two scalars (the responses) plus a commitment point.
    """
    R: bytes                      # commitment point, compressed
    s_x: int                      # response for x
    s_h: int                      # response for h


def _hash_to_scalar(*parts: bytes) -> int:
    """Hash arbitrary bytes to a scalar mod N (Fiat-Shamir challenge)."""
    h = hashlib.sha512()  # wider hash to make modular bias negligible
    for p in parts:
        h.update(len(p).to_bytes(4, "big"))
        h.update(p)
    return int.from_bytes(h.digest(), "big") % N


def prove_pedersen_opening(
    x: int,
    h_blind: int,
    C: Point,
    aux_transcript: bytes = b"",
) -> SchnorrProof:
    """Prove knowledge of (x, h) such that C = x*G + h*H.

    Protocol (Schnorr-2DL, textbook):
      1. Pick random k_x, k_h in [0, N).
      2. Compute R = k_x*G + k_h*H.
      3. Challenge c = H(R || C || aux_transcript).
      4. Responses: s_x = k_x + c*x, s_h = k_h + c*h_blind  (all mod N).
      5. Output (R, s_x, s_h).

    The verifier checks: s_x*G + s_h*H == R + c*C.
    """
    # Sanity check: the witness must actually open the commitment
    assert (x * G + h_blind * H) == C, "witness doesn't open the commitment"

    k_x = randrange(N)
    k_h = randrange(N)
    R = k_x * G + k_h * H

    c = _hash_to_scalar(_compress_point(R), _compress_point(C), aux_transcript)

    s_x = (k_x + c * x) % N
    s_h = (k_h + c * h_blind) % N

    return SchnorrProof(R=_compress_point(R), s_x=s_x, s_h=s_h)


def verify_pedersen_opening(
    proof: SchnorrProof,
    C: Point,
    aux_transcript: bytes = b"",
) -> bool:
    """Verify a Schnorr proof of opening for commitment C."""
    try:
        R = _decompress_point(proof.R)
    except ValueError:
        return False

    if not (0 <= proof.s_x < N) or not (0 <= proof.s_h < N):
        return False

    c = _hash_to_scalar(proof.R, _compress_point(C), aux_transcript)

    lhs = proof.s_x * G + proof.s_h * H
    rhs = R + c * C
    return lhs == rhs


# ---------------------------------------------------------------------------
# Spend nullifier (still hash-based, still post-quantum on its own)
# ---------------------------------------------------------------------------

def nullifier(sk: int, note_id: bytes) -> bytes:
    """Spend marker: H("anon-null", sk_bytes, note_id).

    Same construction as before but takes an integer secret key.
    """
    sk_bytes = sk.to_bytes(32, "big")
    return hashlib.sha256(b"anon-null" + sk_bytes + note_id).digest()
