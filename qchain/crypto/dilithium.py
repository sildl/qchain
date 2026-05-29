"""
Post-quantum signatures using Dilithium (ML-DSA).

Dilithium is a lattice-based signature scheme standardized by NIST as ML-DSA
(FIPS 204). It's believed to be secure against attacks by both classical and
quantum computers, unlike ECDSA which Shor's algorithm can break.

We use pqcrypto.sign.ml_dsa_65 which corresponds to Dilithium3 / ML-DSA-65,
giving NIST Level 3 post-quantum security. Sizes for this variant:
  public key:  1952 bytes
  secret key:  4032 bytes
  signature:   3309 bytes
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

try:
    from pqcrypto.sign import ml_dsa_65 as _dilithium
except ImportError as e:
    raise ImportError(
        "pqcrypto not installed. Run: pip install pqcrypto"
    ) from e


@dataclass(frozen=True)
class Keypair:
    """A Dilithium public/secret keypair. Treat secret_key like a password."""
    public_key: bytes
    secret_key: bytes

    def address(self) -> str:
        """Derive a short hex address from the public key."""
        return hashlib.sha256(self.public_key).hexdigest()[:40]


def generate_keypair() -> Keypair:
    """Create a fresh Dilithium keypair."""
    pk, sk = _dilithium.generate_keypair()
    return Keypair(public_key=pk, secret_key=sk)


def sign(secret_key: bytes, message: bytes) -> bytes:
    """Sign a message. Returns the detached signature."""
    return _dilithium.sign(secret_key, message)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Check whether `signature` is a valid Dilithium signature of `message`."""
    try:
        return bool(_dilithium.verify(public_key, message, signature))
    except Exception:
        return False
