"""Transactions signed with Dilithium post-quantum signatures."""

from __future__ import annotations

import hashlib
import json
import time
from base64 import b64decode, b64encode
from dataclasses import asdict, dataclass, field
from typing import Optional

from qchain.crypto import dilithium


@dataclass
class Transaction:
    """A signed transfer of value from one address to another.

    The signature covers the canonical JSON of (sender, recipient, amount,
    timestamp, nonce, chain_id-if-set). Public key is included so verifiers
    don't need a separate key registry; the sender address is derived from
    it.

    T20 closure: when `chain_id` is set, it is bound into the signing
    payload. A signed tx with chain_id="qchain-v1" will not verify against
    a different chain_id, defending against accidental cross-network replay.
    Legacy transactions with chain_id=None continue to sign without it,
    preserving backward compatibility for chain files that predate this
    pass.
    """
    sender: str           # hex address (or "COINBASE" for block rewards)
    recipient: str        # hex address
    amount: float
    timestamp: float
    nonce: int            # prevents replay of identical (sender, recipient, amount)
    public_key: str = ""  # base64 — empty for coinbase txs
    signature: str = ""   # base64 — empty for coinbase txs
    chain_id: Optional[str] = None    # T20 closure; None = legacy unbound

    # ---- canonical bytes --------------------------------------------------

    def _payload(self) -> bytes:
        """The bytes that get signed. Ordering is fixed for reproducibility.

        T20: chain_id is included in the payload IFF set. A None chain_id
        produces the legacy payload unchanged — existing chain files with
        unbound transactions continue to verify.
        """
        payload = {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
        }
        if self.chain_id is not None:
            payload["chain_id"] = self.chain_id
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    def txid(self) -> str:
        """A stable hash identifier including the signature."""
        full = self._payload() + self.signature.encode()
        return hashlib.sha256(full).hexdigest()

    # ---- signing ----------------------------------------------------------

    def sign(self, keypair: dilithium.Keypair) -> None:
        """Attach a Dilithium signature using the given keypair.

        Also overwrites `sender` with the address derived from the public key,
        so a transaction can't claim to be from someone else.
        """
        self.sender = keypair.address()
        self.public_key = b64encode(keypair.public_key).decode()
        sig = dilithium.sign(keypair.secret_key, self._payload())
        self.signature = b64encode(sig).decode()

    def verify(self) -> bool:
        """Check the signature and that `sender` matches the public key."""
        if self.sender == "COINBASE":
            return True  # block rewards aren't signed
        if not self.signature or not self.public_key:
            return False
        try:
            pk = b64decode(self.public_key)
            sig = b64decode(self.signature)
        except Exception:
            return False
        # The claimed sender must actually be derived from this public key,
        # otherwise anyone could attach their own valid signature to a tx
        # that drains someone else's account.
        expected_addr = hashlib.sha256(pk).hexdigest()[:40]
        if expected_addr != self.sender:
            return False
        return dilithium.verify(pk, self._payload(), sig)

    # ---- serialization ----------------------------------------------------

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Transaction":
        return cls(**d)


def coinbase(recipient: str, amount: float) -> Transaction:
    """A block reward. Has no sender and no signature."""
    return Transaction(
        sender="COINBASE",
        recipient=recipient,
        amount=amount,
        timestamp=time.time(),
        nonce=0,
    )
