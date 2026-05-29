"""ShieldTransaction: a Dilithium-signed on-chain shielding into the STARK pool.

Closes M8.7 Gap D. Before this, the STARK pool was populated by direct
`chain.shield_to_stark_pool(leaf)` calls and was *not* chain-replicated.
With ShieldTransactions, shielding becomes a real on-chain event:

    A ShieldTransaction debits `amount` from the depositor's transparent
    balance and appends a new leaf to the chain's STARK pool. Like every
    other transaction, it's gossiped, included in a block, and replayed
    when nodes sync. Every node ends up with the same STARK pool.

The depositor still keeps (sk, r, v) privately — only the leaf digest
`H(sk, r, v)` is published. So the chain learns "address X shielded
`amount` coins into the pool at this leaf" but cannot link that leaf
to a future spender, which is what the STARK proof handles.

Honest scope note:
    The depositor's transparent address IS visible on the shield tx —
    "X shielded N coins" is on the chain. That's an intrinsic leak of
    this design: somebody has to pay, so transparent-side accounting
    has to identify them. Fully hiding deposits requires its own
    mixer/CoinJoin layer, which is out of scope.

The wire format mirrors `Transaction` with two additional fields:
  * `leaf`: the 4-element Goldilocks digest (serialized as four ints)
  * `amount`: replaces Transaction's `amount`; debited from sender
"""

from __future__ import annotations

import hashlib
import json
from base64 import b64decode, b64encode
from dataclasses import dataclass, field
from typing import Optional, Tuple

from qchain.crypto import dilithium


# A STARK pool leaf is four u64 field elements (Goldilocks digest).
LeafDigest = Tuple[int, int, int, int]


@dataclass
class ShieldTransaction:
    """A depositor-signed shield into the STARK pool.

    Signature covers: (sender, leaf, amount, timestamp, nonce,
    chain_id-if-set). Like `Transaction`, `sender` is overwritten
    by the signer's Dilithium address on `sign()`.

    T20: when `chain_id` is set, it is bound into the signing payload.
    A legacy shield (chain_id=None) signs without it, preserving
    backward compatibility.
    """
    sender: str           # hex address (depositor)
    leaf: LeafDigest      # 4-tuple of u64 — the leaf being added
    amount: float         # transparent coins debited from sender
    timestamp: float
    nonce: int            # replay-protection
    public_key: str = ""  # base64
    signature: str = ""   # base64
    chain_id: Optional[str] = None    # T20 closure; None = legacy unbound

    # ---- canonical payload ----------------------------------------------

    def _payload(self) -> bytes:
        """The bytes that get signed. Ordering fixed for reproducibility.

        T20: chain_id included iff set. None produces legacy payload.
        """
        payload = {
            "sender": self.sender,
            "leaf": list(self.leaf),  # tuple → list for stable JSON
            "amount": self.amount,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
        }
        if self.chain_id is not None:
            payload["chain_id"] = self.chain_id
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    def txid(self) -> str:
        """Stable hash identifier including the signature."""
        full = self._payload() + self.signature.encode()
        return hashlib.sha256(full).hexdigest()

    # ---- signing ---------------------------------------------------------

    def sign(self, keypair: "dilithium.Keypair") -> None:
        """Attach a Dilithium signature; overwrite sender with derived address."""
        self.sender = keypair.address()
        self.public_key = b64encode(keypair.public_key).decode()
        sig = dilithium.sign(keypair.secret_key, self._payload())
        self.signature = b64encode(sig).decode()

    def verify(self) -> bool:
        """Verify signature, sender↔pubkey binding, and basic structure."""
        if not self.signature or not self.public_key:
            return False
        if self.amount <= 0:
            return False
        if not isinstance(self.leaf, (list, tuple)) or len(self.leaf) != 4:
            return False
        # All four leaf elements must be non-negative u64.
        for elem in self.leaf:
            if not isinstance(elem, int) or elem < 0 or elem >= (1 << 64):
                return False
        try:
            pk = b64decode(self.public_key)
            sig = b64decode(self.signature)
        except Exception:
            return False
        # Sender must equal the address derived from the public key —
        # same anti-impersonation check the transparent Transaction does.
        expected_addr = hashlib.sha256(pk).hexdigest()[:40]
        if expected_addr != self.sender:
            return False
        return dilithium.verify(pk, self._payload(), sig)

    # ---- serialization ---------------------------------------------------

    def to_dict(self) -> dict:
        d = {
            "sender": self.sender,
            "leaf": list(self.leaf),
            "amount": self.amount,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "public_key": self.public_key,
            "signature": self.signature,
        }
        # T20: only emit chain_id if set, keeping legacy on-wire bytes
        # identical to pre-T20 format for backward compatibility.
        if self.chain_id is not None:
            d["chain_id"] = self.chain_id
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "ShieldTransaction":
        return cls(
            sender=d["sender"],
            leaf=tuple(d["leaf"]),  # JSON gives a list; normalize to tuple
            amount=d["amount"],
            timestamp=d["timestamp"],
            nonce=d["nonce"],
            public_key=d.get("public_key", ""),
            signature=d.get("signature", ""),
            chain_id=d.get("chain_id"),    # T20: None if absent (legacy)
        )
