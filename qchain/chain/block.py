"""Blocks: containers of transactions linked into a chain by hash."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import List

from qchain.chain.transaction import Transaction


@dataclass
class Block:
    """One block in the chain.

    A block carries two parallel transaction lists:
      * `transactions`       — transparent (signed by Dilithium) txs
      * `anon_transactions`  — anonymous (Schnorr ZK) txs

    Both are committed into the block hash via a single Merkle-ish root.
    For backwards compatibility with milestone-1 blocks that had no anon
    txs, an empty `anon_transactions` list contributes a fixed empty-hash
    so the resulting block hash matches the original construction.
    """
    index: int
    previous_hash: str
    timestamp: float
    transactions: List[Transaction]
    nonce: int = 0
    proposer: str = ""
    # New in milestone 5: anonymous transactions in the same block.
    # Kept as a separate list because they have completely different
    # verification logic. The block hash binds both lists.
    anon_transactions: List["AnonTransaction"] = field(default_factory=list)  # type: ignore[name-defined]
    # New in milestone 8.5: STARK-anonymous transactions (zk-STARK proofs
    # via qstark_py). Coexist with M4 Schnorr-based anon transactions.
    stark_anon_transactions: List["STARKAnonTransaction"] = field(default_factory=list)  # type: ignore[name-defined]
    # New in M8.7-D: depositor-signed shield txs that put leaves into the
    # STARK pool. Apply BEFORE stark_anon_transactions in the same block
    # so a same-block "shield then spend" pattern works.
    shield_transactions: List["ShieldTransaction"] = field(default_factory=list)  # type: ignore[name-defined]
    # M10: mixer-layer transactions for anonymous deposits.
    # mixer_deposit_transactions populate the mixer pool (transparent → mixer).
    # mixer_withdraw_transactions consume mixer leaves anonymously and
    # credit the STARK pool (mixer → STARK pool, hiding the link).
    mixer_deposit_transactions: List["MixerDepositTransaction"] = field(default_factory=list)  # type: ignore[name-defined]
    mixer_withdraw_transactions: List["MixerWithdrawTransaction"] = field(default_factory=list)  # type: ignore[name-defined]

    # ---- hashing ----------------------------------------------------------

    def _header_payload(self) -> bytes:
        """Bytes that get hashed. Includes a root over BOTH tx lists."""
        tx_hashes = [tx.txid() for tx in self.transactions]
        tx_root = hashlib.sha256("".join(tx_hashes).encode()).hexdigest()

        header = {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "tx_root": tx_root,
            "nonce": self.nonce,
            "proposer": self.proposer,
        }
        # Only inject the anon-tx root if there are any, so existing
        # block hashes from milestones 1-3 remain stable.
        if self.anon_transactions:
            anon_hashes = [tx.txid() for tx in self.anon_transactions]
            header["anon_tx_root"] = hashlib.sha256(
                "".join(anon_hashes).encode()
            ).hexdigest()
        # Same idea for M8.5 stark_anon transactions: only inject if present
        # so blocks without them keep their pre-M8.5 hashes stable.
        if self.stark_anon_transactions:
            stark_hashes = [tx.txid() for tx in self.stark_anon_transactions]
            header["stark_anon_tx_root"] = hashlib.sha256(
                "".join(stark_hashes).encode()
            ).hexdigest()
        # M8.7-D: shield txs (depositor-signed pool additions). Same
        # only-if-present rule preserves pre-M8.7 block hashes.
        if self.shield_transactions:
            shield_hashes = [tx.txid() for tx in self.shield_transactions]
            header["shield_tx_root"] = hashlib.sha256(
                "".join(shield_hashes).encode()
            ).hexdigest()
        # M10: mixer-layer transactions. Same only-if-present rule.
        if self.mixer_deposit_transactions:
            md_hashes = [tx.txid() for tx in self.mixer_deposit_transactions]
            header["mixer_deposit_tx_root"] = hashlib.sha256(
                "".join(md_hashes).encode()
            ).hexdigest()
        if self.mixer_withdraw_transactions:
            mw_hashes = [tx.txid() for tx in self.mixer_withdraw_transactions]
            header["mixer_withdraw_tx_root"] = hashlib.sha256(
                "".join(mw_hashes).encode()
            ).hexdigest()

        return json.dumps(header, sort_keys=True, separators=(",", ":")).encode()

    def hash(self) -> str:
        return hashlib.sha256(self._header_payload()).hexdigest()

    # ---- proof of work ----------------------------------------------------

    def mine(self, difficulty: int) -> None:
        """Find a nonce such that the block hash starts with `difficulty` zeros.

        This is placeholder consensus — milestone 3 swaps it for PoS + QRNG.
        """
        target = "0" * difficulty
        while not self.hash().startswith(target):
            self.nonce += 1

    def meets_difficulty(self, difficulty: int) -> bool:
        return self.hash().startswith("0" * difficulty)

    # ---- serialization ----------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "anon_transactions": [tx.to_dict() for tx in self.anon_transactions],
            "stark_anon_transactions": [tx.to_dict() for tx in self.stark_anon_transactions],
            "shield_transactions": [tx.to_dict() for tx in self.shield_transactions],
            "mixer_deposit_transactions": [tx.to_dict() for tx in self.mixer_deposit_transactions],
            "mixer_withdraw_transactions": [tx.to_dict() for tx in self.mixer_withdraw_transactions],
            "nonce": self.nonce,
            "proposer": self.proposer,
            "hash": self.hash(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Block":
        from qchain.chain.anon_tx import AnonTransaction
        from qchain.chain.anon_stark_tx import STARKAnonTransaction
        from qchain.chain.shield_tx import ShieldTransaction
        from qchain.chain.mixer_tx import MixerDepositTransaction, MixerWithdrawTransaction
        return cls(
            index=d["index"],
            previous_hash=d["previous_hash"],
            timestamp=d["timestamp"],
            transactions=[Transaction.from_dict(t) for t in d["transactions"]],
            anon_transactions=[
                AnonTransaction.from_dict(t) for t in d.get("anon_transactions", [])
            ],
            stark_anon_transactions=[
                STARKAnonTransaction.from_dict(t)
                for t in d.get("stark_anon_transactions", [])
            ],
            shield_transactions=[
                ShieldTransaction.from_dict(t)
                for t in d.get("shield_transactions", [])
            ],
            mixer_deposit_transactions=[
                MixerDepositTransaction.from_dict(t)
                for t in d.get("mixer_deposit_transactions", [])
            ],
            mixer_withdraw_transactions=[
                MixerWithdrawTransaction.from_dict(t)
                for t in d.get("mixer_withdraw_transactions", [])
            ],
            nonce=d["nonce"],
            proposer=d.get("proposer", ""),
        )


def genesis_block() -> Block:
    """The first block. Hardcoded so every node agrees on the same starting point."""
    return Block(
        index=0,
        previous_hash="0" * 64,
        timestamp=1700000000.0,  # fixed timestamp = deterministic genesis hash
        transactions=[],
        nonce=0,
        proposer="GENESIS",
    )
