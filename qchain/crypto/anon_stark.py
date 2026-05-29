"""M8.5 — STARK-based anonymous notes.

Uses qstark_py for note commitments and Merkle membership proofs. This
provides genuine zero-knowledge anonymity for the SPENDER (which note
they're spending), unlike the M4 Schnorr-based design which reveals the
leaf being spent through the Merkle proof.

## Scope honesty

This module deliberately implements a SIMPLER capability than M4 to keep
the migration tractable:

  * One input note → unshield to transparent recipient + fee  (no multi-spend)
  * No new shielded outputs                                    (no chained spends)
  * Value is committed inside the leaf hash, but not provably
    conserved on chain (production would use range proofs or
    Pedersen commitments INSIDE the STARK proof — both are real
    M8.6+ work).

The point of M8.5 is to demonstrate that the STARK proof correctly hides
which note was spent, while still binding to:
  * a public nullifier (so chain rejects double-spend)
  * a public Merkle root (so chain confirms the note is in the pool)
  * a public unshield amount (so the transparent ledger updates)

## Tree depth

Set by `qstark_py.m86_merkle_depth()` — currently 8 (256-leaf anonymity set).
This is the M8.6-shipped depth. Bumping qstark to depth 12+ has been
benchmarked and works (4096 notes in ~6 ms) but the MerkleTree test
helper in qstark caps at depth 8, so we ship the value that's fully
test-covered.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import qstark_py as q


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FIELD_MODULUS = q.field_modulus()
MERKLE_DEPTH = q.m86_merkle_depth()
ANONYMITY_SET_SIZE = 1 << MERKLE_DEPTH      # = 256 for depth 8
DIGEST_SIZE_BYTES = 32                       # 4 u64s

Digest = Tuple[int, int, int, int]


def _bytes_to_field_element(b: bytes) -> int:
    """Reduce bytes mod field modulus to get a deterministic field element."""
    return int.from_bytes(hashlib.sha256(b).digest(), "big") % FIELD_MODULUS


def digest_to_bytes(d: Digest) -> bytes:
    """Pack a 4-element digest into 32 bytes (little-endian u64 each)."""
    return b"".join(int(x).to_bytes(8, "little") for x in d)


def bytes_to_digest(b: bytes) -> Digest:
    """Unpack 32 bytes into a 4-element digest."""
    if len(b) != DIGEST_SIZE_BYTES:
        raise ValueError(f"digest must be {DIGEST_SIZE_BYTES} bytes, got {len(b)}")
    return tuple(int.from_bytes(b[i*8:(i+1)*8], "little") for i in range(4))  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------

@dataclass
class STARKNote:
    """A shielded note in the STARK pool.

    Held privately by the owner. On-chain only the leaf commitment is
    published. The nullifier is published when the note is spent.

    Fields are field elements (u64 < FIELD_MODULUS).
    """
    sk: int          # spending key (witness)
    randomness: int  # blinding randomness (witness)
    value: int       # value (witness — not value-hidden on chain in M8.5)

    @classmethod
    def random(cls, value: int) -> "STARKNote":
        """Sample a fresh note with random sk and randomness."""
        sk = int.from_bytes(os.urandom(8), "big") % FIELD_MODULUS
        rnd = int.from_bytes(os.urandom(8), "big") % FIELD_MODULUS
        return cls(sk=sk, randomness=rnd, value=value)

    def leaf(self) -> Digest:
        """Compute the note's leaf commitment.

        leaf = Rp64_256(sk, randomness, value).
        """
        return q.hash_leaf(self.sk, self.randomness, self.value)

    def nullifier(self) -> Digest:
        """Compute the nullifier for this note.

        Distinct nullifiers per (sk, leaf) pair prevent double-spend
        without revealing which leaf was spent. We use a hash of the sk
        with a deterministic separator.

        nullifier = Rp64_256(sk + 1, randomness, value)

        This is one of MANY valid nullifier schemes. The important property:
        deterministic given (sk, rnd, value), so spending the same note
        twice produces the same nullifier. The chain rejects duplicates.
        """
        # Use a different domain than `leaf()` so leaf and nullifier are
        # cryptographically separated.
        return q.hash_leaf((self.sk + 1) % FIELD_MODULUS, self.randomness, self.value)


# ---------------------------------------------------------------------------
# Merkle tree helpers
# ---------------------------------------------------------------------------

class _SparseLayerView:
    """Lazy [level][idx] indexing into a sparse Merkle tree.

    Lets legacy code write `tree._layers[level][idx]` to fetch a single
    node without materializing the whole layer. The dense layout the
    name suggests no longer exists internally; this object adapts the
    sparse storage to the old-shape API.

    Only single-element access is supported. Slicing, iteration, and
    len() are intentionally not implemented — code that needs them
    should use the new `STARKAnonTree.leaf_at()` / explicit-iteration
    APIs instead.
    """
    __slots__ = ("_tree", "_level")

    def __init__(self, tree: "STARKAnonTree", level: int) -> None:
        self._tree = tree
        self._level = level

    def __getitem__(self, idx: int) -> "Digest":
        return self._tree._get_node(self._level, idx)


class _SparseLayersView:
    """Lazy indexing for `tree._layers[level]` → returns a per-level view."""
    __slots__ = ("_tree",)

    def __init__(self, tree: "STARKAnonTree") -> None:
        self._tree = tree

    def __getitem__(self, level: int) -> _SparseLayerView:
        if level < 0 or level > MERKLE_DEPTH:
            raise IndexError(f"level {level} out of range [0..{MERKLE_DEPTH}]")
        return _SparseLayerView(self._tree, level)


class STARKAnonTree:
    """A sparse Merkle tree of shielded note commitments using Rp64_256.

    Append-only. After each addition, root() returns a fresh root that
    spenders can use to construct membership proofs.

    Conceptually fixed-depth with 2^MERKLE_DEPTH leaf slots; storage is
    sparse — only populated leaves are stored. Empty subtrees use
    precomputed zero-subtree hashes at each level so neither memory
    nor construction time scale with 2^DEPTH.

    M8.9 (depth 20): a dense implementation would need 1M zero-digest
    entries at layer 0 plus ~2M hash computations per __init__, which
    is multi-second in Python. Sparse storage makes __init__ O(1).
    """

    # Cache of zero-subtree hashes: zero_subtree_hashes[k] is the hash
    # of an all-zero subtree of height k. Computed lazily once per
    # process at first STARKAnonTree creation.
    _zero_subtree_cache: Optional[List["Digest"]] = None

    @classmethod
    def _zero_subtree_hashes(cls) -> List["Digest"]:
        if cls._zero_subtree_cache is None:
            arr: List["Digest"] = [(0, 0, 0, 0)]
            for _ in range(MERKLE_DEPTH):
                arr.append(q.hash_inner(arr[-1], arr[-1]))
            cls._zero_subtree_cache = arr
        return cls._zero_subtree_cache

    def __init__(self) -> None:
        # Sparse storage: (level, idx) → digest for every NON-empty node.
        self._nodes: Dict[Tuple[int, int], "Digest"] = {}
        self._next_idx: int = 0

    def __len__(self) -> int:
        return self._next_idx

    def _get_node(self, level: int, idx: int) -> "Digest":
        """Look up a node, falling back to the zero-subtree hash."""
        cached = self._nodes.get((level, idx))
        if cached is not None:
            return cached
        return self._zero_subtree_hashes()[level]

    def root(self) -> "Digest":
        return self._get_node(MERKLE_DEPTH, 0)

    def append(self, leaf: "Digest") -> int:
        """Append a leaf and update all parent hashes. Returns its index."""
        if self._next_idx >= ANONYMITY_SET_SIZE:
            raise ValueError(
                f"tree full ({ANONYMITY_SET_SIZE} leaves; rebuild qstark "
                f"with higher MERKLE_DEPTH)"
            )
        idx = self._next_idx
        self._nodes[(0, idx)] = leaf
        self._next_idx += 1
        # Recompute ancestors up to root
        cur_level = 0
        cur_idx = idx
        while cur_level < MERKLE_DEPTH:
            left_idx = cur_idx & ~1     # round down to even
            right_idx = left_idx + 1
            left = self._get_node(cur_level, left_idx)
            right = self._get_node(cur_level, right_idx)
            parent = q.hash_inner(left, right)
            cur_level += 1
            cur_idx //= 2
            self._nodes[(cur_level, cur_idx)] = parent
        return idx

    def auth_path(self, idx: int) -> List[Tuple["Digest", bool]]:
        """Authentication path: list of (sibling, is_right) from leaf to root.

        `is_right == True` means the current node is the right child at
        that level (so the hash inputs are: sibling, current).
        """
        if idx >= ANONYMITY_SET_SIZE:
            raise ValueError(f"idx {idx} out of range")
        path: List[Tuple["Digest", bool]] = []
        for level in range(MERKLE_DEPTH):
            is_right = bool(idx & 1)
            sibling_idx = idx ^ 1
            path.append((self._get_node(level, sibling_idx), is_right))
            idx //= 2
        return path

    def leaf_at(self, idx: int) -> "Digest":
        """Get the leaf at `idx`, or the zero leaf if unpopulated."""
        return self._get_node(0, idx)

    # M8.9 compat shim: legacy code reaches into `tree._layers[level][idx]`
    # directly. We expose `_layers` as a lazy view object that adapts
    # single-element accesses to the sparse storage. Slicing, iteration,
    # and other "whole layer" operations are intentionally unsupported.
    @property
    def _layers(self) -> _SparseLayersView:
        return _SparseLayersView(self)
