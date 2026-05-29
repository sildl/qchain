"""
Incremental Merkle tree for note commitments.

Why a Merkle tree? To spend a shielded note, you must prove the note's
commitment is in the set of all commitments ever created — without
revealing which one. A Merkle inclusion proof does exactly this: it
proves "I know a leaf and a path to the root" while only revealing the
hash siblings along the path.

This is a *fixed-depth* tree (depth D). All commitments occupy slots
0..2^D - 1 in append order; empty slots use a deterministic "zero"
hash so the root is well-defined even for a partially-filled tree.

Production systems (Zcash Sapling, Aztec, etc.) use the same construction
with depth 32 (~4 billion notes). We use depth 16 (~65k notes) for the
demo — easily extended.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from qchain.crypto.commitments import H


TREE_DEPTH = 16  # 2^16 = 65,536 note slots — plenty for a learning project


def _empty_subtree_roots(depth: int) -> List[bytes]:
    """Precompute the root of an all-empty subtree at each level.

    Level 0 (leaves) is the all-zero 32-byte hash. Level k+1 is
    H("emp", empty_k, empty_k). These never change, so we can use them
    as default sibling hashes for unfilled positions.
    """
    roots = [H(b"emp", b"\x00" * 32)]
    for _ in range(depth):
        prev = roots[-1]
        roots.append(H(b"emp", prev, prev))
    return roots


_EMPTY = _empty_subtree_roots(TREE_DEPTH)


@dataclass
class MerkleTree:
    """Append-only Merkle tree of note commitments.

    We store leaves explicitly and recompute the path on demand. This
    is O(D) per insertion/proof, fast enough for a learning project. A
    production system would cache internal nodes.
    """
    leaves: List[bytes] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.leaves)

    @property
    def capacity(self) -> int:
        return 1 << TREE_DEPTH

    # ---- insertion -------------------------------------------------------

    def append(self, commitment: bytes) -> int:
        """Add a commitment; return its leaf index."""
        if len(self.leaves) >= self.capacity:
            raise RuntimeError("merkle tree is full")
        if len(commitment) != 32:
            raise ValueError("commitments must be 32 bytes")
        idx = len(self.leaves)
        self.leaves.append(commitment)
        return idx

    # ---- root computation ------------------------------------------------

    def root(self) -> bytes:
        """Compute the current Merkle root.

        Walks bottom-up. For each level, pairs adjacent nodes; if the
        right child is missing (odd count), uses the empty-subtree
        hash for that level.
        """
        layer: List[bytes] = list(self.leaves)
        # Pad to a power of 2 using the level-0 empty hash so missing leaves
        # are well-defined.
        while len(layer) < (1 << TREE_DEPTH):
            layer.append(_EMPTY[0])

        for level in range(TREE_DEPTH):
            nxt: List[bytes] = []
            for i in range(0, len(layer), 2):
                nxt.append(H(b"mrk", layer[i], layer[i + 1]))
            layer = nxt
        assert len(layer) == 1
        return layer[0]

    # ---- proofs ----------------------------------------------------------

    def proof(self, index: int) -> "MerkleProof":
        """Return the inclusion proof for the leaf at `index`."""
        if index < 0 or index >= self.size:
            raise IndexError(f"index {index} out of range")

        layer: List[bytes] = list(self.leaves)
        while len(layer) < (1 << TREE_DEPTH):
            layer.append(_EMPTY[0])

        siblings: List[bytes] = []
        idx = index
        for level in range(TREE_DEPTH):
            sibling_idx = idx ^ 1  # flip the bottom bit
            siblings.append(layer[sibling_idx])
            # Build the next level
            nxt: List[bytes] = []
            for i in range(0, len(layer), 2):
                nxt.append(H(b"mrk", layer[i], layer[i + 1]))
            layer = nxt
            idx >>= 1

        return MerkleProof(
            leaf=self.leaves[index],
            index=index,
            siblings=siblings,
            root=layer[0],
        )


@dataclass
class MerkleProof:
    """An inclusion proof: leaf + index + sibling path.

    Verifying it doesn't need the tree, just the proof and the expected
    root. This is what gets sent over the wire as part of a shielded
    transaction.
    """
    leaf: bytes
    index: int
    siblings: List[bytes]
    root: bytes

    def verify(self) -> bool:
        """Recompute the root from leaf + siblings and compare."""
        if len(self.siblings) != TREE_DEPTH:
            return False
        if len(self.leaf) != 32:
            return False

        node = self.leaf
        idx = self.index
        for sibling in self.siblings:
            if idx & 1:
                node = H(b"mrk", sibling, node)
            else:
                node = H(b"mrk", node, sibling)
            idx >>= 1
        return node == self.root
