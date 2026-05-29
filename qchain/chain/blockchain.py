"""The chain itself: an ordered list of blocks with a mempool and balance state."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Set

from qchain.chain.anon_tx import AnonOutput, AnonTransaction
from qchain.chain.anon_stark_tx import STARKAnonTransaction
from qchain.chain.block import Block, genesis_block
from qchain.chain.mixer_tx import MixerDepositTransaction, MixerWithdrawTransaction
from qchain.chain.proposer import Validator, select_proposer
from qchain.chain.shield_tx import ShieldTransaction
from qchain.chain.transaction import Transaction, coinbase
from qchain.crypto.anon_stark import Digest as StarkDigest, STARKAnonTree
from qchain.crypto.merkle import MerkleTree
from qchain.quantum.qrng import QRNG

BLOCK_REWARD = 10.0
DIFFICULTY = 3  # leading zero hex chars (PoW mode only)

# ROADMAP 1.5 (T23 closure): cap the total tx count in a single block.
# A malicious miner could otherwise emit a block with millions of txs
# to make honest nodes allocate gigs of memory during validation.
# 10,000 is ~100× the most a research-demo chain would ever produce
# in a single block. Checked in both is_valid() and the network
# admission path (_handle_new_block).
#
# "All categories" means: transparent + anon + STARK-anon + shield +
# mixer-deposit + mixer-withdraw txs combined. A block that splits
# its abuse across categories still triggers.
MAX_BLOCK_TX_COUNT = 10_000


class Blockchain:
    """An in-memory blockchain with optional JSON persistence.

    State managed:
      * `blocks`       — the chain itself
      * `mempool`      — pending transparent transactions
      * `anon_mempool` — pending anonymous transactions
      * `anon_tree`    — Merkle tree of all anon note commitments ever
                        added (replayed from chain history)
      * `nullifiers`   — set of spent anon nullifiers
    """

    def __init__(self) -> None:
        self.blocks: List[Block] = [genesis_block()]
        self.mempool: List[Transaction] = []
        self.anon_mempool: List[AnonTransaction] = []
        # Shielded pool state — kept in sync with chain by `_apply_anon_tx`.
        self.anon_tree: MerkleTree = MerkleTree()
        self.nullifiers: Set[bytes] = set()
        # Replay-defense for transparent transactions. Each mined non-coinbase
        # tx's txid is recorded here so the SAME tx can't be re-submitted and
        # re-mined as a double-payment. Found via property-based testing —
        # see PROPERTY-TESTING-README.md and the test
        # test_property_resubmit_same_transparent_tx_rejected.
        self.mined_txids: Set[str] = set()
        # M8.5: separate STARK-anonymous pool (different hash function, depth-16)
        self.stark_anon_mempool: List[STARKAnonTransaction] = []
        self.stark_anon_tree: STARKAnonTree = STARKAnonTree()
        self.stark_nullifiers: Set[StarkDigest] = set()
        # M8.7-D: depositor-signed shield txs that populate the STARK pool
        # via on-chain events. Closes Gap D — pools are now chain-replicated.
        self.shield_mempool: List[ShieldTransaction] = []
        # M10: mixer layer for anonymous deposits. Separate Merkle tree
        # holds mixer-pool commitments; withdrawals are anonymous via
        # m86_air proofs and credit a leaf into the STARK pool.
        self.mixer_deposit_mempool: List["MixerDepositTransaction"] = []
        self.mixer_withdraw_mempool: List["MixerWithdrawTransaction"] = []
        self.mixer_tree: STARKAnonTree = STARKAnonTree()
        self.mixer_nullifiers: Set[StarkDigest] = set()
        # M-timing: history of mixer roots, indexed by block index.
        # mixer_root_history[i] is the mixer-tree root AFTER block i's
        # mixer deposits were applied (and BEFORE block i's withdrawals
        # consumed nullifiers — withdrawals reference an OLDER anchor).
        # Index 0 = genesis = empty-tree root.
        # Withdrawals reference an anchor_block_index, and the chain
        # checks mwtx.mixer_root == mixer_root_history[anchor_block_index]
        # plus the anchor age constraint (>= DELAY blocks old).
        self.mixer_root_history: List[StarkDigest] = [self.mixer_tree.root()]
        # M-timing: track the leaf count in the mixer tree at each
        # block boundary, so the wallet helper can reconstruct a
        # historical tree state for proof building.
        self.mixer_leaf_count_history: List[int] = [0]
        # Performance: balance cache. balance_of() replays the entire chain
        # on every call, which is O(blocks × txs). With auto-mining at 15s
        # intervals, this becomes progressively slower. The cache maps
        # address → (balance, cache_version). Invalidated when _balance_cache_version
        # changes (i.e., whenever blocks are appended or the chain is reorganized).
        self._balance_cache: dict[str, tuple[float, int]] = {}
        self._balance_cache_version: int = 0

    # ---- accessors --------------------------------------------------------

    @property
    def head(self) -> Block:
        return self.blocks[-1]

    @property
    def height(self) -> int:
        return len(self.blocks) - 1

    def balance_of(self, address: str) -> float:
        """Compute transparent balance by replaying every confirmed transaction.

        Performance: results are cached and invalidated when blocks change
        (new block appended, chain reorganized, or chain rebuilt from disk).
        Without caching, this method is O(blocks × txs) per call, which
        makes the dashboard progressively slower as the chain grows under
        auto-mining (~240 blocks/hour at 15s intervals).

        Accounts for:
          * Transparent transactions (sender debit, recipient credit)
          * Anon shield_in: address that funded the shielding is debited
            (we track this via a special "SHIELD_FROM:<addr>" sender tag
            on a synthetic transparent tx — see submit_anon)
          * Anon unshield_out: unshield_recipient is credited
          * Anon fees: paid to the block proposer

        For simplicity, shield_in's transparent funding is checked at
        submission time but not separately recorded in the chain; the
        existing transparent mempool model assumes the spender will
        include a transparent tx paying themselves out and burning
        the shielded amount in the same block. We instead model
        shield_in as a separate accounting tracked here.
        """
        # Check cache first
        cached = self._balance_cache.get(address)
        if cached is not None:
            cached_bal, cached_version = cached
            if cached_version == self._balance_cache_version:
                return cached_bal
        bal = 0.0
        for block in self.blocks:
            # Transparent txs
            for tx in block.transactions:
                if tx.recipient == address:
                    bal += tx.amount
                if tx.sender == address:
                    bal -= tx.amount
            # Anon txs that touch the transparent ledger
            for atx in block.anon_transactions:
                # Unshield credits the recipient
                if atx.unshield_recipient == address:
                    bal += atx.unshield_out
                # Block proposer gets the fee (handled by transparent
                # coinbase below; we don't double-credit here)
                # Shield_in must have been funded by a transparent tx
                # in the same block (the spender's chain-side software
                # is responsible for pairing them); the transparent
                # tx will already have debited the sender.
            # M8.5 STARK-anon txs: one-shot unshield + fee
            for stx in block.stark_anon_transactions:
                if stx.unshield_recipient == address:
                    bal += stx.unshield_amount
                # Fee is paid via the coinbase reward (above)
            # M8.7-D shield txs: depositor is debited (amount goes into the
            # STARK pool). The shield itself doesn't credit anyone — the
            # value lives inside the pool until a future STARK-anon spend
            # unshields it back out.
            for shtx in block.shield_transactions:
                if shtx.sender == address:
                    bal -= shtx.amount
            # M10 mixer deposits: depositor is debited (amount goes into the
            # mixer pool). The mixer withdrawal (anonymous) later credits
            # the STARK pool — no direct credit to any transparent address.
            for mdtx in block.mixer_deposit_transactions:
                if mdtx.sender == address:
                    bal -= mdtx.amount
            # M10 mixer withdrawals: these credit the STARK pool, not any
            # transparent address. The value flow is mixer pool → STARK pool,
            # so no transparent address is affected here.
        self._balance_cache[address] = (bal, self._balance_cache_version)
        return bal

    # ---- mempool ----------------------------------------------------------

    def _check_chain_id(self, chain_id, tx_type: str) -> None:
        """T20 closure: enforce that incoming txs target this chain.

        A tx with chain_id=None is legacy (pre-T20) and accepted as-is
        for backward compatibility. A tx with chain_id set to anything
        other than self.CHAIN_ID is rejected — this defends against
        accidental cross-network replay (e.g., a wallet pointed at the
        wrong RPC sending a signed tx to a different network).

        Carve-out (documented in THREAT-MODEL.md T20): for STARK-bearing
        transactions, the chain_id field is not bound to the STARK proof.
        An active attacker who edits the chain_id field after broadcast
        would be caught by this admission check ONLY IF they don't also
        re-target the resubmission. Active attackers modifying bytes are
        a different threat from accidental cross-network replay.
        """
        if chain_id is None:
            return    # legacy tx, backward-compat
        if chain_id != self.CHAIN_ID:
            raise ValueError(
                f"{tx_type} targets chain {chain_id!r} but this chain "
                f"is {self.CHAIN_ID!r}; rejecting (T20 cross-network "
                f"replay defense)"
            )

    def submit(self, tx: Transaction) -> None:
        """Add a transaction to the mempool after validating it.

        Replay defense: rejects a tx whose txid is already mined OR
        already pending in the mempool. Found via property-based
        testing (test_property_resubmit_same_transparent_tx_rejected)
        in the post-audit-followup hardening pass; without this check
        the same Transaction object could be mined into multiple
        blocks, double-paying the recipient.

        T20 closure: rejects a tx whose chain_id is set but doesn't
        match self.CHAIN_ID. Legacy txs (chain_id=None) accepted.
        """
        self._check_chain_id(tx.chain_id, "transparent transaction")
        if not tx.verify():
            raise ValueError("invalid signature")
        # Replay defense — must come before balance check so the error
        # message is informative.
        if tx.sender != "COINBASE":
            if tx.txid() in self.mined_txids:
                raise ValueError(f"transaction {tx.txid()[:16]}... already mined")
            for pending in self.mempool:
                if pending.txid() == tx.txid():
                    raise ValueError(
                        f"transaction {tx.txid()[:16]}... already in mempool"
                    )
        if tx.sender != "COINBASE" and self.balance_of(tx.sender) < tx.amount:
            raise ValueError(
                f"insufficient balance: {tx.sender} has "
                f"{self.balance_of(tx.sender)}, needs {tx.amount}"
            )
        if tx.amount <= 0:
            raise ValueError("amount must be positive")
        self.mempool.append(tx)

    def submit_anon(self, atx: AnonTransaction) -> None:
        """Add an anonymous transaction to the anon mempool.

        Validates against the *current* anon pool state. The Merkle root
        embedded in the tx's spend proofs must match the chain's current
        anon_tree root, so the spender must construct the tx against
        the latest pool state.

        T20 closure: chain_id field on the tx is checked at admission.
        See _check_chain_id for the defense and its documented carve-out.
        """
        self._check_chain_id(atx.chain_id, "anon transaction")
        ok, reason = atx.verify(
            anon_tree_root=self.anon_tree.root(),
            seen_nullifiers=self.nullifiers,
        )
        if not ok:
            raise ValueError(f"invalid anon tx: {reason}")
        # Check no nullifier collides with another pending tx in mempool
        pending: Set[bytes] = set()
        for pending_atx in self.anon_mempool:
            for inp in pending_atx.inputs:
                pending.add(inp.statement.nullifier)
        for inp in atx.inputs:
            if inp.statement.nullifier in pending:
                raise ValueError("nullifier conflicts with pending mempool tx")
        self.anon_mempool.append(atx)

    # ---- M8.5 STARK-anon pool ---------------------------------------------

    def shield_to_stark_pool(self, leaf: "StarkDigest") -> int:
        """Append a fresh note's leaf to the STARK pool. Returns its index.

        In M8.5 we don't model the transparent-side debit on chain (the
        existing M4 anon code already has its own shielding flow). This
        method is the minimal hook needed for the M8.5 demo: a way to
        populate the pool so subsequent STARK spends have something to
        prove membership against.

        A production design would couple this with a Transaction-style
        debit of the shielder's transparent balance. See README for the
        honest scope discussion.
        """
        return self.stark_anon_tree.append(leaf)

    def submit_stark_anon(self, stx: STARKAnonTransaction) -> None:
        """Add a STARK-anonymous transaction to the mempool.

        Verifies against the current STARK pool root and nullifier set,
        and rejects mempool-level nullifier collisions (parallel to
        submit_anon for M4 txs).

        T20 closure: chain_id field on the tx is checked at admission.
        The STARK proof itself does NOT bind chain_id (would require
        modifying the AIR — explicitly out of scope this pass). See
        THREAT-MODEL.md T20 for the documented carve-out.
        """
        self._check_chain_id(stx.chain_id, "stark-anon transaction")
        ok, reason = stx.verify(
            current_root=self.stark_anon_tree.root(),
            seen_nullifiers=self.stark_nullifiers,
        )
        if not ok:
            raise ValueError(f"invalid stark-anon tx: {reason}")
        # Mempool-level conflict: no two pending stark-anon txs may share a nullifier
        pending_nullifiers: Set[StarkDigest] = set()
        for pending in self.stark_anon_mempool:
            pending_nullifiers.add(pending.nullifier)
        if stx.nullifier in pending_nullifiers:
            raise ValueError("stark-anon nullifier conflicts with pending mempool tx")
        self.stark_anon_mempool.append(stx)

    def submit_shield(self, shtx: ShieldTransaction) -> None:
        """Add a depositor-signed shield tx to the shield mempool.

        Validation:
          * Signature verifies (depositor controls the sender address)
          * Sender has sufficient balance (taking already-pending shields
            from this depositor into account, so they can't double-spend
            across mempool entries)
          * Amount is positive

        Effect when mined: the sender is debited `amount` and the leaf
        is appended to the STARK pool, making it spendable via a STARK-anon
        transaction.

        T20 closure: chain_id field on the tx is checked at admission.
        Cryptographically bound into the signature for shield txs (the
        sig covers chain_id), so any post-broadcast tampering also
        invalidates the signature.
        """
        self._check_chain_id(shtx.chain_id, "shield transaction")
        if not shtx.verify():
            raise ValueError("invalid shield tx: signature or structure check failed")
        # Account for other pending shields from the same depositor —
        # otherwise multiple mempool entries could collectively overdraw.
        pending_debit = sum(
            existing.amount for existing in self.shield_mempool
            if existing.sender == shtx.sender
        )
        # Same for pending transparent transactions from this address.
        pending_tx_debit = sum(
            tx.amount for tx in self.mempool
            if tx.sender == shtx.sender
        )
        available = self.balance_of(shtx.sender) - pending_debit - pending_tx_debit
        if available < shtx.amount:
            raise ValueError(
                f"insufficient balance for shield: {shtx.sender} has "
                f"{available} available (after pending), needs {shtx.amount}"
            )
        # Reject duplicate txids (a node shouldn't submit the same tx twice).
        for existing in self.shield_mempool:
            if existing.txid() == shtx.txid():
                raise ValueError("duplicate shield tx in mempool")
        self.shield_mempool.append(shtx)

    def submit_mixer_deposit(self, mdtx) -> None:
        """M10: add a mixer-deposit tx to the mempool.

        Validation:
          * Signature verifies (depositor controls the sender address)
          * Amount is in MIXER_DENOMINATIONS (fixed-denomination requirement)
          * Sender has sufficient balance (accounting for pending mempool debits)
          * No duplicate txid in mempool

        T20 closure: chain_id is bound into the deposit signature (the
        depositor's signature covers chain_id), so post-broadcast
        tampering invalidates the signature. The admission check below
        catches the cross-network case before signature verification
        for a clearer error message.
        """
        from qchain.chain.mixer_tx import MIXER_DENOMINATIONS
        self._check_chain_id(mdtx.chain_id, "mixer deposit")
        if not mdtx.verify_signature():
            raise ValueError("invalid mixer deposit: signature check failed")
        if mdtx.amount not in MIXER_DENOMINATIONS:
            raise ValueError(
                f"mixer deposit amount {mdtx.amount} not in allowed denominations "
                f"{MIXER_DENOMINATIONS}"
            )
        # Pending debits from this depositor (mixer + shield + transparent)
        pending_mixer = sum(
            d.amount for d in self.mixer_deposit_mempool
            if d.sender == mdtx.sender
        )
        pending_shield = sum(
            s.amount for s in self.shield_mempool
            if s.sender == mdtx.sender
        )
        pending_tx = sum(
            tx.amount for tx in self.mempool
            if tx.sender == mdtx.sender
        )
        available = self.balance_of(mdtx.sender) - pending_mixer - pending_shield - pending_tx
        if available < mdtx.amount:
            raise ValueError(
                f"insufficient balance for mixer deposit: {mdtx.sender} has "
                f"{available} available (after pending), needs {mdtx.amount}"
            )
        for existing in self.mixer_deposit_mempool:
            if existing.txid() == mdtx.txid():
                raise ValueError("duplicate mixer deposit in mempool")
        self.mixer_deposit_mempool.append(mdtx)

    def submit_mixer_withdraw(self, mwtx) -> None:
        """M10 + M-timing: add a mixer-withdrawal tx to the mempool.

        Validation:
          * The withdrawal must reference an `anchor_block_index` that's
            at least MIXER_WITHDRAWAL_DELAY blocks old. This is the
            timing-attack defense (threat-model T13). Without it, a
            same-block deposit + withdrawal trivially links the
            publicly-known depositor to the otherwise-anonymous
            withdrawal.
          * The withdrawal's `mixer_root` must equal the historical
            mixer root at `anchor_block_index`. Otherwise the prover
            could anchor an attestation against a fake root.
          * The proof must verify against the anchored root.
          * The nullifier must not have been seen.

        T20 closure: chain_id field on the tx is checked at admission.
        The STARK proof itself does NOT bind chain_id (would require
        modifying the AIR — out of scope this pass). See THREAT-MODEL.md
        T20 for the documented carve-out.
        """
        from qchain.chain.mixer_tx import MIXER_WITHDRAWAL_DELAY

        # T20: cross-network replay check
        self._check_chain_id(mwtx.chain_id, "mixer withdrawal")

        # 1. Timing-attack defense: anchor must be old enough.
        if mwtx.anchor_block_index < 0:
            raise ValueError("anchor_block_index must be non-negative")
        if mwtx.anchor_block_index >= len(self.mixer_root_history):
            raise ValueError(
                f"anchor_block_index {mwtx.anchor_block_index} is in the "
                f"future (chain has {len(self.mixer_root_history)} known "
                f"mixer-root snapshots)"
            )
        # Current height = len(blocks) - 1 (genesis at index 0).
        # Note: this is the height BEFORE the about-to-be-mined block.
        # The about-to-be-mined block will be at index height+1.
        anchor_age = self.height - mwtx.anchor_block_index
        if anchor_age < MIXER_WITHDRAWAL_DELAY:
            raise ValueError(
                f"anchor too recent: anchor block {mwtx.anchor_block_index} "
                f"is {anchor_age} blocks behind current height {self.height}; "
                f"timing-attack defense requires >= {MIXER_WITHDRAWAL_DELAY}"
            )

        # 2. Anchor root must match the chain's record of the historical
        # mixer root at that block index.
        expected_root = self.mixer_root_history[mwtx.anchor_block_index]
        if mwtx.mixer_root != expected_root:
            raise ValueError(
                f"mixer_root doesn't match the chain's record at "
                f"anchor_block_index {mwtx.anchor_block_index}"
            )

        # 3. Proof verifies against the anchored root, and nullifier is fresh.
        ok, reason = mwtx.verify(
            anchored_mixer_root=expected_root,
            seen_mixer_nullifiers=self.mixer_nullifiers,
        )
        if not ok:
            raise ValueError(f"invalid mixer withdrawal: {reason}")

        # 4. No duplicate in mempool.
        for existing in self.mixer_withdraw_mempool:
            if existing.txid() == mwtx.txid():
                raise ValueError("duplicate mixer withdrawal in mempool")

        self.mixer_withdraw_mempool.append(mwtx)

    # ---- M-timing helpers --------------------------------------------------

    def latest_valid_mixer_anchor(self) -> int:
        """Return the most recent block index a withdrawal can anchor to.

        A submission landing in the about-to-be-mined block needs an
        anchor at most (current_height - MIXER_WITHDRAWAL_DELAY) old.
        Returns that block index. Caller MUST also ensure their note
        was deposited at or before this block (else the anchored tree
        won't contain the leaf they want to spend).

        Returns -1 if the chain is too short for any valid anchor —
        i.e., current_height < MIXER_WITHDRAWAL_DELAY. In that case
        no withdrawal is yet allowed at all (timing-attack defense
        gate not yet open).
        """
        from qchain.chain.mixer_tx import MIXER_WITHDRAWAL_DELAY
        latest = self.height - MIXER_WITHDRAWAL_DELAY
        return latest if latest >= 0 else -1

    def historical_mixer_tree_for_block(self, block_index: int) -> STARKAnonTree:
        """Reconstruct the mixer tree's state AS OF the given block index.

        The mixer tree is append-only, so reconstructing block_index's
        state means: take the first N leaves that were ever deposited,
        where N is the leaf count recorded in mixer_leaf_count_history
        at block_index. Each leaf retains its original index.

        Caller uses this to build a STARK proof against a historical
        anchor root. The returned tree's root() will equal
        mixer_root_history[block_index].
        """
        if block_index < 0 or block_index >= len(self.mixer_leaf_count_history):
            raise ValueError(
                f"block_index {block_index} out of range "
                f"[0..{len(self.mixer_leaf_count_history)-1}]"
            )
        target_leaf_count = self.mixer_leaf_count_history[block_index]
        # Build a new tree containing the same first N leaves as our
        # current mixer tree. With sparse storage this is cheap.
        historical = STARKAnonTree()
        for i in range(target_leaf_count):
            leaf = self.mixer_tree._layers[0][i]
            historical.append(leaf)
        # Sanity: the historical tree's root must match the recorded one
        if historical.root() != self.mixer_root_history[block_index]:
            raise RuntimeError(
                f"historical mixer tree at block {block_index} doesn't "
                f"match recorded mixer_root_history — chain state is "
                f"inconsistent"
            )
        return historical

    # ---- state transitions ------------------------------------------------

    def _apply_anon_tx(self, atx: AnonTransaction) -> None:
        """Apply a verified anon tx: append outputs to the tree, mark nullifiers."""
        for inp in atx.inputs:
            self.nullifiers.add(inp.statement.nullifier)
        for out in atx.outputs:
            self.anon_tree.append(out.leaf_commitment)

    def _apply_stark_anon_tx(self, stx: STARKAnonTransaction) -> None:
        """Apply a verified STARK-anon tx.

        M8.11: applying a STARK spend involves two state changes:
          1. Mark the nullifier as spent (prevents double-spend)
          2. Append the output_leaf (the change note) to the STARK pool

        The output_leaf is the hash H(sk_out, r_out, v_out) of the new
        shielded note the spender created as change. The chain doesn't
        know the preimage; the spender retains those secrets to spend
        the change note later.

        For full spends (no real change), the spender provided a dummy
        STARKNote with value=0 and random secrets — the resulting leaf
        is indistinguishable from real change. Same pattern as Zcash
        Sapling dummy outputs.
        """
        self.stark_nullifiers.add(stx.nullifier)
        self.stark_anon_tree.append(stx.output_leaf)

    def _apply_shield_tx(self, shtx: ShieldTransaction) -> int:
        """Apply a verified shield tx: append the leaf to the STARK pool.

        Returns the index assigned to the leaf. The depositor's transparent
        debit is *not* applied here — it's handled implicitly by
        `balance_of` summing all confirmed shield txs from that sender.
        """
        return self.stark_anon_tree.append(shtx.leaf)

    def _apply_mixer_deposit_tx(self, mdtx) -> int:
        """M10: apply a mixer deposit. Appends leaf to MIXER pool.
        Transparent debit happens implicitly via balance_of (it includes
        mixer deposits when summing the sender's outflows).
        """
        return self.mixer_tree.append(mdtx.leaf)

    def _apply_mixer_withdraw_tx(self, mwtx) -> None:
        """M10: apply a mixer withdrawal. Marks the mixer nullifier and
        appends the output_leaf to the STARK pool. The withdrawal's value
        is now spendable anonymously via STARK-anon transactions.
        """
        self.mixer_nullifiers.add(mwtx.nullifier)
        self.stark_anon_tree.append(mwtx.output_leaf)

    # ---- block production -------------------------------------------------

    def mine_pending(self, miner_address: str) -> Block:
        """Bundle mempool txs into a block, mine it, and append it.

        Block contents (in this order):
          1. Coinbase tx (block reward + all fees)
          2. Transparent txs
          3. Anon (M4) txs
          4. Shield txs (M8.7-D) — populate the STARK pool
          5. STARK-anon txs (M8.5/M8.6) — spend FROM the STARK pool

        State application order matches:
          1. Anon-tree updates from M4 txs
          2. Pool-tree leaf additions from shields
          3. Nullifier marks from STARK spends

        Shield txs apply BEFORE STARK spends in the same block, so the
        block's "after" state has the new leaves visible. In practice
        the same-block shield+spend pattern is rare since the spender
        needs the leaf's pool index to construct the proof, which they
        only learn after the shield is confirmed.
        """
        # Include fee income from both anon variants in the coinbase reward.
        anon_fee_total = sum(atx.fee for atx in self.anon_mempool)
        stark_fee_total = sum(stx.fee for stx in self.stark_anon_mempool)
        reward = coinbase(miner_address, BLOCK_REWARD + anon_fee_total + stark_fee_total)
        block_txs = [reward] + self.mempool

        block = Block(
            index=self.height + 1,
            previous_hash=self.head.hash(),
            timestamp=time.time(),
            transactions=block_txs,
            proposer=miner_address,
            anon_transactions=list(self.anon_mempool),
            stark_anon_transactions=list(self.stark_anon_mempool),
            shield_transactions=list(self.shield_mempool),
            mixer_deposit_transactions=list(self.mixer_deposit_mempool),
            mixer_withdraw_transactions=list(self.mixer_withdraw_mempool),
        )
        block.mine(DIFFICULTY)
        self.blocks.append(block)

        # Apply state changes after the block is sealed. Order matters:
        # mixer deposits go into mixer pool first; then shields into STARK
        # pool; then mixer withdrawals consume mixer nullifiers AND append
        # to STARK pool; finally STARK spends consume STARK nullifiers.
        self._apply_block_state(block)

        self.mempool = []
        self.anon_mempool = []
        self.stark_anon_mempool = []
        self.shield_mempool = []
        self.mixer_deposit_mempool = []
        self.mixer_withdraw_mempool = []
        return block

    def _apply_block_state(self, block) -> None:
        """Apply a sealed block's state transitions in canonical order.

        Used by mine_pending, propose_pending, and the node's
        block-receive path. The canonical order is:
          1. Transparent-tx mined-txid tracking (replay defense)
          2. Anon-tx outputs / nullifiers (M4)
          3. Mixer deposits (mixer tree grows)
          4. Shield txs (STARK pool grows)
          5. **Snapshot mixer root post-deposits** (for M-timing anchors)
          6. Mixer withdrawals (mixer nullifiers marked; STARK pool grows)
          7. STARK spends (STARK nullifiers marked; STARK pool grows)

        Step 5 records the new mixer root for future blocks' withdrawals
        to anchor against. Importantly, this happens AFTER deposits but
        BEFORE withdrawals — the in-block deposits are visible to
        future withdrawals (good), but the in-block withdrawals'
        nullifier consumption is not (irrelevant to anchor consistency).
        """
        # Invalidate balance cache — confirmed balances change with every
        # new block. The version bump is cheaper than clearing the dict;
        # stale entries are skipped in balance_of via version mismatch.
        self._balance_cache_version += 1
        # 1. Record mined transparent-tx txids for replay defense.
        for tx in block.transactions:
            if tx.sender != "COINBASE":
                self.mined_txids.add(tx.txid())
        for atx in block.anon_transactions:
            self._apply_anon_tx(atx)
        for mdtx in block.mixer_deposit_transactions:
            self._apply_mixer_deposit_tx(mdtx)
        for shtx in block.shield_transactions:
            self._apply_shield_tx(shtx)
        # M-timing: snapshot mixer root after deposits, before withdrawals.
        # block.index is len(self.blocks) - 1 at this point.
        # mixer_root_history is parallel-indexed: append once per block.
        self.mixer_root_history.append(self.mixer_tree.root())
        self.mixer_leaf_count_history.append(self.mixer_tree._next_idx)
        for mwtx in block.mixer_withdraw_transactions:
            self._apply_mixer_withdraw_tx(mwtx)
        for stx in block.stark_anon_transactions:
            self._apply_stark_anon_tx(stx)

    def propose_pending(
        self,
        validators: List[Validator],
        qrng: QRNG,
    ) -> Block:
        """PoS block production: QRNG picks the proposer from `validators`.

        Returns the new block. The proposer is rewarded; everyone else just
        validates. The QRNG-derived seed is embedded in the block so anyone
        replaying the chain can audit who *should* have been chosen and
        check the proposer didn't cheat.

        Same as `mine_pending`, this includes all four tx types: transparent,
        anon (M4), shield (M8.7-D), and STARK-anon (M8.5/M8.6).
        """
        if not validators:
            raise ValueError("PoS requires at least one validator")

        winner = select_proposer(validators, qrng)
        seed_used = qrng.last_source.value if qrng.last_source else "unknown"

        anon_fee_total = sum(atx.fee for atx in self.anon_mempool)
        stark_fee_total = sum(stx.fee for stx in self.stark_anon_mempool)
        reward = coinbase(winner.address, BLOCK_REWARD + anon_fee_total + stark_fee_total)
        block_txs = [reward] + self.mempool

        block = Block(
            index=self.height + 1,
            previous_hash=self.head.hash(),
            timestamp=time.time(),
            transactions=block_txs,
            proposer=winner.address,
            anon_transactions=list(self.anon_mempool),
            stark_anon_transactions=list(self.stark_anon_mempool),
            shield_transactions=list(self.shield_mempool),
            mixer_deposit_transactions=list(self.mixer_deposit_mempool),
            mixer_withdraw_transactions=list(self.mixer_withdraw_mempool),
        )
        block.proposer = f"{winner.address}|qrng={seed_used}"

        self.blocks.append(block)

        # Apply pool state changes (same order as mine_pending, including
        # M-timing's mixer_root_history snapshot via _apply_block_state).
        self._apply_block_state(block)

        self.mempool = []
        self.anon_mempool = []
        self.stark_anon_mempool = []
        self.shield_mempool = []
        self.mixer_deposit_mempool = []
        self.mixer_withdraw_mempool = []
        return block

    # ---- validation -------------------------------------------------------

    def is_valid(self) -> bool:
        """Walk the chain and check every link.

        Validates:
          * Block hash chain
          * PoW difficulty (for PoW-style blocks)
          * Every transparent tx signature
          * Every anon tx against the pool state AT THAT POINT in history
            (we replay anon-pool state during validation)
          * Every shield tx signature (M8.7-D)
          * **M8.10: Every STARK-anon tx proof against the STARK pool state
            at the moment it was included.** Catches forged proofs that
            slipped past submission (e.g. via a malicious peer who
            bypassed their own validator and gossiped to a peer running
            an outdated wheel).

        Note on what's NOT re-verified:
          * Shield tx depositor balance is not re-checked during replay.
            submit_shield enforced it at admission; a production validator
            would re-check to catch a malicious miner who included an
            over-budget shield via direct block injection.
        """
        # Replay anon state from scratch so anon-tx verification sees the
        # tree as it was at the moment that tx was included.
        replay_tree = MerkleTree()
        replay_nullifiers: Set[bytes] = set()
        # Replay-defense set for transparent txs. Property-test finding:
        # is_valid must catch the same double-mine bug submit() catches.
        replay_mined_txids: Set[str] = set()
        # M8.10: parallel replay for the STARK pool. Shield txs add leaves;
        # STARK-anon txs add nullifiers. Verification of each STARK tx
        # checks (proof, current pool root, current nullifier set).
        replay_stark_tree = STARKAnonTree()
        replay_stark_nullifiers: Set[StarkDigest] = set()
        # M10: parallel replay for the mixer pool. Mixer deposits add leaves;
        # mixer withdrawals consume nullifiers AND append to STARK pool.
        replay_mixer_tree = STARKAnonTree()
        replay_mixer_nullifiers: Set[StarkDigest] = set()
        # M-timing: parallel mixer root history during replay. Same
        # invariant as the real chain: index 0 = empty root.
        replay_mixer_root_history: List[StarkDigest] = [replay_mixer_tree.root()]

        for i in range(1, len(self.blocks)):
            prev, curr = self.blocks[i - 1], self.blocks[i]
            if curr.previous_hash != prev.hash():
                return False
            is_pos = "|qrng=" in curr.proposer
            if not is_pos and not curr.meets_difficulty(DIFFICULTY):
                return False

            # ROADMAP 1.5 (T23): cap total tx count per block to defend
            # against memory-exhaustion attacks by malicious miners. A
            # block with more than MAX_BLOCK_TX_COUNT txs across all
            # categories combined is rejected at replay.
            total_tx_count = (
                len(curr.transactions)
                + len(curr.anon_transactions)
                + len(curr.stark_anon_transactions)
                + len(curr.shield_transactions)
                + len(curr.mixer_deposit_transactions)
                + len(curr.mixer_withdraw_transactions)
            )
            if total_tx_count > MAX_BLOCK_TX_COUNT:
                return False

            # Transparent txs
            # Audit-pass finding: previously is_valid() did not check the
            # coinbase amount, allowing a malicious miner to inflate
            # their block reward without rejection. The fix computes the
            # expected reward (BLOCK_REWARD + fees from in-block anon and
            # stark txs) and verifies the block's coinbase matches.
            #
            # The coinbase is, by convention, the first tx in
            # curr.transactions and has sender == "COINBASE".
            anon_fee_this_block = sum(atx.fee for atx in curr.anon_transactions)
            stark_fee_this_block = sum(
                stx.fee for stx in curr.stark_anon_transactions
            )
            expected_reward = BLOCK_REWARD + anon_fee_this_block + stark_fee_this_block
            coinbase_txs = [tx for tx in curr.transactions if tx.sender == "COINBASE"]
            if len(coinbase_txs) != 1:
                # Either no coinbase or multiple coinbases — neither honest.
                return False
            if coinbase_txs[0].amount != expected_reward:
                return False
            for tx in curr.transactions:
                if not tx.verify():
                    return False
                # Replay defense: a non-coinbase txid must not appear in
                # two blocks. Property-test finding from the audit-readiness
                # pass — without this, the same transparent tx could be
                # re-mined and double-pay the recipient.
                if tx.sender != "COINBASE":
                    if tx.txid() in replay_mined_txids:
                        return False
                    replay_mined_txids.add(tx.txid())

            # Anon txs (must validate against the pre-block pool state)
            for atx in curr.anon_transactions:
                ok, reason = atx.verify(
                    anon_tree_root=replay_tree.root(),
                    seen_nullifiers=replay_nullifiers,
                )
                if not ok:
                    return False

            # M8.7-D Shield txs: validate the depositor's signature.
            # (Balance check requires the full chain view; we trust that
            # submit_shield already enforced it at admission time. A
            # production validator would re-check.)
            for shtx in curr.shield_transactions:
                if not shtx.verify():
                    return False

            # M10: Mixer deposits — validate the depositor's signature and
            # denomination (balance is not re-checked here; same trust
            # model as shield txs).
            for mdtx in curr.mixer_deposit_transactions:
                if not mdtx.verify_signature():
                    return False
                # Denomination check (catches a malicious miner who included
                # a deposit with an invalid denomination)
                from qchain.chain.mixer_tx import MIXER_DENOMINATIONS
                if mdtx.amount not in MIXER_DENOMINATIONS:
                    return False

            # M10: Mixer withdrawals — verify the STARK proof against the
            # ANCHORED mixer root (per M-timing), enforce the timing-attack
            # delay, and check the nullifier hasn't been seen.
            from qchain.chain.mixer_tx import MIXER_WITHDRAWAL_DELAY
            for mwtx in curr.mixer_withdraw_transactions:
                # Anchor must be valid (in range, old enough)
                if mwtx.anchor_block_index < 0:
                    return False
                if mwtx.anchor_block_index >= len(replay_mixer_root_history):
                    return False
                # i is the current block being replayed; height-at-admission
                # was i-1 (the previous block had been mined, this one was
                # being assembled).
                anchor_age = (i - 1) - mwtx.anchor_block_index
                if anchor_age < MIXER_WITHDRAWAL_DELAY:
                    return False
                anchored_root = replay_mixer_root_history[mwtx.anchor_block_index]
                if mwtx.mixer_root != anchored_root:
                    return False
                ok, reason = mwtx.verify(
                    anchored_mixer_root=anchored_root,
                    seen_mixer_nullifiers=replay_mixer_nullifiers,
                )
                if not ok:
                    return False

            # M8.10: STARK-anon txs must verify against the pre-block STARK
            # pool state — exactly mirroring submit_stark_anon's checks.
            # Order of validation within block: STARK txs see the STARK
            # pool as it was BEFORE this block's shields were applied,
            # matching mine_pending's behavior (mempool admission happened
            # before this block's shields existed).
            for stx in curr.stark_anon_transactions:
                ok, reason = stx.verify(
                    current_root=replay_stark_tree.root(),
                    seen_nullifiers=replay_stark_nullifiers,
                )
                if not ok:
                    return False

            # Apply all state changes for this block, in order matching
            # mine_pending: anon → mixer deposits → shields → snapshot
            # mixer root → mixer withdrawals → STARK spends.
            for atx in curr.anon_transactions:
                for inp in atx.inputs:
                    replay_nullifiers.add(inp.statement.nullifier)
                for out in atx.outputs:
                    replay_tree.append(out.leaf_commitment)
            # M10: mixer deposits populate the mixer pool
            for mdtx in curr.mixer_deposit_transactions:
                replay_mixer_tree.append(mdtx.leaf)
            # M8.10: shields populate the STARK pool
            for shtx in curr.shield_transactions:
                replay_stark_tree.append(shtx.leaf)
            # M-timing: snapshot mixer root AFTER this block's deposits
            # are applied. This is the value mixer_root_history[i] will
            # have on the real chain after block i is mined.
            replay_mixer_root_history.append(replay_mixer_tree.root())
            # M10: mixer withdrawals consume mixer nullifiers AND credit
            # the STARK pool with their output_leaf
            for mwtx in curr.mixer_withdraw_transactions:
                replay_mixer_nullifiers.add(mwtx.nullifier)
                replay_stark_tree.append(mwtx.output_leaf)
            # M8.11: STARK spends consume STARK nullifiers AND append their
            # output_leaf (change note) to the STARK pool.
            for stx in curr.stark_anon_transactions:
                replay_stark_nullifiers.add(stx.nullifier)
                replay_stark_tree.append(stx.output_leaf)

        return True

    # ---- persistence ------------------------------------------------------

    # T20 closure: chain identifier bound into transaction signatures and
    # carried as a field on STARK-bearing transactions, checked at admission.
    # This defends against accidental cross-network replay (e.g., a wallet
    # pointed at the wrong RPC sending the same signed tx to a different
    # network). See THREAT-MODEL.md T20 for the carve-out: STARK proofs
    # themselves are NOT modified by this pass — the chain_id field on
    # STARK txs is checked at admission but is not cryptographically bound
    # to the proof.
    CHAIN_ID = "qchain-v1"

    # Audit-pass: version field for the saved chain format. Bumped when
    # the on-disk schema changes incompatibly. Old saves are tagged
    # version=1 by inference (no version field present).
    #
    # M-timing: bumped to 2. The mixer-withdrawal record now includes
    # an `anchor_block_index` field. Pre-version-2 saves loaded by
    # this code default that field to 0; chains that contained mixer
    # withdrawals BEFORE the timing-pass will fail is_valid() because
    # the implied anchor doesn't match the real historical roots.
    # Mixer-free pre-2 saves load fine.
    PERSISTENCE_VERSION = 2

    def save(self, path: str | Path) -> None:
        data = {
            "version": self.PERSISTENCE_VERSION,
            "blocks": [b.to_dict() for b in self.blocks],
        }
        Path(path).write_text(json.dumps(data, indent=2))

    @classmethod
    def load(cls, path: str | Path, validate: bool = True) -> "Blockchain":
        """Load a chain from disk and rebuild derived state.

        The saved file contains the block history only — every in-memory
        tree (anon_tree, stark_anon_tree, mixer_tree) and nullifier set
        is deterministically reconstructible from those blocks.

        After load() returns:
          * `blocks` is populated from disk
          * `anon_tree` reflects all M4 anon-tx outputs ever included
          * `nullifiers` contains every M4 nullifier ever consumed
          * `stark_anon_tree` reflects all shield txs + mixer withdrawal
            outputs + STARK-spend change outputs in their original order
          * `stark_nullifiers` contains every STARK-anon nullifier
          * `mixer_tree` reflects all mixer deposits in their original order
          * `mixer_nullifiers` contains every consumed mixer deposit

        Mempools are all empty (transactions still pending at save time
        are lost — same as how a real validator's mempool isn't part of
        the persisted state).

        Version field: saves before the audit-pass had no version field.
        Such files are accepted as version=1 (current). Files with a
        version newer than this code knows about are rejected.

        Validation (T18 closure): by default, load() calls is_valid()
        on the reconstructed chain before returning, catching corrupt-
        but-parseable persistence files (bit-flips, partial truncation,
        malicious edits). If validation fails, raises ValueError.

        Pass `validate=False` to skip this check. The opt-out exists
        for tests that deliberately work with invalid chain state. The
        safe default is on; turning it off should be explicit.

        Performance: is_valid() re-verifies every signature and STARK
        proof in the chain, which scales O(N) in chain length. For long
        chains this can take seconds. This is intentional — load time
        is rare, and partial validation would create a configuration
        surface that's itself a security concern.
        """
        data = json.loads(Path(path).read_text())
        # Audit-pass version check. Files predating this change have no
        # version field; treat them as version=1 (current). Files with
        # higher versions indicate a schema this code doesn't understand.
        file_version = data.get("version", 1)
        if file_version > cls.PERSISTENCE_VERSION:
            raise ValueError(
                f"chain file has version {file_version}, but this code "
                f"only supports up to version {cls.PERSISTENCE_VERSION}. "
                f"Upgrade qchain to load this file."
            )
        bc = cls()
        bc.blocks = [Block.from_dict(b) for b in data["blocks"]]
        bc._rebuild_derived_state_from_blocks()
        # T18 closure: validate the reconstructed chain end-to-end before
        # handing it back. Catches corrupt-but-parseable files that
        # _rebuild_derived_state_from_blocks doesn't notice (e.g., a
        # tampered previous_hash linking, an invalid signature, a forged
        # STARK proof). Opt-out via validate=False for tests.
        if validate and not bc.is_valid():
            raise ValueError(
                f"chain file at {path} parsed and reconstructed but "
                f"failed is_valid() — file is corrupt or has been "
                f"tampered with. Pass validate=False to load anyway "
                f"(at your own risk)."
            )
        return bc

    def _rebuild_derived_state_from_blocks(self) -> None:
        """Reconstruct all in-memory trees and nullifier sets by
        replaying every block's tx in canonical order.

        Used by load(). Does NOT re-verify proofs or signatures —
        that's is_valid()'s job. Just deterministically rebuilds
        the state that mine_pending / propose_pending would have
        produced if the chain had been built live.

        Uses _apply_block_state so the order — including the
        M-timing mixer_root_history snapshot — matches the original
        run exactly.
        """
        # Fresh state objects (replace whatever __init__ created)
        self.anon_tree = MerkleTree()
        self.nullifiers = set()
        self.mined_txids = set()
        self.stark_anon_tree = STARKAnonTree()
        self.stark_nullifiers = set()
        self.mixer_tree = STARKAnonTree()
        self.mixer_nullifiers = set()
        # M-timing: reset history to genesis state. _apply_block_state
        # will re-append a snapshot for each block.
        self.mixer_root_history = [self.mixer_tree.root()]
        self.mixer_leaf_count_history = [0]
        # Reset balance cache — _apply_block_state will bump the version
        # for each block, but clearing avoids accumulating stale entries.
        self._balance_cache = {}
        self._balance_cache_version = 0

        # Skip genesis (block 0) — it has no real txs that affect state
        for block in self.blocks[1:]:
            self._apply_block_state(block)
