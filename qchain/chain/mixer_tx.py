"""M10 — Mixer layer for anonymous deposits.

The M8.7-D ShieldTransaction publicly reveals the depositor's address.
Chain analysis can correlate "address X shielded 100 coins at time T"
with any later STARK spend of 100 coins.

The mixer layer breaks this link. Users:

  1. Deposit transparent coins into a separate "mixer pool" via a
     MixerDepositTransaction (publicly — depositor identity visible)
  2. Wait (decoupling deposit from withdrawal in time)
  3. Withdraw via a MixerWithdrawTransaction — a STARK proof that
     proves "I know the preimage to SOME leaf in the mixer pool"
     without revealing which one. The withdrawal credits a new
     leaf into the STARK pool (where further spending remains
     anonymous via M8.5/M8.11 mechanics).

The mixer's anonymity set is the population of un-withdrawn deposits
of the same denomination. Fixed denominations (1, 10, 100, ...) are
required — otherwise the anonymity set is partitioned by amount and
the privacy guarantee collapses.

This module reuses the M8.6+ m86_air AIR (membership + nullifier
binding + value attestation). No new cryptography is introduced —
the novelty is the orchestration: a separate Merkle tree, fixed
denominations, and the withdrawal-credits-shield-pool flow.

Honest scope notes:
  * Denomination enforcement is chain-side, not in the AIR. The AIR
    proves v_in = unshield + fee + v_out without constraining v_in
    to a denomination. The chain rejects deposits/withdrawals whose
    amounts aren't in the allowed set.
  * No timing-attack defense: a withdrawal can land in the same block
    as its deposit, making linkability trivial. Production deployments
    would enforce a minimum delay (e.g., "withdrawals only valid after
    100 blocks").
  * The depositor's transparent debit IS recorded (the chain has to
    debit them). The mixer privacy is between deposit and *withdrawal*,
    not against the network observing the deposit.
"""

from __future__ import annotations

import hashlib
import time
from base64 import b64decode, b64encode
from dataclasses import dataclass, field
from typing import Optional, Set

import qstark_py as q

from qchain.crypto.anon_stark import (
    Digest, STARKNote, bytes_to_digest, digest_to_bytes,
)
from qchain.crypto import dilithium


# Fixed denominations for mixer deposits/withdrawals.
# Picked so the anonymity set isn't fragmented across too many amounts.
# Production designs would tune these.
MIXER_DENOMINATIONS: tuple[int, ...] = (1, 10, 100, 1000)

# Mixer timing-attack defense (T13 mitigation).
#
# A withdrawal must reference a mixer root that's at least
# MIXER_WITHDRAWAL_DELAY blocks old. This forces a chain-analysis
# observer attempting to link a deposit to a withdrawal to wait at
# least that many blocks — during which more deposits can land,
# growing the anonymity set.
#
# Without this delay, a same-block or 1-block-apart deposit +
# withdrawal trivially links the publicly-known depositor to the
# otherwise-anonymous withdrawal. The threat model entry T13
# documents the attack in detail.
#
# Reference points:
#   * Tornado Cash: no explicit protocol delay; relied on
#     time-since-deposit being long anyway
#   * Zcash: ~100 blocks (`min_confirmations`) for spends from
#     shielded notes
#
# For QChain (PoW, manually-triggered blocks in the demo) 5 blocks
# is meaningful without grinding tests/demos to a halt. A real
# deployment would tune this.
MIXER_WITHDRAWAL_DELAY: int = 5

# T14 partial mitigation: maximum ADDITIONAL randomized delay (in blocks)
# the wallet adds on top of the deterministic chain-side minimum above.
# A wallet-side withdrawal picks a random delay D ~ Uniform[0, MAX] blocks
# and the user is expected to hold the withdrawal off-chain for D blocks
# before submitting.
#
# Combined with MIXER_WITHDRAWAL_DELAY this gives a total deposit→submit
# wait of [5, 25] blocks at default settings — spreading withdrawals
# across a 20-block window so a naive timing-correlation attacker can't
# pinpoint a specific deposit→withdraw pair.
#
# Honest scope: this is `[HEURISTIC]`, not `[DEFENDED]`. An attacker who
# applies statistical analysis over many blocks can still link deposits
# and withdrawals probabilistically — the randomization just widens the
# correlation window. Full mitigation (constant-rate decoy traffic,
# mix nets, or decoy-based ZK proofs) is multi-month research work
# explicitly out of scope. See THREAT-MODEL.md T14.
MIXER_WITHDRAWAL_DELAY_RANDOMIZATION_MAX: int = 20


# ============================================================================
# MixerDepositTransaction
# ============================================================================

@dataclass
class MixerDepositTransaction:
    """A transparent deposit into the mixer pool.

    Functionally similar to ShieldTransaction: a depositor publicly
    burns transparent coins to add a commitment leaf to the mixer
    tree. The leaf hides (sk, r) but not the denomination (enforced
    chain-side).

    T20: when `chain_id` is set, its bytes are hashed into the
    signing payload after the nonce. Legacy deposits with
    chain_id=None sign without it (backward compatible).
    """
    leaf: Digest               # commitment H(sk, r, denomination)
    amount: int                # must be in MIXER_DENOMINATIONS
    timestamp: float = field(default_factory=time.time)
    nonce: int = 0
    sender: str = ""           # filled in by sign() — depositor's address
    public_key: str = ""       # base64 of the depositor's Dilithium pubkey
    signature: str = ""        # base64 of the Dilithium signature
    chain_id: Optional[str] = None    # T20 closure; None = legacy unbound

    def _payload(self) -> bytes:
        """Bytes that get signed. Ordering fixed for reproducibility.

        T20: chain_id bytes appended iff set. Absence (None) produces
        the legacy payload unchanged so pre-T20 signatures still verify.
        """
        h = hashlib.sha256()
        h.update(b"MixerDepositTx")
        h.update(self.sender.encode())
        h.update(b"".join(int(x).to_bytes(8, "big", signed=False) for x in self.leaf))
        h.update(self.amount.to_bytes(8, "big", signed=False))
        h.update(int(self.timestamp * 1e6).to_bytes(8, "big", signed=False))
        h.update(self.nonce.to_bytes(8, "big", signed=False))
        if self.chain_id is not None:
            h.update(b"|chain_id|")          # domain separator
            h.update(self.chain_id.encode())
        return h.digest()

    def sign(self, keypair: "dilithium.Keypair") -> None:
        """Attach a Dilithium signature; overwrite sender with derived address."""
        self.sender = keypair.address()
        self.public_key = b64encode(keypair.public_key).decode()
        sig = dilithium.sign(keypair.secret_key, self._payload())
        self.signature = b64encode(sig).decode()

    def verify_signature(self) -> bool:
        """Verify signature, sender↔pubkey binding, and basic structure."""
        if not self.signature or not self.public_key:
            return False
        if self.amount <= 0:
            return False
        if not isinstance(self.leaf, (list, tuple)) or len(self.leaf) != 4:
            return False
        for elem in self.leaf:
            if not isinstance(elem, int) or elem < 0 or elem >= (1 << 64):
                return False
        try:
            pk = b64decode(self.public_key)
            sig = b64decode(self.signature)
        except Exception:
            return False
        # Sender must equal the address derived from the public key.
        expected_addr = hashlib.sha256(pk).hexdigest()[:40]
        if expected_addr != self.sender:
            return False
        return dilithium.verify(pk, self._payload(), sig)

    def txid(self) -> str:
        """Stable hash identifier including the signature."""
        full = self._payload() + self.signature.encode()
        return hashlib.sha256(full).hexdigest()

    def to_dict(self) -> dict:
        d = {
            "kind": "mixer_deposit",
            "sender": self.sender,
            "leaf": list(self.leaf),
            "amount": self.amount,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "public_key": self.public_key,
            "signature": self.signature,
        }
        # T20: emit chain_id only if set (legacy bytes unchanged)
        if self.chain_id is not None:
            d["chain_id"] = self.chain_id
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "MixerDepositTransaction":
        return cls(
            leaf=tuple(d["leaf"]),               # type: ignore[arg-type]
            amount=d["amount"],
            timestamp=d.get("timestamp", time.time()),
            nonce=d.get("nonce", 0),
            sender=d.get("sender", ""),
            public_key=d.get("public_key", ""),
            signature=d.get("signature", ""),
            chain_id=d.get("chain_id"),          # T20: None if absent (legacy)
        )


# ============================================================================
# MixerWithdrawTransaction
# ============================================================================

@dataclass
class MixerWithdrawTransaction:
    """An anonymous withdrawal from the mixer pool.

    Uses the M8.6 m86_air AIR to prove:
      * I know (sk, r, v) for some leaf in the mixer tree
      * Nullifier H(sk+1, r, v) hasn't been seen
      * Three-way value conservation: v == 0 + 0 + v_out
        (unshield=0, fee=0; v_out is the M8.11 "change" but here it's
        the full credit that lands in the STARK pool with the
        spender's new secrets)

    The withdrawal credits `output_leaf` into the STARK pool. The
    spender retains (sk_out, r_out, v_out) and can spend that note
    anonymously via M8.5/M8.11 mechanics.

    Privacy note (hardening pass): this struct does NOT carry a
    `withdraw_amount` field. Earlier versions did, but the field was
    only admin-side — not bound to the proof via Fiat-Shamir. That
    meant a malicious peer could tamper it in flight, misleading any
    chain-analysis tool partitioning the anonymity set by
    denomination. Removing the field is strictly more private: the
    denomination is now hidden inside `output_leaf` (which IS FS-bound
    via the m86_air proof) and can only be learned by someone who
    already knows the spender's `(sk_out, r_out)` secrets. Value
    conservation is unaffected — the AIR enforces it cryptographically
    regardless of any denomination label.

    Timing-attack defense (T13 mitigation): `anchor_block_index`
    declares which historical mixer root the withdrawal is proving
    against. Chain enforces:
      * anchor_block_index <= current_height - MIXER_WITHDRAWAL_DELAY
        (the anchored root must be at least DELAY blocks old)
      * mixer_root must equal mixer_root_history[anchor_block_index]
    A withdrawer reveals nothing more about their deposit by
    selecting an old anchor — the AIR proof works against any
    valid historical root. Honest withdrawers should pick an anchor
    that's old enough to satisfy the delay but recent enough to
    include their deposit. The wallet's `create_mixer_withdrawal`
    picks this automatically.

    Migration: from_dict accepts old-format payloads containing
    `withdraw_amount` and silently discards the field, so saved chains
    written before the hardening pass still load. The anchor_block_index
    field, added in M-timing, requires its own migration: pre-timing
    saves don't have it, but those are version-1 chains; loading
    version-1 chains containing mixer withdrawals is not supported.
    """
    # Public inputs to the AIR
    mixer_root: Digest               # historical mixer root the proof attests against
    nullifier: Digest                # spent-mixer-leaf nullifier
    output_leaf: Digest              # new leaf for the STARK pool

    # The STARK proof bytes
    proof: bytes

    # M-timing: which historical block's mixer-root state this withdrawal
    # is anchored to. Chain enforces a minimum age (MIXER_WITHDRAWAL_DELAY)
    # between this block index and the current chain height at withdrawal
    # admission time.
    anchor_block_index: int = 0

    timestamp: float = field(default_factory=time.time)

    # T20 closure: identifies the chain this withdrawal targets. NOT bound
    # to the STARK proof (that would require modifying the AIR). Checked
    # at chain admission only. This defends against ACCIDENTAL cross-network
    # replay; an active attacker who modifies this field after broadcast
    # would not be caught by this check (the proof itself doesn't bind it).
    # See THREAT-MODEL.md T20 for the documented carve-out.
    chain_id: Optional[str] = None

    def txid(self) -> str:
        h = hashlib.sha256()
        h.update(b"MixerWithdrawTx")
        h.update(digest_to_bytes(self.mixer_root))
        h.update(digest_to_bytes(self.nullifier))
        h.update(digest_to_bytes(self.output_leaf))
        h.update(self.anchor_block_index.to_bytes(8, "big", signed=False))
        h.update(self.proof)
        return h.hexdigest()

    def to_dict(self) -> dict:
        d = {
            "kind": "mixer_withdraw",
            "mixer_root": list(self.mixer_root),
            "nullifier": list(self.nullifier),
            "output_leaf": list(self.output_leaf),
            "proof": self.proof.hex(),
            "anchor_block_index": self.anchor_block_index,
            "timestamp": self.timestamp,
        }
        # T20: emit chain_id only if set, keeping legacy on-wire bytes
        # identical for backward compatibility.
        if self.chain_id is not None:
            d["chain_id"] = self.chain_id
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "MixerWithdrawTransaction":
        # `withdraw_amount` is silently discarded if present (hardening-pass legacy).
        # `anchor_block_index` defaults to 0 if absent (timing-pass legacy).
        # `chain_id` defaults to None if absent (pre-T20 legacy).
        # A reader of a pre-timing-pass chain with mixer activity will
        # silently load with anchor=0; the chain's load() rebuild may
        # then reject the chain if the anchor doesn't match a real
        # historical root. This is the migration we don't formally
        # support — pre-timing-pass saves with mixer withdrawals.
        return cls(
            mixer_root=tuple(d["mixer_root"]),       # type: ignore[arg-type]
            nullifier=tuple(d["nullifier"]),         # type: ignore[arg-type]
            output_leaf=tuple(d["output_leaf"]),     # type: ignore[arg-type]
            proof=bytes.fromhex(d["proof"]),
            anchor_block_index=d.get("anchor_block_index", 0),
            timestamp=d.get("timestamp", time.time()),
            chain_id=d.get("chain_id"),              # T20: None if missing (legacy)
        )

    def verify(
        self,
        anchored_mixer_root: Digest,
        seen_mixer_nullifiers: Set[Digest],
    ) -> tuple[bool, str]:
        """Verify against the supplied (anchored) mixer pool root.

        The caller (chain admission or chain replay) is responsible for
        looking up the historical mixer root corresponding to this
        withdrawal's `anchor_block_index` and passing it as
        `anchored_mixer_root`. The timing-attack defense — checking
        that the anchor is at least MIXER_WITHDRAWAL_DELAY blocks old —
        is enforced at the chain layer, not here.
        """
        # 1. Anchored root match
        if self.mixer_root != anchored_mixer_root:
            return False, "stale or wrong-anchor mixer root"

        # 2. Nullifier not seen
        if self.nullifier in seen_mixer_nullifiers:
            return False, "mixer nullifier already seen (double-withdraw)"

        # 3. STARK proof verifies. The AIR's value-conservation constraint:
        #     v_in == unshield_amount + fee + v_out
        # For mixer withdrawals the entire deposit value flows into the
        # output (STARK pool credit), so unshield_amount=0, fee=0,
        # v_out=denomination. The denomination itself is private — it lives
        # inside output_leaf's hidden preimage. The chain cannot determine
        # which denomination was withdrawn without also knowing the
        # spender's output-side secrets.
        try:
            ok = q.verify_m86_membership(
                self.proof,
                self.mixer_root,
                self.nullifier,
                0,                          # unshield_amount = 0 (matches prover)
                0,                          # fee = 0
                self.output_leaf,
            )
        except Exception as e:
            return False, f"STARK verification raised: {type(e).__name__}: {e}"
        if not ok:
            return False, "STARK proof failed to verify"

        return True, "ok"


# ============================================================================
# Construction helpers
# ============================================================================

def create_mixer_deposit_tx(
    sender_wallet,                   # qchain.chain.wallet.Wallet
    denomination: int,
    note: STARKNote,
) -> MixerDepositTransaction:
    """Build and sign a mixer deposit tx.

    The sender's wallet authorizes the transparent debit. The note's
    secrets are retained by the sender to authorize a later withdrawal.

    Returns a ready-to-broadcast MixerDepositTransaction. Caller must
    also retain `note` to later prove ownership.
    """
    if denomination not in MIXER_DENOMINATIONS:
        raise ValueError(
            f"denomination {denomination} not in allowed set {MIXER_DENOMINATIONS}"
        )
    if int(note.value) != denomination:
        raise ValueError(
            f"note value {int(note.value)} does not match denomination {denomination}"
        )
    deposit = MixerDepositTransaction(
        sender="",                   # filled in by sign()
        leaf=note.leaf(),
        amount=denomination,
        timestamp=time.time(),
        nonce=int(time.time() * 1e6),
    )
    deposit.sign(sender_wallet.keypair)
    return deposit


def create_mixer_withdraw_tx(
    note: STARKNote,                 # the depositor's note (preimage of a mixer leaf)
    leaf_idx: int,                   # the note's position in the mixer tree
    mixer_tree,                      # STARKAnonTree at the anchor block (NOT necessarily current)
    output_note: STARKNote,          # the NEW shielded note to land in STARK pool
    anchor_block_index: int = 0,     # M-timing: which historical block the proof anchors to
) -> MixerWithdrawTransaction:
    """Build a mixer withdrawal tx.

    The depositor proves they know the preimage to some mixer leaf and
    designates a new shielded note (`output_note`) that the chain will
    append to the STARK pool. The new note's value must equal the
    original deposit's denomination (no value created or destroyed).

    Timing-attack defense (M-timing): the proof anchors against the
    mixer-pool state AT BLOCK `anchor_block_index`, not the current
    chain head. The caller provides a `mixer_tree` reflecting that
    historical state (it must contain the depositor's leaf at
    `leaf_idx` with the same value as at deposit time). The chain
    will reject withdrawals whose anchor is too recent
    (must be <= current_height - MIXER_WITHDRAWAL_DELAY).
    """
    denomination = int(note.value)
    if denomination not in MIXER_DENOMINATIONS:
        raise ValueError(
            f"mixer leaf denomination {denomination} not in allowed set"
        )
    if int(output_note.value) != denomination:
        raise ValueError(
            f"output_note value {int(output_note.value)} must equal "
            f"deposit denomination {denomination} (no value created or destroyed)"
        )

    # Verify the note actually sits at leaf_idx in the supplied (historical) tree.
    expected_leaf = note.leaf()
    actual_leaf = mixer_tree._layers[0][leaf_idx]
    if actual_leaf != expected_leaf:
        raise ValueError(
            f"note's leaf doesn't match mixer tree position {leaf_idx}"
        )

    # Build the STARK proof using the existing m86_air.
    # Map the M10 semantics onto m86_air's parameters:
    #   * Spend the full mixer leaf (unshield = denomination)
    #   * fee = 0 (mixer charges no fee)
    #   * v_out = 0 (the AIR equation v_in == unshield + fee + v_out
    #     requires v_out=0 when unshield = v_in)
    #   * output_leaf = H(output_note.sk, output_note.randomness, 0)
    #     But wait — output_note.value is `denomination`, not 0!
    #
    # We need v_out to equal the output_note's value (so the chain can
    # safely append output_leaf to the STARK pool and the spender can
    # later spend `denomination` from it).
    #
    # The right mapping:
    #   * unshield = 0 (no transparent payout — the value flows into STARK pool)
    #   * fee = 0
    #   * v_out = denomination (the output_note's value)
    # Then v_in == 0 + 0 + denomination = denomination ✓

    path = mixer_tree.auth_path(leaf_idx)
    proof, claimed_root, claimed_nullifier, claimed_output_leaf = q.prove_m86_membership(
        note.sk, note.randomness, note.value, path,
        0,                                              # unshield_amount = 0
        0,                                              # fee = 0
        output_note.sk, output_note.randomness, output_note.value,
    )

    if claimed_root != mixer_tree.root():
        raise RuntimeError(
            "STARK computed root doesn't match mixer tree root — "
            "tree may have changed during proof construction"
        )
    if claimed_nullifier != note.nullifier():
        raise RuntimeError("STARK computed nullifier doesn't match note.nullifier()")
    if claimed_output_leaf != output_note.leaf():
        raise RuntimeError("STARK computed output_leaf doesn't match output_note.leaf()")

    return MixerWithdrawTransaction(
        mixer_root=claimed_root,
        nullifier=claimed_nullifier,
        output_leaf=claimed_output_leaf,
        proof=proof,
        anchor_block_index=anchor_block_index,
    )
