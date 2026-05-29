"""A wallet: a Dilithium keypair plus convenience methods for sending.

M10 Phase 4 extension: tracks shielded notes the wallet owns in the
mixer pool and the STARK pool, with helpers for finding them by their
leaf index in the relevant tree.

Shielded-note bookkeeping is PERSISTED across `save()` / `load()`
as of the persistence pass. ROADMAP item 1.6 adds a
`reconcile_with_chain(chain)` helper that classifies each owned
note's current status (pending / confirmed / missing) given a
chain — useful after `load()` to see what the wallet thinks it
owns vs. what's actually on-chain. See
WALLET-NOTE-LIFECYCLE-README.md for the lifecycle model and what
the reconciliation does and does not catch.

Encryption-at-rest (closes T21 from THREAT-MODEL):
`save(path, passphrase=...)` encrypts the wallet's secrets with
argon2id (KDF) + AES-256-GCM (authenticated cipher); `load(path,
passphrase=...)` decrypts. Both `save` and `load` work without a
passphrase too — they fall back to the legacy plaintext format,
preserving backward compatibility with existing wallet files.
See WALLET-KEY-ENCRYPTION-README.md for details.
"""

from __future__ import annotations

import json
import os
import time
from base64 import b64decode, b64encode
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

from qchain.chain.transaction import Transaction
from qchain.crypto import dilithium
from qchain.crypto.anon_stark import STARKNote

if TYPE_CHECKING:
    from qchain.chain.blockchain import Blockchain
    from qchain.chain.mixer_tx import (
        MixerDepositTransaction, MixerWithdrawTransaction,
    )


# ---------------------------------------------------------------------------
# Encryption parameters
# ---------------------------------------------------------------------------
# These are the defaults used when `save(path, passphrase=...)` is called
# without overrides. argon2id parameters follow the OWASP 2023 cheat-sheet
# recommendation for the "less constrained" profile, balancing resistance
# against modern GPUs with reasonable laptop CPU time (~0.5s on a typical
# 2020s laptop).

DEFAULT_KDF_MEMORY_KIB = 64 * 1024   # 64 MiB
DEFAULT_KDF_ITERATIONS = 3
DEFAULT_KDF_PARALLELISM = 4
KDF_OUTPUT_BYTES = 32                # AES-256 key length
SALT_BYTES = 16
NONCE_BYTES = 12                     # AES-GCM standard nonce
ENCRYPTED_FORMAT_VERSION = "encrypted-v1"
# T19 closure: plaintext wallet files now carry an explicit version
# tag too. Files predating this change have no wallet_format key
# and are accepted as the legacy form (backward compat). Future
# plaintext-v2 etc. is rejected by load() unless this code knows it.
PLAINTEXT_FORMAT_VERSION = "plaintext-v1"


def _derive_key(
    passphrase: str,
    salt: bytes,
    memory_kib: int = DEFAULT_KDF_MEMORY_KIB,
    iterations: int = DEFAULT_KDF_ITERATIONS,
    parallelism: int = DEFAULT_KDF_PARALLELISM,
) -> bytes:
    """argon2id(passphrase, salt) → 32-byte key.

    Imported lazily so the wallet module doesn't pull argon2-cffi into
    every import path (most chain operations don't need encryption).
    """
    from argon2.low_level import hash_secret_raw, Type
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=iterations,
        memory_cost=memory_kib,
        parallelism=parallelism,
        hash_len=KDF_OUTPUT_BYTES,
        type=Type.ID,
    )


def _encrypt_payload(plaintext: bytes, passphrase: str) -> dict:
    """Encrypt `plaintext` with a passphrase-derived key.

    Returns a dict ready for JSON serialization, including all the
    parameters needed for decryption (salt, nonce, KDF settings).
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt = os.urandom(SALT_BYTES)
    key = _derive_key(passphrase, salt)
    nonce = os.urandom(NONCE_BYTES)
    aes = AESGCM(key)
    ciphertext = aes.encrypt(nonce, plaintext, associated_data=None)
    return {
        "wallet_format": ENCRYPTED_FORMAT_VERSION,
        "kdf": {
            "name": "argon2id",
            "salt": b64encode(salt).decode("ascii"),
            "memory_kib": DEFAULT_KDF_MEMORY_KIB,
            "iterations": DEFAULT_KDF_ITERATIONS,
            "parallelism": DEFAULT_KDF_PARALLELISM,
        },
        "cipher": {
            "name": "aes-256-gcm",
            "nonce": b64encode(nonce).decode("ascii"),
            "ciphertext": b64encode(ciphertext).decode("ascii"),
        },
    }


def _decrypt_payload(envelope: dict, passphrase: str) -> bytes:
    """Reverse `_encrypt_payload`. Raises `InvalidPassphraseError` on auth
    failure; raises `ValueError` on schema problems."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if envelope.get("wallet_format") != ENCRYPTED_FORMAT_VERSION:
        raise ValueError(
            f"unsupported wallet format: {envelope.get('wallet_format')!r}, "
            f"this build only knows {ENCRYPTED_FORMAT_VERSION!r}"
        )
    kdf = envelope["kdf"]
    if kdf.get("name") != "argon2id":
        raise ValueError(f"unsupported KDF: {kdf.get('name')!r}")
    cipher = envelope["cipher"]
    if cipher.get("name") != "aes-256-gcm":
        raise ValueError(f"unsupported cipher: {cipher.get('name')!r}")
    salt = b64decode(kdf["salt"])
    nonce = b64decode(cipher["nonce"])
    ciphertext = b64decode(cipher["ciphertext"])
    # Use the KDF parameters stored IN the file, not the module defaults —
    # that way old wallets keep loading even if defaults change.
    key = _derive_key(
        passphrase,
        salt,
        memory_kib=kdf["memory_kib"],
        iterations=kdf["iterations"],
        parallelism=kdf["parallelism"],
    )
    aes = AESGCM(key)
    try:
        return aes.decrypt(nonce, ciphertext, associated_data=None)
    except InvalidTag:
        raise InvalidPassphraseError(
            "decryption failed: wrong passphrase, or wallet file tampered with"
        )


class InvalidPassphraseError(Exception):
    """Raised by `Wallet.load(path, passphrase=...)` when the passphrase
    is wrong or the encrypted wallet's GCM tag fails to verify (i.e.,
    the file was modified after encryption).
    """


# ---------------------------------------------------------------------------
# ROADMAP 1.6: note reconciliation reporting
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReconciledNote:
    """A single owned note's status against a chain at a point in time.

    `pool` is "mixer" or "stark" — which tree the note belongs in.
    `leaf_idx` is the note's position in that tree if confirmed,
    None if the note is pending (not yet on-chain).
    """
    note: STARKNote
    pool: str
    leaf_idx: Optional[int]


@dataclass
class WalletReconciliation:
    """Report from `Wallet.reconcile_with_chain(chain)`.

    Each ReconciledNote belongs to exactly one of the two lists:
      * `confirmed` — leaf is present in the relevant tree (mixer or stark)
      * `pending`   — leaf is NOT present; note may be in-mempool,
                      on a different fork, or genuinely lost

    The wallet's own state is not mutated by reconciliation.
    """
    confirmed: List[ReconciledNote] = field(default_factory=list)
    pending: List[ReconciledNote] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Wallet
# ---------------------------------------------------------------------------


class Wallet:
    def __init__(self, keypair: dilithium.Keypair | None = None) -> None:
        self.keypair = keypair or dilithium.generate_keypair()
        # M10 Phase 4: shielded-note bookkeeping. The wallet tracks notes
        # it owns in each pool. NOT persisted across restarts in this
        # implementation; recover via chain scanning if needed.
        self.mixer_notes: List[STARKNote] = []
        self.stark_notes: List[STARKNote] = []

    @property
    def address(self) -> str:
        return self.keypair.address()

    def create_tx(self, recipient: str, amount: float,
                  chain_id: Optional[str] = None) -> Transaction:
        """Build and sign a transaction to `recipient`.

        T20: pass `chain_id` to bind this transaction to a specific
        network. The signature covers chain_id, so a tx signed for
        "qchain-v1" will not verify on a different network. Omitting
        chain_id (or passing None) produces a legacy unbound
        transaction — backward-compatible with pre-T20 chain files.
        """
        tx = Transaction(
            sender="",  # filled in by sign() from the public key
            recipient=recipient,
            amount=amount,
            timestamp=time.time(),
            nonce=int(time.time() * 1000),
            chain_id=chain_id,
        )
        tx.sign(self.keypair)
        return tx

    # ---- M10 mixer bookkeeping --------------------------------------------

    def create_mixer_deposit(self, denomination: int) -> "MixerDepositTransaction":
        """Generate a fresh note, build a signed deposit, remember the note.

        After calling this, the caller submits the deposit to a chain
        (and gossips it). When the deposit is mined, the wallet's stored
        note can be used to construct a withdrawal later — call
        `create_mixer_withdrawal(chain, mixer_note)` once the deposit
        is on-chain.
        """
        from qchain.chain.mixer_tx import (
            MIXER_DENOMINATIONS, create_mixer_deposit_tx,
        )
        if denomination not in MIXER_DENOMINATIONS:
            raise ValueError(
                f"denomination {denomination} not in allowed set {MIXER_DENOMINATIONS}"
            )
        note = STARKNote.random(value=denomination)
        deposit = create_mixer_deposit_tx(self, denomination, note)
        # Remember the note so we can withdraw it later
        self.mixer_notes.append(note)
        return deposit

    def find_mixer_note_idx(
        self, chain: "Blockchain", note: STARKNote,
    ) -> Optional[int]:
        """Find the leaf index of an owned mixer note in the pool.

        Returns the index if found, None if not yet on-chain (deposit
        still in mempool or different chain). Scans only the real leaves
        (up to `_next_idx`), not the depth-16 zero-padding.
        """
        target_leaf = note.leaf()
        for i in range(chain.mixer_tree._next_idx):
            if chain.mixer_tree._layers[0][i] == target_leaf:
                return i
        return None

    def find_stark_note_idx(
        self, chain: "Blockchain", note: STARKNote,
    ) -> Optional[int]:
        """Find the leaf index of an owned STARK-pool note (e.g., a
        change output from a STARK spend, or a withdrawal credit from
        a mixer withdrawal).
        """
        target_leaf = note.leaf()
        for i in range(chain.stark_anon_tree._next_idx):
            if chain.stark_anon_tree._layers[0][i] == target_leaf:
                return i
        return None

    def create_mixer_withdrawal(
        self,
        chain: "Blockchain",
        mixer_note: STARKNote,
        randomize_delay: bool = True,
    ) -> "MixerWithdrawTransaction":
        """Build a withdrawal proof for an owned mixer note.

        The wallet picks a fresh output note (random sk, randomness) of
        matching value. After mining, the wallet remembers the output
        note in `stark_notes` so the spender can later spend it via
        STARK-anon mechanics.

        M-timing: the proof is built against a HISTORICAL mixer root
        that's at least MIXER_WITHDRAWAL_DELAY blocks old. The wallet
        picks the latest valid anchor automatically. The mixer note
        being withdrawn must have been deposited at or before that
        anchor's block index — otherwise the historical tree won't
        contain it and the proof construction will fail.

        T14 partial mitigation: when `randomize_delay=True` (the default),
        the returned withdrawal carries a `suggested_delay_blocks` attribute
        with a uniformly-distributed random value in
        [0, MIXER_WITHDRAWAL_DELAY_RANDOMIZATION_MAX]. The CALLER is
        expected to hold the withdrawal for that many additional blocks
        before submitting to the chain, spreading withdrawals across a
        wider window than the deterministic chain-side
        MIXER_WITHDRAWAL_DELAY alone provides.

        Pass `randomize_delay=False` for deterministic tests; in that
        case `suggested_delay_blocks` is set to 0.

        Honest scope: this is a `[HEURISTIC]` partial mitigation, not a
        full `[DEFENDED]` defense. An attacker who applies statistical
        analysis over many blocks can still link deposits and
        withdrawals probabilistically — the randomization just widens
        the correlation window. See THREAT-MODEL.md T14.

        Raises ValueError if the mixer_note isn't actually in the mixer
        pool (e.g., the deposit hasn't been mined yet), the wallet
        doesn't own it, or the chain is too young for any anchor to
        satisfy the timing-attack delay.
        """
        from qchain.chain.mixer_tx import (
            create_mixer_withdraw_tx,
            MIXER_WITHDRAWAL_DELAY_RANDOMIZATION_MAX,
        )
        if mixer_note not in self.mixer_notes:
            raise ValueError("wallet does not own that mixer note")

        # Pick the most recent anchor that satisfies the timing-attack delay.
        anchor_idx = chain.latest_valid_mixer_anchor()
        if anchor_idx < 0:
            from qchain.chain.mixer_tx import MIXER_WITHDRAWAL_DELAY
            raise ValueError(
                f"chain too young for a valid mixer withdrawal anchor "
                f"(need at least {MIXER_WITHDRAWAL_DELAY} blocks "
                f"after deposit; chain height is {chain.height})"
            )
        # Reconstruct the mixer tree state as of that anchor block
        anchored_tree = chain.historical_mixer_tree_for_block(anchor_idx)
        # The note must be present in the historical tree
        leaf_idx = None
        target_leaf = mixer_note.leaf()
        for i in range(anchored_tree._next_idx):
            if anchored_tree._layers[0][i] == target_leaf:
                leaf_idx = i
                break
        if leaf_idx is None:
            raise ValueError(
                f"mixer note not present in mixer tree at anchor block "
                f"{anchor_idx} — deposit may be too recent (must be at "
                f"or before block {anchor_idx})"
            )
        # Fresh secrets for the output note (the chain credit)
        output_note = STARKNote.random(value=int(mixer_note.value))
        withdrawal = create_mixer_withdraw_tx(
            note=mixer_note,
            leaf_idx=leaf_idx,
            mixer_tree=anchored_tree,
            output_note=output_note,
            anchor_block_index=anchor_idx,
        )

        # T14: attach the randomized delay suggestion. The CALLER is
        # responsible for actually holding the withdrawal off-chain
        # for the suggested duration. Using secrets.randbelow for
        # crypto-quality randomness (we don't want a PRNG-predictable
        # delay distribution).
        import secrets
        if randomize_delay:
            withdrawal.suggested_delay_blocks = secrets.randbelow(
                MIXER_WITHDRAWAL_DELAY_RANDOMIZATION_MAX + 1
            )
        else:
            withdrawal.suggested_delay_blocks = 0

        # Remember the output note so we can spend it later
        self.stark_notes.append(output_note)
        # The mixer note is now "spent" — remove it from owned-mixer-notes
        self.mixer_notes.remove(mixer_note)
        return withdrawal

    # ---- ROADMAP 1.6: note reconciliation with chain -----------------------
    #
    # The wallet's mixer_notes / stark_notes lists are the spender's
    # knowledge of "notes I own." These lists are persisted across save/load.
    # But the lists alone don't say which notes are actually on-chain — a
    # note added to mixer_notes by create_mixer_deposit() is in the wallet
    # IMMEDIATELY, before the deposit is gossiped or mined. If the deposit
    # never makes it on-chain (network drop, mining failure, fork
    # resolution), the wallet would carry a "dead" note forever without
    # knowing.
    #
    # `reconcile_with_chain(chain)` answers the question: "for each note
    # I think I own, what does the chain currently say about it?" It
    # returns a structured report; it does NOT mutate the wallet state.
    # Callers can use the report to decide what to do (drop missing notes,
    # log warnings, etc.) without the wallet making a policy decision.
    #
    # Honest scope:
    # - Reconciliation only checks PRESENCE of the note in the chain's
    #   mixer_tree or stark_anon_tree. It does NOT check for spent-ness
    #   via nullifier lookups; a fully-spent note will appear "confirmed"
    #   if its leaf is still in the tree. Adding nullifier-check is a
    #   follow-up.
    # - Reconciliation is read-only with respect to the wallet. A future
    #   `prune_missing()` method could mutate based on the report, but
    #   that's a policy decision the user should make.
    # - The status "pending" means "this wallet owns the note but it's
    #   not yet in the chain's tree." It could be in mempool, on a fork,
    #   or simply lost. Reconciliation does not distinguish these cases.

    def reconcile_with_chain(self, chain: "Blockchain") -> "WalletReconciliation":
        """Classify each owned note by its presence in the chain.

        Returns a `WalletReconciliation` report:
          * `confirmed`: notes whose leaf is in the relevant tree
          * `pending`:   notes the wallet owns but whose leaf isn't (yet?)
                         in the tree — could be in mempool, on a fork,
                         or simply never made it

        The wallet's state is NOT mutated; callers decide what to do
        with the report.

        See `reconcile_summary()` for a one-line human-readable view.
        """
        confirmed: List[ReconciledNote] = []
        pending: List[ReconciledNote] = []
        # Mixer notes — check mixer_tree
        for note in self.mixer_notes:
            idx = self.find_mixer_note_idx(chain, note)
            entry = ReconciledNote(note=note, pool="mixer", leaf_idx=idx)
            if idx is not None:
                confirmed.append(entry)
            else:
                pending.append(entry)
        # STARK-pool notes — check stark_anon_tree
        for note in self.stark_notes:
            idx = self.find_stark_note_idx(chain, note)
            entry = ReconciledNote(note=note, pool="stark", leaf_idx=idx)
            if idx is not None:
                confirmed.append(entry)
            else:
                pending.append(entry)
        return WalletReconciliation(confirmed=confirmed, pending=pending)

    def reconcile_summary(self, chain: "Blockchain") -> str:
        """One-line human-readable reconciliation summary for logging
        / dashboard display.

        Example: "2 confirmed (2 mixer, 0 stark), 1 pending (1 mixer)"
        """
        rec = self.reconcile_with_chain(chain)
        c_mixer = sum(1 for r in rec.confirmed if r.pool == "mixer")
        c_stark = sum(1 for r in rec.confirmed if r.pool == "stark")
        p_mixer = sum(1 for r in rec.pending if r.pool == "mixer")
        p_stark = sum(1 for r in rec.pending if r.pool == "stark")
        return (
            f"{len(rec.confirmed)} confirmed ({c_mixer} mixer, {c_stark} stark), "
            f"{len(rec.pending)} pending ({p_mixer} mixer, {p_stark} stark)"
        )

    def prune_pending_notes(self, chain: "Blockchain") -> int:
        """Remove from mixer_notes/stark_notes any notes that are NOT
        on-chain. Returns the number of notes removed.

        This is the canonical "I just loaded a wallet and want to drop
        notes for failed-to-mine deposits" workflow. It IS destructive —
        notes that are merely in-mempool (not yet confirmed) will also
        be pruned. Use with care; usually you want this only after a
        long-enough delay that mempool-pending notes would have been
        mined or rejected.

        Use `reconcile_with_chain()` first if you want to inspect
        before pruning.
        """
        rec = self.reconcile_with_chain(chain)
        pending_notes = [r.note for r in rec.pending]
        removed = 0
        for note in pending_notes:
            # Note may appear in either list; remove from whichever has it
            if note in self.mixer_notes:
                self.mixer_notes.remove(note)
                removed += 1
            if note in self.stark_notes:
                self.stark_notes.remove(note)
                removed += 1
        return removed

    # ---- persistence ------------------------------------------------------
    # Wallets are stored as JSON. With a passphrase, the wallet's secrets
    # (keypair + shielded-note bookkeeping) are encrypted with argon2id +
    # AES-256-GCM; the on-disk JSON has only the KDF parameters, salt,
    # nonce, and ciphertext. Without a passphrase, the legacy
    # base64-only format is used (backward compatible with pre-T21 files).
    #
    # As of the persistence pass: mixer_notes and stark_notes are
    # persisted (as lists of (sk, randomness, value) triples). A wallet
    # restart preserves the bookkeeping needed to spend the user's
    # shielded notes.
    #
    # T21 closure: see WALLET-KEY-ENCRYPTION-README.md for the threat
    # model, parameter choices, and what's still out of scope (memory-
    # resident attackers, hardware-backed keys, etc.).

    def _build_save_payload(self) -> dict:
        """The plaintext wallet state, as a dict ready for JSON encoding.

        This is what gets either written plaintext (legacy format) or
        encrypted (new format) by save().
        """
        return {
            "public_key": b64encode(self.keypair.public_key).decode(),
            "secret_key": b64encode(self.keypair.secret_key).decode(),
            # Shielded note bookkeeping. Each note is (sk, randomness, value)
            # serialized as a 3-element list of ints. Both fields are
            # always-present lists (possibly empty) so loaders don't have
            # to do migration on old files written before this change.
            "mixer_notes": [
                [int(n.sk), int(n.randomness), int(n.value)]
                for n in self.mixer_notes
            ],
            "stark_notes": [
                [int(n.sk), int(n.randomness), int(n.value)]
                for n in self.stark_notes
            ],
        }

    def save(
        self,
        path: str | Path,
        passphrase: Optional[str] = None,
        *,
        allow_plaintext: bool = False,
    ) -> None:
        """Write the wallet to `path` as JSON.

        Encryption is the default. Callers MUST either:
          * provide a non-empty `passphrase` (wallet is encrypted at rest
            via argon2id + AES-256-GCM; the on-disk file contains only
            KDF parameters and ciphertext), OR
          * explicitly pass `allow_plaintext=True` to opt out of
            encryption (legacy behavior; not recommended).

        Calling `wallet.save(path)` with no passphrase and no
        `allow_plaintext=True` raises `ValueError`. This was a
        deliberate behavior change in the wallet-security pass —
        previously a no-passphrase save silently wrote plaintext,
        which let the Dilithium secret key sit unprotected on disk.

        `allow_plaintext` is keyword-only (note the `*` separator
        in the signature) so a positional argument can't accidentally
        enable it.

        Note: passing `passphrase=""` (empty string) is treated as
        "no passphrase" and triggers the same `ValueError` — empty
        strings aren't passphrases.
        """
        payload = self._build_save_payload()
        if passphrase:
            plaintext = json.dumps(payload).encode("utf-8")
            envelope = _encrypt_payload(plaintext, passphrase)
            Path(path).write_text(json.dumps(envelope))
            return
        # No passphrase. Refuse unless explicitly opted out.
        if not allow_plaintext:
            raise ValueError(
                "Wallet.save() requires a passphrase to encrypt the "
                "Dilithium secret key at rest. Saving in plaintext "
                "lets anyone who reads the file spend wallet funds. "
                "Pass a passphrase to encrypt (recommended), or pass "
                "allow_plaintext=True to explicitly opt out of "
                "encryption."
            )
        # Explicit plaintext opt-out path. T19 closure: tag the file
        # with PLAINTEXT_FORMAT_VERSION so future schema changes can
        # detect-and-reject (or migrate) old files instead of silently
        # mis-loading them. The version field is added to a COPY of the
        # payload so _build_save_payload() stays format-agnostic.
        plaintext_envelope = dict(payload)
        plaintext_envelope["wallet_format"] = PLAINTEXT_FORMAT_VERSION
        Path(path).write_text(json.dumps(plaintext_envelope))

    @classmethod
    def load(cls, path: str | Path, passphrase: Optional[str] = None) -> "Wallet":
        """Load a wallet from `path`.

        Auto-detects whether the file is encrypted by looking for the
        `wallet_format` key. If the file IS encrypted, a passphrase is
        required and `InvalidPassphraseError` is raised if it's wrong
        or omitted. If the file is NOT encrypted, the passphrase
        argument is ignored (a legacy plaintext file with a passphrase
        passed is harmless, not an error).
        """
        on_disk = json.loads(Path(path).read_text())
        if on_disk.get("wallet_format") == ENCRYPTED_FORMAT_VERSION:
            if not passphrase:
                raise InvalidPassphraseError(
                    f"wallet file {path} is encrypted; passphrase required"
                )
            plaintext = _decrypt_payload(on_disk, passphrase)
            data = json.loads(plaintext.decode("utf-8"))
        elif on_disk.get("wallet_format") == PLAINTEXT_FORMAT_VERSION:
            # T19 closure: new tagged plaintext format. Same payload
            # shape as legacy, just with an explicit version marker.
            # Strip the version field before passing on so downstream
            # field-by-field reads don't see it.
            data = {k: v for k, v in on_disk.items() if k != "wallet_format"}
        elif "wallet_format" in on_disk:
            # File self-identifies as some format we don't know.
            # Don't guess — refuse cleanly so a future encrypted-v2
            # or plaintext-v2 wallet doesn't get silently misread.
            raise ValueError(
                f"unsupported wallet format: {on_disk['wallet_format']!r}, "
                f"this build knows {ENCRYPTED_FORMAT_VERSION!r}, "
                f"{PLAINTEXT_FORMAT_VERSION!r}, and the legacy plaintext "
                f"format (no wallet_format key)"
            )
        else:
            # Legacy plaintext format — no wallet_format field at all.
            # Pre-T19-closure files in the wild look like this.
            data = on_disk
        kp = dilithium.Keypair(
            public_key=b64decode(data["public_key"]),
            secret_key=b64decode(data["secret_key"]),
        )
        w = cls(kp)
        # Migration-friendly: old wallet files don't have these keys.
        for entry in data.get("mixer_notes", []):
            w.mixer_notes.append(
                STARKNote(sk=entry[0], randomness=entry[1], value=entry[2])
            )
        for entry in data.get("stark_notes", []):
            w.stark_notes.append(
                STARKNote(sk=entry[0], randomness=entry[1], value=entry[2])
            )
        return w
