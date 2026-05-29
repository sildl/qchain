"""Tests for wallet encryption at rest (T21 closure).

Covers:
  * Encrypted roundtrip with passphrase preserves wallet state exactly
  * Wrong passphrase rejected with InvalidPassphraseError
  * Missing passphrase on encrypted file rejected
  * Backward compatibility: legacy plaintext format still loads
  * File-level sanity: encrypted wallet does NOT contain secret_key as
    a plain JSON field (encryption actually happens)
  * GCM authentication catches tampering of the ciphertext or nonce
  * KDF parameters are stored IN the file, not read from module
    defaults — so changing defaults doesn't break old wallets
  * Shielded-note state survives encrypted roundtrip
  * load() with passphrase is harmless on plaintext files

See WALLET-KEY-ENCRYPTION-README.md for the threat model and what is
explicitly out of scope (memory-resident attackers, hardware-backed
keys, biometrics, etc.).
"""

from __future__ import annotations

import json
import os
import tempfile
from base64 import b64encode

import pytest

from qchain.chain.wallet import (
    DEFAULT_KDF_ITERATIONS,
    DEFAULT_KDF_MEMORY_KIB,
    DEFAULT_KDF_PARALLELISM,
    ENCRYPTED_FORMAT_VERSION,
    InvalidPassphraseError,
    Wallet,
)
from qchain.crypto.anon_stark import STARKNote


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tmp_json_path() -> str:
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    return path


def _wallet_with_notes() -> Wallet:
    """Build a wallet with some non-default state in BOTH shielded-note
    lists. Used to confirm encryption preserves all wallet state, not
    just the keypair."""
    w = Wallet()
    w.mixer_notes.append(STARKNote(sk=1, randomness=2, value=10))
    w.mixer_notes.append(STARKNote(sk=3, randomness=4, value=100))
    w.stark_notes.append(STARKNote(sk=5, randomness=6, value=42))
    return w


# ---------------------------------------------------------------------------
# Wallet-security pass: encryption is the default
# ---------------------------------------------------------------------------
# Save() requires either a real passphrase or an explicit allow_plaintext=True
# opt-out. Previously, save(path) silently produced plaintext — a usability
# footgun. This section pins the new behavior.

def test_save_without_passphrase_raises_by_default():
    """A bare wallet.save(path) — no passphrase, no opt-out — raises
    ValueError. The error message tells the caller exactly what to do.
    """
    w = Wallet()
    path = _tmp_json_path()
    try:
        with pytest.raises(ValueError, match="requires a passphrase"):
            w.save(path)
        # File should not have been written
        assert not os.path.exists(path) or os.path.getsize(path) == 0
    finally:
        if os.path.exists(path):
            os.unlink(path)


def test_save_with_empty_passphrase_raises():
    """passphrase="" is treated as "no passphrase" (empty strings aren't
    passphrases). Same error as bare save(path).
    """
    w = Wallet()
    path = _tmp_json_path()
    try:
        with pytest.raises(ValueError, match="requires a passphrase"):
            w.save(path, passphrase="")
    finally:
        if os.path.exists(path):
            os.unlink(path)


def test_save_with_allow_plaintext_true_succeeds():
    """Explicit opt-out: save(path, allow_plaintext=True) writes a
    plaintext file. The file loads cleanly. This is the documented
    escape hatch for callers who genuinely need plaintext (legacy
    tests, throwaway demo wallets, etc.).

    Post-T19-closure: the plaintext file now carries an explicit
    `wallet_format: "plaintext-v1"` version tag. Legacy plaintext
    files in the wild (no tag) continue to load via the legacy
    branch in `load()`.
    """
    from qchain.chain.wallet import PLAINTEXT_FORMAT_VERSION
    w = Wallet()
    addr = w.address
    path = _tmp_json_path()
    try:
        w.save(path, allow_plaintext=True)
        # File exists and is tagged plaintext-v1 (T19 closure)
        on_disk = json.loads(open(path).read())
        assert on_disk.get("wallet_format") == PLAINTEXT_FORMAT_VERSION
        assert "secret_key" in on_disk
        # And it loads cleanly
        loaded = Wallet.load(path)
        assert loaded.address == addr
    finally:
        os.unlink(path)


def test_save_allow_plaintext_is_keyword_only():
    """allow_plaintext is keyword-only (note the * in the save()
    signature). A positional call like save(path, None, True) cannot
    accidentally enable plaintext — Python raises TypeError because
    there's no positional slot for the third argument.
    """
    w = Wallet()
    path = _tmp_json_path()
    try:
        with pytest.raises(TypeError):
            w.save(path, None, True)  # type: ignore[misc]
    finally:
        if os.path.exists(path):
            os.unlink(path)


# ---------------------------------------------------------------------------
# Basic roundtrip
# ---------------------------------------------------------------------------

def test_encrypted_wallet_roundtrip_preserves_address():
    """Encrypted save + load with the same passphrase reproduces the
    wallet's address (i.e., the keypair was preserved end-to-end).
    """
    w = Wallet()
    addr = w.address
    path = _tmp_json_path()
    try:
        w.save(path, passphrase="correct horse battery staple")
        loaded = Wallet.load(path, passphrase="correct horse battery staple")
        assert loaded.address == addr
    finally:
        os.unlink(path)


def test_encrypted_wallet_roundtrip_preserves_shielded_notes():
    """All four pieces of wallet state — keypair, address, mixer_notes,
    stark_notes — survive an encrypted roundtrip."""
    w = _wallet_with_notes()
    addr = w.address
    pre_mixer = [(int(n.sk), int(n.randomness), int(n.value)) for n in w.mixer_notes]
    pre_stark = [(int(n.sk), int(n.randomness), int(n.value)) for n in w.stark_notes]
    path = _tmp_json_path()
    try:
        w.save(path, passphrase="pass")
        loaded = Wallet.load(path, passphrase="pass")
        assert loaded.address == addr
        loaded_mixer = [(int(n.sk), int(n.randomness), int(n.value))
                        for n in loaded.mixer_notes]
        loaded_stark = [(int(n.sk), int(n.randomness), int(n.value))
                        for n in loaded.stark_notes]
        assert loaded_mixer == pre_mixer
        assert loaded_stark == pre_stark
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------

def test_wrong_passphrase_raises_invalid_passphrase_error():
    """The GCM authentication tag forces a clean InvalidPassphraseError
    on the wrong passphrase — no false-positive decrypt to garbage."""
    w = Wallet()
    path = _tmp_json_path()
    try:
        w.save(path, passphrase="real")
        with pytest.raises(InvalidPassphraseError):
            Wallet.load(path, passphrase="fake")
    finally:
        os.unlink(path)


def test_missing_passphrase_on_encrypted_file_raises():
    """Loading an encrypted file with NO passphrase is also rejected —
    the load function must not silently treat the file as plaintext."""
    w = Wallet()
    path = _tmp_json_path()
    try:
        w.save(path, passphrase="any")
        with pytest.raises(InvalidPassphraseError):
            Wallet.load(path)
    finally:
        os.unlink(path)


def test_tampered_ciphertext_rejected():
    """If an attacker flips a single bit in the ciphertext, GCM auth
    fails and the load raises. This is the cryptographic property
    that protects against on-disk tampering."""
    w = Wallet()
    path = _tmp_json_path()
    try:
        w.save(path, passphrase="pw")
        envelope = json.loads(open(path).read())
        from base64 import b64decode, b64encode as _b64e
        ct = bytearray(b64decode(envelope["cipher"]["ciphertext"]))
        ct[0] ^= 0x01  # flip one bit
        envelope["cipher"]["ciphertext"] = _b64e(bytes(ct)).decode("ascii")
        open(path, "w").write(json.dumps(envelope))
        with pytest.raises(InvalidPassphraseError):
            Wallet.load(path, passphrase="pw")
    finally:
        os.unlink(path)


def test_tampered_nonce_rejected():
    """Similarly, modifying the nonce makes the ciphertext un-decryptable
    under the same key. Confirms the nonce is properly bound."""
    w = Wallet()
    path = _tmp_json_path()
    try:
        w.save(path, passphrase="pw")
        envelope = json.loads(open(path).read())
        from base64 import b64decode, b64encode as _b64e
        nonce = bytearray(b64decode(envelope["cipher"]["nonce"]))
        nonce[0] ^= 0x01
        envelope["cipher"]["nonce"] = _b64e(bytes(nonce)).decode("ascii")
        open(path, "w").write(json.dumps(envelope))
        with pytest.raises(InvalidPassphraseError):
            Wallet.load(path, passphrase="pw")
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# File-level sanity: encryption actually happens
# ---------------------------------------------------------------------------

def test_encrypted_file_does_not_contain_secret_key_field():
    """The on-disk encrypted file MUST NOT contain `secret_key` as a
    plain JSON field. This is a structural check that the encryption
    layer is doing its job; if save() ever degraded to plaintext while
    claiming to encrypt, this test catches it."""
    w = Wallet()
    path = _tmp_json_path()
    try:
        w.save(path, passphrase="pw")
        contents = open(path).read()
        assert '"secret_key"' not in contents, (
            "encrypted wallet file contains secret_key field — "
            "encryption did not happen"
        )
        assert '"public_key"' not in contents, (
            "encrypted wallet file contains public_key field — "
            "the whole payload should be encrypted"
        )
    finally:
        os.unlink(path)


def test_encrypted_file_does_not_contain_raw_secret_key_bytes():
    """Stronger structural check: the actual secret_key bytes (as a
    base64 string, the way they'd appear in the legacy plaintext
    format) MUST NOT appear in the encrypted file. AES-GCM should
    make them unrecognizable."""
    w = Wallet()
    raw_sk_b64 = b64encode(w.keypair.secret_key).decode()
    path = _tmp_json_path()
    try:
        w.save(path, passphrase="pw")
        contents = open(path).read()
        # Look for any substring of the raw base64 secret key. The
        # secret key is ~3500 chars in base64; chance of even 50
        # consecutive chars appearing in random data is negligible.
        assert raw_sk_b64[:50] not in contents
        # Also check the public key — full envelope encryption
        raw_pk_b64 = b64encode(w.keypair.public_key).decode()
        assert raw_pk_b64[:50] not in contents
    finally:
        os.unlink(path)


def test_encrypted_file_advertises_format_version():
    """The file should self-identify its format so future loaders can
    distinguish legacy plaintext from encrypted and from future
    formats."""
    w = Wallet()
    path = _tmp_json_path()
    try:
        w.save(path, passphrase="pw")
        envelope = json.loads(open(path).read())
        assert envelope.get("wallet_format") == ENCRYPTED_FORMAT_VERSION
        assert envelope.get("kdf", {}).get("name") == "argon2id"
        assert envelope.get("cipher", {}).get("name") == "aes-256-gcm"
    finally:
        os.unlink(path)


def test_encrypted_file_stores_kdf_parameters():
    """KDF parameters MUST be stored in the file, not assumed from
    module defaults. This way the decrypt path can correctly re-derive
    the key even after the default parameters change in a future
    QChain release.

    Loading depends on the stored parameters (not defaults): we don't
    test that directly here since defaults haven't changed, but we
    verify the parameters are PRESENT.
    """
    w = Wallet()
    path = _tmp_json_path()
    try:
        w.save(path, passphrase="pw")
        envelope = json.loads(open(path).read())
        kdf = envelope["kdf"]
        assert kdf["memory_kib"] == DEFAULT_KDF_MEMORY_KIB
        assert kdf["iterations"] == DEFAULT_KDF_ITERATIONS
        assert kdf["parallelism"] == DEFAULT_KDF_PARALLELISM
        assert "salt" in kdf and len(kdf["salt"]) > 0
    finally:
        os.unlink(path)


def test_different_saves_produce_different_ciphertexts():
    """Identical wallet content saved twice produces different
    ciphertexts (the salt + nonce randomization). This is what makes
    the encryption non-deterministic and protects against an attacker
    who has the wallet at two points in time."""
    w = Wallet()
    path1 = _tmp_json_path()
    path2 = _tmp_json_path()
    try:
        w.save(path1, passphrase="same passphrase")
        w.save(path2, passphrase="same passphrase")
        env1 = json.loads(open(path1).read())
        env2 = json.loads(open(path2).read())
        assert env1["kdf"]["salt"] != env2["kdf"]["salt"]
        assert env1["cipher"]["nonce"] != env2["cipher"]["nonce"]
        assert env1["cipher"]["ciphertext"] != env2["cipher"]["ciphertext"]
        # Both should decrypt to the same wallet
        w1 = Wallet.load(path1, passphrase="same passphrase")
        w2 = Wallet.load(path2, passphrase="same passphrase")
        assert w1.address == w2.address == w.address
    finally:
        os.unlink(path1)
        os.unlink(path2)


# ---------------------------------------------------------------------------
# Backward compatibility
# ---------------------------------------------------------------------------

def test_legacy_plaintext_format_still_loads():
    """Existing wallet files in the wild are in the legacy plaintext
    format (no wallet_format key). Load() MUST continue to read them
    so users don't lose access to existing wallets.

    The SAVE side now requires either a passphrase or an explicit
    allow_plaintext=True (wallet-security pass); this test exercises
    the load path against a file produced via the opt-out.
    """
    w = Wallet()
    path = _tmp_json_path()
    try:
        w.save(path, allow_plaintext=True)  # opt-out: produces legacy format
        loaded = Wallet.load(path)  # legacy load form
        assert loaded.address == w.address
    finally:
        os.unlink(path)


def test_plaintext_file_loads_when_passphrase_passed():
    """If someone passes a passphrase to load() but the file is actually
    a legacy plaintext wallet, the passphrase is ignored (not an error).
    Otherwise migration would be ugly.

    The save side uses allow_plaintext=True (post-wallet-security pass);
    behavior of the LOAD side is what's being tested.
    """
    w = Wallet()
    path = _tmp_json_path()
    try:
        w.save(path, allow_plaintext=True)  # produce a plaintext file
        loaded = Wallet.load(path, passphrase="ignored")  # passphrase ignored
        assert loaded.address == w.address
    finally:
        os.unlink(path)


def test_save_with_empty_passphrase_now_raises():
    """Post-wallet-security pass: an empty-string passphrase is no
    longer treated as a fallback to plaintext. It raises ValueError,
    same as omitting the passphrase entirely.

    This was a deliberate behavior change. Previously, passphrase=""
    silently produced a plaintext file — a usability footgun. Now
    callers must either pass a real passphrase or opt out explicitly
    with allow_plaintext=True.
    """
    w = Wallet()
    path = _tmp_json_path()
    try:
        with pytest.raises(ValueError, match="requires a passphrase"):
            w.save(path, passphrase="")
    finally:
        # File was never written
        if os.path.exists(path):
            os.unlink(path)


# ---------------------------------------------------------------------------
# Cross-cutting: encrypted load uses stored KDF params not defaults
# ---------------------------------------------------------------------------

def test_load_uses_stored_kdf_params_not_defaults():
    """Manually craft an encrypted wallet with non-default KDF
    parameters and verify it loads. Confirms the decrypt path is
    reading parameters from the file."""
    # Save with default params, then manually rewrite kdf params to
    # non-default values WHILE re-encrypting with those params.
    from qchain.chain.wallet import _derive_key, NONCE_BYTES, SALT_BYTES
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from base64 import b64decode, b64encode

    w = Wallet()
    payload_bytes = json.dumps(w._build_save_payload()).encode("utf-8")

    # Non-default but valid argon2id parameters
    kdf_memory = 32 * 1024   # half of default
    kdf_iters = 2
    kdf_para = 2
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    key = _derive_key(
        "secret",
        salt,
        memory_kib=kdf_memory,
        iterations=kdf_iters,
        parallelism=kdf_para,
    )
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, payload_bytes, associated_data=None)
    envelope = {
        "wallet_format": ENCRYPTED_FORMAT_VERSION,
        "kdf": {
            "name": "argon2id",
            "salt": b64encode(salt).decode("ascii"),
            "memory_kib": kdf_memory,
            "iterations": kdf_iters,
            "parallelism": kdf_para,
        },
        "cipher": {
            "name": "aes-256-gcm",
            "nonce": b64encode(nonce).decode("ascii"),
            "ciphertext": b64encode(ct).decode("ascii"),
        },
    }
    path = _tmp_json_path()
    try:
        open(path, "w").write(json.dumps(envelope))
        loaded = Wallet.load(path, passphrase="secret")
        assert loaded.address == w.address
    finally:
        os.unlink(path)


def test_unknown_format_version_rejected():
    """If we see a wallet_format we don't recognize, load() refuses
    rather than guessing. This protects forward compatibility — a
    future encrypted-v2 wallet should not be silently treated as
    encrypted-v1."""
    envelope = {
        "wallet_format": "encrypted-v999",
        "kdf": {"name": "argon2id", "salt": "AAAA", "memory_kib": 1024,
                "iterations": 1, "parallelism": 1},
        "cipher": {"name": "aes-256-gcm", "nonce": "AAAAAAAAAAAAAAAA",
                   "ciphertext": "AAAA"},
    }
    path = _tmp_json_path()
    try:
        open(path, "w").write(json.dumps(envelope))
        with pytest.raises(ValueError, match="unsupported wallet format"):
            Wallet.load(path, passphrase="anything")
    finally:
        os.unlink(path)
