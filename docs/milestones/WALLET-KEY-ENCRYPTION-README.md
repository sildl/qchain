# WALLET-KEY-ENCRYPTION-README

Implementation of ROADMAP item 1.4: encryption-at-rest for wallet
files. Closes threat **T21** (Wallet key compromise) from
[`THREAT-MODEL.md`](../../THREAT-MODEL.md).

## What this is

`Wallet.save(path, passphrase=...)` now encrypts the wallet's
secrets with argon2id (KDF) + AES-256-GCM (authenticated cipher)
before writing to disk. `Wallet.load(path, passphrase=...)`
decrypts. Both methods continue to support the legacy plaintext
format when no passphrase is supplied.

## What the threat is, exactly

An attacker who gets **read-only filesystem access** to a wallet
file but does NOT have:
- access to a running process (where the decrypted key would be in
  memory)
- access to the user's passphrase
- access to the passphrase-input channel (keylogger etc.)

Before this work, such an attacker could decode the base64 secret
key directly out of the JSON and forge transactions. With this
work, they instead face an offline brute-force attack against an
argon2id KDF — practically infeasible for any passphrase with
moderate entropy.

Concrete realistic scenarios this defends against:
- **Laptop theft.** The attacker has the encrypted disk image but
  not the user's login password (assuming FDE didn't apply) or
  wallet passphrase.
- **Backup leak.** A cloud-sync service exposes the wallet file but
  the attacker doesn't have credentials to the user's environment.
- **Accidental commit to version control.** The encrypted wallet
  doesn't expose the secret key the way a plaintext one would.
- **Misconfigured filesystem permissions.** A casual `cat
  ~/.qchain/wallet.json` no longer reveals the key.

## What it does NOT defend against

Listed honestly so users don't over-trust the mechanism:

- **Memory-resident attackers.** Once `Wallet.load()` returns, the
  decrypted Dilithium key is in process memory. A process-attaching
  attacker (ptrace, /proc/*/mem, debugger) reads it directly.
- **Passphrase-capture attacks.** Keyloggers, shoulder-surfing,
  malicious shell config that intercepts `getpass`, etc. — these
  beat encryption at rest because they steal the input directly.
- **Trivially weak passphrases.** argon2id makes brute force expensive
  per guess, but a passphrase like "password" or "qchain" is
  recoverable in seconds even with strong KDF settings.
- **Hardware-backed key storage.** TPM, secure enclaves, hardware
  wallets — out of scope. Adding these would be a separate ROADMAP
  item with its own design.
- **User decisions.** If the user calls `save(path)` without a
  passphrase, the legacy plaintext format is used. Policy enforcement
  ("you MUST encrypt") is not part of this pass.

## Design choices

### KDF: argon2id

OWASP 2023 cheat-sheet recommendation for the "less constrained"
profile. Parameters:

| Parameter | Default value | Rationale |
|---|---:|---|
| Memory | 64 MiB | Hard for GPU attackers, fine for laptop CPUs |
| Iterations | 3 | Time-cost baseline |
| Parallelism | 4 | Matches typical laptop core count |
| Output | 32 bytes | AES-256 key length |
| Salt | 16 bytes random | Per-save randomization |

Measured time on the development container: ~180ms per derive. On
slower laptops this rises toward 500ms. That's well-tuned for an
interactive UI (single human-noticeable delay at save/load) and
costly enough to make brute-force searches impractical even with
specialized hardware.

The KDF parameters are STORED IN the encrypted file. Loading uses
the parameters from the file, not the module defaults — so an old
file remains loadable even after the defaults change in a future
QChain release.

### Cipher: AES-256-GCM

Authenticated encryption with associated data (AEAD). Authentication
is essential: without it, an attacker could tamper with the
ciphertext and the decryption might silently return garbage that
gets parsed as a wallet. GCM's 16-byte tag makes tampering
detection rate-limited only by the tag length (effectively never
false-positive).

Nonce: 12 bytes, random per save. With ~10^11 keys per nonce-bound
key (well within AES-GCM safety bounds for typical wallet-save
frequency), nonce reuse is not a practical concern at the savings
rate of a single user.

### File format

```json
{
  "wallet_format": "encrypted-v1",
  "kdf": {
    "name": "argon2id",
    "salt": "<base64, 16 bytes>",
    "memory_kib": 65536,
    "iterations": 3,
    "parallelism": 4
  },
  "cipher": {
    "name": "aes-256-gcm",
    "nonce": "<base64, 12 bytes>",
    "ciphertext": "<base64, encrypted payload + 16-byte GCM tag>"
  }
}
```

The plaintext that gets encrypted is the JSON serialization of:
- `public_key` (base64-encoded)
- `secret_key` (base64-encoded)
- `mixer_notes` (list of `[sk, randomness, value]` triples)
- `stark_notes` (list of `[sk, randomness, value]` triples)

**Everything is encrypted, not just the secret key.** The
`mixer_notes` and `stark_notes` contain the `(sk, randomness,
value)` triples for shielded notes — those secrets let anyone who
has them spend the notes. Encrypting only the Dilithium key would
leak the shielded-note secrets. The public key isn't sensitive but
gets encrypted too for simplicity.

### Format versioning

The `wallet_format` field self-identifies the format. Three behaviors:

- `wallet_format: "encrypted-v1"` → decrypt with passphrase
- `wallet_format` absent → legacy plaintext format
- Any other `wallet_format` value → raise `ValueError` (don't guess)

This makes future formats (encrypted-v2 with different KDF/cipher,
say) drop-in compatible without breaking the load path.

### Passphrase handling

`save(path, passphrase: Optional[str])`:
- `None` or `""` → legacy plaintext format
- Non-empty string → encrypted

`load(path, passphrase: Optional[str])`:
- File is plaintext → passphrase argument ignored (graceful)
- File is encrypted, passphrase provided → decrypt
- File is encrypted, passphrase missing or wrong → `InvalidPassphraseError`

The wallet module deliberately does NOT prompt the user
interactively. Whether the passphrase comes from `getpass`, an
environment variable, a config file, or a hardware-backed prompt is
the caller's choice. Keeping that decision out of the wallet module
preserves testability and lets the dashboard / CLI / scripts each
handle it appropriately.

## Backward compatibility

The legacy plaintext format remains supported indefinitely:
- `save(path)` (no passphrase) writes legacy plaintext
- `load(path)` (no passphrase) reads either format via auto-detect
- Existing wallet files load without modification

All 245 existing QChain Python tests pass without changes. No
test calling `save(path)` or `Wallet.load(path)` needed to be
updated.

## Tests

`test_wallet_encryption.py` — 16 tests:

| # | Test | What it verifies |
|---|---|---|
| 1 | `encrypted_wallet_roundtrip_preserves_address` | Basic encrypt+decrypt restores keypair |
| 2 | `encrypted_wallet_roundtrip_preserves_shielded_notes` | mixer_notes + stark_notes survive |
| 3 | `wrong_passphrase_raises_invalid_passphrase_error` | Auth tag catches wrong passphrase |
| 4 | `missing_passphrase_on_encrypted_file_raises` | Load without passphrase rejected |
| 5 | `tampered_ciphertext_rejected` | Bit-flip in ciphertext → AuthError |
| 6 | `tampered_nonce_rejected` | Bit-flip in nonce → AuthError |
| 7 | `encrypted_file_does_not_contain_secret_key_field` | No "secret_key" JSON field |
| 8 | `encrypted_file_does_not_contain_raw_secret_key_bytes` | Base64 secret_key bytes absent |
| 9 | `encrypted_file_advertises_format_version` | wallet_format / kdf / cipher fields present |
| 10 | `encrypted_file_stores_kdf_parameters` | KDF params actually saved |
| 11 | `different_saves_produce_different_ciphertexts` | Salt + nonce randomization |
| 12 | `legacy_plaintext_save_load_still_works` | Backward compat |
| 13 | `plaintext_file_loads_when_passphrase_passed` | Graceful passphrase ignore on plaintext |
| 14 | `save_with_empty_passphrase_treats_as_plaintext` | "" passphrase → plaintext format |
| 15 | `load_uses_stored_kdf_params_not_defaults` | Old wallets still load after defaults change |
| 16 | `unknown_format_version_rejected` | Future formats rejected, not guessed |

Runtime: ~3 seconds total (mostly KDF time across the encrypted
tests).

## Test results

| Layer | Pre-encryption | Post-encryption |
|---|---:|---:|
| qstark Rust | 110 | 110 |
| qstark_py Python | 21 | 21 |
| QChain Python | 229 | **245** (+16 wallet-encryption) |
| **Total** | **360** | **376** |

All green.

## New dependencies

Two pure-Python wheels added (no native compilation beyond what
they bring themselves):

- `cryptography` (was already a transitive dependency in the test
  environment; explicitly used here for `cryptography.hazmat.primitives.ciphers.aead.AESGCM`)
- `argon2-cffi` (new — pulls in `argon2-cffi-bindings`)

Neither is pinned in a `requirements.txt` since QChain has none by
design; both install via `pip install cryptography argon2-cffi`.

## What changed in the repo

| File | Change |
|---|---|
| `qchain/chain/wallet.py` | +~150 lines: `_derive_key`, `_encrypt_payload`, `_decrypt_payload`, `InvalidPassphraseError`, encryption module-level constants, updated `save()` and `load()` signatures |
| `qchain/tests/test_wallet_encryption.py` | New file, 16 tests |
| `qchain/THREAT-MODEL.md` | T21 updated from `[NOT DEFENDED]` to `[DEFENDED]` (with caveats) |
| `qchain/ROADMAP.md` | 1.4 references corrected (T17 → T21); 1.5 references corrected (T18 removed, "four" → "three") |
| `qchain/WALLET-KEY-ENCRYPTION-README.md` | This document |

No changes to:
- The on-disk wire format for existing plaintext wallets
- Any existing test
- The chain protocol, network layer, dashboard, or any other module
- Wallet API signature beyond adding the optional `passphrase`
  parameter

## Honest scope notes

- **No UI exposure.** The dashboard does not yet have a "save
  encrypted" or "load encrypted" flow. Anyone using `Wallet.save(...,
  passphrase=...)` does so from a script. A dashboard flow would be a
  separate small pass — worth doing but not blocking.
- **No passphrase change mechanism.** Once you encrypt a wallet, the
  only way to change the passphrase is to load with the old one and
  save with the new one. A dedicated `change_passphrase()` helper
  would be a small follow-up.
- **Argon2id parameters are conservative.** Higher memory/iterations
  give stronger protection but slower interactive UX. The chosen
  defaults are OWASP's baseline; users with stronger threat models
  should override.
- **No HSM, no hardware wallet integration.** Out of scope. Adding
  these requires platform-specific work; ROADMAP item for the
  future.
- **The KDF is not constant-time WITH RESPECT TO PASSPHRASE LENGTH.**
  argon2id's hash time depends on the parameter `time_cost`, not on
  the secret. A side-channel attacker timing the KDF doesn't learn
  passphrase content. They could learn the KDF parameters, but those
  are stored in the file in plaintext anyway.
- **The InvalidPassphraseError exception message is intentionally
  vague** ("wrong passphrase, or wallet file tampered with"). This
  doesn't reveal to an attacker whether their guess was almost-right
  or the file was modified — both look identical to GCM. This is
  intentional from a security standpoint.

## What this gives the project

- T21 closes from `[NOT DEFENDED]` to `[DEFENDED]`
- One full threat-model entry now has a real mechanism, not just
  a roadmap pointer
- An end-user concern (`I want to back up my wallet without
  exposing my key`) has a real answer
- Foundation for any future ROADMAP work that needs encrypted
  containers (e.g., wallet-recovery backups, audit-log encryption)

## What's next

- ROADMAP item 1.5 (rate limiting / DoS hardening, T15/T22/T23) is
  the natural next session if continuing through the next-up list.
- ROADMAP item 1.3 (publication writeup) and item 1.1 (external audit
  engagement) remain the highest-priority items long-term.
- A dashboard flow for encrypted wallets is a small follow-up if
  someone wants encryption to be one-click rather than
  scripted-only.
