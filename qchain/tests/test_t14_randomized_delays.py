"""Tests for T14 partial mitigation: randomized withdrawal delays.

The defense: wallets generating mixer withdrawals attach a randomized
`suggested_delay_blocks` (uniform in [0, MIXER_WITHDRAWAL_DELAY_RANDOMIZATION_MAX])
to each withdrawal. The CALLER is expected to hold the withdrawal
off-chain for that many additional blocks before submitting, so that
withdrawals from any single deposit are spread across a wider window
than the chain-side MIXER_WITHDRAWAL_DELAY alone provides.

Honest scope: this is a `[HEURISTIC]` partial mitigation. A determined
attacker who applies statistical analysis over many blocks can still
link deposits and withdrawals probabilistically — the randomization
just widens the correlation window. See THREAT-MODEL.md T14.

This file tests:
  * The delay falls within the expected range
  * The distribution is non-degenerate (not all the same value)
  * `randomize_delay=False` gives deterministic 0 (for tests)
  * The delay attribute doesn't leak into to_dict() (on-chain serialization)
  * The default `randomize_delay=True` is the safe default
"""

from __future__ import annotations

from qchain.chain.blockchain import Blockchain
from qchain.chain.wallet import Wallet
from qchain.chain.mixer_tx import (
    MIXER_WITHDRAWAL_DELAY,
    MIXER_WITHDRAWAL_DELAY_RANDOMIZATION_MAX,
)


def _fresh_chain_with_funded_wallet():
    """Build a chain where a wallet has enough balance to deposit and
    the chain has aged enough that a valid mixer anchor exists.

    Returns (chain, wallet) after the fund-deposit-mine-age sequence.
    """
    chain = Blockchain()
    w = Wallet()
    # Fund the wallet
    for _ in range(2):
        chain.mine_pending(w.address)
    # Deposit
    dep = w.create_mixer_deposit(denomination=10)
    chain.submit_mixer_deposit(dep)
    chain.mine_pending(w.address)
    # Age the chain so the chain-side minimum delay is satisfied
    for _ in range(MIXER_WITHDRAWAL_DELAY + 1):
        chain.mine_pending(w.address)
    return chain, w


def test_t14_randomized_delay_in_expected_range():
    """The wallet's suggested_delay_blocks falls in [0, MAX]."""
    chain, w = _fresh_chain_with_funded_wallet()
    note = w.mixer_notes[0]
    wd = w.create_mixer_withdrawal(chain, note)
    assert hasattr(wd, "suggested_delay_blocks"), (
        "withdrawal should carry a suggested_delay_blocks attribute"
    )
    assert 0 <= wd.suggested_delay_blocks <= MIXER_WITHDRAWAL_DELAY_RANDOMIZATION_MAX, (
        f"delay {wd.suggested_delay_blocks} out of expected range "
        f"[0, {MIXER_WITHDRAWAL_DELAY_RANDOMIZATION_MAX}]"
    )


def test_t14_randomize_delay_false_gives_zero():
    """For deterministic tests, randomize_delay=False sets delay to 0."""
    chain, w = _fresh_chain_with_funded_wallet()
    note = w.mixer_notes[0]
    wd = w.create_mixer_withdrawal(chain, note, randomize_delay=False)
    assert wd.suggested_delay_blocks == 0


def test_t14_distribution_is_non_degenerate():
    """Across many withdrawals, the random delay produces more than one
    distinct value. This is a sanity check on the distribution — if every
    delay came back the same number, randomization isn't actually random.

    With MAX=20 and 30 samples, the chance of accidentally seeing < 5
    unique values is astronomically small under a true uniform
    distribution. If this test fails, the random source is broken.
    """
    observed_delays = set()
    for _ in range(30):
        chain, w = _fresh_chain_with_funded_wallet()
        note = w.mixer_notes[0]
        wd = w.create_mixer_withdrawal(chain, note)
        observed_delays.add(wd.suggested_delay_blocks)
    assert len(observed_delays) >= 5, (
        f"distribution too narrow: only {len(observed_delays)} unique "
        f"delays seen across 30 samples — randomization may be broken"
    )


def test_t14_suggested_delay_does_not_leak_into_serialization():
    """The suggested_delay_blocks attribute is a wallet-side concept; it
    must NOT appear in to_dict() (the on-chain serialization). Otherwise
    the chain would see the suggestion, defeating the defense (the
    attacker would just read it off the tx).
    """
    chain, w = _fresh_chain_with_funded_wallet()
    note = w.mixer_notes[0]
    wd = w.create_mixer_withdrawal(chain, note)
    d = wd.to_dict()
    assert "suggested_delay_blocks" not in d, (
        f"suggested_delay_blocks leaked into on-chain serialization: {d}"
    )


def test_t14_default_is_randomize_on():
    """The DEFAULT behavior of create_mixer_withdrawal is to randomize
    (i.e., the secure default). Tests/callers who don't pass any flag
    get randomization. This is the safe default; opt-out (for tests)
    requires explicit randomize_delay=False.
    """
    chain, w = _fresh_chain_with_funded_wallet()
    note = w.mixer_notes[0]
    # No explicit randomize_delay parameter — default kicks in
    wd = w.create_mixer_withdrawal(chain, note)
    # Default has randomization on, so the delay can be ANY value in
    # the range (including 0 by chance). The test asserts that the
    # attribute exists AND is in range — not that it's necessarily
    # non-zero on a single call.
    assert hasattr(wd, "suggested_delay_blocks")
    assert 0 <= wd.suggested_delay_blocks <= MIXER_WITHDRAWAL_DELAY_RANDOMIZATION_MAX
