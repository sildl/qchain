"""Hypothesis strategies for QChain property-based testing.

These strategies generate VALID, WELL-FORMED inputs that the chain
should accept. Bug-finding happens by composing many valid inputs and
checking that invariants the chain claims (conservation, double-spend
impossibility, persistence roundtrip, etc.) hold over the resulting
state.

Design choices:

- **Bounded ranges**: amounts, denomination indices, address counts are
  all kept small (typically 1-10) so Hypothesis can shrink failures
  to minimal repros quickly. Realistic chain volumes aren't the goal;
  *coverage of decision branches* is.
- **No proof generation in strategies**: STARK proofs take ~25ms each.
  Strategies generate transaction REQUESTS; tests that need real
  proofs build them on demand. This keeps strategy evaluation fast.
- **Strategies don't enforce inter-tx consistency**: e.g., the strategy
  for "transparent transfer" doesn't check the sender has the balance.
  Tests are responsible for either funding wallets first or filtering
  out infeasible txs at apply time.

The "scenarios" strategy (build_chain_scenario) composes these into
sequences of operations the test can replay on a chain.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple, Union

from hypothesis import strategies as st

from qchain.chain.mixer_tx import MIXER_DENOMINATIONS


# ---------------------------------------------------------------------------
# Primitive strategies
# ---------------------------------------------------------------------------

# Wallet indices: a fixed pool of N wallets per test scenario. The
# scenario builder creates these wallets up front and assigns each one
# an integer index. Operations reference wallets by index.
def wallet_indices(n_wallets: int) -> st.SearchStrategy[int]:
    """A wallet picker. We keep `n_wallets` small so Hypothesis can
    explore interactions between them effectively."""
    assert n_wallets >= 1
    return st.integers(min_value=0, max_value=n_wallets - 1)


# Small denominations from the mixer's allowed set.
mixer_denomination = st.sampled_from(MIXER_DENOMINATIONS)


# Transfer amount: 1..50 (well within the 10 coins/block PoW reward,
# so wallets fund themselves quickly).
transfer_amount = st.integers(min_value=1, max_value=50)


# Shield amount: same range.
shield_amount = st.integers(min_value=1, max_value=50)


# ---------------------------------------------------------------------------
# Operation types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class OpMine:
    """Mine a block, paying the coinbase reward to wallet[miner_idx]."""
    miner_idx: int


@dataclass(frozen=True)
class OpTransfer:
    """Wallet[sender_idx] sends `amount` to wallet[recipient_idx]."""
    sender_idx: int
    recipient_idx: int
    amount: int


@dataclass(frozen=True)
class OpMixerDeposit:
    """Wallet[depositor_idx] deposits one mixer note of given denomination."""
    depositor_idx: int
    denomination: int


@dataclass(frozen=True)
class OpShield:
    """Wallet[sender_idx] shields `amount` into a fresh stark note."""
    sender_idx: int
    amount: int


Op = Union[OpMine, OpTransfer, OpMixerDeposit, OpShield]


# ---------------------------------------------------------------------------
# Composed strategies
# ---------------------------------------------------------------------------

def operation(n_wallets: int) -> st.SearchStrategy[Op]:
    """Any single chain operation referencing one of n_wallets wallets.

    Weighted toward mining (since most ops need funds first) but
    Hypothesis will explore other distributions during shrinking.
    """
    wi = wallet_indices(n_wallets)
    return st.one_of(
        st.builds(OpMine, miner_idx=wi),
        st.builds(OpMine, miner_idx=wi),         # weight ×2
        st.builds(OpMine, miner_idx=wi),         # weight ×3
        st.builds(OpTransfer, sender_idx=wi, recipient_idx=wi, amount=transfer_amount),
        st.builds(OpMixerDeposit, depositor_idx=wi, denomination=mixer_denomination),
        st.builds(OpShield, sender_idx=wi, amount=shield_amount),
    )


def operation_sequences(
    n_wallets: int = 3,
    min_size: int = 5,
    max_size: int = 30,
) -> st.SearchStrategy[Tuple[int, List[Op]]]:
    """Generate (n_wallets, [op, op, ...]).

    The default (3 wallets, 5..30 ops) gives Hypothesis enough state
    space to explore meaningful interactions without explosion.
    """
    return st.tuples(
        st.just(n_wallets),
        st.lists(operation(n_wallets), min_size=min_size, max_size=max_size),
    )


# ---------------------------------------------------------------------------
# Scenario execution
# ---------------------------------------------------------------------------

def execute_scenario(chain, wallets: list, ops: List[Op]) -> List[Tuple[Op, str]]:
    """Run `ops` against `chain` with `wallets`, returning [(op, outcome), ...].

    Outcome is "ok" if the operation succeeded, or "skipped: <reason>" if
    it was infeasible (insufficient balance, etc.). Tests use this to
    distinguish "operation was rejected as expected" from "test setup is
    wrong".

    Errors raised during apply are returned as outcomes rather than
    propagated, so the test can verify "the chain didn't crash on any
    input from the generator".
    """
    from qchain.chain.mixer_tx import create_mixer_deposit_tx
    from qchain.chain.shield_tx import ShieldTransaction
    from qchain.crypto.anon_stark import STARKNote
    import time as _time

    log: List[Tuple[Op, str]] = []

    for op in ops:
        try:
            if isinstance(op, OpMine):
                chain.mine_pending(wallets[op.miner_idx].address)
                log.append((op, "ok"))
            elif isinstance(op, OpTransfer):
                sender = wallets[op.sender_idx]
                recipient = wallets[op.recipient_idx]
                if chain.balance_of(sender.address) < op.amount:
                    log.append((op, "skipped: insufficient balance"))
                    continue
                tx = sender.create_tx(recipient.address, op.amount)
                chain.submit(tx)
                log.append((op, "ok"))
            elif isinstance(op, OpMixerDeposit):
                depositor = wallets[op.depositor_idx]
                if chain.balance_of(depositor.address) < op.denomination:
                    log.append((op, "skipped: insufficient balance for deposit"))
                    continue
                deposit = depositor.create_mixer_deposit(denomination=op.denomination)
                chain.submit_mixer_deposit(deposit)
                log.append((op, "ok"))
            elif isinstance(op, OpShield):
                sender = wallets[op.sender_idx]
                if chain.balance_of(sender.address) < op.amount:
                    log.append((op, "skipped: insufficient balance for shield"))
                    continue
                note = STARKNote.random(value=op.amount)
                shtx = ShieldTransaction(
                    sender="", leaf=note.leaf(), amount=float(op.amount),
                    timestamp=_time.time(),
                    nonce=int(_time.time() * 1e6) + op.amount,  # nonce differentiation
                )
                shtx.sign(sender.keypair)
                chain.submit_shield(shtx)
                log.append((op, "ok"))
            else:
                log.append((op, f"unknown op type"))
        except ValueError as e:
            # Chain rejected the op — this is FINE if the op was
            # infeasible; the test should not crash. Log and move on.
            log.append((op, f"rejected: {e}"))
        except Exception as e:
            # Anything else IS a bug — propagate
            raise

    return log
