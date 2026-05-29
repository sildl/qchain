"""Per-key sliding-window rate limiter.

Used by the network layer (per-peer message limits, T15) and the
dashboard (per-IP endpoint limits, T22). The primitive is small and
unit-tested so the two integration points share known-correct
mechanics.

Design notes:

- The window is "sliding" via a per-key deque of timestamps. Each
  call to `try_consume` first prunes expired timestamps, then checks
  the remaining count against the capacity. If under capacity, the
  new timestamp is appended and the call returns True.

- Memory is bounded by `capacity` per active key. Inactive keys'
  deques are NOT auto-pruned by `try_consume`; callers should call
  `prune_inactive()` periodically if the key space is unbounded
  (e.g., per-IP for an internet-facing service). For our use,
  per-peer with a small fixed peer set, this isn't an issue.

- Thread safety: a `threading.Lock` guards the internal state.
  The network layer dispatches messages from multiple threads
  (one per peer connection), and the dashboard's FastAPI routes
  run in an asyncio loop that may interleave with the chain
  thread; both paths must call try_consume safely.

- Time source: `time.monotonic()`. Not affected by wall-clock
  changes (NTP, manual adjustments). Counting in seconds for ease
  of reading; resolution is fine for the scales we care about
  (10-1000 messages per second per key).

The class is deliberately small and reusable. Future ROADMAP items
that need rate limiting (e.g., authentication retry limits, audit-log
rate limiting) can reuse it.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Hashable


class SlidingWindowRateLimiter:
    """Tracks recent action timestamps per key; rejects when the key
    has exceeded `capacity` actions in the trailing `window_seconds`.

    Example:
        # 100 messages per peer per 1-second window
        limiter = SlidingWindowRateLimiter(capacity=100, window_seconds=1.0)
        if limiter.try_consume(peer_addr):
            handle_message(...)
        else:
            log.warning(f"rate-limited peer {peer_addr}")
    """

    def __init__(self, capacity: int, window_seconds: float) -> None:
        if capacity <= 0:
            raise ValueError(f"capacity must be > 0, got {capacity}")
        if window_seconds <= 0:
            raise ValueError(f"window_seconds must be > 0, got {window_seconds}")
        self.capacity = capacity
        self.window_seconds = float(window_seconds)
        self._lock = threading.Lock()
        self._timestamps: Dict[Hashable, Deque[float]] = defaultdict(deque)

    def try_consume(self, key: Hashable, now: float | None = None) -> bool:
        """Attempt to record one action against `key`.

        Returns True if the action is allowed (key has < capacity
        actions in the current window); records the timestamp and
        returns True. Returns False if the key is over capacity;
        does NOT record (refused actions don't extend the window).

        The `now` parameter is for testing — pass a specific
        `time.monotonic()` value to make behavior deterministic. In
        production, leave it as None.
        """
        if now is None:
            now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            ts = self._timestamps[key]
            # Drop expired timestamps from the front
            while ts and ts[0] < cutoff:
                ts.popleft()
            if len(ts) >= self.capacity:
                return False
            ts.append(now)
            return True

    def current_count(self, key: Hashable, now: float | None = None) -> int:
        """Number of actions recorded for `key` in the current window.

        Helpful for diagnostics / tests. Also prunes the deque as a
        side effect (cheap).
        """
        if now is None:
            now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            ts = self._timestamps[key]
            while ts and ts[0] < cutoff:
                ts.popleft()
            return len(ts)

    def reset(self, key: Hashable | None = None) -> None:
        """Drop all recorded timestamps for `key`, or for everything
        if `key` is None. Used by tests to isolate cases; production
        code shouldn't typically need this."""
        with self._lock:
            if key is None:
                self._timestamps.clear()
            else:
                self._timestamps.pop(key, None)

    def prune_inactive(self, now: float | None = None) -> int:
        """Drop deques whose all timestamps are outside the window.

        Returns the number of keys removed. Call periodically if the
        key space is unbounded (e.g., when keys are IPs from the
        internet). For our use cases this is rarely needed.
        """
        if now is None:
            now = time.monotonic()
        cutoff = now - self.window_seconds
        removed = 0
        with self._lock:
            for key in list(self._timestamps.keys()):
                ts = self._timestamps[key]
                while ts and ts[0] < cutoff:
                    ts.popleft()
                if not ts:
                    del self._timestamps[key]
                    removed += 1
        return removed
