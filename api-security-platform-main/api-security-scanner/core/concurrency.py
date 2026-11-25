"""Scan concurrency helpers that can never wedge the whole scan.

Why this module exists
----------------------
A live DVWA scan stalled at 49/50 endpoints (twice, on two different builds).
The cause was a semaphore-permit leak:

* every probe took `_IN_FLIGHT_SEMAPHORE` with no timeout;
* a probe that hung past its request timeout (e.g. a DNS stall) kept its permit;
* once all permits were held by hung threads, every live worker waited forever;
* the outer pool used a bare `executor.map` with no timeout, so the scan never
  returned and the final roll-up never ran.

The fixes live here, free of heavy imports (no torch/sklearn) so they can be
unit-tested on their own:

1. `BoundedSlot`      - take a permit with a timeout; raise `SlotTimeout`
                        instead of waiting forever.
2. `run_bounded_pool` - run endpoint workers with a hard wall-clock budget per
                        endpoint. An endpoint that exceeds it is *abandoned*
                        (reported, skipped) and no longer occupies a worker
                        slot, so one wedged endpoint cannot block the roll-up.
3. Stop registry      - lets the watchdog / cancel button tell a scan to stop
                        launching new work.
"""

import logging
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)


class SlotTimeout(Exception):
    """Raised when an in-flight request slot could not be acquired in time."""


class BoundedSlot:
    """Context manager: acquire `semaphore` within `timeout` seconds or raise.

    Usage:  with BoundedSlot(sem, 60): send_request(...)
    The permit is released only if it was actually acquired.
    """

    def __init__(self, semaphore: threading.BoundedSemaphore, timeout: float):
        self._semaphore = semaphore
        self._timeout = timeout
        self._acquired = False

    def __enter__(self):
        self._acquired = self._semaphore.acquire(timeout=self._timeout)
        if not self._acquired:
            raise SlotTimeout(f"no request slot free after {self._timeout}s")
        return self

    def __exit__(self, exc_type, exc, tb):
        if self._acquired:
            self._semaphore.release()
            self._acquired = False
        return False


def run_bounded_pool(
    items: Iterable[Any],
    worker: Callable[[Any], None],
    concurrency: int,
    per_item_budget: float,
    on_abandon: Optional[Callable[[Any, float], None]] = None,
    on_start: Optional[Callable[[Any], None]] = None,
    stop_event: Optional[threading.Event] = None,
    poll_interval: float = 0.5,
) -> Dict[str, List[Any]]:
    """Run `worker(item)` for every item, at most `concurrency` at a time.

    Unlike `ThreadPoolExecutor.map`, this never waits forever:

    * each item gets `per_item_budget` seconds of wall-clock time;
    * an item that exceeds it is abandoned: `on_abandon(item, elapsed)` is
      called, and it stops counting against `concurrency`, so queued items
      still run. (Python cannot kill a thread; the abandoned thread is a
      daemon and is simply left behind.)
    * when `stop_event` is set, no new items are started and still-running
      ones are abandoned at once, so the call returns promptly.

    `worker` is expected to handle its own exceptions; any that escape are
    logged here and the item is treated as finished.

    Returns {"finished": [...], "abandoned": [...], "not_started": [...]}.
    """
    pending = list(items)
    running: Dict[threading.Thread, Any] = {}
    started_at: Dict[threading.Thread, float] = {}
    finished: List[Any] = []
    abandoned: List[Any] = []
    concurrency = max(1, int(concurrency))

    def _target(item):
        try:
            worker(item)
        except Exception as exc:  # never let a worker die silently
            logger.error("Pool worker for %r crashed: %s", item, exc)

    while pending or running:
        now = time.monotonic()
        stopping = bool(stop_event is not None and stop_event.is_set())

        for thread in list(running):
            item = running[thread]
            elapsed = now - started_at[thread]
            if not thread.is_alive():
                finished.append(item)
                del running[thread], started_at[thread]
            elif stopping or elapsed > per_item_budget:
                abandoned.append(item)
                del running[thread], started_at[thread]
                if on_abandon is not None:
                    try:
                        on_abandon(item, elapsed)
                    except Exception as exc:
                        logger.error("on_abandon failed for %r: %s", item, exc)

        if stopping:
            break

        while pending and len(running) < concurrency:
            item = pending.pop(0)
            if on_start is not None:
                try:
                    on_start(item)
                except Exception:
                    pass
            thread = threading.Thread(target=_target, args=(item,), daemon=True)
            running[thread] = item
            started_at[thread] = time.monotonic()
            thread.start()

        if pending or running:
            time.sleep(poll_interval)

    return {"finished": finished, "abandoned": abandoned, "not_started": pending}


# ---------------------------------------------------------------------------
# Stop registry: the dashboard's watchdog / cancel button -> the running scan
# ---------------------------------------------------------------------------
_STOP_EVENTS: Dict[str, threading.Event] = {}
_STOP_LOCK = threading.Lock()


def get_stop_event(session_id: Any) -> threading.Event:
    """Return (creating if needed) the stop event for a scan session."""
    key = str(session_id)
    with _STOP_LOCK:
        return _STOP_EVENTS.setdefault(key, threading.Event())


def request_stop(session_id: Any) -> None:
    """Ask a running scan to stop launching/continuing endpoint work."""
    get_stop_event(session_id).set()


def release_stop_event(session_id: Any) -> None:
    """Forget a finished scan's stop event so the registry can't grow."""
    with _STOP_LOCK:
        _STOP_EVENTS.pop(str(session_id), None)
