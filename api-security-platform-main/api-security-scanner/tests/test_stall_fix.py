"""Regression tests for the DVWA 49/50 stall (semaphore-permit leak).

These use only core/concurrency.py (no torch/sklearn), so they run anywhere.
"""
import threading
import time

import pytest

from core.concurrency import (
    BoundedSlot, SlotTimeout, run_bounded_pool,
    get_stop_event, request_stop, release_stop_event,
)


def _hold_permit(sem, release_evt):
    sem.acquire()
    release_evt.wait()
    sem.release()


def test_permit_leak_no_longer_wedges_workers():
    """Reproduces the incident: all permits held by hung threads."""
    sem = threading.BoundedSemaphore(2)
    release = threading.Event()
    zombies = [threading.Thread(target=_hold_permit, args=(sem, release), daemon=True)
               for _ in range(2)]
    for z in zombies:
        z.start()
    time.sleep(0.1)  # let both zombies take a permit

    started = time.monotonic()
    with pytest.raises(SlotTimeout):
        with BoundedSlot(sem, timeout=0.5):
            pytest.fail("should not get a slot while all permits are leaked")
    assert time.monotonic() - started < 3  # old code: waited forever
    release.set()


def test_slot_releases_permit_on_exit_and_on_error():
    sem = threading.BoundedSemaphore(1)
    with BoundedSlot(sem, 1):
        pass
    with pytest.raises(RuntimeError):
        with BoundedSlot(sem, 1):
            raise RuntimeError("probe failed")
    assert sem.acquire(timeout=0.5)  # permit was returned both times
    sem.release()


def test_failed_acquire_does_not_release_a_foreign_permit():
    sem = threading.BoundedSemaphore(1)
    sem.acquire()
    with pytest.raises(SlotTimeout):
        with BoundedSlot(sem, 0.2):
            pass
    sem.release()  # BoundedSemaphore raises ValueError if over-released
    assert sem.acquire(timeout=0.2)


def test_wedged_endpoint_is_abandoned_and_scan_still_finishes():
    done, abandoned_log = [], []
    block = threading.Event()

    def worker(item):
        if item == 3:
            block.wait()          # the wedged endpoint
        done.append(item)

    started = time.monotonic()
    result = run_bounded_pool(
        range(1, 7), worker, concurrency=2, per_item_budget=1.0,
        on_abandon=lambda item, elapsed: abandoned_log.append(item),
        poll_interval=0.05,
    )
    elapsed = time.monotonic() - started
    block.set()
    assert elapsed < 10
    assert result["abandoned"] == [3]
    assert abandoned_log == [3]
    assert sorted(done) == [1, 2, 4, 5, 6]   # everything else still ran
    assert result["not_started"] == []


def test_all_workers_wedged_still_makes_progress():
    """Abandoned endpoints must free their worker slot."""
    block = threading.Event()
    done = []

    def worker(item):
        if item in (1, 2):
            block.wait()
        done.append(item)

    result = run_bounded_pool(
        range(1, 6), worker, concurrency=2, per_item_budget=0.5, poll_interval=0.05,
    )
    block.set()
    assert sorted(result["abandoned"]) == [1, 2]
    assert sorted(done) == [3, 4, 5]


def test_stop_event_returns_promptly():
    stop = threading.Event()
    block = threading.Event()
    started_items = []

    def worker(item):
        started_items.append(item)
        block.wait()

    threading.Timer(0.3, stop.set).start()
    started = time.monotonic()
    result = run_bounded_pool(
        range(1, 20), worker, concurrency=2, per_item_budget=60,
        stop_event=stop, poll_interval=0.05,
    )
    block.set()
    assert time.monotonic() - started < 5
    assert len(started_items) == 2           # nothing new launched after stop
    assert len(result["abandoned"]) == 2
    assert len(result["not_started"]) == 17


def test_worker_exception_does_not_break_pool():
    seen = []

    def worker(item):
        if item == 2:
            raise ValueError("boom")
        seen.append(item)

    result = run_bounded_pool(range(1, 5), worker, concurrency=2,
                              per_item_budget=5, poll_interval=0.05)
    assert sorted(seen) == [1, 3, 4]
    assert sorted(result["finished"]) == [1, 2, 3, 4]


def test_stop_registry_round_trip():
    evt = get_stop_event("sess-1")
    assert not evt.is_set()
    request_stop("sess-1")
    assert get_stop_event("sess-1").is_set()
    release_stop_event("sess-1")
    assert not get_stop_event("sess-1").is_set()   # fresh event after release
    release_stop_event("sess-1")
