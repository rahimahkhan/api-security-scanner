"""Regression tests for the parallel endpoint scan (Nov 2026 speed fix).

Endpoints used to be scanned strictly one at a time. They now run
concurrently (ENDPOINT_CONCURRENCY workers, global in-flight cap). The
end-to-end check below runs the real pipeline in a subprocess against a
tiny local target so it gets an isolated database; it pins the behaviour
that matters: the scan completes, real vulns still Confirm, and clean
endpoints still do not.
"""

import os
import subprocess
import sys


def test_parallel_endpoint_scan_end_to_end(tmp_path):
    db_path = tmp_path / "parallel.db"
    script = os.path.join(os.path.dirname(__file__), "parallel_scan_check.py")
    result = subprocess.run(
        [sys.executable, script, str(db_path)],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, (
        "parallel scan check failed:\n"
        + result.stdout[-3000:]
        + "\n--- stderr ---\n"
        + result.stderr[-3000:]
    )
    assert "SQL_Injection" in result.stdout
    assert "XSS" in result.stdout
    assert "CLEAN_CONFIRMED: 0" in result.stdout


def test_scan_concurrency_defaults_are_bounded():
    import main

    assert main.ENDPOINT_CONCURRENCY >= 1
    assert main.MAX_IN_FLIGHT_REQUESTS >= 1
    # Probe workers may exceed the in-flight cap (threads park on the
    # semaphore); the cap itself is what bounds load on the target.
    assert main.ACTIVE_CONCURRENCY >= 1
    assert main._IN_FLIGHT_SEMAPHORE._value == main.MAX_IN_FLIGHT_REQUESTS
