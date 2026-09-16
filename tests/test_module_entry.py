"""`python -m depwolf` must behave like the `depwolf` console script."""

import subprocess
import sys


def test_module_entry_runs_help():
    proc = subprocess.run(
        [sys.executable, "-m", "depwolf", "--help"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0
    assert "usage" in (proc.stdout + proc.stderr).lower()