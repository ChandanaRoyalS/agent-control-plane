"""No source file is ignored by git.

An unanchored `audit/` in `.gitignore` once matched `src/acp/audit/`, so a new module
there was never committed: the tests passed where it was written and failed everywhere
else (ADR 0078's first patch).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.skipif(
    shutil.which("git") is None or not (ROOT / ".git").exists(), reason="not a git checkout"
)
def test_no_python_file_under_src_or_tests_is_ignored() -> None:
    listed = subprocess.run(
        ["git", "ls-files", "--others", "--ignored", "--exclude-standard", "--", "src", "tests"],  # noqa: S607
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()

    assert [path for path in listed if path.endswith(".py")] == []
