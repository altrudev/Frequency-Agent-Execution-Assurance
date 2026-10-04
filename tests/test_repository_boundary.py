from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

ALLOWED_TOP_LEVEL_FILES = {
    ".gitignore",
    "LICENSE.md",
    "README.md",
    "SECURITY.md",
    "requirements-dev.txt",
    "frequency-agent-execution-assurance-logo.png",
}
ALLOWED_TOP_LEVEL_DIRS = {
    "adapters",
    "conformance",
    "docs",
    "fixtures",
    "tests",
    ".github",
}


def test_tracked_repository_boundary_contains_only_faea_surface():
    if not (ROOT / ".git").exists():
        pytest.skip("repository metadata unavailable")

    result = subprocess.run(
        ["git", "ls-files"],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )
    tracked = [line for line in result.stdout.splitlines() if line]

    unexpected = []
    for path in tracked:
        parts = Path(path).parts
        if len(parts) == 1:
            if path not in ALLOWED_TOP_LEVEL_FILES:
                unexpected.append(path)
        elif parts[0] not in ALLOWED_TOP_LEVEL_DIRS:
            unexpected.append(path)

    assert unexpected == [], (
        "unexpected tracked files crossed the public FAEA repository boundary: "
        + ", ".join(unexpected)
    )
