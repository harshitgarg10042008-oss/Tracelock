"""Validate the files required for the TraceLock Phase 12 release package."""

from __future__ import annotations

import json
import sys
from pathlib import Path

REQUIRED_FILES = (
    "README.md",
    "compose.yaml",
    "pyproject.toml",
    "policies/demo-policy.yaml",
    "scripts/run_local.sh",
    "scripts/check_direct_bypass.py",
    "docs/phase-12-release.md",
    "docs/phase-11-assurance.md",
    "tests/integration/test_assurance.py",
)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    missing = [path for path in REQUIRED_FILES if not (root / path).is_file()]
    readable = [path for path in REQUIRED_FILES if path not in missing]
    report = {
        "release": "tracelock-phase-12",
        "valid": not missing,
        "required_file_count": len(REQUIRED_FILES),
        "present_file_count": len(readable),
        "missing_files": missing,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not missing else 1


if __name__ == "__main__":
    sys.exit(main())
