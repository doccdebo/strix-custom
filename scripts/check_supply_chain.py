#!/usr/bin/env python3
"""Lightweight guardrail for common supply-chain anti-patterns."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST_MARKER = "guardrail: allow"
SCAN_GLOBS = (
    "containers/Dockerfile",
    "scripts/*.sh",
    ".github/workflows/*.y*ml",
)
PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("unpinned image tag (:latest)", re.compile(r":[Ll][Aa][Tt][Ee][Ss][Tt]\b")),
    ("unpinned package/tool version (@latest)", re.compile(r"@latest\b", re.IGNORECASE)),
    (
        "shell pipe installer (curl|wget ... | sh)",
        re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:env\s+[^|]+\s+)?(?:bash|sh)\b"),
    ),
    ("dynamic GitHub latest release lookup", re.compile(r"releases/latest")),
)
GIT_CLONE_PATTERN = re.compile(r"\bgit\s+clone\b")
GIT_CHECKOUT_PATTERN = re.compile(r"\bgit\s+-C\s+\S+\s+checkout\b")


def _iter_candidate_files() -> list[Path]:
    files: list[Path] = []
    for pattern in SCAN_GLOBS:
        files.extend(ROOT.glob(pattern))
    return sorted({f for f in files if f.is_file()})


def main() -> int:
    violations: list[str] = []
    for path in _iter_candidate_files():
        rel = path.relative_to(ROOT)
        lines = path.read_text(encoding="utf-8").splitlines()
        for idx, line in enumerate(lines):
            line_no = idx + 1
            if ALLOWLIST_MARKER in line.lower():
                continue
            for rule, pattern in PATTERNS:
                if pattern.search(line):
                    violations.append(f"{rel}:{line_no}: {rule}: {line.strip()}")
                    break
            if GIT_CLONE_PATTERN.search(line):
                lookahead = "\n".join(lines[idx : idx + 4])
                if GIT_CHECKOUT_PATTERN.search(lookahead):
                    continue
                violations.append(f"{rel}:{line_no}: possibly unpinned git clone: {line.strip()}")

    if violations:
        sys.stderr.write("Supply-chain guardrail violations found:\n\n")
        sys.stderr.write("\n".join(violations))
        sys.stderr.write(
            "\nIf a line is intentionally allowed, add an inline comment containing "
            f"'{ALLOWLIST_MARKER}'.\n",
        )
        return 1

    sys.stdout.write("Supply-chain guardrail passed.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
