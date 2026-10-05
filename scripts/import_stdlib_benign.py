#!/usr/bin/env python3
"""Extract docstrings from CPython's standard library as benign training text.

    uv run python scripts/import_stdlib_benign.py

Writes `corpus/external/stdlib/documents.jsonl`. Docstrings are real technical prose
full of imperatives ("Return the...", "Call this before...") that are not attacks,
which is what a classifier must learn not to flag (ADR 0074). Modules are taken in
sorted order, at most three docstrings each, 150 to 2,000 characters, skipping tests,
so the output depends only on the Python version, which is recorded.
"""

from __future__ import annotations

import ast
import json
import platform
import sys
import sysconfig
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "corpus" / "external" / "stdlib"
PER_MODULE = 3
MIN_CHARS, MAX_CHARS = 150, 2000
LIMIT = 1500
SKIP = ("test", "tests", "idlelib", "lib2to3", "turtledemo", "site-packages", "ensurepip")


def docstrings(path: Path) -> list[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError, ValueError):
        return []
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            text = ast.get_docstring(node)
            if text and MIN_CHARS <= len(text) <= MAX_CHARS:
                found.append(text)
    return found[:PER_MODULE]


def main() -> int:
    root = Path(sysconfig.get_paths()["stdlib"])
    rows = []
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root)
        if any(part in SKIP for part in rel.parts):
            continue
        module = ".".join(rel.with_suffix("").parts)
        for index, text in enumerate(docstrings(path)):
            rows.append(
                {"id": f"stdlib/{module}/{index}", "group": f"stdlib/{module}", "text": text}
            )
        if len(rows) >= LIMIT:
            break
    OUT.mkdir(parents=True, exist_ok=True)
    with (OUT / "documents.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows[:LIMIT]:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    version = platform.python_version()
    (OUT / "SOURCE.md").write_text(
        "# CPython standard library docstrings\n\n"
        f"Extracted by `scripts/import_stdlib_benign.py` from Python {version}'s standard\n"
        "library. Benign training data for the learned classifier (ADR 0074): never\n"
        "used as an evaluation set. Licence: the Python Software Foundation License\n"
        "(https://docs.python.org/3/license.html).\n",
        encoding="utf-8",
    )
    print(f"{min(len(rows), LIMIT)} docstrings from Python {version}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
