"""Owned subprocess entry point for exact pre-generated coverage inventory."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path, PurePosixPath

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from osqar_inspector.configuration import canonical_json
from osqar_inspector.coverage_adapter import _inventory


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--root", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args(argv)

    report = PurePosixPath(arguments.report)
    _, tree_sha256 = _inventory(Path(arguments.root), report.parent, report.name)
    Path(arguments.output).write_bytes(
        canonical_json(
            {
                "entry_point": report.name,
                "report_tree_sha256": tree_sha256,
                "schema": "osqar.inspector.coverage-inventory.v1",
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
