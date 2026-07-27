"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .verify import VerificationError, verify_bundle


def main() -> int:
    parser = argparse.ArgumentParser(prog="osqar-inspector")
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--bundle", required=True)
    args = parser.parse_args()
    try:
        bundle_id = verify_bundle(Path(args.bundle))
    except VerificationError as error:
        print(
            json.dumps(
                {"diagnostics": [error.diagnostic()], "valid": False},
                separators=(",", ":"),
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps({"bundle_id": bundle_id, "valid": True}, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
