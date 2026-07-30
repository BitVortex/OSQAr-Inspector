"""Compare the current release policy with a Git baseline."""

from __future__ import annotations

import json
import subprocess
import sys

from osqar_inspector.release_gate import (
    ContractPolicyError,
    load_release_policy,
    validate_contract_change,
)

POLICY_PATH = "src/osqar_inspector/resources/release-policy-v1.json"


def main() -> int:
    if len(sys.argv) != 2 or not sys.argv[1] or set(sys.argv[1]) == {"0"}:
        print("contract comparison requires a nonzero Git baseline", file=sys.stderr)
        return 2
    baseline = sys.argv[1]
    commit = subprocess.run(
        ["git", "cat-file", "-e", f"{baseline}^{{commit}}"],
        capture_output=True,
        check=False,
    )
    if commit.returncode != 0:
        print("contract comparison baseline is not available", file=sys.stderr)
        return 1
    result = subprocess.run(
        ["git", "show", f"{baseline}:{POLICY_PATH}"],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        print("release policy baseline initialized; no prior policy to compare")
        return 0
    try:
        previous = json.loads(result.stdout)
        current = load_release_policy()
        contracts_changed = (
            previous.get("contract_assets") != current["contract_assets"]
            or previous.get("support") != current["support"]
        )
        validate_contract_change(
            previous,
            current,
            contracts_changed=contracts_changed,
        )
    except (json.JSONDecodeError, AttributeError, ContractPolicyError) as error:
        print(f"contract change gate failed: {error}", file=sys.stderr)
        return 1
    if contracts_changed:
        changed = subprocess.run(
            ["git", "diff", "--name-only", baseline, "--", "CHANGELOG.md"],
            capture_output=True,
            check=False,
            text=True,
        )
        if changed.returncode != 0 or "CHANGELOG.md" not in changed.stdout.splitlines():
            print(
                "contract change gate failed: CHANGELOG.md update is required",
                file=sys.stderr,
            )
            return 1
    print("contract change policy satisfied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
