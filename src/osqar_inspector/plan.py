"""Pure deterministic construction of ``osqar.inspector.plan.v1``."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from .adapters import CapabilityRequirements, DeclarativeStagePlan, Diagnostic
from .configuration import ResolvedConfiguration, canonical_json
from .coverage_adapter import CoverageAdapter
from .doxygen_adapter import DoxygenAdapter
from .snapshot import GitSnapshot

SCHEMA_ID = "osqar.inspector.plan.v1"


class DeclarationAdapter(Protocol):
    """The pure subset of the producer-adapter protocol permitted during planning."""

    def validate_declaration(
        self, config: Mapping[str, Any]
    ) -> tuple[tuple[Diagnostic, ...], CapabilityRequirements]: ...

    def plan_declaration(
        self, config: Mapping[str, Any], snapshot: GitSnapshot
    ) -> DeclarativeStagePlan: ...


@dataclass(frozen=True)
class ExecutionPlan:
    value: dict[str, Any]
    plan_bytes: bytes
    blocked: bool


DEFAULT_ADAPTERS: Mapping[str, DeclarationAdapter] = {
    "coverage": CoverageAdapter(),
    "doxygen": DoxygenAdapter(),
}


def _snapshot_identity(snapshot: GitSnapshot) -> dict[str, Any]:
    return {
        key: value
        for key, value in snapshot.manifest.items()
        if key != "metadata"
    }


def create_plan(
    configuration: ResolvedConfiguration,
    snapshot: GitSnapshot,
    adapters: Mapping[str, DeclarationAdapter] = DEFAULT_ADAPTERS,
) -> ExecutionPlan:
    """Create a plan using declaration-only adapter operations."""

    stages: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    selected_paths = {record["path"] for record in snapshot.files}
    blocked = False
    enabled = configuration.value["stages"]
    for stage_id in sorted(enabled, key=str.encode):
        policy = enabled[stage_id]
        if not policy["enabled"]:
            continue
        adapter = adapters[stage_id]
        declared_diagnostics, capability = adapter.validate_declaration(configuration.value)
        declaration = adapter.plan_declaration(configuration.value, snapshot)
        missing = tuple(path for path in declaration.required_inputs if path not in selected_paths)
        stage_diagnostics = list(declared_diagnostics)
        stage_diagnostics.extend(
            Diagnostic("plan.input_missing", f"selected snapshot does not contain {path!r}")
            for path in missing
        )
        is_blocking = bool(stage_diagnostics) and policy["required"]
        blocked = blocked or is_blocking
        diagnostics.extend(
            {
                "blocking": is_blocking,
                "code": diagnostic.code,
                "message": diagnostic.message,
                "stage": stage_id,
            }
            for diagnostic in stage_diagnostics
        )
        capability_value = (
            None
            if capability.executable is None
            else {
                "executable": capability.executable,
                "status": "unresolved",
                "version_constraint": capability.version_constraint,
            }
        )
        stages.append(
            {
                "adapter": {"selector": declaration.selector},
                "adapter_options": dict(declaration.adapter_options),
                "capability": capability_value,
                "dependencies": list(declaration.dependencies),
                "expected_outputs": list(declaration.expected_outputs),
                "id": declaration.stage,
                "invocation": {"argv": list(declaration.invocation)},
                "policy": "required" if policy["required"] else "optional",
                "required_inputs": list(declaration.required_inputs),
                "workspace": declaration.workspace,
            }
        )
    stages.sort(key=lambda stage: stage["id"].encode())
    edges = sorted(
        (
            {"from": dependency, "to": stage["id"]}
            for stage in stages
            for dependency in stage["dependencies"]
        ),
        key=lambda edge: (edge["from"].encode(), edge["to"].encode()),
    )
    diagnostics.sort(key=lambda item: (item["stage"].encode(), item["code"].encode()))
    identity: dict[str, Any] = {
        "configuration": configuration.identity,
        "diagnostics": diagnostics,
        "edges": edges,
        "schema": SCHEMA_ID,
        "snapshot": _snapshot_identity(snapshot),
        "stages": stages,
    }
    digest = hashlib.sha256(canonical_json({"kind": "plan", "identity": identity})).hexdigest()
    value = {**identity, "plan_digest": digest}
    return ExecutionPlan(value=value, plan_bytes=canonical_json(value), blocked=blocked)