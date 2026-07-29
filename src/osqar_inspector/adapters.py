"""Immutable producer-adapter lifecycle contracts."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from .process_runner import OutputDeclaration, OwnedWorkspace, ProcessResult


@dataclass(frozen=True)
class Diagnostic:
    code: str
    message: str


@dataclass(frozen=True)
class CapabilityRequirements:
    executable: str | None
    version_constraint: str | None = None


@dataclass(frozen=True)
class DeclarativeStagePlan:
    stage: str
    selector: str
    dependencies: tuple[str, ...]
    required_inputs: tuple[str, ...]
    invocation: tuple[str, ...]
    expected_outputs: tuple[str, ...]
    workspace: str
    adapter_options: tuple[tuple[str, bool], ...] = ()


@dataclass(frozen=True)
class Capability:
    executable: str
    version: str


@dataclass(frozen=True)
class CommandPlan:
    argv: tuple[str, ...]
    accepted_exit_codes: frozenset[int] = frozenset({0})
    outputs: tuple[OutputDeclaration, ...] = ()


class ProducerAdapter(ABC):
    @abstractmethod
    def validate_declaration(
        self, config: Any
    ) -> tuple[tuple[Diagnostic, ...], CapabilityRequirements]: ...

    @abstractmethod
    def plan_declaration(
        self, config: Any, snapshot: Any
    ) -> DeclarativeStagePlan: ...

    @abstractmethod
    def probe(self, config: Any, workspace: OwnedWorkspace) -> Capability: ...

    @abstractmethod
    def validate_capability(
        self, config: Any, capability: Capability
    ) -> tuple[Diagnostic, ...]: ...

    @abstractmethod
    def plan_command(
        self,
        plan: DeclarativeStagePlan,
        capability: Capability,
        workspace: OwnedWorkspace,
    ) -> CommandPlan: ...

    @abstractmethod
    def execute(self, command_plan: CommandPlan) -> ProcessResult: ...

    @abstractmethod
    def collect(self, process_result: ProcessResult, workspace: OwnedWorkspace) -> Any: ...

    @abstractmethod
    def normalize(self, producer_output: Any, snapshot: Any) -> Any: ...
