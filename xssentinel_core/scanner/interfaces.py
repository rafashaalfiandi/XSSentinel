"""Extension interfaces for scanner subsystems.

These protocols describe the boundaries used by the runner. Existing function
APIs remain available; default service implementations adapt those functions to
these interfaces.
"""

from __future__ import annotations

import argparse
from typing import Protocol

from .models import Finding, HttpResult, ScanTarget, TargetIntelligence


class HttpTransport(Protocol):
    """Sends HTTP requests for scan attempts and discovery helpers."""

    def request(
        self,
        url: str,
        user_agent: str,
        timeout: float,
        method: str = "GET",
        data: str | None = None,
        content_type: str | None = None,
        verify_https: bool = True,
        extra_headers: dict[str, str] | None = None,
    ) -> HttpResult:
        ...


class TargetDiscovery(Protocol):
    """Builds concrete scan targets from CLI arguments and discovery context."""

    def discover(self, args: argparse.Namespace, user_agent: str) -> list[ScanTarget]:
        ...


class ContextProvider(Protocol):
    """Infers response reflection contexts for a target before payload planning."""

    def infer(self, target: ScanTarget, args: argparse.Namespace, user_agents: list[str]) -> set[str]:
        ...


class IntelligenceProvider(Protocol):
    """Collects CSP, WAF, script, and target intelligence."""

    def analyze(
        self,
        target: ScanTarget,
        args: argparse.Namespace,
        user_agents: list[str],
        contexts: set[str],
    ) -> TargetIntelligence:
        ...


class PayloadPlanner(Protocol):
    """Selects the primary and fallback payload batches for a target."""

    def batches(
        self,
        payloads: list[str],
        contexts: set[str],
        args: argparse.Namespace,
    ) -> tuple[list[str], list[str]]:
        ...


class BrowserValidator(Protocol):
    """Confirms browser execution evidence for a payload attempt."""

    def validate(
        self,
        url: str,
        user_agent: str,
        timeout_ms: int,
        payload: str,
        method: str = "GET",
        data: str | None = None,
        content_type: str = "application/x-www-form-urlencoded",
        verify_https: bool = True,
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[bool, str]:
        ...


class ScannerPlugin(Protocol):
    """Optional lifecycle hook interface for scanner extensions.

    Plugins may implement any subset of these methods. Hooks are advisory: they
    observe and may enrich externally-owned services through a registry before a
    scan starts, but default behavior is preserved when no plugins are present.
    """

    name: str

    def configure(self, registry: object) -> None:
        ...

    def before_scan(self, args: argparse.Namespace, targets: list[ScanTarget]) -> None:
        ...

    def before_target(self, target: ScanTarget, contexts: set[str]) -> None:
        ...

    def after_finding(self, finding: Finding) -> None:
        ...

    def after_target(self, target: ScanTarget, findings: list[Finding]) -> None:
        ...

    def after_scan(self, findings: list[Finding], intelligence: list[TargetIntelligence]) -> None:
        ...
