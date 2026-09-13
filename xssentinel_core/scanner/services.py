"""Default scanner service implementations.

This module adapts the existing function-oriented scanner internals to stable
interfaces used by the runner. Callers can inject a `ScanServices` instance to
replace individual subsystems without changing the public CLI.
"""

# Updated by ell GITHUB: https://github.com/ruyynn

from __future__ import annotations

import argparse
from dataclasses import dataclass, field, replace

from .browser import confirm_with_browser
from .config import ScannerRuntimeConfig
from .http_client import request_detailed
from .intelligence import analyze_target_intelligence
from .interfaces import (
    BrowserValidator,
    ContextProvider,
    HttpTransport,
    IntelligenceProvider,
    PayloadPlanner,
    ScannerPlugin,
    TargetDiscovery,
)
from .models import HttpResult, ScanTarget, TargetIntelligence
from .payloads import infer_target_contexts, select_payload_batches
from .plugins import ExtensionRegistry, LifecycleManager, configure_plugins
from .fileinput import file_scan_targets
from .targets import make_scan_targets


class DefaultHttpTransport:
    """Default HTTP transport backed by `http_client.request_detailed`."""

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
        return request_detailed(url, user_agent, timeout, method, data, content_type, verify_https, extra_headers)


class DefaultTargetDiscovery:
    """Default target discovery backed by `targets.make_scan_targets` and file inputs."""

    def discover(self, args: argparse.Namespace, user_agent: str) -> list[ScanTarget]:
        file_targets = file_scan_targets(args)
        if file_targets is not None:
            return file_targets
        return make_scan_targets(args, user_agent)


class DefaultContextProvider:
    """Default context inference backed by payload probing."""

    def infer(self, target: ScanTarget, args: argparse.Namespace, user_agents: list[str]) -> set[str]:
        return infer_target_contexts(target, args, user_agents) if args.smart else set()


class DefaultIntelligenceProvider:
    """Default intelligence collector backed by `intelligence.py`."""

    def analyze(
        self,
        target: ScanTarget,
        args: argparse.Namespace,
        user_agents: list[str],
        contexts: set[str],
    ) -> TargetIntelligence:
        return analyze_target_intelligence(target, args, user_agents, contexts)


class DefaultPayloadPlanner:
    """Default smart payload planner backed by existing payload ordering."""

    def batches(self, payloads: list[str], contexts: set[str], args: argparse.Namespace) -> tuple[list[str], list[str]]:
        if args.smart:
            return select_payload_batches(payloads, contexts, args.limit, args.exhaustive_fallback)
        return payloads, []


class DefaultBrowserValidator:
    """Default browser validator backed by `browser.confirm_with_browser`."""

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
        return confirm_with_browser(
            url,
            user_agent,
            timeout_ms,
            payload,
            method,
            data,
            content_type,
            verify_https,
            extra_headers,
        )


@dataclass(frozen=True)
class ScanServices:
    """Service container injected into scan orchestration."""

    http: HttpTransport
    target_discovery: TargetDiscovery
    contexts: ContextProvider
    intelligence: IntelligenceProvider
    payloads: PayloadPlanner
    browser: BrowserValidator
    lifecycle: LifecycleManager
    config: ScannerRuntimeConfig = field(default_factory=ScannerRuntimeConfig.from_env)

    @classmethod
    def defaults(cls) -> "ScanServices":
        return cls(
            http=DefaultHttpTransport(),
            target_discovery=DefaultTargetDiscovery(),
            contexts=DefaultContextProvider(),
            intelligence=DefaultIntelligenceProvider(),
            payloads=DefaultPayloadPlanner(),
            browser=DefaultBrowserValidator(),
            lifecycle=LifecycleManager(),
            config=ScannerRuntimeConfig.from_env(),
        )

    @classmethod
    def from_registry(cls, registry: ExtensionRegistry) -> "ScanServices":
        defaults = cls.defaults()
        return replace(
            defaults,
            http=registry.http_transport or defaults.http,
            target_discovery=registry.target_discovery or defaults.target_discovery,
            contexts=registry.context_provider or defaults.contexts,
            intelligence=registry.intelligence_provider or defaults.intelligence,
            payloads=registry.payload_planner or defaults.payloads,
            browser=registry.browser_validator or defaults.browser,
            lifecycle=LifecycleManager(registry.plugins),
            config=registry.runtime_config or defaults.config,
        )


def build_scan_services(
    plugins: list[ScannerPlugin] | None = None,
    registry: ExtensionRegistry | None = None,
) -> ScanServices:
    """Create services from defaults plus optional plugin registrations."""

    active_registry = registry or ExtensionRegistry()
    configure_plugins(active_registry, plugins)
    return ScanServices.from_registry(active_registry)
