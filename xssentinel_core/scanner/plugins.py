"""Plugin registry and lifecycle hook dispatch.

The registry is intentionally small. It gives extensions a stable place to swap
service implementations while keeping the public CLI unchanged.
"""

from __future__ import annotations

import argparse
import logging
from dataclasses import dataclass, field
from typing import Any

from .config import ScannerRuntimeConfig
from .interfaces import (
    BrowserValidator,
    ContextProvider,
    HttpTransport,
    IntelligenceProvider,
    PayloadPlanner,
    ScannerPlugin,
    TargetDiscovery,
)
from .models import Finding, ScanTarget, TargetIntelligence


LOGGER = logging.getLogger(__name__)


@dataclass
class ExtensionRegistry:
    """Mutable registration point for scanner services and plugins."""

    http_transport: HttpTransport | None = None
    target_discovery: TargetDiscovery | None = None
    context_provider: ContextProvider | None = None
    intelligence_provider: IntelligenceProvider | None = None
    payload_planner: PayloadPlanner | None = None
    browser_validator: BrowserValidator | None = None
    runtime_config: ScannerRuntimeConfig | None = None
    plugins: list[ScannerPlugin] = field(default_factory=list)

    def register_http_transport(self, service: HttpTransport) -> None:
        self.http_transport = service

    def register_target_discovery(self, service: TargetDiscovery) -> None:
        self.target_discovery = service

    def register_context_provider(self, service: ContextProvider) -> None:
        self.context_provider = service

    def register_intelligence_provider(self, service: IntelligenceProvider) -> None:
        self.intelligence_provider = service

    def register_payload_planner(self, service: PayloadPlanner) -> None:
        self.payload_planner = service

    def register_browser_validator(self, service: BrowserValidator) -> None:
        self.browser_validator = service

    def register_runtime_config(self, config: ScannerRuntimeConfig) -> None:
        self.runtime_config = config

    def register_plugin(self, plugin: ScannerPlugin) -> None:
        self.plugins.append(plugin)


class LifecycleManager:
    """Dispatches plugin hooks without making plugins mandatory."""

    def __init__(self, plugins: list[ScannerPlugin] | None = None) -> None:
        self.plugins = list(plugins or [])

    def before_scan(self, args: argparse.Namespace, targets: list[ScanTarget]) -> None:
        self._notify("before_scan", args, targets)

    def before_target(self, target: ScanTarget, contexts: set[str]) -> None:
        self._notify("before_target", target, contexts)

    def after_finding(self, finding: Finding) -> None:
        self._notify("after_finding", finding)

    def after_target(self, target: ScanTarget, findings: list[Finding]) -> None:
        self._notify("after_target", target, findings)

    def after_scan(self, findings: list[Finding], intelligence: list[TargetIntelligence]) -> None:
        self._notify("after_scan", findings, intelligence)

    def _notify(self, hook: str, *args: Any) -> None:
        for plugin in self.plugins:
            callback = getattr(plugin, hook, None)
            if not callable(callback):
                continue
            try:
                callback(*args)
            except Exception as exc:  # noqa: BLE001 - one plugin must not break scan lifecycle.
                name = getattr(plugin, "name", plugin.__class__.__name__)
                LOGGER.warning(
                    "plugin hook failed plugin=%s hook=%s error=%s",
                    name,
                    hook,
                    exc,
                )


def configure_plugins(registry: ExtensionRegistry, plugins: list[ScannerPlugin] | None = None) -> ExtensionRegistry:
    """Register plugins and let them replace services before scanning starts."""

    for plugin in plugins or []:
        registry.register_plugin(plugin)
        configure = getattr(plugin, "configure", None)
        if callable(configure):
            configure(registry)
    return registry
