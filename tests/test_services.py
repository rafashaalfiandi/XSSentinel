import argparse
import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from xssentinel_core.scanner.config import BrowserRuntimeConfig, CrawlerRuntimeConfig, ScannerRuntimeConfig
from xssentinel_core.scanner.models import CSPAnalysis, FingerprintAnalysis, HttpResult, ScanTarget, ScriptAnalysis, TargetIntelligence
from xssentinel_core.scanner.plugins import ExtensionRegistry
from xssentinel_core.scanner.runner import scan, selected_payload_count
from xssentinel_core.scanner.services import ScanServices, build_scan_services


def scanner_args(payload_file: Path, user_agent_file: Path) -> argparse.Namespace:
    return argparse.Namespace(
        payloads=str(payload_file),
        user_agents=str(user_agent_file),
        browser=False,
        browser_all=False,
        smart=False,
        timeout=1.0,
        delay=0.0,
        limit=1,
        browser_confirm_limit=1,
        workers=1,
        exhaustive_fallback=False,
        stop_on_confirmed=False,
        verify_https=False,
        headers={},
    )


def target_intelligence(target: ScanTarget) -> TargetIntelligence:
    return TargetIntelligence(
        target,
        200,
        CSPAnalysis("", {}, ["CSP not found"], 0),
        [],
        ScriptAnalysis(0, [], []),
        [],
        FingerprintAnalysis([], []),
    )


class StaticTargetDiscovery:
    def __init__(self, target: ScanTarget) -> None:
        self.target = target

    def discover(self, _args: argparse.Namespace, _user_agent: str) -> list[ScanTarget]:
        return [self.target]


class StaticContextProvider:
    def infer(self, _target: ScanTarget, _args: argparse.Namespace, _user_agents: list[str]) -> set[str]:
        return {"html-text"}


class StaticIntelligenceProvider:
    def analyze(
        self,
        target: ScanTarget,
        _args: argparse.Namespace,
        _user_agents: list[str],
        _contexts: set[str],
    ) -> TargetIntelligence:
        return target_intelligence(target)


class SinglePayloadPlanner:
    def batches(self, _payloads: list[str], _contexts: set[str], _args: argparse.Namespace) -> tuple[list[str], list[str]]:
        return ["plain"], []


class RecordingHttpTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str | None]] = []

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
        self.calls.append((method, url, data))
        return HttpResult(200, "no reflection", {"Content-Type": "text/html"}, None)


class NoopBrowserValidator:
    def validate(self, *_args, **_kwargs) -> tuple[bool, str]:
        raise AssertionError("browser validation should not run")


class RecordingLifecycle:
    def __init__(self) -> None:
        self.events: list[str] = []

    def before_scan(self, _args: argparse.Namespace, _targets: list[ScanTarget]) -> None:
        self.events.append("before_scan")

    def before_target(self, _target: ScanTarget, _contexts: set[str]) -> None:
        self.events.append("before_target")

    def after_finding(self, _finding) -> None:
        self.events.append("after_finding")

    def after_target(self, _target: ScanTarget, _findings) -> None:
        self.events.append("after_target")

    def after_scan(self, _findings, _intelligence) -> None:
        self.events.append("after_scan")


class PayloadPlugin:
    name = "payload-plugin"

    def __init__(self, planner: SinglePayloadPlanner) -> None:
        self.planner = planner
        self.configured = False

    def configure(self, registry: ExtensionRegistry) -> None:
        self.configured = True
        registry.register_payload_planner(self.planner)


class ConfigPlugin:
    name = "config-plugin"

    def __init__(self, config: ScannerRuntimeConfig) -> None:
        self.config = config

    def configure(self, registry: ExtensionRegistry) -> None:
        registry.register_runtime_config(self.config)


class ServiceInjectionTests(unittest.TestCase):
    def test_selected_payload_count_matches_smart_limit_rules(self) -> None:
        self.assertEqual(selected_payload_count(["a", "b", "c"], argparse.Namespace(smart=False, limit=1)), 3)
        self.assertEqual(selected_payload_count(["a", "b", "c"], argparse.Namespace(smart=True, limit=2)), 2)
        self.assertEqual(selected_payload_count(["a", "b"], argparse.Namespace(smart=True, limit=None)), 2)

    def test_scan_uses_injected_services_and_lifecycle_hooks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            payload_file = root / "payloads.txt"
            user_agent_file = root / "agents.txt"
            payload_file.write_text("plain\n", encoding="utf-8")
            user_agent_file.write_text("unit-agent\n", encoding="utf-8")
            target = ScanTarget("GET", "https://example.test/search?q=FUZZ", None, "application/x-www-form-urlencoded", ["query:q"], "unit")
            http = RecordingHttpTransport()
            lifecycle = RecordingLifecycle()
            services = ScanServices(
                http=http,
                target_discovery=StaticTargetDiscovery(target),
                contexts=StaticContextProvider(),
                intelligence=StaticIntelligenceProvider(),
                payloads=SinglePayloadPlanner(),
                browser=NoopBrowserValidator(),
                lifecycle=lifecycle,
            )

            with patch("xssentinel_core.scanner.runner.time.sleep", return_value=None), contextlib.redirect_stdout(io.StringIO()):
                findings, intelligence = scan(scanner_args(payload_file, user_agent_file), services)

        self.assertEqual(len(findings), 1)
        self.assertEqual(len(intelligence), 1)
        self.assertEqual(findings[0].status, "NOT_CONFIRMED")
        self.assertEqual(http.calls[0][0], "GET")
        self.assertIn("q=plain", http.calls[0][1])
        self.assertEqual(lifecycle.events, ["before_scan", "before_target", "after_finding", "after_target", "after_scan"])

    def test_plugin_can_replace_registered_service(self) -> None:
        planner = SinglePayloadPlanner()
        plugin = PayloadPlugin(planner)

        services = build_scan_services(plugins=[plugin])

        self.assertTrue(plugin.configured)
        self.assertIs(services.payloads, planner)

    def test_plugin_can_inject_runtime_configuration(self) -> None:
        config = ScannerRuntimeConfig(
            CrawlerRuntimeConfig(max_depth=2, max_pages=3, max_workers=1, max_scripts=0),
            BrowserRuntimeConfig(launch_timeout_s=1.0),
        )

        services = build_scan_services(plugins=[ConfigPlugin(config)])

        self.assertIs(services.config, config)
        self.assertEqual(services.config.crawler.max_depth, 2)


if __name__ == "__main__":
    unittest.main()
