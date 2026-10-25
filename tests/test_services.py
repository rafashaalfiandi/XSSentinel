import argparse
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import html
import io
import json
import tempfile
import unittest
from pathlib import Path
from threading import Thread
import urllib.parse
import uuid
from unittest.mock import patch

from xssentinel_core.scanner.config import BrowserRuntimeConfig, CrawlerRuntimeConfig, ScannerRuntimeConfig
from xssentinel_core.scanner.models import CSPAnalysis, FingerprintAnalysis, HttpResult, ScanTarget, ScriptAnalysis, TargetIntelligence
from xssentinel_core.scanner.plugins import ExtensionRegistry
from xssentinel_core.scanner.runner import scan, selected_payload_count
from xssentinel_core.scanner.reporting import build_json_report
from xssentinel_core.scanner.services import DefaultHttpTransport, ScanServices, build_scan_services
from xssentinel_core.scanner.http_client import request_governor_snapshot


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
        self.results: list[HttpResult] = []

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
        result = HttpResult(200, "no reflection", {"Content-Type": "text/html"}, None)
        self.results.append(result)
        return result


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
        self.assertTrue(findings[0].attempt_id)
        self.assertTrue(findings[0].trace_intelligence["scan_id"])
        self.assertEqual(findings[0].evidence_bundle["attempt_id"], findings[0].attempt_id)
        self.assertEqual(http.calls[0][0], "GET")
        self.assertEqual(http.results[0].attempt_id, findings[0].attempt_id)
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

    def test_header_analysis_is_integrated_with_scan_and_local_fixture(self) -> None:
        class FixtureHandler(BaseHTTPRequestHandler):
            mode = "text"

            def do_GET(self):
                marker = self.headers.get("Referer", "")
                if not marker:
                    body = "<html><body>baseline</body></html>"
                elif self.mode == "text":
                    body = f"<html><body><div>{html.escape(marker)}</div></body></html>"
                elif self.mode == "encoded":
                    body = f"<html><body><div>{urllib.parse.quote(marker, safe='')}</div></body></html>"
                else:
                    body = "<html><body>header ignored</body></html>"
                encoded = body.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, *_args):
                pass

        results = {}
        for mode in ("text", "encoded", "ignored"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                payload_file = root / "payloads.txt"
                user_agent_file = root / "agents.txt"
                payload_file.write_text("plain\n", encoding="utf-8")
                user_agent_file.write_text("fixture-agent\n", encoding="utf-8")
                server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
                server.RequestHandlerClass.mode = mode
                thread = Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    class RecordingLocalTransport:
                        def __init__(self):
                            self.delegate = DefaultHttpTransport()
                            self.results = []
                            self.headers = []

                        def request(self, url, user_agent, timeout, method="GET", data=None, content_type=None, verify_https=True, extra_headers=None):
                            result = self.delegate.request(url, user_agent, timeout, method, data, content_type, verify_https, extra_headers)
                            self.results.append(result)
                            self.headers.append(dict(extra_headers or {}))
                            return result

                    url = f"http://127.0.0.1:{server.server_port}/?q=FUZZ"
                    target = ScanTarget("GET", url, None, "application/x-www-form-urlencoded", ["query:q"], "fixture")
                    lifecycle = RecordingLifecycle()
                    transport = RecordingLocalTransport()
                    services = ScanServices(
                        http=transport,
                        target_discovery=StaticTargetDiscovery(target),
                        contexts=StaticContextProvider(),
                        intelligence=StaticIntelligenceProvider(),
                        payloads=SinglePayloadPlanner(),
                        browser=NoopBrowserValidator(),
                        lifecycle=lifecycle,
                    )
                    args = scanner_args(payload_file, user_agent_file)
                    args.test_headers = ["Referer"]
                    rendered = io.StringIO()
                    with patch.dict("os.environ", {"XSSENTINEL_REQUESTS_PER_SECOND": "100", "XSSENTINEL_REQUEST_BUDGET": "100"}), \
                         patch("xssentinel_core.scanner.runner.time.sleep", return_value=None), \
                        contextlib.redirect_stdout(rendered):
                        findings, _ = scan(args, services)
                    accounting = request_governor_snapshot()
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=1)

                header_findings = [item for item in findings if item.trace_intelligence.get("header_analysis")]
                self.assertEqual(len(header_findings), 1)
                self.assertEqual(lifecycle.events.count("after_finding"), 2)
                finding = header_findings[0]
                header_trace = finding.trace_intelligence["header_analysis"]
                self.assertEqual(header_trace["header_name"], "Referer")
                self.assertTrue(finding.attempt_id)
                self.assertEqual(finding.trace_intelligence["input_location"], ["header:Referer"])
                self.assertIsNotNone(finding.trace_intelligence["marker_id"])
                self.assertTrue(any(item.attempt_id == finding.attempt_id for item in finding.diagnostics.evidence))
                self.assertEqual(header_trace["baseline_attempt_id"], uuid.UUID(hex=header_trace["baseline_attempt_id"]).hex)
                self.assertEqual(accounting["total_used"], 3)
                self.assertEqual(accounting["by_channel"], {"http": 3, "browser": 0})
                self.assertEqual(len(transport.results), 3)
                self.assertTrue(all(result.attempt_id for result in transport.results))
                self.assertEqual(len({result.attempt_id for result in transport.results}), 3)
                self.assertEqual(transport.results[1].attempt_id, header_trace["baseline_attempt_id"])
                self.assertEqual(transport.results[2].attempt_id, finding.attempt_id)
                self.assertEqual(transport.headers[2]["Referer"], finding.payload)
                self.assertIn(finding.trace_intelligence["marker_id"], finding.payload)
                self.assertIn("header=Referer", rendered.getvalue())
                report = build_json_report(findings, args._xti_scan_id, accounting)
                report_header = next(item for item in report["findings"] if item["trace"]["header_analysis"])
                self.assertEqual(report_header["xti_status"], finding.xti_status)
                self.assertEqual(report_header["attempt_id"], finding.attempt_id)
                self.assertEqual(report_header["trace"]["header_analysis"]["outcome"], header_trace["outcome"])
                results[mode] = (finding, header_trace)

        text_finding, text_trace = results["text"]
        self.assertEqual(text_trace["outcome"], "marker_reflected")
        self.assertEqual(text_finding.xti_status, "CONTEXT_IDENTIFIED")
        self.assertNotEqual(text_finding.xti_status, "CONFIRMED_XSS")
        self.assertTrue(any(text_finding.payload in reflection.snippet for reflection in text_finding.reflections))
        self.assertEqual(text_finding.evidence_bundle["xti_status"], text_finding.xti_status)

        encoded_finding, encoded_trace = results["encoded"]
        self.assertEqual(encoded_trace["outcome"], "marker_transformed")
        self.assertEqual(encoded_finding.xti_status, "REFLECTED")
        self.assertNotEqual(encoded_finding.xti_status, "CONFIRMED_XSS")
        self.assertIn("url_percent_encoding", {item["kind"] for item in encoded_finding.trace_intelligence["transformations"]})

        ignored_finding, ignored_trace = results["ignored"]
        self.assertEqual(ignored_trace["outcome"], "marker_not_observed")
        self.assertEqual(ignored_finding.xti_status, "NOT_REFLECTED")
        ignored_report = build_json_report([ignored_finding])
        self.assertEqual(ignored_report["findings"][0]["status"], ignored_finding.status)
        self.assertEqual(ignored_report["findings"][0]["xti_status"], ignored_finding.xti_status)
        self.assertNotIn(ignored_finding.payload, json.dumps(ignored_report))


if __name__ == "__main__":
    unittest.main()
