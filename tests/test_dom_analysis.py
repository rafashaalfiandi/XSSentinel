import argparse
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from xssentinel_core.scanner.intelligence import analyze_javascript, analyze_target_intelligence
from xssentinel_core.scanner.models import ScanTarget
from xssentinel_core.scanner.plugins import LifecycleManager
from xssentinel_core.scanner.runner import scan
from xssentinel_core.scanner.services import DefaultHttpTransport, DefaultIntelligenceProvider, ScanServices


class DomStaticAnalysisTests(unittest.TestCase):
    def test_source_and_sink_are_distinct_from_identifier_linked_heuristic(self):
        candidate_script = "const candidate = location.hash; element.innerHTML = candidate;"
        findings = analyze_javascript(candidate_script, "inline fixture")
        kinds = {finding.kind for finding in findings}

        self.assertIn("dom-source", kinds)
        self.assertIn("dom-sink", kinds)
        self.assertTrue(all(finding.severity <= 45 for finding in findings))

    def test_unrelated_source_and_sink_do_not_become_flow_candidate(self):
        source_script = "const tainted = location.hash; element.innerHTML = constantText;"
        disconnected_script = "function readInput() { return location.hash; } function render() { node.innerHTML = staticText; }"

        self.assertFalse(any(item.kind == "dom-flow-candidate-heuristic" for item in analyze_javascript(source_script, "negative")))
        self.assertFalse(any(item.kind == "dom-flow-candidate-heuristic" for item in analyze_javascript(disconnected_script, "negative-functions")))

    def test_real_intelligence_pipeline_analyzes_local_fixture_script(self):
        body = (
            "<!doctype html><html><body><script>"
            "const candidate = location.hash; document.querySelector('#out').innerHTML = candidate;"
            "</script></body></html>"
        )

        class FixtureHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                encoded = body.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            target = ScanTarget(
                "GET",
                f"http://127.0.0.1:{server.server_port}/?q=FUZZ",
                None,
                "application/x-www-form-urlencoded",
                ["query:q"],
                "dom-fixture",
            )
            args = argparse.Namespace(
                timeout=1.0,
                verify_https=True,
                headers={},
            )
            with patch.dict("os.environ", {"XSSENTINEL_REQUESTS_PER_SECOND": "100", "XSSENTINEL_REQUEST_BUDGET": "50"}):
                from xssentinel_core.scanner.http_client import configure_request_governor, configure_scope_origins
                configure_request_governor()
                configure_scope_origins([])
                intelligence = analyze_target_intelligence(target, args, ["fixture-agent"], set())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)

        kinds = {finding.kind for finding in intelligence.script_analysis.suspicious_scripts}
        self.assertIn("dom-source", kinds)
        self.assertIn("dom-sink", kinds)
        self.assertTrue(intelligence.script_analysis.dom_flow_candidates)
        candidate = intelligence.script_analysis.dom_flow_candidates[0]
        self.assertEqual(candidate.kind, "dom-flow-candidate-heuristic")
        self.assertIn("scope/data flow unverified", candidate.detail)
        self.assertEqual(intelligence.script_analysis.data_flows, [])

    def test_dom_static_analysis_is_reached_by_main_scan_runner(self):
        body = (
            "<!doctype html><html><body><script>"
            "const candidate = location.hash; document.querySelector('#out').innerHTML = candidate;"
            "</script></body></html>"
        )

        class FixtureHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                encoded = body.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, *_args):
                pass

        class StaticDiscovery:
            def __init__(self, scan_target):
                self.scan_target = scan_target

            def discover(self, _args, _user_agent):
                return [self.scan_target]

        class StaticContexts:
            def infer(self, *_args):
                return set()

        class StaticPayloadPlanner:
            def batches(self, _payloads, _contexts, _args):
                return ["inert-input"], []

        class NoBrowser:
            def validate(self, *_args, **_kwargs):
                return False, "browser not requested"

        server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            payload_file = root / "payloads.txt"
            user_agent_file = root / "agents.txt"
            payload_file.write_text("inert-input\n", encoding="utf-8")
            user_agent_file.write_text("fixture-agent\n", encoding="utf-8")
            scan_target = ScanTarget(
                "GET",
                f"http://127.0.0.1:{server.server_port}/?q=FUZZ",
                None,
                "application/x-www-form-urlencoded",
                ["query:q"],
                "dom-fixture",
            )
            services = ScanServices(
                http=DefaultHttpTransport(),
                target_discovery=StaticDiscovery(scan_target),
                contexts=StaticContexts(),
                intelligence=DefaultIntelligenceProvider(),
                payloads=StaticPayloadPlanner(),
                browser=NoBrowser(),
                lifecycle=LifecycleManager(),
            )
            args = argparse.Namespace(
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
                verify_https=True,
                headers={},
                test_headers=[],
            )
            try:
                with patch.dict("os.environ", {
                    "XSSENTINEL_REQUESTS_PER_SECOND": "100",
                    "XSSENTINEL_REQUEST_BUDGET": "50",
                }), patch("xssentinel_core.scanner.runner.time.sleep", return_value=None), contextlib.redirect_stdout(io.StringIO()):
                    findings, intelligence = scan(args, services)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=1)

        analysis = intelligence[0].script_analysis
        kinds = {finding.kind for finding in analysis.suspicious_scripts}
        self.assertIn("dom-source", kinds)
        self.assertIn("dom-sink", kinds)
        self.assertTrue(analysis.dom_flow_candidates)
        self.assertEqual(analysis.data_flows, [])
        self.assertIn("scope/data flow unverified", analysis.dom_flow_candidates[0].detail)
        self.assertEqual(len(findings), 1)
        self.assertNotEqual(findings[0].xti_status, "CONFIRMED_XSS")


if __name__ == "__main__":
    unittest.main()
