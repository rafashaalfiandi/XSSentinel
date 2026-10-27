"""Offline regression fixtures for evidence and payload transport semantics."""

import argparse
import hashlib
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import unittest
import urllib.parse

from xssentinel_core.scanner import browser
from xssentinel_core.scanner.decisions import AttemptState, evaluate_scan_attempt
from xssentinel_core.scanner.http_client import configure_request_governor, configure_scope_origins, request_detailed
from xssentinel_core.scanner.models import HttpResult, ScanTarget
from xssentinel_core.scanner.payloads import expand_payloads, select_payload_batches
from xssentinel_core.scanner.settings import FORCED_SMART_PAYLOAD_POSITIONS, PAYLOAD_FILE
from xssentinel_core.scanner.targets import build_request_target
from xssentinel_core.scanner.utils import load_lines


class LocalFixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        value = query.get("q", [""])[0]
        case = query.get("case", [""])[0]

        if parsed.path == "/dynamic":
            body = f'<!doctype html><div data-value="{value}"></div>'
        elif parsed.path == "/independent-popup":
            body = '<!doctype html><script>alert("unrelated-static-popup")</script><main>no input reflection</main>'
        elif parsed.path == "/dom":
            body = (
                '<!doctype html><div id="output"></div><script>'
                'const input = new URLSearchParams(location.search).get("q") || "";'
                'document.querySelector("#output").innerHTML = input;'
                '</script>'
            )
        elif parsed.path == "/attribute":
            body = f'<!doctype html><div data-value="{value}">attribute fixture</div>'
        elif case == "escaped":
            body = f"<p>{html.escape(value, quote=True)}</p>"
        else:
            body = f"<!doctype html><main>{value}</main>"

        encoded = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, _format, *_args):
        return


class XssEvidenceRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), LocalFixtureHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.origin = f"http://127.0.0.1:{cls.server.server_port}"
        configure_scope_origins([cls.origin])
        configure_request_governor(max_requests=100, requests_per_second=100)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=2)
        cls.server.server_close()
        configure_scope_origins([])
        configure_request_governor(max_requests=5000, requests_per_second=5)

    def args(self, **overrides):
        values = {
            "browser": False,
            "browser_all": False,
            "browser_confirm_limit": 4,
            "timeout": 2.0,
            "verify_https": True,
            "headers": {},
            "stop_on_confirmed": False,
            "_xti_scan_id": "local-regression",
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def fixture_target(self, path="/reflect", case=""):
        query = f"case={urllib.parse.quote_plus(case)}&q=FUZZ" if case else "q=FUZZ"
        return ScanTarget(
            "GET",
            f"{self.origin}{path}?{query}",
            None,
            "application/x-www-form-urlencoded",
            ["query:q"],
            source="local-regression-fixture",
        )

    def run_fixture_attempt(self, target, payload, args=None, validator=None):
        url, body = build_request_target(target, payload)
        result = request_detailed(url, "XSSentinel-local-regression", 2.0, "GET", body, target.content_type, True, {})
        decision = evaluate_scan_attempt(
            target,
            payload,
            url,
            body,
            result,
            args or self.args(),
            "XSSentinel-local-regression",
            None,
            "smart",
            1,
            AttemptState(),
            validator or (lambda *_args: (False, "no alert/confirm/prompt popup detected")),
        )
        return url, result, decision

    def test_benign_and_escaped_reflections_are_not_confirmed(self):
        benign = "safe-local-marker-7"
        _, benign_response, benign_decision = self.run_fixture_attempt(self.fixture_target(), benign)
        self.assertEqual(benign_response.status, 200)
        self.assertTrue(benign_decision.finding.reflected)
        self.assertFalse(benign_decision.finding.browser_confirmed)
        self.assertNotEqual(benign_decision.finding.xti_status, "CONFIRMED_XSS")

        escaped = "<script>window.fixture = true</script>"
        _, escaped_response, escaped_decision = self.run_fixture_attempt(
            self.fixture_target(case="escaped"), escaped
        )
        self.assertIn("&lt;script&gt;", escaped_response.body)
        self.assertFalse(escaped_decision.finding.browser_confirmed)
        self.assertNotEqual(escaped_decision.finding.xti_status, "CONFIRMED_XSS")

    @unittest.skipUnless(browser.local_chromium_binary(), "local Chromium/Chrome is unavailable")
    def test_reflected_but_nonexecuting_input_is_not_confirmed(self):
        payload = "<script>window.fixtureOnly=true</script>"
        _url, response, decision = self.run_fixture_attempt(
            self.fixture_target(case="escaped"),
            payload,
            self.args(browser=True, browser_all=True),
            browser.confirm_with_browser,
        )

        self.assertEqual(response.status, 200)
        self.assertFalse(decision.finding.browser_confirmed)
        self.assertNotEqual(decision.finding.status, "CONFIRMED")
        self.assertEqual(decision.finding.trace_intelligence["browser_verification_status"], "NOT_CONFIRMED")

    def test_catalog_payload_seven_identity_and_get_transport(self):
        raw_catalog = load_lines(PAYLOAD_FILE)
        expanded_catalog = expand_payloads(raw_catalog, True)
        selected_payloads, _fallback = select_payload_batches(expanded_catalog, {"html-text"}, 90, True)
        payload = raw_catalog[6]

        self.assertEqual(payload, FORCED_SMART_PAYLOAD_POSITIONS[0][1])
        self.assertEqual(selected_payloads[6], payload)
        payload_fingerprint = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
        self.assertEqual(payload_fingerprint, "79e68ac94012d5c7b579")
        self.assertEqual(len(payload_fingerprint), 20)

        target = self.fixture_target()
        request_url, request_body = build_request_target(target, payload)
        parsed = urllib.parse.urlsplit(request_url)
        sent_value = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))["q"]

        self.assertEqual(target.method, "GET")
        self.assertEqual(target.fuzz_locations, ["query:q"])
        self.assertIsNone(request_body)
        self.assertEqual(sent_value, payload)

    @unittest.skipUnless(browser.local_chromium_binary(), "local Chromium/Chrome is unavailable")
    def test_catalog_payload_seven_executes_in_controlled_attribute_fixture(self):
        catalog = load_lines(PAYLOAD_FILE)
        expanded_catalog = expand_payloads(catalog, True)
        selected_payloads, _fallback = select_payload_batches(expanded_catalog, {"html-attribute"}, 90, True)
        payload = selected_payloads[6]
        self.assertEqual(payload, catalog[6])
        fingerprint = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
        self.assertEqual(fingerprint, "79e68ac94012d5c7b579")
        target = self.fixture_target(path="/attribute")
        request_url, response, decision = self.run_fixture_attempt(
            target,
            payload,
            self.args(browser=True, browser_all=True),
            browser.confirm_with_browser,
        )

        finding = decision.finding
        self.assertEqual(fingerprint, hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20])
        self.assertEqual(target.method, "GET")
        self.assertEqual(target.fuzz_locations, ["query:q"])
        self.assertIn("data-value", response.body)
        self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(request_url).query)["q"][0], payload)
        self.assertEqual(finding.status, "CONFIRMED", finding.browser_evidence)
        self.assertTrue(finding.browser_confirmed)
        self.assertEqual(finding.xti_status, "CONFIRMED_XSS")
        browser_items = [item for item in finding.diagnostics.evidence if item.kind == "browser-confirmed"]
        self.assertTrue(browser_items)
        for item in browser_items:
            self.assertEqual(item.attempt_id, finding.attempt_id)
            self.assertIn(item.evidence_id, finding.trace_intelligence["evidence_ids"])

    @unittest.skipUnless(browser.local_chromium_binary(), "local Chromium/Chrome is unavailable")
    def test_dynamic_popup_argument_executes_and_is_correlated_to_call_site(self):
        payload = '"><img src=x onerror=alert(location.href)>'
        target = self.fixture_target(path="/dynamic")
        _url, response, decision = self.run_fixture_attempt(
            target,
            payload,
            self.args(browser=True, browser_all=True),
            browser.confirm_with_browser,
        )

        finding = decision.finding
        self.assertEqual(response.status, 200)
        self.assertIn("onerror=alert(location.href)", response.body)
        self.assertTrue(finding.browser_confirmed, finding.browser_evidence)
        self.assertEqual(finding.status, "CONFIRMED")
        self.assertEqual(finding.xti_status, "CONFIRMED_XSS")
        self.assertIn(f"attempt-popup-source:{finding.attempt_id}:alert", finding.browser_evidence)

    @unittest.skipUnless(browser.local_chromium_binary(), "local Chromium/Chrome is unavailable")
    def test_independent_popup_does_not_confirm_unrelated_input(self):
        payload = '"><img src=x onerror=alert(location.href)>'
        target = self.fixture_target(path="/independent-popup")
        _url, response, decision = self.run_fixture_attempt(
            target,
            payload,
            self.args(browser=True, browser_all=True),
            browser.confirm_with_browser,
        )

        finding = decision.finding
        self.assertEqual(response.status, 200)
        self.assertNotIn(payload, response.body)
        self.assertFalse(finding.browser_confirmed)
        self.assertNotEqual(finding.status, "CONFIRMED")

    @unittest.skipUnless(browser.local_chromium_binary(), "local Chromium/Chrome is unavailable")
    def test_reflected_script_execution_without_popup_is_confirmed_locally(self):
        payload = "<script>window.__xssentinelFixtureSignal=window.__xssentinelAttemptId</script>"
        url, response, decision = self.run_fixture_attempt(
            self.fixture_target(),
            payload,
            self.args(browser=True, browser_all=True),
            browser.confirm_with_browser,
        )

        finding = decision.finding
        self.assertEqual(response.status, 200)
        self.assertTrue(browser.is_loopback_url(url))
        self.assertEqual(
            finding.trace_intelligence["browser_verification_status"], "CONFIRMED",
            f"checked={finding.diagnostics.browser_checked}; evidence={finding.browser_evidence!r}",
        )
        self.assertEqual(finding.status, "CONFIRMED", finding.browser_evidence)
        self.assertEqual(finding.xti_status, "CONFIRMED_XSS")
        self.assertTrue(finding.browser_evidence.startswith("dom-signal:"))
        self.assertIn(f"dom-signal:{finding.attempt_id}", finding.browser_evidence)
        browser_items = [item for item in finding.diagnostics.evidence if item.kind == "browser-confirmed"]
        self.assertTrue(browser_items)
        for item in browser_items:
            self.assertEqual(item.attempt_id, finding.attempt_id)
            self.assertIn(item.evidence_id, finding.trace_intelligence["evidence_ids"])

    @unittest.skipUnless(browser.local_chromium_binary(), "local Chromium/Chrome is unavailable")
    def test_dom_sink_execution_without_popup_is_confirmed_locally(self):
        payload = '<img src=x onerror="window.__xssentinelFixtureSignal=window.__xssentinelAttemptId">'
        url, response, decision = self.run_fixture_attempt(
            self.fixture_target(path="/dom"),
            payload,
            self.args(browser=True, browser_all=True),
            browser.confirm_with_browser,
        )

        finding = decision.finding
        self.assertEqual(response.status, 200)
        self.assertIn("innerHTML", response.body)
        self.assertTrue(browser.is_loopback_url(url))
        self.assertEqual(finding.status, "CONFIRMED", finding.browser_evidence)
        self.assertEqual(finding.xti_status, "CONFIRMED_XSS")
        self.assertIn(f"dom-signal:{finding.attempt_id}", finding.browser_evidence)


if __name__ == "__main__":
    unittest.main()
