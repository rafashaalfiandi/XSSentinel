import argparse
import unittest

from xssentinel_core.scanner import browser
from xssentinel_core.scanner.decisions import AttemptState, evaluate_scan_attempt
from xssentinel_core.scanner.models import HttpResult, ScanTarget
from xssentinel_core.scanner.reflection import attempt_popup_evidence, attempt_popup_source_evidence
from xssentinel_core.scanner.settings import PAYLOAD_FILE
from xssentinel_core.scanner.utils import load_lines


def scanner_args(**overrides):
    values = {
        "browser": False,
        "browser_all": False,
        "browser_confirm_limit": 4,
        "timeout": 1.0,
        "verify_https": False,
        "headers": {},
        "stop_on_confirmed": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class DecisionTests(unittest.TestCase):
    def test_popup_payload_without_response_reflection_still_runs_browser(self) -> None:
        target = ScanTarget(
            "GET",
            "https://fixture.test/search?q=FUZZ",
            None,
            "application/x-www-form-urlencoded",
            ["query:q"],
        )
        calls = []

        decision = evaluate_scan_attempt(
            target,
            "<svg onload=prompt(8)>",
            "https://fixture.test/search?q=encoded-payload",
            None,
            HttpResult(200, "<html><body>search page</body></html>", {"Content-Type": "text/html"}),
            scanner_args(browser=True),
            "unit-test-agent",
            None,
            "smart",
            7,
            AttemptState(),
            lambda *_args: (calls.append(True) or False, "no alert/confirm/prompt popup detected"),
        )

        self.assertEqual(calls, [True])
        self.assertTrue(decision.finding.diagnostics.browser_checked)
        self.assertEqual(decision.finding.status, "NOT_CONFIRMED")
        self.assertEqual(decision.finding.xti_status, "NOT_REFLECTED")

    def test_catalog_payload_seven_parameter_popup_is_confirmed_by_current_attempt(self) -> None:
        payload = load_lines(PAYLOAD_FILE)[6]
        target = ScanTarget(
            "GET",
            "https://fixture.test/search?q=FUZZ",
            None,
            "application/x-www-form-urlencoded",
            ["query:q"],
        )
        result = HttpResult(
            200,
            f'<!doctype html><div data-value="{payload}"></div>',
            {"Content-Type": "text/html; charset=utf-8"},
        )

        def validator(*_args):
            attempt_id = browser._ACTIVE_BROWSER_ATTEMPT_ID.get()
            evidence = (
                attempt_popup_evidence(attempt_id, "prompt", "8"),
                attempt_popup_source_evidence(attempt_id, "prompt"),
            )
            return True, "; ".join(evidence)

        decision = evaluate_scan_attempt(
            target,
            payload,
            "https://fixture.test/search?q=encoded-payload",
            None,
            result,
            scanner_args(browser=True),
            "unit-test-agent",
            None,
            "smart",
            7,
            AttemptState(),
            validator,
        )

        self.assertTrue(decision.finding.diagnostics.browser_checked)
        self.assertEqual(
            decision.finding.status,
            "CONFIRMED",
            f"{decision.finding.browser_evidence}; reflections={[(item.context, item.snippet) for item in decision.finding.reflections]!r}",
        )
        self.assertEqual(decision.finding.xti_status, "CONFIRMED_XSS")
        self.assertTrue(decision.finding.trace_intelligence["browser_evidence_correlated"])
        self.assertTrue(any(
            evidence.kind == "browser-confirmed"
            and evidence.attempt_id == decision.finding.attempt_id
            for evidence in decision.finding.diagnostics.evidence
        ))

    def test_dynamic_popup_argument_is_confirmed_for_current_attempt(self) -> None:
        payload = '"><img src=x onerror=alert(location.href)>'
        target = ScanTarget(
            "GET",
            "https://fixture.test/search?q=FUZZ",
            None,
            "application/x-www-form-urlencoded",
            ["query:q"],
        )

        def validator(*_args):
            attempt_id = browser._ACTIVE_BROWSER_ATTEMPT_ID.get()
            evidence = (
                attempt_popup_evidence(attempt_id, "alert", "https://fixture.test/search?q=dynamic"),
                attempt_popup_source_evidence(attempt_id, "alert"),
            )
            return True, "; ".join(evidence)

        decision = evaluate_scan_attempt(
            target,
            payload,
            "https://fixture.test/search?q=encoded-payload",
            None,
            HttpResult(200, f'<div data-value="{payload}"></div>', {"Content-Type": "text/html"}),
            scanner_args(browser=True),
            "unit-test-agent",
            None,
            "smart",
            1,
            AttemptState(),
            validator,
        )

        self.assertTrue(decision.finding.diagnostics.browser_checked)
        self.assertTrue(
            decision.finding.browser_confirmed,
            f"{decision.finding.browser_evidence}; reflections={[(item.context, item.snippet) for item in decision.finding.reflections]!r}",
        )
        self.assertEqual(decision.finding.status, "CONFIRMED")
        self.assertEqual(decision.finding.xti_status, "CONFIRMED_XSS")

    def test_confirmed_browser_evidence_is_not_overridden_by_blocking_http_status(self) -> None:
        payload = '"><img src=x onerror=alert(1)>'
        target = ScanTarget(
            "GET",
            "https://fixture.test/search?q=FUZZ",
            None,
            "application/x-www-form-urlencoded",
            ["query:q"],
        )

        def validator(*_args):
            attempt_id = browser._ACTIVE_BROWSER_ATTEMPT_ID.get()
            return True, "; ".join((
                attempt_popup_evidence(attempt_id, "alert", "1"),
                attempt_popup_source_evidence(attempt_id, "alert"),
            ))

        decision = evaluate_scan_attempt(
            target,
            payload,
            "https://fixture.test/search?q=encoded-payload",
            None,
            HttpResult(403, f'<div data-value="{payload}"></div>', {"Content-Type": "text/html"}, "HTTP 403"),
            scanner_args(browser=True),
            "unit-test-agent",
            None,
            "smart",
            1,
            AttemptState(),
            validator,
        )

        self.assertTrue(decision.finding.browser_confirmed, decision.finding.browser_evidence)
        self.assertEqual(decision.finding.status, "CONFIRMED")
        self.assertEqual(decision.finding.xti_status, "CONFIRMED_XSS")

    def test_truncated_response_is_inconclusive_without_browser_proof(self) -> None:
        target = ScanTarget("GET", "https://fixture.test/search?q=FUZZ", None, "application/x-www-form-urlencoded", ["query:q"])
        decision = evaluate_scan_attempt(
            target,
            "plain-marker",
            "https://fixture.test/search?q=plain-marker",
            None,
            HttpResult(200, "partial response", {"Content-Type": "text/html"}, truncated=True),
            scanner_args(),
            "unit-test-agent",
            None,
            "smart",
            1,
            AttemptState(),
            lambda *_args: self.fail("browser should not run for an inert marker"),
        )

        self.assertEqual(decision.finding.xti_status, "INCONCLUSIVE")
        self.assertTrue(decision.finding.trace_intelligence["response_truncated"])
        self.assertTrue(any(item.kind == "response-truncated" for item in decision.finding.diagnostics.evidence))

    def test_global_request_budget_stops_remaining_targets_as_inconclusive(self) -> None:
        target = ScanTarget("GET", "https://example.test/search?q=FUZZ", None, "application/x-www-form-urlencoded", ["query:q"])

        decision = evaluate_scan_attempt(
            target,
            "plain",
            "https://example.test/search?q=plain",
            None,
            HttpResult(None, "", {}, "scan-wide HTTP request budget exhausted"),
            scanner_args(),
            "unit-test-agent",
            None,
            "smart",
            1,
            AttemptState(),
            lambda *_args: self.fail("browser should not run after request budget exhaustion"),
        )

        self.assertTrue(decision.target_done)
        self.assertTrue(decision.stop_all_targets)
        self.assertEqual(decision.finding.xti_status, "INCONCLUSIVE")
        self.assertNotEqual(decision.finding.xti_status, "NOT_REFLECTED")

    def test_api_delivery_evidence_forces_browser_validation_when_available(self) -> None:
        calls = []

        def validator(*args):
            calls.append(args)
            return False, "no alert/confirm/prompt popup detected"

        target = ScanTarget("GET", "https://example.test/api/search?q=FUZZ", None, "application/x-www-form-urlencoded", ["query:q"])
        payload = "<svg onload=alert(1)>"
        result = HttpResult(200, f'{{"value":"{payload}"}}', {"Content-Type": "application/json"}, None)

        decision = evaluate_scan_attempt(
            target,
            payload,
            "https://example.test/api/search?q=%3Csvg%20onload%3Dalert%281%29%3E",
            None,
            result,
            scanner_args(browser=True),
            "unit-test-agent",
            None,
            "smart",
            1,
            AttemptState(),
            validator,
        )

        self.assertEqual(len(calls), 1)
        self.assertTrue(decision.finding.diagnostics.browser_checked)
        self.assertIn(decision.finding.status, {"API_REFLECTED", "API_RISK"})
        self.assertFalse(decision.target_done)
        self.assertIn("browser=no alert/confirm/prompt popup detected", decision.finding.browser_evidence)
        self.assertEqual(decision.state.browser_checks_done, 1)

    def test_repeated_rejected_http_status_reaches_skip_threshold(self) -> None:
        target = ScanTarget("GET", "https://example.test/search?q=FUZZ", None, "application/x-www-form-urlencoded", ["query:q"])

        decision = evaluate_scan_attempt(
            target,
            "plain",
            "https://example.test/search?q=plain",
            None,
            HttpResult(204, "", {}, None),
            scanner_args(),
            "unit-test-agent",
            None,
            "smart",
            11,
            AttemptState(rejected_status_streak=10, last_rejected_status=204),
            lambda *_args: self.fail("browser validator should not run"),
        )

        self.assertEqual(decision.finding.status, "HTTP_SKIPPED")
        self.assertTrue(decision.target_done)
        self.assertEqual(decision.state.rejected_status_streak, 11)
        self.assertIn("no content after 11 consecutive", decision.finding.diagnostics.skip_reason)

    def test_network_errors_stop_only_the_current_target_by_default(self) -> None:
        target = ScanTarget("GET", "https://missing.example/?q=FUZZ", None, "application/x-www-form-urlencoded", ["query:q"])

        decision = evaluate_scan_attempt(
            target,
            "plain",
            "https://missing.example/?q=plain",
            None,
            HttpResult(None, "", {}, "DNS lookup failed for host 'missing.example'"),
            scanner_args(),
            "unit-test-agent",
            None,
            "smart",
            1,
            AttemptState(),
            lambda *_args: self.fail("browser validator should not run"),
        )

        self.assertEqual(decision.finding.status, "NETWORK_ERROR")
        self.assertTrue(decision.target_done)
        self.assertFalse(decision.stop_all_targets)


if __name__ == "__main__":
    unittest.main()
