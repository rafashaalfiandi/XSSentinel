import argparse
import unittest

from xssentinel_core.scanner.decisions import AttemptState, evaluate_scan_attempt
from xssentinel_core.scanner.models import HttpResult, ScanTarget


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
