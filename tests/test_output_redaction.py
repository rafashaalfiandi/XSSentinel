import contextlib
import hashlib
import io
import unittest
import urllib.parse

from xssentinel_core.scanner.models import Finding, Reflection, ScanDiagnostics, ScanTarget
from xssentinel_core.scanner.output import browser_evidence_label, display_target_url, print_endpoint_discovery_summary, print_result, print_summary
from xssentinel_core.scanner.utils import redact_sensitive_text, redact_sensitive_url


class OutputRedactionTests(unittest.TestCase):
    def test_result_line_is_compact_and_keeps_useful_status(self) -> None:
        payload = "payload-not-for-terminal"
        finding = Finding(
            "REFLECTED_LOW", "https://fixture.test/?q=value", "GET", None, payload,
            True, [Reflection("active-attribute", "reflected URL attribute", 75, location="a[href]")], False,
            "no alert/confirm/prompt popup detected", 200,
            attempt_id="0123456789abcdef0123456789abcdef",
            trace_intelligence={
                "payload_id": hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20],
                "browser_verification_status": "NOT_CONFIRMED",
                "response_truncated": True,
            },
            xti_status="INCONCLUSIVE",
        )
        finding.diagnostics = ScanDiagnostics("smart", 7, browser_checked=True)
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            print_result(7, finding)

        rendered = output.getvalue()
        self.assertIn("#0007", rendered)
        self.assertIn("probe 07", rendered)
        self.assertIn("browser unconfirmed", rendered)
        self.assertIn("XTI inconclusive", rendered)
        self.assertIn("response truncated", rendered)
        self.assertIn("a[href]", rendered)
        self.assertNotIn("attempt=", rendered)
        self.assertNotIn("payload=", rendered)
        self.assertNotIn("no alert/confirm/prompt popup detected", rendered)
        self.assertLess(len(rendered), 250)
        self.assertNotIn(payload, rendered)

    def test_attempt_correlated_browser_evidence_hides_marker_and_message(self) -> None:
        evidence = "attempt-popup:0123456789abcdef0123456789abcdef:alert:c2VjcmV0"

        rendered = browser_evidence_label(evidence)

        self.assertEqual(rendered, "attempt-tagged popup matched expected payload token")
        self.assertNotIn("0123456789abcdef", rendered)
        self.assertNotIn("c2VjcmV0", rendered)

    def test_url_redaction_hides_credentials_and_sensitive_query_values(self) -> None:
        url = "https://user:pass@example.test/search?q=visible&access_token=private&api_key=secret"

        redacted = redact_sensitive_url(url)
        parsed = urllib.parse.urlsplit(redacted)
        query = dict(urllib.parse.parse_qsl(parsed.query))

        self.assertEqual(parsed.netloc, "example.test")
        self.assertEqual(query["q"], "visible")
        self.assertEqual(query["access_token"], "[REDACTED]")
        self.assertEqual(query["api_key"], "[REDACTED]")
        self.assertNotIn("user", redacted)
        self.assertNotIn("private", redacted)
        self.assertNotIn("secret", redacted)

    def test_url_redaction_preserves_normal_parameters_and_raw_encoding(self) -> None:
        url = "https://example.test/p?q=a%2Fb+test&monkey=banana&apiKey=private&X-Api-Key=also-private&access%5Ftoken=hidden"

        redacted = redact_sensitive_url(url)

        self.assertIn("q=a%2Fb+test", redacted)
        self.assertIn("monkey=banana", redacted)
        self.assertIn("apiKey=[REDACTED]", redacted)
        self.assertIn("X-Api-Key=[REDACTED]", redacted)
        self.assertIn("access%5Ftoken=[REDACTED]", redacted)
        self.assertNotIn("hidden", redacted)

    def test_malformed_url_does_not_echo_possible_credentials(self) -> None:
        redacted = redact_sensitive_url("https://user:private@[broken/?token=hidden")

        self.assertEqual(redacted, "[URL REDACTED: invalid URL]")
        self.assertNotIn("private", redacted)
        self.assertNotIn("hidden", redacted)

    def test_text_redaction_hides_headers_and_sensitive_assignments(self) -> None:
        text = 'Cookie: sid=private; theme=dark\n{"password":"secret", "q":"visible"}'

        redacted = redact_sensitive_text(text)

        self.assertNotIn("sid=private", redacted)
        self.assertNotIn('"secret"', redacted)
        self.assertIn('"q":"visible"', redacted)
        self.assertIn("[REDACTED]", redacted)

    def test_terminal_target_display_redacts_sensitive_query_values(self) -> None:
        rendered = display_target_url("https://example.test/search?q=FUZZ&session_id=private")

        self.assertIn("q=", rendered)
        self.assertNotIn("private", rendered)
        self.assertIn("REDACTED", rendered)

    def test_confirmed_summary_redacts_sensitive_url_and_browser_evidence(self) -> None:
        finding = Finding(
            "CONFIRMED",
            "https://example.test/?access_token=private-url-value",
            "GET",
            None,
            "inert-test-payload",
            False,
            [],
            True,
            "dialog:alert:token=private-evidence-value",
            200,
            confidence=90,
        )
        rendered = io.StringIO()

        with contextlib.redirect_stdout(rendered):
            print_summary([finding])

        output = rendered.getvalue()
        self.assertNotIn("private-url-value", output)
        self.assertNotIn("private-evidence-value", output)
        self.assertIn("[REDACTED]", output)

    def test_discovery_summary_redacts_url_userinfo(self) -> None:
        scan_target = ScanTarget(
            "GET", "https://user:private@example.test/?q=FUZZ", None,
            "application/x-www-form-urlencoded", ["query:q"], "direct",
        )
        rendered = io.StringIO()

        with contextlib.redirect_stdout(rendered):
            print_endpoint_discovery_summary([scan_target])

        output = rendered.getvalue()
        self.assertNotIn("user", output)
        self.assertNotIn("private", output)
        self.assertIn("https://example.test", output)


if __name__ == "__main__":
    unittest.main()
