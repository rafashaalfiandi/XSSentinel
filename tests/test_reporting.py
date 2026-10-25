import json
import tempfile
import unittest
from pathlib import Path

from xssentinel_core.scanner.models import EvidenceItem, Finding, Reflection, ScanDiagnostics
from xssentinel_core.scanner.reporting import REPORT_SCHEMA_VERSION, build_json_report, write_json_report


class JsonReportingTests(unittest.TestCase):
    def make_finding(self) -> Finding:
        attempt_id = "attempt-fixture-1"
        finding = Finding(
            "REFLECTED_LOW",
            "https://example.test/search?q=ordinary&session_token=do-not-print",
            "GET",
            'password=body-secret',
            "payload-with-sensitive-marker",
            True,
            [Reflection("html-text", "marker reflected", 35, location="div", snippet='opaque-private-phrase response-secret')],
            False,
            "Authorization: Bearer browser-secret",
            200,
            confidence=32,
            attempt_id=attempt_id,
            xti_status="CONTEXT_IDENTIFIED",
            trace_intelligence={
                "scan_id": "scan-fixture",
                "target_id": "target-hash",
                "attempt_id": attempt_id,
                "marker_id": None,
                "input_location": ["query:q", "body:session_token"],
                "request_method": "GET",
                "request_fingerprint": "request-hash",
                "payload_id": "payload-hash",
                "context_id": "context-hash",
                "response_id": "response-hash",
                "browser_run_id": None,
                "evidence_ids": [f"{attempt_id}:e01"],
                "contexts": [{
                    "category": "HTML_TEXT",
                    "source_context": "html-text",
                    "output_location": "div",
                    "confidence": "high",
                    "active_context": False,
                    "evidence": "text context",
                    "evidence_id": f"{attempt_id}:ctx01",
                }],
                "transformations": [],
                "status": "CONTEXT_IDENTIFIED",
                "legacy_status": "REFLECTED_LOW",
                "header_analysis": {
                    "header_name": "Referer",
                    "outcome": "marker_reflected",
                    "server_acceptance": "not_determined",
                    "baseline_response_id": "baseline-hash",
                    "marker_fingerprint": "marker-hash",
                    "request_method": "GET",
                    "browser_validation": "not_run_for_inert_diagnostic_marker",
                },
            },
        )
        finding.diagnostics = ScanDiagnostics(
            "smart", 1, evidence=[EvidenceItem(
                "html-text", "marker reflection", 35, "div", 'Cookie: sid=response-cookie', attempt_id,
                f"{attempt_id}:e01",
            )],
        )
        return finding

    def test_report_schema_keeps_legacy_and_xti_statuses(self) -> None:
        finding = self.make_finding()

        report = build_json_report(
            [finding],
            request_metrics={
                "used": 3,
                "limit": 50,
                "requests_per_second": 2.0,
                "total_used": 5,
                "browser_used": 2,
                "browser_run_count": 1,
                "by_channel": {"http": 3, "browser": 2},
            },
        )

        self.assertEqual(report["schema_version"], REPORT_SCHEMA_VERSION)
        self.assertEqual(report["scan_id"], "scan-fixture")
        self.assertEqual(report["findings"][0]["status"], "REFLECTED_LOW")
        self.assertEqual(report["findings"][0]["xti_status"], "CONTEXT_IDENTIFIED")
        self.assertEqual(report["findings"][0]["attempt_id"], finding.attempt_id)
        self.assertEqual(report["findings"][0]["trace"]["browser_verification_status"], "NOT_TESTED")
        self.assertEqual(report["summary"]["finding_count"], 1)
        self.assertEqual(report["summary"]["http_transport_requests"]["used"], 3)
        self.assertEqual(report["summary"]["request_accounting"]["total_used"], 5)
        self.assertEqual(report["summary"]["request_accounting"]["by_channel"]["browser"], 2)
        self.assertEqual(report["findings"][0]["trace"]["header_analysis"]["header_name"], "Referer")
        self.assertEqual(report["findings"][0]["trace"]["header_analysis"]["outcome"], "marker_reflected")

    def test_report_omits_raw_payload_bodies_and_redacts_sensitive_data(self) -> None:
        report_text = json.dumps(build_json_report([self.make_finding()]))

        for secret in (
            "do-not-print", "body-secret", "response-secret", "browser-secret", "response-cookie",
            "payload-with-sensitive-marker", "opaque-private-phrase",
        ):
            self.assertNotIn(secret, report_text)
        self.assertIn("[REDACTED]", report_text)
        self.assertIn("https://example.test/[PATH AND QUERY OMITTED]", report_text)
        self.assertNotIn("q=ordinary", report_text)
        self.assertNotIn('"body"', report_text)
        self.assertIn('"snippet_included": false', report_text)
        self.assertIn('"message_included": false', report_text)

    def test_writer_creates_valid_json_and_does_not_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.json"
            written = write_json_report(path, [self.make_finding()])
            loaded = json.loads(path.read_text(encoding="utf-8"))

            self.assertEqual(written, path)
            self.assertEqual(loaded["schema_version"], REPORT_SCHEMA_VERSION)
            with self.assertRaises(FileExistsError):
                write_json_report(path, [])
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["summary"]["finding_count"], 1)


if __name__ == "__main__":
    unittest.main()
