import argparse
from concurrent.futures import ThreadPoolExecutor
import unittest

from xssentinel_core.scanner.agents import ContextAnalyzerAgent, EvidenceManagerAgent, IntelligentCache, RuntimeMetrics, TraceRecorder
from xssentinel_core.scanner import browser
from xssentinel_core.scanner.browser import BrowserRequestGovernor
from xssentinel_core.scanner.decisions import AttemptState, evaluate_scan_attempt
from xssentinel_core.scanner.models import Finding, HttpResult, Reflection, ScanTarget
from xssentinel_core.scanner.trace_intelligence import (
    TRACE_STATUS,
    analyze_transformations,
    classify_trace_status,
    fingerprint_contexts,
    validate_browser_confirmation,
)
from xssentinel_core.scanner.reflection import attempt_popup_evidence, attempt_popup_source_evidence
from xssentinel_core.scanner.contexts import analyze_response_context


PAYLOAD = "TRACE_MARKER_42"


def scan_args(**overrides):
    values = {
        "browser": False,
        "browser_all": False,
        "browser_confirm_limit": 4,
        "timeout": 1.0,
        "verify_https": False,
        "headers": {},
        "stop_on_confirmed": False,
        "_xti_scan_id": "test-scan",
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def target(url="https://fixture.test/?q=FUZZ"):
    return ScanTarget("GET", url, None, "application/x-www-form-urlencoded", ["query:q"])


def evaluate(payload, body, content_type="text/html", browser=False, browser_all=False, validator=None):
    url = "https://fixture.test/?q=FUZZ"
    sent_url = "https://fixture.test/?q=encoded"
    result = HttpResult(200, body, {"Content-Type": content_type}, None)
    return evaluate_scan_attempt(
        target(url), payload, sent_url, None, result,
        scan_args(browser=browser, browser_all=browser_all), "fixture-agent", None, "smart", 1,
        AttemptState(), validator or (lambda *_args: (False, "no alert/confirm/prompt popup detected")),
    ).finding


class TraceIdentityTests(unittest.TestCase):
    def test_context_cache_does_not_reuse_different_post_body_or_headers(self):
        class Contexts:
            def __init__(self):
                self.calls = []

            def infer(self, scan_target, _args, _user_agents):
                self.calls.append((scan_target.data, _args.headers.get("X-Fixture")))
                return {str(len(self.calls))}

        class Services:
            pass

        services = Services()
        services.contexts = Contexts()
        analyzer = ContextAnalyzerAgent()
        cache = IntelligentCache(RuntimeMetrics())
        trace = TraceRecorder()
        args = argparse.Namespace(smart=True, timeout=1.0, verify_https=True, headers={"X-Fixture": "one"})
        first = ScanTarget("POST", "https://fixture.test/write", "body=one", "application/json", ["body:body"])
        second = ScanTarget("POST", "https://fixture.test/write", "body=two", "application/json", ["body:body"])

        analyzer.analyze(first, args, ["ua"], services, cache, trace)
        analyzer.analyze(second, args, ["ua"], services, cache, trace)
        args.headers = {"X-Fixture": "two"}
        analyzer.analyze(second, args, ["ua"], services, cache, trace)

        self.assertEqual(len(services.contexts.calls), 3)
        self.assertEqual(services.contexts.calls, [("body=one", "one"), ("body=two", "one"), ("body=two", "two")])

    def test_two_parallel_attempts_keep_evidence_isolated(self):
        cases = [("TRACE_ALPHA_42", "<div>TRACE_ALPHA_42</div>"), ("TRACE_BETA_91", "<!-- TRACE_BETA_91 -->")]
        with ThreadPoolExecutor(max_workers=2) as executor:
            findings = list(executor.map(lambda pair: evaluate(pair[0], pair[1]), cases))

        self.assertNotEqual(findings[0].attempt_id, findings[1].attempt_id)
        for finding in findings:
            self.assertTrue(finding.attempt_id)
            self.assertTrue(finding.trace_intelligence["response_id"])
            evidence_ids = set(finding.trace_intelligence["evidence_ids"])
            self.assertTrue(evidence_ids)
            self.assertTrue(evidence_ids.isdisjoint(set(findings[1 if finding is findings[0] else 0].trace_intelligence["evidence_ids"])))
            for item in finding.diagnostics.evidence:
                self.assertEqual(item.attempt_id, finding.attempt_id)
                self.assertIn(item.evidence_id, evidence_ids)

    def test_agent_trace_is_filtered_by_attempt_not_global_recency(self):
        recorder = TraceRecorder()
        recorder.emit("Decision Engine", "decision", "REFLECTED", 50, "alpha", {"attempt_id": "attempt-a"})
        recorder.emit("Decision Engine", "decision", "NOT_REFLECTED", 40, "beta", {"attempt_id": "attempt-b"})
        manager = EvidenceManagerAgent()
        findings = [
            Finding("REFLECTED_LOW", "https://fixture.test/", "GET", None, "x", True, [], False, "", 200, attempt_id="attempt-a"),
            Finding("NOT_CONFIRMED", "https://fixture.test/", "GET", None, "y", False, [], False, "", 200, attempt_id="attempt-b"),
        ]

        with ThreadPoolExecutor(max_workers=2) as executor:
            list(executor.map(lambda finding: manager.attach_trace(finding, recorder), findings))

        self.assertEqual(findings[0].evidence_bundle["decision_explanation"], "alpha")
        self.assertEqual(findings[1].evidence_bundle["decision_explanation"], "beta")
        self.assertEqual(findings[0].evidence_bundle["agent_trace"][0]["data"]["attempt_id"], "attempt-a")
        self.assertEqual(findings[1].evidence_bundle["agent_trace"][0]["data"]["attempt_id"], "attempt-b")

    def test_scan_identity_is_shared_and_attempt_identity_is_unique(self):
        first = evaluate(PAYLOAD, f"<p>{PAYLOAD}</p>")
        second = evaluate(PAYLOAD, f"<p>{PAYLOAD}</p>")
        self.assertEqual(first.trace_intelligence["scan_id"], second.trace_intelligence["scan_id"])
        self.assertNotEqual(first.attempt_id, second.attempt_id)


class ContextAndTransformationTests(unittest.TestCase):
    def test_context_fingerprints_cover_supported_parser_contexts(self):
        fixtures = [
            (f"<div>{PAYLOAD}</div>", {"category": "HTML_TEXT"}),
            (f'<div title="{PAYLOAD}">x</div>', {"category": "HTML_ATTRIBUTE"}),
            (f"<!-- {PAYLOAD} -->", {"category": "HTML_COMMENT"}),
            (f'<a href="{PAYLOAD}">x</a>', {"category": "URL_RELATED"}),
            (f'{{"value":"{PAYLOAD}"}}', {"category": "JSON"}),
            (f'const value = "{PAYLOAD}";', {"category": "JAVASCRIPT"}),
        ]
        for body, expected in fixtures:
            headers = {"Content-Type": "application/json"} if body.startswith("{") else (
                {"Content-Type": "application/javascript"} if body.startswith("const") else {"Content-Type": "text/html"}
            )
            parsed = analyze_response_context(body, PAYLOAD, headers, "https://fixture.test/page")
            fingerprints = fingerprint_contexts(parsed.reflections, parsed.parser)
            self.assertIn(expected["category"], {item["category"] for item in fingerprints}, body)

    def test_missing_marker_is_not_reflected(self):
        finding = evaluate(PAYLOAD, "<p>ordinary fixture content</p>")
        self.assertEqual(finding.xti_status, "NOT_REFLECTED")

    def test_plain_reflection_and_escaped_reflection_are_not_confirmed(self):
        plain = evaluate(PAYLOAD, f"<p>{PAYLOAD}</p>")
        escaped_payload = "<TRACE&>"
        escaped = evaluate(escaped_payload, "<p>&lt;TRACE&amp;&gt;</p>")

        self.assertEqual(plain.xti_status, "CONTEXT_IDENTIFIED")
        self.assertNotEqual(plain.xti_status, "CONFIRMED_XSS")
        self.assertIn(escaped.xti_status, {"REFLECTED", "CONTEXT_IDENTIFIED"})
        self.assertNotEqual(escaped.xti_status, "POTENTIAL_XSS")
        self.assertNotEqual(escaped.xti_status, "CONFIRMED_XSS")
        self.assertIn("html_entity_encoding", {item["kind"] for item in escaped.trace_intelligence["transformations"]})

    def test_transformation_observations_are_not_execution_evidence(self):
        observations = analyze_transformations("<tag>", "&lt;tag&gt;")
        self.assertEqual(observations, [{"kind": "html_entity_encoding", "observation": "representation_present"}])
        self.assertNotIn("execution", str(observations).lower())

    def test_unknown_context_is_not_overstated(self):
        reflected = evaluate(PAYLOAD, PAYLOAD, "application/octet-stream")
        self.assertIn(reflected.xti_status, {"REFLECTED", "CONTEXT_IDENTIFIED"})
        self.assertNotEqual(reflected.xti_status, "CONFIRMED_XSS")


class BrowserCorrelationTests(unittest.TestCase):
    def test_unrelated_browser_error_is_not_browser_evidence(self):
        payload = "alert('TRACE-Q7')"
        finding = evaluate(
            payload, f'<script>const note = "{payload}";</script>', browser=True,
            validator=lambda *_args: (False, "Chromium CDP error: unrelated timeout"),
        )
        self.assertFalse(finding.browser_confirmed)
        self.assertFalse(any(item.kind.startswith("browser-") for item in finding.diagnostics.evidence))
        self.assertNotEqual(finding.xti_status, "BROWSER_EVIDENCE")
        self.assertNotEqual(finding.xti_status, "CONFIRMED_XSS")

    def test_unmatched_browser_event_is_not_confirmed(self):
        payload = "alert('TRACE-Q7')"

        def validator(*_args):
            attempt_id = browser._ACTIVE_BROWSER_ATTEMPT_ID.get()
            return False, attempt_popup_evidence(attempt_id, "alert", "unrelated-message")

        finding = evaluate(
            payload, f'<script>const note = "{payload}";</script>', browser=True,
            validator=validator,
        )
        self.assertEqual(finding.trace_intelligence["browser_verification_status"], "INCONCLUSIVE")
        self.assertEqual(finding.xti_status, "INCONCLUSIVE")
        self.assertFalse(finding.browser_confirmed)
        self.assertNotEqual(finding.xti_status, "CONFIRMED_XSS")

    def test_browser_verifier_error_with_reflection_is_inconclusive(self):
        payload = "<svg onload=alert(7)>"
        finding = evaluate(
            payload,
            f'<div data-input="{payload}"></div>',
            browser=True,
            validator=lambda *_args: (False, "Browser verifier error: RuntimeError"),
        )

        self.assertTrue(finding.reflected)
        self.assertFalse(finding.browser_confirmed)
        self.assertEqual(finding.trace_intelligence["browser_verification_status"], "INCONCLUSIVE")
        self.assertEqual(finding.xti_status, "INCONCLUSIVE")
        self.assertNotEqual(finding.status, "CONFIRMED")

    def test_popup_from_previous_attempt_cannot_confirm_current_attempt(self):
        payload = "alert('TRACE-Q7')"
        stale_attempt_id = "0123456789abcdef0123456789abcdef"
        finding = evaluate(
            payload,
            f'<script>const note = "{payload}";</script>',
            browser=True,
            validator=lambda *_args: (
                True,
                "; ".join((
                    attempt_popup_evidence(stale_attempt_id, "alert", "TRACE-Q7"),
                    attempt_popup_source_evidence(stale_attempt_id, "alert", "script"),
                )),
            ),
        )

        self.assertFalse(finding.browser_confirmed)
        self.assertNotEqual(finding.xti_status, "CONFIRMED_XSS")

    def test_correlated_browser_popup_is_confirmed_for_current_attempt(self):
        payload = "alert('TRACE-Q7')"
        governor_ids = []

        def validator(*_args):
            governor_ids.append(BrowserRequestGovernor(10, 30).run_id)
            attempt_id = browser._ACTIVE_BROWSER_ATTEMPT_ID.get()
            return True, "; ".join((
                attempt_popup_evidence(attempt_id, "alert", "TRACE-Q7"),
                attempt_popup_source_evidence(attempt_id, "alert", "script"),
            ))

        finding = evaluate(
            payload, f"<script>{payload}</script>", browser=True,
            validator=validator,
        )
        self.assertTrue(finding.browser_confirmed)
        self.assertEqual(finding.xti_status, "CONFIRMED_XSS")
        self.assertTrue(finding.trace_intelligence["browser_run_id"])
        self.assertEqual(governor_ids, [finding.trace_intelligence["browser_run_id"]])
        browser_evidence = [item for item in finding.diagnostics.evidence if item.kind == "browser-confirmed"]
        self.assertEqual(len(browser_evidence), 1)
        self.assertEqual(browser_evidence[0].attempt_id, finding.attempt_id)

    def test_browser_confirmation_requires_payload_correlated_event(self):
        attempt_id = "0123456789abcdef0123456789abcdef"
        self.assertFalse(validate_browser_confirmation(
            "alert('expected')", True,
            "; ".join((
                attempt_popup_evidence(attempt_id, "alert", "unrelated"),
                attempt_popup_source_evidence(attempt_id, "alert"),
            )),
            attempt_id=attempt_id,
            reflections=[Reflection("event-attribute", "handler reflection", 90, snippet="alert('expected')")],
        ))
        self.assertTrue(validate_browser_confirmation(
            "alert('expected')", True,
            "; ".join((
                attempt_popup_evidence(attempt_id, "alert", "expected"),
                attempt_popup_source_evidence(attempt_id, "alert"),
            )),
            attempt_id=attempt_id,
            reflections=[Reflection("event-attribute", "handler reflection", 90, snippet="alert('expected')")],
        ))

    def test_popup_message_substring_is_not_attempt_correlation(self):
        attempt_id = "0123456789abcdef0123456789abcdef"
        self.assertFalse(validate_browser_confirmation(
            "alert('1')", True,
            "; ".join((
                attempt_popup_evidence(attempt_id, "alert", "11"),
                attempt_popup_source_evidence(attempt_id, "alert"),
            )),
            attempt_id=attempt_id,
            reflections=[Reflection("event-attribute", "handler reflection", 90, snippet="alert('1')")],
        ))

    def test_browser_timeout_is_inconclusive_not_a_negative_verification(self):
        payload = "alert('TRACE-Q7')"
        finding = evaluate(
            payload,
            f"<div>{payload}</div>",
            browser=True,
            validator=lambda *_args: (False, "Chromium CDP error: navigation timed out"),
        )

        self.assertEqual(finding.trace_intelligence["browser_verification_status"], "INCONCLUSIVE")
        self.assertEqual(finding.xti_status, "INCONCLUSIVE")
        self.assertFalse(finding.browser_confirmed)

    def test_browser_startup_failure_without_reflection_is_not_clean(self):
        payload = "alert('TRACE-Q7')"
        finding = evaluate(
            payload,
            "<p>fixture has no reflected input</p>",
            browser=True,
            browser_all=True,
            validator=lambda *_args: (False, "local Chromium/Chrome binary was not found"),
        )

        self.assertEqual(finding.trace_intelligence["browser_verification_status"], "INCONCLUSIVE")
        self.assertEqual(finding.xti_status, "INCONCLUSIVE")
        self.assertFalse(finding.browser_confirmed)

    def test_browser_verifier_exception_is_inconclusive(self):
        def fail_verifier(*_args):
            raise RuntimeError("fixture browser launch failure")

        finding = evaluate(
            "alert('TRACE-Q7')",
            "<p>fixture has no reflected input</p>",
            browser=True,
            browser_all=True,
            validator=fail_verifier,
        )

        self.assertEqual(finding.trace_intelligence["browser_verification_status"], "INCONCLUSIVE")
        self.assertEqual(finding.xti_status, "INCONCLUSIVE")
        self.assertEqual(finding.browser_evidence, "Browser verifier error: RuntimeError")

    def test_local_dom_signal_must_match_the_current_attempt(self):
        attempt_id = "0123456789abcdef0123456789abcdef"
        self.assertTrue(
            validate_browser_confirmation(
                "fixture-dom-signal",
                True,
                f"dom-signal:{attempt_id}",
                attempt_id=attempt_id,
                allow_dom_signal=True,
            )
        )
        self.assertFalse(
            validate_browser_confirmation(
                "fixture-dom-signal",
                True,
                "dom-signal:stale-attempt",
                attempt_id=attempt_id,
                allow_dom_signal=True,
            )
        )

    def test_fixture_dom_signal_is_never_accepted_for_non_loopback_targets(self):
        payload = "fixture-dom-signal"
        attempt_id = "0123456789abcdef0123456789abcdef"
        finding = evaluate(
            payload,
            f"<div>{payload}</div>",
            browser=True,
            browser_all=True,
            validator=lambda *_args: (True, f"dom-signal:{attempt_id}"),
        )

        self.assertFalse(finding.browser_confirmed)
        self.assertNotEqual(finding.xti_status, "CONFIRMED_XSS")


class ClassificationTests(unittest.TestCase):
    def test_status_vocabulary_and_network_classification(self):
        self.assertEqual(len(TRACE_STATUS), 8)
        self.assertEqual(classify_trace_status([], [], network_error=True), "BLOCKED_OR_UNREACHABLE")
        self.assertEqual(classify_trace_status([], [], inconclusive=True), "INCONCLUSIVE")
        self.assertEqual(classify_trace_status([], [], browser_confirmed=True, inconclusive=True), "CONFIRMED_XSS")
        self.assertEqual(classify_trace_status([], [], browser_confirmed=True, network_error=True), "CONFIRMED_XSS")
        self.assertEqual(classify_trace_status([], []), "NOT_REFLECTED")

    def test_legacy_status_remains_available_in_evidence_bundle(self):
        finding = evaluate(PAYLOAD, f"<p>{PAYLOAD}</p>")
        self.assertIn(finding.status, {"REFLECTED_LOW", "REFLECTED_RISK", "NOT_CONFIRMED"})
        self.assertEqual(finding.evidence_bundle["xti_status"], finding.xti_status)
        self.assertEqual(finding.evidence_bundle["attempt_id"], finding.attempt_id)


if __name__ == "__main__":
    unittest.main()
