import json
import os
import urllib.parse
import unittest
from unittest import mock

from xssentinel_core.scanner import browser
from xssentinel_core.scanner.config import BrowserRuntimeConfig
from xssentinel_core.scanner.settings import PAYLOAD_FILE
from xssentinel_core.scanner.utils import load_lines
from xssentinel_core.scanner.reflection import attempt_popup_source_evidence


class BrowserConfigurationTests(unittest.TestCase):
    def tearDown(self) -> None:
        for name in list(os.environ):
            if name.startswith("XSSENTINEL_BROWSER_"):
                os.environ.pop(name, None)

    def test_browser_runtime_config_uses_defaults(self) -> None:
        config = BrowserRuntimeConfig.from_env()
        self.assertEqual(config.launch_timeout_s, 3.0)
        self.assertEqual(config.launch_retries, 2)
        self.assertEqual(config.playwright_interaction_rounds, 3)

    def test_browser_runtime_config_clamps_env_values(self) -> None:
        os.environ["XSSENTINEL_BROWSER_LAUNCH_TIMEOUT"] = "0.1"
        os.environ["XSSENTINEL_BROWSER_LAUNCH_RETRIES"] = "99"
        os.environ["XSSENTINEL_BROWSER_PLAYWRIGHT_WAIT"] = "9000"

        config = BrowserRuntimeConfig.from_env()

        self.assertEqual(config.launch_timeout_s, 0.5)
        self.assertEqual(config.launch_retries, 10)
        self.assertEqual(config.playwright_interaction_wait_ms, 5000)


class BrowserFallbackTests(unittest.TestCase):
    def tearDown(self) -> None:
        browser.local_chromium_binary.cache_clear()
        browser.playwright_available.cache_clear()

    def test_confirm_with_browser_keeps_no_popup_result_without_playwright_fallback(self) -> None:
        with mock.patch.object(browser, "confirm_with_local_chromium", return_value=(False, browser.NO_POPUP_EVIDENCE)):
            with mock.patch.object(browser, "playwright_available") as playwright_available:
                confirmed, evidence = browser.confirm_with_browser("https://example.test", "ua", 1000, "alert(1)")

        self.assertFalse(confirmed)
        self.assertEqual(evidence, browser.NO_POPUP_EVIDENCE)
        playwright_available.assert_not_called()

    def test_confirm_with_browser_reports_playwright_unavailable_after_cdp_error(self) -> None:
        with mock.patch.object(browser, "confirm_with_local_chromium", return_value=(False, "Chromium CDP error: boom")):
            with mock.patch.object(browser, "playwright_available", return_value=False):
                confirmed, evidence = browser.confirm_with_browser("https://example.test", "ua", 1000, "alert(1)")

        self.assertFalse(confirmed)
        self.assertEqual(evidence, "Chromium CDP error: boom | Playwright is not available")


class BrowserUtilityTests(unittest.TestCase):
    def test_isolated_dialog_evidence_is_tagged_to_active_attempt(self) -> None:
        attempt_id = "0123456789abcdef0123456789abcdef"

        with browser.browser_run_context("browser-run-fixture", attempt_id):
            confirmed, evidence = browser._return_browser_evidence(
                'prompt(8)',
                ["dialog:prompt:8", attempt_popup_source_evidence(attempt_id, "prompt", "script")],
                "https://fixture.test/",
            )

        self.assertTrue(confirmed)
        self.assertIn(f"attempt-popup:{attempt_id}:prompt", evidence)

    def test_isolated_dialog_evidence_requires_exact_expected_message(self) -> None:
        attempt_id = "0123456789abcdef0123456789abcdef"

        with browser.browser_run_context("browser-run-fixture", attempt_id):
            confirmed, _evidence = browser._return_browser_evidence(
                'prompt(8)',
                ["dialog:prompt:18", attempt_popup_source_evidence(attempt_id, "prompt", "script")],
                "https://fixture.test/",
            )

        self.assertFalse(confirmed)

    def test_dialog_for_catalog_payload_seven_is_detected(self) -> None:
        payload_seven = load_lines(PAYLOAD_FILE)[6]
        attempt_id = "0123456789abcdef0123456789abcdef"

        with browser.browser_run_context("browser-run-fixture", attempt_id):
            confirmed, evidence = browser._return_browser_evidence(
                payload_seven,
                ["dialog:prompt:8", attempt_popup_source_evidence(attempt_id, "prompt", "script")],
                "https://fixture.test/",
            )

        self.assertTrue(confirmed)
        self.assertIn(f"attempt-popup:{attempt_id}:prompt", evidence)

    def test_dialog_during_navigation_is_kept_for_attempt_confirmation(self) -> None:
        attempt_id = "0123456789abcdef0123456789abcdef"
        dialog = {
            "method": "Page.javascriptDialogOpening",
            "params": {"type": "prompt", "message": "8"},
        }

        class FakeCDP:
            timeout = 1.0
            allowed_origin = None
            request_governor = None

            def __init__(self):
                self.dialog_events = []
                self.frames = [
                    json.dumps(dialog).encode(),
                    json.dumps({"id": 1, "result": {"frameId": "fixture"}}).encode(),
                ]
                self.commands = []

            def send(self, method, params=None):
                self.commands.append((method, params))
                return len(self.commands)

            def set_timeout(self, _seconds):
                pass

            def _recv_frame(self):
                return self.frames.pop(0) if self.frames else b""

        cdp = FakeCDP()
        navigation_id = cdp.send("Page.navigate", {"url": "https://fixture.test/"})
        navigation_events = browser.collect_cdp_events(cdp, wanted_id=navigation_id, seconds=0.1)
        self.assertTrue(any(event.get("id") == navigation_id for event in navigation_events))
        self.assertIn(("Page.handleJavaScriptDialog", {"accept": False}), cdp.commands)

        config = BrowserRuntimeConfig(followup_rounds=0, load_window_s=0.01, trigger_window_s=0.01)
        with mock.patch.object(browser, "collect_cdp_events", return_value=[]), \
                mock.patch.object(browser, "cdp_call_collect", return_value=[]), \
                browser.browser_run_context("browser-run-fixture", attempt_id):
            hits = browser._collect_cdp_hits(cdp, 0.01, config)
            confirmed, evidence = browser._return_browser_evidence(
                'prompt(8)',
                [*hits, attempt_popup_source_evidence(attempt_id, "prompt", "script")],
                "https://fixture.test/",
            )

        self.assertTrue(confirmed)
        self.assertIn(f"attempt-popup:{attempt_id}:prompt", evidence)

    def test_browser_request_governor_caps_one_validation_run(self) -> None:
        governor = browser.BrowserRequestGovernor(max_requests=2, requests_per_second=30)

        self.assertTrue(governor.acquire())
        self.assertTrue(governor.acquire())
        self.assertFalse(governor.acquire())
        self.assertEqual(governor.used, 2)

    def test_browser_request_limits_are_loaded_from_clamped_environment(self) -> None:
        with mock.patch.dict(os.environ, {
            "XSSENTINEL_BROWSER_MAX_HTTP_REQUESTS": "50000",
            "XSSENTINEL_BROWSER_HTTP_REQUESTS_PER_SECOND": "99",
        }):
            config = BrowserRuntimeConfig.from_env()

        self.assertEqual(config.max_http_requests, 1000)
        self.assertEqual(config.http_requests_per_second, 30.0)

    def test_cdp_fetch_interception_continues_scoped_and_fails_external_requests(self) -> None:
        class FakeCDP:
            timeout = 1.0

            def __init__(self):
                self.allowed_origin = ("https", "example.test", 443)
                self.request_governor = browser.BrowserRequestGovernor(1, 30)
                self.frames = [
                    {"method": "Fetch.requestPaused", "params": {"requestId": "same", "request": {"url": "https://example.test/app.js"}}},
                    {"method": "Fetch.requestPaused", "params": {"requestId": "same-over-budget", "request": {"url": "https://example.test/image.png"}}},
                    {"method": "Fetch.requestPaused", "params": {"requestId": "external", "request": {"url": "https://cdn.example.test/app.js"}}},
                    {"id": 999, "result": {}},
                ]
                self.commands = []

            def set_timeout(self, _seconds):
                pass

            def _recv_frame(self):
                return json.dumps(self.frames.pop(0)).encode("utf-8") if self.frames else b""

            def send(self, method, params=None):
                self.commands.append((method, params))
                return len(self.commands)

        cdp = FakeCDP()
        browser.REQUEST_GOVERNOR.configure(max_requests=20, requests_per_second=100)
        try:
            browser.collect_cdp_events(cdp, wanted_id=999, seconds=1.0)
            accounting = browser.REQUEST_GOVERNOR.snapshot()
            run_used = cdp.request_governor.used
        finally:
            browser.REQUEST_GOVERNOR.configure(max_requests=5000, requests_per_second=5)

        self.assertIn(("Fetch.continueRequest", {"requestId": "same"}), cdp.commands)
        self.assertIn(("Fetch.failRequest", {"requestId": "same-over-budget", "errorReason": "BlockedByClient"}), cdp.commands)
        self.assertIn(("Fetch.failRequest", {"requestId": "external", "errorReason": "BlockedByClient"}), cdp.commands)
        self.assertEqual(run_used, 1)
        self.assertEqual(accounting["total_used"], 1)
        self.assertEqual(accounting["browser_used"], 1)

    def test_post_form_data_url_escapes_action_and_fields(self) -> None:
        data_url = browser.post_form_data_url("https://example.test/post?next=<x>", "name=a%26b&empty=")
        self.assertTrue(data_url.startswith("data:text/html;charset=utf-8,"))
        document = urllib.parse.unquote(data_url.split(",", 1)[1])
        self.assertIn('name="name"', document)
        self.assertIn('value="a&amp;b"', document)
        self.assertIn("next=&lt;x&gt;", document)

    def test_browser_scope_allows_only_same_origin_resources(self) -> None:
        with mock.patch.object(browser, "is_url_in_scope", return_value=True):
            self.assertTrue(browser.browser_request_is_scoped("about:blank", "https://example.test/search"))
            self.assertTrue(browser.browser_request_is_scoped("https://example.test/app.js", "https://example.test/search"))
            self.assertFalse(browser.browser_request_is_scoped("https://cdn.example.test/app.js", "https://example.test/search"))

    def test_browser_validation_rejects_initial_target_outside_allowlist(self) -> None:
        with mock.patch.object(browser, "is_url_in_scope", return_value=False):
            confirmed, evidence = browser.confirm_with_browser(
                "https://outside.example.test/", "ua", 1000, "inert fixture string"
            )

        self.assertFalse(confirmed)
        self.assertIn("scope policy", evidence)

    def test_chromium_command_does_not_disable_sandbox_or_tls_checks_by_default(self) -> None:
        command = browser._chromium_command("chromium", "/tmp/xss-profile", True)

        self.assertNotIn("--no-sandbox", command)
        self.assertNotIn("--ignore-certificate-errors", command)


if __name__ == "__main__":
    unittest.main()
