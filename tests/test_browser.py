import os
import urllib.parse
import unittest
from unittest import mock

from xssentinel_core.scanner import browser
from xssentinel_core.scanner.config import BrowserRuntimeConfig


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
    def test_post_form_data_url_escapes_action_and_fields(self) -> None:
        data_url = browser.post_form_data_url("https://example.test/post?next=<x>", "name=a%26b&empty=")
        self.assertTrue(data_url.startswith("data:text/html;charset=utf-8,"))
        document = urllib.parse.unquote(data_url.split(",", 1)[1])
        self.assertIn('name="name"', document)
        self.assertIn('value="a&amp;b"', document)
        self.assertIn("next=&lt;x&gt;", document)


if __name__ == "__main__":
    unittest.main()
