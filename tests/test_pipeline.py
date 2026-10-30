import argparse
import unittest

from xssentinel_core.scanner.models import Reflection
from xssentinel_core.scanner.pipeline import browser_validation_budget, classify_response, response_evidence_items, should_verify_with_browser


class PipelineTests(unittest.TestCase):
    def test_classify_response_prioritizes_browser_confirmation(self) -> None:
        status = classify_response([Reflection("html-text", "reflected", 20)], True)
        self.assertEqual(status, "CONFIRMED")

    def test_classify_response_uses_api_evidence_when_present(self) -> None:
        status = classify_response([], False, api_evidence="api reflects payload")
        self.assertEqual(status, "API_REFLECTED")

    def test_browser_budget_expands_for_reflections(self) -> None:
        args = argparse.Namespace(browser=True, browser_all=False, browser_confirm_limit=4)
        self.assertGreater(browser_validation_budget("alert(1)", [Reflection("html-text", "reflected", 20)], args), 1000)

    def test_browser_verification_skips_inert_payloads(self) -> None:
        args = argparse.Namespace(browser=True, browser_all=False, browser_confirm_limit=4)
        self.assertFalse(should_verify_with_browser("plain text", [], args))

    def test_popup_probe_is_verified_even_without_http_reflection_for_dom_xss(self) -> None:
        args = argparse.Namespace(browser=True, browser_all=False, browser_confirm_limit=4)
        self.assertTrue(should_verify_with_browser("<svg onload=prompt(8)>", [], args))

    def test_non_reflected_popup_probe_browser_checks_remain_bounded(self) -> None:
        args = argparse.Namespace(browser=True, browser_all=False, browser_confirm_limit=4)
        self.assertEqual(browser_validation_budget("<svg onload=prompt(8)>", [], args), 4)

    def test_response_evidence_items_include_snippets(self) -> None:
        items = response_evidence_items([Reflection("html-text", "reflected", 20)], False, "", "api", "", ["snippet"])
        self.assertTrue(any(item.kind == "snippet" for item in items))


if __name__ == "__main__":
    unittest.main()
