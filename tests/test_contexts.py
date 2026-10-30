import unittest

from xssentinel_core.scanner.contexts import analyze_response_context
from xssentinel_core.scanner.pipeline import classify_response


class ContextAnalysisTests(unittest.TestCase):
    def test_json_reflection_is_classified_as_structured(self) -> None:
        body = '{"user":{"name":"xss"},"meta":"safe"}'
        context = analyze_response_context(body, "xss", {"Content-Type": "application/json"}, "https://example.test/api/user")
        self.assertEqual(context.parser, "json")
        self.assertTrue(context.is_structured)
        self.assertTrue(any(item.context == "json-string" for item in context.reflections))

    def test_css_executable_construct_is_flagged(self) -> None:
        body = "body{background-image:url(javascript:xss)}"
        context = analyze_response_context(body, "xss", {"Content-Type": "text/css"}, "https://example.test/app.css")
        self.assertEqual(context.parser, "css")
        self.assertTrue(any(item.context == "css-executable" for item in context.reflections))

    def test_html_event_attribute_carries_snippet(self) -> None:
        body = '<input onfocus="xss">'
        context = analyze_response_context(body, "xss", {"Content-Type": "text/html"}, "https://example.test/")
        self.assertEqual(context.parser, "html")
        self.assertTrue(any(item.context == "event-attribute" for item in context.reflections))
        self.assertTrue(context.snippets)

    def test_partial_popup_call_is_not_a_payload_reflection(self) -> None:
        payload = "<img src=x onerror=alert(7)>"
        context = analyze_response_context(
            "alert(7)", payload, {"Content-Type": "text/html"}, "https://fixture.test/"
        )

        # v1.1.0 required the payload (or an encoded representation) itself
        # to appear; a matching popup substring alone was not a reflection.
        self.assertEqual(context.reflections, [])
        self.assertEqual(context.snippets, [])

    def test_plain_reflection_remains_reflected_not_confirmed(self) -> None:
        context = analyze_response_context(
            "<p>TRACE_MARKER_42</p>",
            "TRACE_MARKER_42",
            {"Content-Type": "text/html"},
            "https://fixture.test/",
        )

        status = classify_response(context.reflections, browser_confirmed=False)
        self.assertTrue(context.reflections)
        self.assertEqual(status, "REFLECTED_LOW")
        self.assertNotEqual(status, "CONFIRMED")


if __name__ == "__main__":
    unittest.main()
