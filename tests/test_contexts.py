import unittest

from xssentinel_core.scanner.contexts import analyze_response_context


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


if __name__ == "__main__":
    unittest.main()
