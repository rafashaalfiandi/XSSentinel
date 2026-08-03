import unittest

from xssentinel_core.scanner.parserkit import (
    input_name_candidates,
    parse_css_reflections,
    parse_html_reflections,
    parse_html_structure,
    parse_javascript_reflections,
    parse_json_reflections,
)


class ParserKitTests(unittest.TestCase):
    def test_input_name_candidates_normalizes_framework_fields(self) -> None:
        attrs = {"ng-model": "profile.message", "placeholder": "Search term"}
        candidates = input_name_candidates(attrs)
        self.assertIn("message", candidates)
        self.assertIn("search_term", candidates)

    def test_html_structure_parser_collects_forms_links_scripts_and_csp(self) -> None:
        body = """
        <meta http-equiv="content-security-policy" content="default-src 'self'">
        <form method="post" action="/comment"><textarea name="message"></textarea></form>
        <a href="/search?q=test">search</a>
        <script>fetch('/api', {method:'POST'})</script><script src="/app.js"></script>
        """
        parser = parse_html_structure(body, "https://example.test/base")
        self.assertEqual(parser.forms[0].method, "POST")
        self.assertEqual(parser.forms[0].action, "https://example.test/comment")
        self.assertIn("https://example.test/search?q=test", parser.links)
        self.assertEqual(len(parser.inline_scripts), 1)
        self.assertEqual(parser.external_scripts[0], "https://example.test/app.js")
        self.assertTrue(parser.meta_csp)
        self.assertGreater(parser.diagnostics.source_length, 0)

    def test_html_reflection_parser_records_attribute_and_text_diagnostics(self) -> None:
        parser = parse_html_reflections('<div title="xss">xss</div>', {"xss"})
        contexts = {reflection.context for reflection in parser.reflections}
        self.assertIn("html-attribute", contexts)
        self.assertIn("html-text", contexts)
        self.assertEqual(parser.diagnostics.matched_items, 2)

    def test_json_parser_reports_paths_and_parse_errors(self) -> None:
        reflections, diagnostics = parse_json_reflections('{"user":{"bio":"xss"}}', {"xss"})
        self.assertIsNone(diagnostics.parse_error)
        self.assertEqual(reflections[0].location, "$.user.bio")
        _, bad = parse_json_reflections('{"broken":', {"xss"})
        self.assertIsNotNone(bad.parse_error)

    def test_css_and_javascript_parsers_return_typed_reflections(self) -> None:
        css, css_diag = parse_css_reflections("a{background:url(javascript:xss)}", {"xss"})
        js, js_diag = parse_javascript_reflections("const a = 'xss'; alert(a)", {"xss"})
        self.assertEqual(css[0].context, "css-executable")
        self.assertEqual(js[0].context, "javascript-response")
        self.assertEqual(css_diag.matched_items, 1)
        self.assertEqual(js_diag.matched_items, 1)


if __name__ == "__main__":
    unittest.main()
