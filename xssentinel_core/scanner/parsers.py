"""Compatibility facade for scanner parser components."""

from .parserkit import (
    HtmlReflectionParser as DOMReflectionParser,
    HtmlStructureParser,
    ParserDiagnostics,
    input_name_candidates,
    is_submittable_input,
    parse_css_reflections,
    parse_html_reflections,
    parse_html_structure,
    parse_javascript_reflections,
    parse_json_reflections,
)


__all__ = [
    "DOMReflectionParser",
    "FormDiscoveryParser",
    "PageStructureParser",
    "ParserDiagnostics",
    "extract_page_structure",
    "input_name_candidates",
    "is_submittable_input",
    "parse_css_reflections",
    "parse_html_reflections",
    "parse_html_structure",
    "parse_javascript_reflections",
    "parse_json_reflections",
]


class FormDiscoveryParser(HtmlStructureParser):
    """Backward-compatible form/link discovery parser."""


class PageStructureParser(HtmlStructureParser):
    """Backward-compatible page structure parser."""


def extract_page_structure(body: str, base_url: str) -> PageStructureParser:
    parser = PageStructureParser(base_url)
    parser.diagnostics.source_length = len(body)
    try:
        parser.feed(body)
    except Exception as exc:  # noqa: BLE001 - exposed through diagnostics.
        parser.diagnostics.parse_error = str(exc)
    return parser
