"""Response context classification for reflected payload evidence."""

import html
import urllib.parse

from .models import Reflection, ResponseContext
from .parserkit import contains_needle, parse_css_reflections, parse_html_reflections, parse_javascript_reflections, parse_json_reflections
from .utils import one_line, unique_lines


def content_type_label(headers: dict[str, str]) -> str:
    for key, value in headers.items():
        if key.lower() == "content-type":
            return value.split(";", 1)[0].strip().lower()
    return ""


def reflection_needles_for_context(payload: str) -> set[str]:
    decoded = urllib.parse.unquote_plus(payload)
    return {item for item in (payload, decoded, html.escape(decoded, quote=True), html.escape(decoded, quote=False), html.unescape(decoded)) if item}


def context_snippets(body: str, needles: set[str], max_items: int = 4, radius: int = 120) -> list[str]:
    snippets: list[str] = []
    lowered = body.lower()
    for needle in unique_lines(needles):
        index = lowered.find(needle.lower())
        if index < 0:
            continue
        start = max(0, index - radius)
        end = min(len(body), index + len(needle) + radius)
        snippets.append(one_line(body[start:end], radius * 2 + 40))
        if len(snippets) >= max_items:
            break
    return snippets


def analyze_json_context(body: str, needles: set[str]) -> tuple[list[Reflection], str | None]:
    reflections, diagnostics = parse_json_reflections(body, needles)
    return reflections, diagnostics.parse_error


def analyze_css_context(body: str, needles: set[str]) -> list[Reflection]:
    reflections, _ = parse_css_reflections(body, needles)
    return reflections


def analyze_javascript_context(body: str, needles: set[str]) -> list[Reflection]:
    reflections, _ = parse_javascript_reflections(body, needles)
    return reflections


def analyze_html_context(body: str, needles: set[str]) -> list[Reflection]:
    parser = parse_html_reflections(body, needles)
    return parser.reflections


def analyze_response_context(body: str, payload: str, headers: dict[str, str] | None = None, url: str = "") -> ResponseContext:
    headers = headers or {}
    content_type = content_type_label(headers)
    needles = reflection_needles_for_context(payload)
    parser = "html"
    reflections: list[Reflection] = []
    parse_error: str | None = None
    is_structured = False
    diagnostics = None

    if not body:
        return ResponseContext(content_type, "empty", [], [])

    url_path = urllib.parse.urlsplit(url).path.lower()
    stripped = body.lstrip()
    if "json" in content_type or stripped.startswith(("{", "[")) or url_path.endswith(".json"):
        parser = "json"
        is_structured = True
        reflections, diagnostics = parse_json_reflections(body, needles)
        parse_error = diagnostics.parse_error
        if parse_error and contains_needle(body, needles):
            reflections.append(Reflection("json-raw", "payload reflected in non-parseable JSON-like response", 24, "raw-reflection", "body"))
    elif "javascript" in content_type or url_path.endswith((".js", ".mjs")):
        parser = "javascript"
        reflections, diagnostics = parse_javascript_reflections(body, needles)
    elif "css" in content_type or url_path.endswith(".css"):
        parser = "css"
        reflections, diagnostics = parse_css_reflections(body, needles)
    else:
        html_parser = parse_html_reflections(body, needles)
        reflections = html_parser.reflections
        diagnostics = html_parser.diagnostics

    raw = html.unescape(body)
    if contains_needle(raw, needles) and not reflections:
        reflections.append(Reflection("raw-response", "payload reflected in response body", 30, "raw-reflection", "body"))
    return ResponseContext(content_type, parser, reflections, context_snippets(body, needles), is_structured, parse_error, diagnostics)
