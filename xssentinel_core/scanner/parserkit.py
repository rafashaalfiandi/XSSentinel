"""Reusable parser components for HTML, JSON, JavaScript, and CSS.

The scanner keeps this layer focused on data extraction. Higher-level modules
compose these parsers into discovery, context analysis, and reporting.
"""

import html
import json
import re
import urllib.parse
from dataclasses import dataclass
from html.parser import HTMLParser

from .models import FormCandidate, Reflection
from .settings import VOID_TAGS
from .utils import one_line, unique_lines


FIELD_WORD_PATTERN = re.compile(r"[a-z][a-z0-9_:-]{0,47}")
STYLE_EXEC_PATTERN = re.compile(r"expression\s*\(|url\s*\(\s*['\"]?\s*javascript\s*:", re.I)
JSON_XSS_PATTERN = re.compile(r"<\s*(script|svg|img|iframe)\b|on[a-z]+\s*=|javascript\s*:", re.I)
JAVASCRIPT_EXEC_PATTERN = re.compile(r"\b(alert|confirm|prompt|eval|Function|setTimeout|setInterval)\b|`|['\"]\s*\+", re.I)


@dataclass
class ParserDiagnostics:
    name: str
    source_length: int = 0
    parse_error: str | None = None
    structured: bool = False
    matched_items: int = 0


def attrs_dict(attrs: list[tuple[str, str | None]]) -> dict[str, str]:
    return {name.lower(): value or "" for name, value in attrs}


def contains_needle(value: str, needles: set[str]) -> bool:
    decoded = html.unescape(value)
    return any(needle in value or needle in decoded for needle in needles)


def normalize_field_candidate(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    return value.rsplit(".", 1)[-1].rsplit("[", 1)[-1].strip("] ")


def input_name_candidates(attrs: dict[str, str]) -> list[str]:
    candidates: list[str] = []
    for key in ("name", "id", "formcontrolname", "data-name", "data-field", "data-param", "ng-model", "v-model"):
        value = normalize_field_candidate(attrs.get(key, ""))
        if value:
            candidates.append(value)
    for key in ("placeholder", "aria-label", "title"):
        value = attrs.get(key, "").strip().lower()
        if not value:
            continue
        words = FIELD_WORD_PATTERN.findall(value)
        if words:
            candidates.append("_".join(words[:3]))
            candidates.extend(words[:3])
    return unique_lines(item for item in candidates if item)


def is_submittable_input(attrs: dict[str, str]) -> bool:
    return attrs.get("type", "").lower() not in {"submit", "button", "reset", "image", "file"}


class HtmlReflectionParser(HTMLParser):
    def __init__(self, needles: set[str]):
        super().__init__(convert_charrefs=False)
        self.needles = {needle for needle in needles if needle}
        self.reflections: list[Reflection] = []
        self.diagnostics = ParserDiagnostics("html-reflection")
        self._tag_stack: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag not in VOID_TAGS:
            self._tag_stack.append(tag)
        for name, value in attrs:
            self._record_attribute(tag, name.lower(), value or "")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        for index in range(len(self._tag_stack) - 1, -1, -1):
            if self._tag_stack[index] == tag:
                del self._tag_stack[index:]
                break

    def handle_data(self, data: str) -> None:
        if not contains_needle(data, self.needles):
            return
        self.diagnostics.matched_items += 1
        context = self._tag_stack[-1] if self._tag_stack else "text"
        if context == "script":
            self._append("script-block", "payload reflected inside <script>", 85, "script", data)
        elif context == "style":
            severity = 64 if STYLE_EXEC_PATTERN.search(data) else 45
            self._append("style-block", "payload reflected inside <style>", severity, "style", data)
        else:
            self._append("html-text", f"payload reflected inside <{context}>", 35, context, data)

    def handle_comment(self, data: str) -> None:
        if contains_needle(data, self.needles):
            self.diagnostics.matched_items += 1
            self._append("html-comment", "payload reflected inside HTML comment", 20, "comment", data)

    def _record_attribute(self, tag: str, attr: str, value: str) -> None:
        if not contains_needle(value, self.needles):
            return
        self.diagnostics.matched_items += 1
        if attr.startswith("on"):
            self._append("event-attribute", f"{tag}[{attr}]", 90, f"{tag}[{attr}]", value)
        elif tag in {"script", "iframe", "object", "embed"} or attr in {"src", "href", "data", "srcdoc"}:
            self._append("active-attribute", f"{tag}[{attr}]", 75, f"{tag}[{attr}]", value)
        elif attr == "style":
            severity = 62 if STYLE_EXEC_PATTERN.search(value) else 48
            self._append("style-attribute", f"{tag}[{attr}]", severity, f"{tag}[{attr}]", value)
        else:
            self._append("html-attribute", f"{tag}[{attr}]", 55, f"{tag}[{attr}]", value)

    def _append(self, context: str, detail: str, severity: int, location: str, value: str) -> None:
        self.reflections.append(Reflection(context, detail, severity, "html-reflection", location, one_line(value, 180)))


class HtmlStructureParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.forms: list[FormCandidate] = []
        self.links: list[str] = []
        self.standalone_fields: list[str] = []
        self.meta_text: list[str] = []
        self.meta_csp: list[str] = []
        self.inline_scripts: list[str] = []
        self.external_scripts: list[str] = []
        self.diagnostics = ParserDiagnostics("html-structure")
        self._current_form: FormCandidate | None = None
        self._inside_script = False
        self._script_chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attrs_map = attrs_dict(attrs)
        if tag == "form":
            method = (attrs_map.get("method") or "GET").upper()
            if method not in {"GET", "POST"}:
                method = "GET"
            action = urllib.parse.urljoin(self.base_url, attrs_map.get("action") or self.base_url)
            self._current_form = FormCandidate(method, action, [])
            self.diagnostics.matched_items += 1
            return
        if tag == "a":
            href = attrs_map.get("href", "").strip()
            if href:
                self.links.append(urllib.parse.urljoin(self.base_url, href))
        if tag == "meta":
            content = attrs_map.get("content", "").strip()
            if content:
                self.meta_text.append(content)
            if attrs_map.get("http-equiv", "").lower() == "content-security-policy" and content:
                self.meta_csp.append(content)
        if tag == "script":
            src = attrs_map.get("src", "").strip()
            if src:
                self.external_scripts.append(urllib.parse.urljoin(self.base_url, src))
            else:
                self._inside_script = True
                self._script_chunks = []
        if tag in {"input", "textarea", "select"} and is_submittable_input(attrs_map):
            candidates = input_name_candidates(attrs_map)
            self.meta_text.extend(candidates)
            if self._current_form:
                self._current_form.fields.extend(candidates)
            else:
                self.standalone_fields.extend(candidates)
        if self._current_form and tag == "button":
            name = attrs_map.get("name", "").strip()
            if name:
                self._current_form.fields.append(name)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "form" and self._current_form:
            self._current_form.fields = unique_lines(self._current_form.fields)
            if self._current_form.fields:
                self.forms.append(self._current_form)
            self._current_form = None
        if tag == "script" and self._inside_script:
            self.inline_scripts.append("".join(self._script_chunks))
            self._inside_script = False
            self._script_chunks = []

    def handle_data(self, data: str) -> None:
        if self._inside_script:
            self._script_chunks.append(data)


def feed_html(parser: HTMLParser, body: str, diagnostics: ParserDiagnostics) -> None:
    diagnostics.source_length = len(body)
    try:
        parser.feed(body)
    except Exception as exc:  # noqa: BLE001 - surfaced through diagnostics.
        diagnostics.parse_error = str(exc)


def parse_html_reflections(body: str, needles: set[str]) -> HtmlReflectionParser:
    parser = HtmlReflectionParser(needles)
    feed_html(parser, body, parser.diagnostics)
    return parser


def parse_html_structure(body: str, base_url: str) -> HtmlStructureParser:
    parser = HtmlStructureParser(base_url)
    feed_html(parser, body, parser.diagnostics)
    return parser


def parse_json_reflections(body: str, needles: set[str]) -> tuple[list[Reflection], ParserDiagnostics]:
    diagnostics = ParserDiagnostics("json", len(body), structured=True)
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as exc:
        diagnostics.parse_error = f"invalid json: {exc.msg}"
        return [], diagnostics
    reflections = _walk_json_reflections(parsed, needles)
    diagnostics.matched_items = len(reflections)
    return reflections, diagnostics


def _walk_json_reflections(value: object, needles: set[str], path: str = "$") -> list[Reflection]:
    if isinstance(value, dict):
        return _walk_json_object(value, needles, path)
    if isinstance(value, list):
        return _walk_json_list(value, needles, path)
    if isinstance(value, str):
        return _walk_json_string(value, needles, path)
    return []


def _walk_json_object(value: dict, needles: set[str], path: str) -> list[Reflection]:
    reflections: list[Reflection] = []
    for key, item in value.items():
        child = f"{path}.{key}" if path != "$" else f"$.{key}"
        if contains_needle(str(key), needles):
            reflections.append(Reflection("json-key", f"payload reflected in JSON key {child}", 28, "structured-reflection", child))
        reflections.extend(_walk_json_reflections(item, needles, child))
    return reflections


def _walk_json_list(value: list, needles: set[str], path: str) -> list[Reflection]:
    reflections: list[Reflection] = []
    for index, item in enumerate(value):
        reflections.extend(_walk_json_reflections(item, needles, f"{path}[{index}]"))
    return reflections


def _walk_json_string(value: str, needles: set[str], path: str) -> list[Reflection]:
    if not contains_needle(value, needles):
        return []
    severity = 42 if JSON_XSS_PATTERN.search(value) else 26
    return [Reflection("json-string", f"payload reflected in JSON string {path}", severity, "structured-reflection", path, one_line(value, 180))]


def parse_css_reflections(body: str, needles: set[str]) -> tuple[list[Reflection], ParserDiagnostics]:
    diagnostics = ParserDiagnostics("css", len(body), structured=True)
    reflections: list[Reflection] = []
    for needle in unique_lines(item for item in needles if item):
        for match in re.finditer(re.escape(needle), body, re.I):
            start = max(0, match.start() - 100)
            end = min(len(body), match.end() + 100)
            snippet = one_line(body[start:end], 200)
            if STYLE_EXEC_PATTERN.search(snippet):
                reflections.append(Reflection("css-executable", "payload reflected in executable CSS construct", 64, "css-reflection", "stylesheet", snippet))
            else:
                reflections.append(Reflection("css-token", "payload reflected in stylesheet", 36, "css-reflection", "stylesheet", snippet))
    diagnostics.matched_items = len(reflections)
    return reflections, diagnostics


def parse_javascript_reflections(body: str, needles: set[str]) -> tuple[list[Reflection], ParserDiagnostics]:
    diagnostics = ParserDiagnostics("javascript", len(body), structured=True)
    reflections: list[Reflection] = []
    for needle in unique_lines(item for item in needles if item):
        for match in re.finditer(re.escape(needle), body, re.I):
            start = max(0, match.start() - 120)
            end = min(len(body), match.end() + 120)
            snippet = one_line(body[start:end], 240)
            severity = 72 if JAVASCRIPT_EXEC_PATTERN.search(snippet) else 48
            reflections.append(Reflection("javascript-response", "payload reflected in JavaScript response", severity, "js-reflection", "script", snippet))
    diagnostics.matched_items = len(reflections)
    return reflections, diagnostics
