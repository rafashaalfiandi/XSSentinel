"""HTML parsers used by scanner discovery and reflection analysis."""

from .settings import *
from .models import *

def input_name_candidates(attrs: dict[str, str]) -> list[str]:
    candidates: list[str] = []
    for key in ("name", "id", "formcontrolname", "data-name", "data-field", "data-param", "ng-model", "v-model"):
        value = attrs.get(key, "").strip()
        if not value:
            continue
        value = value.rsplit(".", 1)[-1].rsplit("[", 1)[-1].strip("] ")
        candidates.append(value)
    for key in ("placeholder", "aria-label", "title"):
        value = attrs.get(key, "").strip().lower()
        if not value:
            continue
        words = re.findall(r"[a-z][a-z0-9_:-]{0,47}", value)
        if words:
            candidates.append("_".join(words[:3]))
            candidates.extend(words[:3])
    return list(dict.fromkeys(item for item in candidates if item))

def is_submittable_input(attrs: dict[str, str]) -> bool:
    input_type = attrs.get("type", "").lower()
    return input_type not in {"submit", "button", "reset", "image", "file"}

class DOMReflectionParser(HTMLParser):
    def __init__(self, needles: set[str]):
        super().__init__(convert_charrefs=False)
        self.needles = {n for n in needles if n}
        self.reflections: list[Reflection] = []
        self._tag_stack: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag not in VOID_TAGS:
            self._tag_stack.append(tag)
        for name, value in attrs:
            value = value or ""
            if self._contains(value):
                attr = name.lower()
                if attr.startswith("on"):
                    self.reflections.append(Reflection("event-attribute", f"{tag}[{name}]", 90))
                elif tag.lower() in {"script", "iframe", "object", "embed"} or attr in {"src", "href", "data", "srcdoc"}:
                    self.reflections.append(Reflection("active-attribute", f"{tag}[{name}]", 75))
                else:
                    self.reflections.append(Reflection("html-attribute", f"{tag}[{name}]", 55))

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in self._tag_stack:
            self._tag_stack.pop()

    def handle_data(self, data: str) -> None:
        if not self._contains(data):
            return
        context = self._tag_stack[-1] if self._tag_stack else "text"
        if context == "script":
            self.reflections.append(Reflection("script-block", "payload reflected inside <script>", 85))
        elif context == "style":
            self.reflections.append(Reflection("style-block", "payload reflected inside <style>", 45))
        else:
            self.reflections.append(Reflection("html-text", f"payload reflected inside <{context}>", 35))

    def handle_comment(self, data: str) -> None:
        if self._contains(data):
            self.reflections.append(Reflection("html-comment", "payload reflected inside HTML comment", 20))

    def _contains(self, value: str) -> bool:
        decoded = html.unescape(value)
        return any(n in value or n in decoded for n in self.needles)

class FormDiscoveryParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.forms: list[FormCandidate] = []
        self.links: list[str] = []
        self.standalone_fields: list[str] = []
        self.meta_text: list[str] = []
        self._current: FormCandidate | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {name.lower(): value or "" for name, value in attrs}
        tag = tag.lower()
        if tag == "form":
            method = (attrs_dict.get("method") or "GET").upper()
            if method not in {"GET", "POST"}:
                method = "GET"
            action = urllib.parse.urljoin(self.base_url, attrs_dict.get("action") or self.base_url)
            self._current = FormCandidate(method, action, [])
            return
        if tag == "a":
            href = attrs_dict.get("href", "").strip()
            if href:
                self.links.append(urllib.parse.urljoin(self.base_url, href))
        if tag == "meta":
            content = attrs_dict.get("content", "").strip()
            if content:
                self.meta_text.append(content)
        if tag in {"input", "textarea", "select"} and is_submittable_input(attrs_dict):
            candidates = input_name_candidates(attrs_dict)
            self.meta_text.extend(candidates)
            if self._current:
                self._current.fields.extend(candidates)
            else:
                self.standalone_fields.extend(candidates)
        if self._current and tag == "button":
            name = attrs_dict.get("name", "").strip()
            if name:
                self._current.fields.append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._current:
            self._current.fields = list(dict.fromkeys(self._current.fields))
            if self._current.fields:
                self.forms.append(self._current)
            self._current = None

class PageStructureParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=False)
        self.base_url = base_url
        self.meta_csp: list[str] = []
        self.inline_scripts: list[str] = []
        self.external_scripts: list[str] = []
        self._inside_script = False
        self._script_chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {name.lower(): value or "" for name, value in attrs}
        tag = tag.lower()
        if tag == "meta" and attrs_dict.get("http-equiv", "").lower() == "content-security-policy":
            content = attrs_dict.get("content", "").strip()
            if content:
                self.meta_csp.append(content)
        if tag == "script":
            src = attrs_dict.get("src", "").strip()
            if src:
                self.external_scripts.append(urllib.parse.urljoin(self.base_url, src))
            else:
                self._inside_script = True
                self._script_chunks = []

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._inside_script:
            self.inline_scripts.append("".join(self._script_chunks))
            self._inside_script = False
            self._script_chunks = []

    def handle_data(self, data: str) -> None:
        if self._inside_script:
            self._script_chunks.append(data)

def extract_page_structure(body: str, base_url: str) -> PageStructureParser:
    parser = PageStructureParser(base_url)
    try:
        parser.feed(body)
    except Exception:
        pass
    return parser
