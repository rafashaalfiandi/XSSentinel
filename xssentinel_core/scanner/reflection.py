"""Reflection and popup evidence analysis."""

from .settings import *
from .models import *
from .parsers import *
from .contexts import analyze_response_context
from .utils import *
import base64

def reflection_needles(payload: str) -> set[str]:
    decoded = urllib.parse.unquote_plus(payload)
    return {payload, decoded, html.escape(decoded, quote=True), html.escape(decoded, quote=False)}

def popup_source_variants(payload: str) -> list[str]:
    variants = [payload]
    for _ in range(3):
        current = variants[-1]
        decoded = html.unescape(urllib.parse.unquote_plus(current))
        if decoded == current:
            break
        variants.append(decoded)
    expanded = []
    for value in variants:
        expanded.append(normalize_popup_source(value))
        expanded.extend(extract_data_uri_sources(value))
    return list(dict.fromkeys(item for item in expanded if item))

def extract_data_uri_sources(value: str) -> list[str]:
    sources = []
    for match in re.finditer(r"data:text/html(?:;charset=[^,;]+)?(?P<base64>;base64)?,(?P<data>[^\s'\"<>]+)", value, re.I):
        data = match.group("data")
        try:
            if match.group("base64"):
                decoded = base64.b64decode(data, validate=False).decode("utf-8", errors="replace")
            else:
                decoded = urllib.parse.unquote_plus(data)
        except Exception:
            continue
        sources.append(normalize_popup_source(html.unescape(decoded)))
    return sources

def expected_popup_tokens(payload: str) -> list[str]:
    sources = popup_source_variants(payload)
    tokens: list[str] = []
    # Comprehensive call patterns for alert/confirm/prompt
    call_patterns = [
        # Standard calls: alert(1), alert('x'), alert`x`
        re.compile(r"\b(alert|confirm|prompt)\s*\(\s*([^)]{0,120})\)", re.I),
        # Double-wrapped: (alert)(1)
        re.compile(r"\(\s*(alert|confirm|prompt)\s*\)\s*\(\s*([^)]{0,120})\)", re.I),
        # Array notation: window["alert"]("x") or ["alert"][0]("x")
        re.compile(r"\[['\"]?\s*(alert|confirm|prompt)\s*['\"]?\]\s*\(\s*([^)]{0,120})\)", re.I),
        # Optional chaining: alert?.()
        re.compile(r"(alert|confirm|prompt)\s*\?\.\s*\(\s*([^)]{0,120})\)", re.I),
        # Call/apply: alert.call(null, "x") or alert.apply(null, ["x"])
        re.compile(r"(alert|confirm|prompt)\s*\.\s*(?:call|apply)\s*\(\s*[^,)]*,\s*([^)]{0,120})\)", re.I),
        # Reflect.apply: Reflect.apply(alert, null, ["x"])
        re.compile(r"Reflect\.apply\s*\(\s*(alert|confirm|prompt)\s*,\s*[^,)]*,\s*\[\s*([^\]]{0,120})\]", re.I),
        # setTimeout/setInterval: setTimeout("alert(1)", 0) - string eval pattern
        re.compile(r"\b(?:setTimeout|setInterval)\s*\(\s*(['\"])([^'\"]{0,120})\1\s*,\s*[^\)]*\)", re.I),
        # setTimeout with direct function
        re.compile(r"\b(?:setTimeout|setInterval)\s*\(\s*(alert|confirm|prompt)\s*,\s*[^,)]*,\s*([^)]{0,120})\)", re.I),
        # Template literals: alert`x`
        re.compile(r"\b(alert|confirm|prompt)\s*`([^`]{0,120})`", re.I),
        # Variable assignment: a=alert; a(1)
        re.compile(r"\b(\w+)\s*=\s*(alert|confirm|prompt)\b", re.I),
        # constructor pattern: constructor.constructor("alert(1)")
        re.compile(r"constructor\.constructor\s*\(\s*(['\"])([^'\")]{0,120})\1\s*\)", re.I),
        # Function constructor: new Function("alert(1)")()
        re.compile(r"\bnew\s+Function\s*\(\s*(['\"])([^'\")]{0,120})\1\s*\)\s*\(", re.I),
        # Encoded patterns: &#97;lert(1) or alert(1)
        re.compile(r"&#(?:x)?([0-9a-fA-F]+)[^;]*?\s*\(\s*([^)]{0,60})\)", re.I),
        # Window object: window['alert']("x")
        re.compile(r"window\s*\[(['\"])(alert|confirm|prompt)\1\]\s*\(\s*([^)]{0,120})\)", re.I),
        # Self-executing: (function(){alert(1)})()
        re.compile(r"\bfunction[^{]*?\{[^}]*?\b(alert|confirm|prompt)\s*\(\s*([^)]{0,120})\)[^}]*?\}[^;]*?\(", re.I),
    ]
    for source in sources:
        for pattern in call_patterns:
            for match in pattern.finditer(source):
                # Handle different group structures
                if pattern.groups >= 2:
                    func_name = match.group(1) if re.match(r"^(alert|confirm|prompt)$", match.group(1) or "", re.I) else match.group(1)
                    arg = match.group(2) if pattern.groups >= 2 else ""
                    if func_name and re.match(r"^(alert|confirm|prompt)$", func_name, re.I):
                        tokens.extend(popup_tokens_from_arg(func_name, arg))
                    elif pattern.groups == 2 and arg:
                        # String eval pattern: setTimeout("alert(1)", 0) - extract inner calls
                        tokens.extend(extract_inner_popup_calls(arg))
        # Handle nested constructor patterns
        for nested in re.finditer(r"(?:Function|constructor\.constructor)\s*(?:`|\()\s*(['\"]?)([^`'\")]{0,160})\1", source, re.I):
            nested_source = normalize_popup_source(nested.group(2))
            for pattern in call_patterns[:8]:  # Use standard patterns for nested
                for match in pattern.finditer(nested_source):
                    if re.match(r"^(alert|confirm|prompt)$", match.group(1) or "", re.I):
                        tokens.extend(popup_tokens_from_arg(match.group(1), match.group(2)))
        # Check for prompt without argument
        if re.search(r"\b(?:a\s*=\s*)?prompt\b", source, re.I) and not tokens:
            tokens.append("prompt:")
    return list(dict.fromkeys(token for token in tokens if token is not None))


def popup_source_fragments(payload: str) -> list[str]:
    """Return popup call expressions that browser instrumentation can match to a call site."""
    pattern = re.compile(
        r"\b(alert|confirm|prompt)\b\s*(?:\?\.)?\s*(?:\([^;\r\n]{0,180}\)|`[^`\r\n]{0,180}`)",
        re.I,
    )
    fragments = []
    for source in popup_source_variants(payload):
        fragments.extend(match.group(0) for match in pattern.finditer(source))
    return list(dict.fromkeys(fragment for fragment in fragments if fragment))


def expected_popup_calls_for_function(payload: str, function_name: str) -> list[tuple[str, str]]:
    """Return directly written calls paired with their literal popup messages."""
    calls: list[tuple[str, str]] = []
    pattern = re.compile(rf"\b{re.escape(function_name)}\s*\(\s*([^)]{{0,120}})\)", re.I)
    for source in popup_source_variants(payload):
        for match in pattern.finditer(source):
            argument = match.group(1).strip()
            if re.fullmatch(r"[-+]?\d+(?:\.\d+)?", argument):
                calls.append((match.group(0), argument))
                continue
            quoted = re.fullmatch(r"(['\"])([^'\"]*)\1", argument)
            if quoted:
                calls.append((match.group(0), quoted.group(2)))
    return list(dict.fromkeys(calls))


def extract_inner_popup_calls(code: str) -> list[str]:
    """Extract alert/confirm/prompt calls from code inside setTimeout strings."""
    tokens = []
    inner_patterns = [
        re.compile(r"\b(alert|confirm|prompt)\s*\(\s*([^)]{0,60})\)", re.I),
        re.compile(r"\b(alert|confirm|prompt)\s*`([^`]{0,60})`", re.I),
    ]
    for pattern in inner_patterns:
        for match in pattern.finditer(code):
            if re.match(r"^(alert|confirm|prompt)$", match.group(1) or "", re.I):
                tokens.extend(popup_tokens_from_arg(match.group(1), match.group(2)))
    return tokens

def payload_expects_popup(payload: str) -> bool:
    return bool(expected_popup_tokens(payload) or payload_popup_functions(payload))

def popup_tokens_from_arg(function_name: str, arg: str) -> list[str]:
    arg = arg.strip()
    if not arg:
        return [function_name.lower() + ":"]
    quoted = re.match(r"^(['\"])(.*?)\1", arg)
    if quoted:
        return [quoted.group(2)]
    number = re.match(r"^[-+]?\d+(?:\.\d+)?", arg)
    if number:
        return [number.group(0)]
    return []

def normalize_popup_source(value: str) -> str:
    def replace_unicode(match: re.Match[str]) -> str:
        try:
            return chr(int(match.group(1).strip("{}"), 16))
        except ValueError:
            return match.group(0)

    def replace_hex(match: re.Match[str]) -> str:
        try:
            return chr(int(match.group(1), 16))
        except ValueError:
            return match.group(0)

    value = re.sub(r"\\u\{([0-9a-fA-F]{1,8})\}", replace_unicode, value)
    value = re.sub(r"\\u([0-9a-fA-F]{4})", replace_unicode, value)
    value = re.sub(r"\\x([0-9a-fA-F]{2})", replace_hex, value)
    return value

def payload_popup_functions(payload: str) -> set[str]:
    decoded_sources = "\n".join(popup_source_variants(payload)).lower()
    return {name for name in ("alert", "confirm", "prompt") if re.search(rf"\b{name}\b", decoded_sources)}

def payload_match_variants(payload: str) -> list[str]:
    variants = [payload]
    variants.extend(popup_source_variants(payload))
    decoded = html.unescape(urllib.parse.unquote_plus(payload))
    if decoded:
        variants.append(decoded)
    return list(dict.fromkeys(item for item in variants if item))

def response_header_value(headers: dict[str, str], name: str) -> str:
    wanted = name.lower()
    for key, value in headers.items():
        if key.lower() == wanted:
            return value
    return ""

def response_content_type(headers: dict[str, str]) -> str:
    return response_header_value(headers, "Content-Type").split(";", 1)[0].strip().lower()

def is_api_like_response(headers: dict[str, str], url: str) -> bool:
    content_type = response_content_type(headers)
    parsed = urllib.parse.urlsplit(url)
    url_hint = " ".join([parsed.path, parsed.query]).lower()
    if any(token in content_type for token in ("json", "xml", "graphql")):
        return True
    return any(token in url_hint for token in ("/api/", "/graphql", "json", "ajax", "rest", "rpc"))

def payload_has_active_xss(payload: str) -> bool:
    for variant in payload_match_variants(payload):
        if any(pattern.search(variant) for pattern, _, _ in ACTIVE_XSS_PATTERNS):
            return True
    return False

def response_contains_payload(body: str, payload: str) -> bool:
    raw = html.unescape(body)
    needles = set(reflection_needles(payload))
    needles.update(payload_match_variants(payload))
    return any(needle and (needle in body or needle in raw) for needle in needles)

def is_download_or_api_delivery(headers: dict[str, str], url: str) -> bool:
    disposition = response_header_value(headers, "Content-Disposition").lower()
    parsed = urllib.parse.urlsplit(url)
    url_hint = " ".join([parsed.path, parsed.query]).lower()
    if "attachment" in disposition or "filename=" in disposition:
        return True
    return any(token in url_hint for token in ("/api/", "download", "export", "file", "proxy", "web-proxy"))

def api_reflection_evidence(payload: str, body: str, headers: dict[str, str], url: str) -> str:
    if not body or not is_api_like_response(headers, url) or not response_contains_payload(body, payload):
        return ""
    content_type = response_content_type(headers) or "api response"
    return f"{content_type} reflects payload; requires frontend/browser sink confirmation"

def delivered_payload_evidence(payload: str, body: str, headers: dict[str, str], url: str) -> str:
    if not body or not payload_has_active_xss(payload) or not response_contains_payload(body, payload):
        return ""
    disposition = response_header_value(headers, "Content-Disposition")
    content_type = response_header_value(headers, "Content-Type")
    if disposition and ("attachment" in disposition.lower() or "filename=" in disposition.lower()):
        return "downloaded file contains active XSS payload"
    if is_download_or_api_delivery(headers, url):
        label = content_type.split(";", 1)[0] if content_type else "api/download response"
        if any(token in label for token in ("html", "xhtml", "javascript", "svg")):
            return f"{label} contains active XSS payload"
    return ""

def popup_evidence_is_valid(payload: str, evidence_items: list[str]) -> bool:
    popup_hits = [item for item in evidence_items if re.match(r"^(alert|confirm|prompt|dialog):", item)]
    if not popup_hits:
        return False
    functions = payload_popup_functions(payload)
    if not functions:
        return False
    # Extract typed hits (function name, message) from evidence
    typed_hits: list[tuple[str, str]] = []
    for hit in popup_hits:
        parts = hit.split(":", 2)
        if len(parts) >= 2 and parts[0] in {"alert", "confirm", "prompt"}:
            # Format: "alert:" or "alert:message"
            message = parts[1] if len(parts) >= 2 else ""
            typed_hits.append((parts[0], message))
        elif len(parts) >= 3 and parts[0] == "dialog":
            # Format: "dialog:alert:message"
            typed_hits.append((parts[1], parts[2]))
    # Filter to only functions that exist in payload
    typed_hits = [(kind, message) for kind, message in typed_hits if kind in functions]
    if not typed_hits:
        return False
    tokens = expected_popup_tokens(payload)
    for kind, message in typed_hits:
        if not message:
            if any(token == f"{kind}:" for token in tokens):
                return True
            continue
        if tokens:
            for token in tokens:
                if token == f"{kind}:":
                    return True
                if message.strip() == token.strip():
                    return True
    return False

def normalize_browser_hits(hits: Iterable[str]) -> list[str]:
    clean = []
    for hit in hits:
        hit = str(hit).strip()
        if re.match(r"^(alert|confirm|prompt|dialog):", hit):
            clean.append(hit)
    return list(dict.fromkeys(clean))

def normalize_browser_evidence(hits: Iterable[str]) -> list[str]:
    """Normalize popup and dedicated local-fixture execution signals."""
    values = [str(hit).strip() for hit in hits]
    clean = normalize_browser_hits(values)
    clean.extend(
        hit for hit in values
        if re.match(r"^dom-signal:[0-9a-f]{32}$", hit)
        or re.match(r"^attempt-popup:[0-9a-f]{32}:(?:alert|confirm|prompt):[A-Za-z0-9_-]*$", hit)
        or re.match(r"^attempt-popup-source:[0-9a-f]{32}:(?:alert|confirm|prompt):(event|script)$", hit)
    )
    return list(dict.fromkeys(clean))

def attempt_popup_evidence(attempt_id: str, kind: str, message: str) -> str:
    """Encode one popup event with its attempt identity and exact message."""
    encoded = base64.urlsafe_b64encode(message.encode("utf-8")).decode("ascii").rstrip("=")
    return f"attempt-popup:{attempt_id}:{kind}:{encoded}"


def attempt_popup_source_evidence(attempt_id: str, kind: str, context: str = "event") -> str:
    """Identify a popup call whose runtime caller matched an event handler or current script."""
    if context not in {"event", "script"}:
        raise ValueError("popup source context must be 'event' or 'script'")
    return f"attempt-popup-source:{attempt_id}:{kind}:{context}"

def attempt_popup_evidence_is_valid(payload: str, evidence_items: Iterable[str], attempt_id: str | None) -> bool:
    """Accept attempt-tagged popups with exact literal tokens or source proof."""
    if not attempt_id:
        return False
    prefix = f"attempt-popup:{attempt_id}:"
    evidence = list(evidence_items)
    functions = payload_popup_functions(payload)
    dynamic_functions = {
        match.group(1).lower()
        for fragment in popup_source_fragments(payload)
        if (match := re.match(r"\s*(alert|confirm|prompt)\b", fragment, re.I))
    }
    source_proofs = {
        item for item in evidence
        if item.startswith(f"attempt-popup-source:{attempt_id}:")
    }
    for item in evidence:
        if not item.startswith(prefix):
            continue
        _, _, kind, encoded = item.split(":", 3)
        has_source_proof = any(
            proof.startswith(f"attempt-popup-source:{attempt_id}:{kind}:")
            for proof in source_proofs
        )
        if kind not in functions:
            continue
        try:
            message = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        function_calls = expected_popup_calls_for_function(payload, kind)
        if function_calls:
            if any(message == token for _call, token in function_calls):
                return True
            continue
        if has_source_proof and kind in dynamic_functions:
            return True
    return False

def analyze_reflection(body: str, payload: str) -> list[Reflection]:
    context = analyze_response_context(body, payload)
    reflections = list(context.reflections)
    raw = html.unescape(body)
    active = active_reflection(payload, raw)
    if active:
        reflections.append(active)
    if any(n in body or n in raw for n in reflection_needles(payload)) and not reflections:
        reflections.append(Reflection("raw-response", "payload reflected in response body", 30))
    return reflections

def active_reflection(payload: str, decoded_body: str) -> Reflection | None:
    decoded_payload = html.unescape(urllib.parse.unquote_plus(payload))
    if not decoded_payload or decoded_payload not in decoded_body:
        return None
    for pattern, detail, severity in ACTIVE_XSS_PATTERNS:
        if pattern.search(decoded_payload):
            return Reflection("active-html", detail, severity)
    return None
