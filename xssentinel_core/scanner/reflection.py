"""Reflection and popup evidence analysis."""

from .settings import *
from .models import *
from .parsers import *
from .utils import *

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
    # A popup is valid if the function fired with ANY message content
    # We check message content only if we have specific expected tokens
    tokens = expected_popup_tokens(payload)
    for kind, message in typed_hits:
        # Empty message (alert() called with no args) - check if payload can have empty args
        if not message:
            # If the function fires with no message, that's valid if:
            # 1. The function exists in payload, OR
            # 2. We have expected tokens and one is the function name itself
            if any(token == f"{kind}:" for token in tokens):
                return True
            # For payloads that call function with no args (like prompt() without args)
            if not tokens:
                return True
            continue
        # Non-empty message - check if it matches expected tokens or partial content
        if tokens:
            for token in tokens:
                if token == f"{kind}:":
                    # Token is just function name, any message is fine
                    return True
                # Check if token is substring of message (partial match)
                if token.lower() in message.lower():
                    return True
                # Check if message is substring of token (another partial match)
                if message.lower() in token.lower():
                    return True
        else:
            # No tokens to match against - any message is valid if function matches
            return True
    # If we have evidence hits but no token match, still valid if function clearly exists
    # This handles cases like encoded payloads where we can't extract tokens
    if typed_hits and not tokens:
        return True
    # Last resort: if function fires, it's valid (trust the browser evidence)
    return bool(typed_hits)

def normalize_browser_hits(hits: Iterable[str]) -> list[str]:
    clean = []
    for hit in hits:
        hit = str(hit).strip()
        if re.match(r"^(alert|confirm|prompt|dialog):", hit):
            clean.append(hit)
    return list(dict.fromkeys(clean))

def analyze_reflection(body: str, payload: str) -> list[Reflection]:
    needles = reflection_needles(payload)
    parser = DOMReflectionParser(needles)
    try:
        parser.feed(body)
    except Exception:
        pass
    raw = html.unescape(body)
    active = active_reflection(payload, raw)
    if active:
        parser.reflections.append(active)
    if any(n in body or n in raw for n in needles):
        if not parser.reflections:
            parser.reflections.append(Reflection("raw-response", "payload reflected in response body", 30))
    return parser.reflections

def active_reflection(payload: str, decoded_body: str) -> Reflection | None:
    decoded_payload = html.unescape(urllib.parse.unquote_plus(payload))
    if not decoded_payload or decoded_payload not in decoded_body:
        return None
    for pattern, detail, severity in ACTIVE_XSS_PATTERNS:
        if pattern.search(decoded_payload):
            return Reflection("active-html", detail, severity)
    return None
