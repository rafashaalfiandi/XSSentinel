"""Target discovery and FUZZ replacement helpers."""

from .settings import *
from .models import *
from .parsers import *
from .http_client import *
from .utils import *

def normalize_input_url(raw_url: str) -> str:
    url = raw_url.strip()
    if not url:
        raise SystemExit("Target cannot be empty.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://" + url
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise SystemExit("Target URL must use http:// or https:// and include a hostname.")
    path = parsed.path or "/"
    return urllib.parse.urlunsplit((parsed.scheme.lower(), parsed.netloc, path, parsed.query, parsed.fragment))

def discovery_url_candidates(url: str) -> list[str]:
    parsed = urllib.parse.urlsplit(normalize_input_url(url))
    host = parsed.netloc
    hosts = [host]
    if host.startswith("www."):
        hosts.append(host[4:])
    else:
        hosts.append("www." + host)
    schemes = [parsed.scheme, "http" if parsed.scheme == "https" else "https"]
    candidates = []
    for scheme in schemes:
        for candidate_host in hosts:
            candidates.append(urllib.parse.urlunsplit((scheme, candidate_host, parsed.path or "/", parsed.query, parsed.fragment)))
    return unique_lines(candidates)

def fetch_discovery_page(
    url: str,
    user_agent: str,
    timeout: float,
    verify_https: bool,
    extra_headers: dict[str, str] | None = None,
) -> tuple[str, int | None, str, str | None, list[str]]:
    errors = []
    for candidate in discovery_url_candidates(url):
        status, body, error = request_url(candidate, user_agent, timeout, "GET", None, None, verify_https, extra_headers)
        error = normalize_request_error(error, candidate)
        if body:
            return candidate, status, body, error, errors
        detail = f"HTTP {status}" if status else error or "empty response"
        errors.append(f"{candidate} -> {detail}")
    return url, None, "", errors[-1] if errors else "empty response", errors

def fuzzable_params(url: str) -> list[str]:
    parsed = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    return [name for name, value in pairs if value == "FUZZ"]

def query_params(url: str) -> list[str]:
    parsed = urllib.parse.urlsplit(url)
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    return [name for name, _ in pairs]

def normalize_query_values_to_fuzz(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if not parsed.query:
        return url
    parts = []
    for item in parsed.query.split("&"):
        key, sep, _ = item.partition("=")
        if sep:
            parts.append(f"{key}=FUZZ")
        else:
            parts.append(f"{key}=FUZZ")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "&".join(parts), parsed.fragment))

def query_fuzz_urls_by_parameter(url: str) -> list[str]:
    parsed = urllib.parse.urlsplit(url)
    if not parsed.query:
        return []
    parts = parsed.query.split("&")
    candidates: list[str] = []
    seen_names: set[str] = set()
    for index, item in enumerate(parts):
        key, sep, _ = item.partition("=")
        if not key:
            continue
        decoded_key = urllib.parse.unquote_plus(key)
        if decoded_key in seen_names:
            continue
        seen_names.add(decoded_key)
        fuzzed = []
        for inner_index, inner_item in enumerate(parts):
            inner_key, inner_sep, _ = inner_item.partition("=")
            if inner_index == index:
                fuzzed.append(f"{inner_key}=FUZZ")
            elif inner_sep:
                fuzzed.append(inner_item)
            else:
                fuzzed.append(inner_item)
        candidates.append(urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "&".join(fuzzed), parsed.fragment)))
    return candidates

def fuzzable_form_params(data: str | None) -> list[str]:
    if not data:
        return []
    pairs = urllib.parse.parse_qsl(data, keep_blank_values=True)
    return [name for name, value in pairs if value == "FUZZ"]

def body_has_fuzz(data: str | None) -> bool:
    return bool(data and "FUZZ" in data)

def json_fuzz_locations(data: str | None) -> list[str]:
    if not data:
        return []
    try:
        parsed = json.loads(data)
    except json.JSONDecodeError:
        return ["body:raw"] if "FUZZ" in data else []

    locations: list[str] = []

    def walk(value: object, path: str = "") -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                child_path = f"{path}.{key}" if path else str(key)
                if item == "FUZZ":
                    locations.append(f"body:{child_path}")
                else:
                    walk(item, child_path)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, f"{path}[{index}]" if path else f"[{index}]")
        elif value == "FUZZ" and path:
            locations.append(f"body:{path}")

    walk(parsed)
    return locations

def looks_preencoded(payload: str) -> bool:
    if not re.search(r"%[0-9a-fA-F]{2}", payload):
        return False
    decoded = urllib.parse.unquote(payload)
    return decoded != payload and any(ch in decoded for ch in "<>'\"")

def encode_query_value(payload: str) -> str:
    # Keep valid percent-encoded XSS payloads from the payload file intact, but
    # encode raw payloads so query separators inside payloads do not break URL parsing.
    safe = "%" if looks_preencoded(payload) else ""
    return urllib.parse.quote(payload, safe=safe)

def encode_form_value(payload: str) -> str:
    safe = "%" if looks_preencoded(payload) else ""
    return urllib.parse.quote_plus(payload, safe=safe)

def build_url(template_url: str, payload: str) -> str:
    parsed = urllib.parse.urlsplit(template_url)
    parts = []
    for item in parsed.query.split("&") if parsed.query else []:
        key, sep, value = item.partition("=")
        decoded_value = urllib.parse.unquote_plus(value)
        if sep and decoded_value == "FUZZ":
            parts.append(f"{key}={encode_query_value(payload)}")
        else:
            parts.append(item)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "&".join(parts), parsed.fragment))

def build_single_query_fuzz_url(template_url: str, fuzz_name: str) -> str:
    parsed = urllib.parse.urlsplit(template_url)
    parts = []
    for item in parsed.query.split("&") if parsed.query else []:
        key, sep, value = item.partition("=")
        decoded_key = urllib.parse.unquote_plus(key)
        decoded_value = urllib.parse.unquote_plus(value)
        if sep and decoded_value == "FUZZ":
            replacement = "FUZZ" if decoded_key == fuzz_name else benign_value_for_field(decoded_key)
            parts.append(f"{key}={urllib.parse.quote_plus(replacement)}")
        else:
            parts.append(item)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "&".join(parts), parsed.fragment))

def detect_content_type(data: str | None, requested: str) -> str:
    if requested != "auto":
        return requested
    if not data:
        return "application/x-www-form-urlencoded"
    stripped = data.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        return "application/json"
    return "application/x-www-form-urlencoded"

def replace_json_fuzz(value: object, payload: str) -> object:
    if isinstance(value, str):
        return payload if value == "FUZZ" else value.replace("FUZZ", payload)
    if isinstance(value, list):
        return [replace_json_fuzz(item, payload) for item in value]
    if isinstance(value, dict):
        return {key: replace_json_fuzz(item, payload) for key, item in value.items()}
    return value

def build_body(template_data: str | None, payload: str, content_type: str) -> str | None:
    if template_data is None:
        return None
    if content_type == "application/json":
        try:
            parsed = json.loads(template_data)
            return json.dumps(replace_json_fuzz(parsed, payload), ensure_ascii=False, separators=(",", ":"))
        except json.JSONDecodeError:
            return template_data.replace("FUZZ", payload)
    if content_type == "application/x-www-form-urlencoded":
        parts = []
        for item in template_data.split("&") if template_data else []:
            key, sep, value = item.partition("=")
            decoded_value = urllib.parse.unquote_plus(value)
            if sep and decoded_value == "FUZZ":
                parts.append(f"{key}={encode_form_value(payload)}")
            else:
                parts.append(item.replace("FUZZ", encode_form_value(payload)))
        return "&".join(parts)
    return template_data.replace("FUZZ", payload)

def target_fuzz_locations(target: ScanTarget) -> list[str]:
    locations = [f"query:{name}" for name in fuzzable_params(target.url)]
    if target.data:
        if target.content_type == "application/json":
            locations.extend(json_fuzz_locations(target.data))
            return locations
        form_params = fuzzable_form_params(target.data) if target.content_type == "application/x-www-form-urlencoded" else []
        if form_params:
            locations.extend(f"body:{name}" for name in form_params)
        elif body_has_fuzz(target.data):
            locations.append("body:raw")
    return locations

def benign_value_for_field(name: str) -> str:
    lowered = name.lower()
    if "email" in lowered:
        return "test@example.test"
    if any(token in lowered for token in ("password", "passwd", "pwd")):
        return "Password123!"
    if any(token in lowered for token in ("id", "page", "offset", "limit", "count", "qty", "amount")):
        return "1"
    return "test"

def is_control_field(name: str) -> bool:
    lowered = name.lower()
    return (
        lowered in {"_method", "utf8", "submit", "commit", "button"}
        or any(token in lowered for token in ("csrf", "xsrf", "nonce", "captcha", "recaptcha", "authenticity_token"))
    )

def fuzz_candidate_fields(fields: list[str]) -> list[str]:
    fields = unique_lines(fields)
    candidates = [field for field in fields if not is_control_field(field)]
    return candidates or fields

def form_data_template(fields: list[str], fuzz_field: str | None = None) -> str:
    parts = []
    for name in fields:
        value = "FUZZ" if fuzz_field is None or name == fuzz_field else benign_value_for_field(name)
        parts.append(f"{urllib.parse.quote_plus(name)}={urllib.parse.quote_plus(value)}")
    return "&".join(parts)

def json_data_template(fields: list[str], fuzz_field: str | None = None) -> str:
    return json.dumps(
        {name: ("FUZZ" if fuzz_field is None or name == fuzz_field else benign_value_for_field(name)) for name in fields},
        separators=(",", ":"),
    )

def form_candidate_to_target(form: FormCandidate, fuzz_field: str | None = None) -> ScanTarget:
    if form.method == "POST":
        target = ScanTarget("POST", normalize_query_values_to_fuzz(form.action), form_data_template(form.fields, fuzz_field), "application/x-www-form-urlencoded", [])
    else:
        separator = "&" if urllib.parse.urlsplit(form.action).query else "?"
        url = form.action + separator + form_data_template(form.fields, fuzz_field)
        target = ScanTarget("GET", url, None, "application/x-www-form-urlencoded", [])
    target.fuzz_locations = target_fuzz_locations(target)
    return target

def field_names_to_post_target(
    base_url: str,
    fields: list[str],
    content_type: str = "application/x-www-form-urlencoded",
    source: str = "js-post",
) -> ScanTarget | None:
    fields = [field for field in unique_lines(fields) if sane_parameter_name(field)]
    if not fields:
        return None
    data = json_data_template(fields[:8]) if content_type == "application/json" else form_data_template(fields[:8])
    target = ScanTarget("POST", normalize_query_values_to_fuzz(base_url), data, content_type, [], source)
    target.fuzz_locations = target_fuzz_locations(target)
    return target if target.fuzz_locations else None

def field_names_to_post_targets(
    base_url: str,
    fields: list[str],
    content_type: str = "application/x-www-form-urlencoded",
    source: str = "js-post",
) -> list[ScanTarget]:
    fields = [field for field in unique_lines(fields) if sane_parameter_name(field)][:8]
    targets: list[ScanTarget] = []
    for field in fuzz_candidate_fields(fields):
        data = json_data_template(fields, field) if content_type == "application/json" else form_data_template(fields, field)
        target = ScanTarget("POST", normalize_query_values_to_fuzz(base_url), data, content_type, [], source)
        target.fuzz_locations = target_fuzz_locations(target)
        if target.fuzz_locations:
            targets.append(target)
    return targets

def query_link_to_target(url: str) -> ScanTarget | None:
    parsed = urllib.parse.urlsplit(url)
    if not parsed.query:
        return None
    target = ScanTarget("GET", normalize_query_values_to_fuzz(url), None, "application/x-www-form-urlencoded", [])
    target.fuzz_locations = target_fuzz_locations(target)
    return target if target.fuzz_locations else None

def field_names_to_get_target(base_url: str, fields: list[str]) -> ScanTarget | None:
    fields = [field for field in unique_lines(fields) if sane_parameter_name(field)]
    if not fields:
        return None
    parsed = urllib.parse.urlsplit(base_url)
    query = "&".join(f"{urllib.parse.quote_plus(field)}=FUZZ" for field in fields[:8])
    url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", query, parsed.fragment))
    target = ScanTarget("GET", url, None, "application/x-www-form-urlencoded", [])
    target.fuzz_locations = target_fuzz_locations(target)
    return target

def same_origin_url(base_url: str, candidate: str) -> str | None:
    candidate = candidate.strip()
    if not candidate or candidate.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
        return None
    resolved = urllib.parse.urljoin(base_url, candidate)
    parsed_base = urllib.parse.urlsplit(base_url)
    parsed = urllib.parse.urlsplit(resolved)
    if parsed.scheme not in {"http", "https"} or parsed.netloc != parsed_base.netloc:
        return None
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, parsed.fragment))

def sane_parameter_name(name: str) -> bool:
    if not 1 <= len(name) <= 48:
        return False
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_.:-]*$", name):
        return False
    blocked = {
        "accept", "author", "cache", "charset", "content", "content-type", "credentials",
        "description", "headers", "integrity", "keywords", "method", "mode", "redirect",
        "referrerpolicy", "robots", "signal", "viewport",
    }
    return name.lower() not in blocked

def extract_object_literal_params(text: str) -> list[str]:
    candidates: list[str] = []
    object_patterns = [
        re.compile(r"JSON\.stringify\s*\(\s*\{([\s\S]{0,1200}?)\}\s*\)", re.I),
        re.compile(r"\b(?:body|data|params|variables|input|query)\s*:\s*\{([\s\S]{0,1200}?)\}", re.I),
        re.compile(r"new\s+URLSearchParams\s*\(\s*\{([\s\S]{0,800}?)\}\s*\)", re.I),
    ]
    key_pattern = re.compile(r"(?:^|[,\{\s])['\"]?([A-Za-z_][A-Za-z0-9_.:-]{0,47})['\"]?\s*:")
    for pattern in object_patterns:
        for match in pattern.finditer(text):
            candidates.extend(key.group(1) for key in key_pattern.finditer(match.group(1)))
    return [name for name in unique_lines(candidates) if sane_parameter_name(name)]

def extract_candidate_params_from_text(text: str) -> list[str]:
    candidates: list[str] = []
    patterns = [
        re.compile(r"(?:searchParams|get|set|append|delete)\(\s*['\"]([A-Za-z_][A-Za-z0-9_.:-]{0,47})['\"]", re.I),
        re.compile(r"(?:FormData|URLSearchParams)[\s\S]{0,300}?\.(?:append|set)\(\s*['\"]([A-Za-z_][A-Za-z0-9_.:-]{0,47})['\"]", re.I),
        re.compile(r"\b(?:append|set)\(\s*['\"]([A-Za-z_][A-Za-z0-9_.:-]{0,47})['\"]\s*,", re.I),
        re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_.:-]{0,47})=", re.I),
        re.compile(r"['\"]([A-Za-z_][A-Za-z0-9_.:-]{0,47})['\"]\s*:\s*(?:['\"]|\d|true|false|null|\{)", re.I),
        re.compile(r"\b(?:name|field|param|key)\s*[:=]\s*['\"]([A-Za-z_][A-Za-z0-9_.:-]{0,47})['\"]", re.I),
        re.compile(r"\b(?:query|params|data|body|variables|input)\s*:\s*\{[\s\S]{0,500}?\b([A-Za-z_][A-Za-z0-9_.:-]{0,47})\s*:", re.I),
        re.compile(r"\b(?:useSearchParams|router\.push|router\.replace|createSearchParams|useForm|register)\b[\s\S]{0,300}?['\"]([A-Za-z_][A-Za-z0-9_.:-]{0,47})['\"]", re.I),
    ]
    for pattern in patterns:
        candidates.extend(match.group(1) for match in pattern.finditer(text))
    candidates.extend(extract_object_literal_params(text))
    common_hints = {
        "search": ["q", "search", "keyword", "query"],
        "filter": ["filter", "category", "type"],
        "page": ["page", "offset", "limit"],
        "login": ["username", "email", "password"],
        "id": ["id"],
    }
    lowered = text.lower()
    for hint, names in common_hints.items():
        if re.search(rf"\b{re.escape(hint)}\b", lowered):
            candidates.extend(names)
    return [name for name in unique_lines(candidates) if sane_parameter_name(name)]

def extract_post_endpoints_from_text(text: str, base_url: str) -> list[str]:
    endpoints: list[str] = []
    patterns = [
        re.compile(r"\b(?:fetch|axios\.post|\$\.post)\(\s*['\"]([^'\"]{1,240})['\"]", re.I),
        re.compile(r"\b(?:url|endpoint|action)\s*[:=]\s*['\"]([^'\"]{1,240})['\"][\s\S]{0,220}?\bmethod\s*[:=]\s*['\"]POST['\"]", re.I),
        re.compile(r"\bmethod\s*[:=]\s*['\"]POST['\"][\s\S]{0,220}?\b(?:url|endpoint|action)\s*[:=]\s*['\"]([^'\"]{1,240})['\"]", re.I),
        re.compile(r"<form[^>]+(?:method=['\"]?post['\"]?)[^>]+action=['\"]([^'\"]{1,240})['\"]", re.I),
    ]
    for pattern in patterns:
        for match in pattern.finditer(text):
            resolved = same_origin_url(base_url, html.unescape(match.group(1)))
            if resolved:
                endpoints.append(resolved)
    return unique_lines(endpoints)

def text_has_post_behavior(text: str) -> bool:
    return bool(re.search(r"\b(method\s*[:=]\s*['\"]POST['\"]|axios\.post|\$\.post|new\s+FormData|JSON\.stringify\s*\(|server action|__next_f|__ACTION__)", text, re.I))

def likely_json_post(text: str) -> bool:
    return bool(re.search(r"application/json|JSON\.stringify\s*\(|\bbody\s*:\s*\{|\bdata\s*:\s*\{", text, re.I))

def js_post_targets_from_text(text: str, base_url: str) -> list[ScanTarget]:
    if not text_has_post_behavior(text):
        return []
    fields = extract_candidate_params_from_text(text)
    if not fields:
        return []
    endpoints = extract_post_endpoints_from_text(text, base_url) or [base_url]
    content_type = "application/json" if likely_json_post(text) else "application/x-www-form-urlencoded"
    targets: list[ScanTarget] = []
    for endpoint in endpoints[:8]:
        targets.extend(field_names_to_post_targets(endpoint, fields, content_type, "js-post-json" if content_type == "application/json" else "js-post"))
    return targets

def fetch_discovery_scripts(urls: list[str], base_url: str, user_agent: str, timeout: float, verify_https: bool, extra_headers: dict[str, str]) -> list[str]:
    base_host = urllib.parse.urlsplit(base_url).netloc
    sources: list[str] = []
    for script_url in urls[:8]:
        parsed = urllib.parse.urlsplit(script_url)
        if parsed.scheme not in {"http", "https"} or parsed.netloc != base_host:
            continue
        result = request_detailed(script_url, user_agent, min(timeout, 4.0), "GET", None, None, verify_https, extra_headers)
        if result.body:
            sources.append(result.body[:700_000])
    return sources

def fallback_common_target(base_url: str, text: str) -> ScanTarget | None:
    candidates = extract_candidate_params_from_text(text)
    if not candidates:
        candidates = ["q", "search", "keyword", "query", "id", "page"]
    return field_names_to_get_target(base_url, candidates[:6])

def dedupe_targets(targets: list[ScanTarget]) -> list[ScanTarget]:
    seen: set[tuple[str, str, str | None]] = set()
    result: list[ScanTarget] = []
    for target in targets:
        key = (target.method, target.url, target.data)
        if key not in seen and target.fuzz_locations:
            seen.add(key)
            result.append(target)
    return result

def split_get_targets_by_parameter(targets: list[ScanTarget]) -> list[ScanTarget]:
    result: list[ScanTarget] = []
    for target in targets:
        query_names = fuzzable_params(target.url) if target.method == "GET" else []
        if len(query_names) <= 1:
            result.append(target)
            continue
        for name in query_names:
            split_target = ScanTarget(
                "GET",
                build_single_query_fuzz_url(target.url, name),
                None,
                target.content_type,
                [],
                target.source,
            )
            split_target.fuzz_locations = target_fuzz_locations(split_target)
            if split_target.fuzz_locations:
                result.append(split_target)
    return result

def target_priority_key(t: ScanTarget) -> tuple[int, int, str]:
    source_order = {
        "high-value-form": 0,
        "form": 1,
        "js-post-json": 2,
        "js-post": 3,
        "html-standalone": 4,
        "link": 5,
        "js-single": 6,
        "grouped": 7,
        "fallback": 8,
        "unknown": 9,
    }.get(t.source, 10)
    return (0 if t.method == "POST" else 1, source_order, t.url)

def discover_form_targets(
    url: str,
    user_agent: str,
    timeout: float,
    verify_https: bool,
    extra_headers: dict[str, str] | None = None,
) -> list[ScanTarget]:
    resolved_url, status, body, error, attempted = fetch_discovery_page(url, user_agent, timeout, verify_https, extra_headers)
    if not body:
        detail = f"HTTP {status}" if status else error or "empty response"
        attempts = "; ".join(attempted[:4])
        suffix = f" Tried: {attempts}" if attempts else ""
        raise SystemExit(f"Could not discover testable inputs from target: {detail}.{suffix}")
    url = resolved_url
    parser = FormDiscoveryParser(url)
    try:
        parser.feed(body)
    except Exception:
        pass

    targets: list[ScanTarget] = []

    # High-value keywords for priority scanning
    high_value_keywords = ["login", "signin", "auth", "search", "comment", "contact", "register", "signup", "reset", "password", "subscribe", "submit", "send", "message"]

    # =========================================================
    # PHASE 1: POST forms - HIGHEST PRIORITY
    # =========================================================
    # Priority 1a: High-value POST forms (login, search, comment, etc)
    high_value_forms = []
    other_forms = []
    for form in parser.forms:
        is_high_value = any(
            kw in form.action.lower() or any(kw in f.lower() for f in form.fields)
            for kw in high_value_keywords
        )
        source = "high-value-form" if is_high_value else "form"
        form_fields = form.fields[:12]
        form_targets = [form_candidate_to_target(form, field) for field in fuzz_candidate_fields(form_fields)]
        for target in form_targets:
            target.source = source
        if is_high_value:
            high_value_forms.extend(form_targets)
        else:
            other_forms.extend(form_targets)

    # Sort high-value forms by keyword specificity
    def form_priority(t: ScanTarget) -> int:
        action = urllib.parse.urlsplit(t.url).path.lower()
        for i, kw in enumerate(high_value_keywords):
            if kw in action:
                return i
        return len(high_value_keywords)

    high_value_forms.sort(key=form_priority)
    targets.extend(high_value_forms)
    targets.extend(other_forms)

    # =========================================================
    # PHASE 2: GET and JavaScript-discovered endpoints
    # =========================================================
    get_targets: list[ScanTarget] = []
    for link in parser.links:
        target = query_link_to_target(link)
        if target:
            target.source = "link"
            get_targets.append(target)

    standalone_target = field_names_to_get_target(url, parser.standalone_fields)
    if standalone_target:
        standalone_target.source = "html-standalone"
        get_targets.append(standalone_target)

    page_structure = extract_page_structure(body, url)
    discovery_text = "\n".join(parser.meta_text + page_structure.inline_scripts)
    for source in fetch_discovery_scripts(page_structure.external_scripts, url, user_agent, timeout, verify_https, extra_headers or {}):
        discovery_text += "\n" + source

    js_candidates = extract_candidate_params_from_text(discovery_text)
    targets.extend(js_post_targets_from_text(discovery_text, url))

    for candidate_name in js_candidates[:12]:
        js_target = field_names_to_get_target(url, [candidate_name])
        if js_target:
            js_target.source = "js-single"
            get_targets.append(js_target)

    grouped_js_target = field_names_to_get_target(url, js_candidates)
    if grouped_js_target:
        grouped_js_target.source = "grouped"
        get_targets.append(grouped_js_target)

    targets.extend(get_targets)

    if not targets:
        fallback = fallback_common_target(url, discovery_text or body[:30000])
        if fallback:
            fallback.source = "fallback"
            targets.append(fallback)

    targets = split_get_targets_by_parameter(targets)
    targets = dedupe_targets(targets)

    targets.sort(key=target_priority_key)
    return targets


def resolve_scan_url_candidate(
    url: str,
    user_agent: str,
    timeout: float,
    verify_https: bool,
    extra_headers: dict[str, str] | None = None,
) -> str:
    candidates = discovery_url_candidates(url)
    if len(candidates) <= 1:
        return url
    for candidate in candidates:
        status, body, error = request_url(candidate, user_agent, min(timeout, 3.0), "GET", None, None, verify_https, extra_headers)
        error = normalize_request_error(error, candidate)
        if status is not None or body:
            return candidate
    return url

def make_scan_target(args: argparse.Namespace) -> ScanTarget:
    content_type = detect_content_type(args.data, args.content_type)
    method = args.method.upper()
    has_query_fuzz = bool(fuzzable_params(args.url))
    has_body_fuzz = body_has_fuzz(args.data)
    if method == "AUTO":
        method = "POST" if has_body_fuzz else "GET"
    target = ScanTarget(method=method, url=args.url, data=args.data, content_type=content_type, fuzz_locations=[])
    target.fuzz_locations = target_fuzz_locations(target)
    if method == "GET" and not has_query_fuzz:
        raise SystemExit("GET requires at least one query parameter with the exact value FUZZ, for example ?q=FUZZ")
    if method == "POST" and not (has_body_fuzz or has_query_fuzz):
        raise SystemExit("POST requires FUZZ in the body or query, for example body: q=FUZZ&id=1")
    if not target.fuzz_locations:
        raise SystemExit("Target must contain at least one testable FUZZ location.")
    return target

def make_direct_get_targets(args: argparse.Namespace, user_agent: str) -> list[ScanTarget]:
    resolved_url = resolve_scan_url_candidate(args.url, user_agent, args.timeout, args.verify_https, args.headers)
    if fuzzable_params(resolved_url):
        fuzz_urls = split_get_targets_by_parameter([ScanTarget("GET", resolved_url, None, "application/x-www-form-urlencoded", [])])
        urls = [target.url for target in fuzz_urls] or [resolved_url]
    else:
        urls = query_fuzz_urls_by_parameter(resolved_url)
    targets: list[ScanTarget] = []
    for url in urls:
        target = ScanTarget("GET", url, None, "application/x-www-form-urlencoded", [], "direct")
        target.fuzz_locations = target_fuzz_locations(target)
        if target.fuzz_locations:
            targets.append(target)
    return targets

def make_scan_targets(args: argparse.Namespace, user_agent: str) -> list[ScanTarget]:
    args.url = normalize_input_url(args.url)
    if query_params(args.url) and not body_has_fuzz(args.data) and args.method.upper() in {"AUTO", "GET"}:
        targets = make_direct_get_targets(args, user_agent)
        if targets:
            return targets
    if query_params(args.url) or body_has_fuzz(args.data):
        if query_params(args.url) and not fuzzable_params(args.url):
            args.url = normalize_query_values_to_fuzz(args.url)
        return [make_scan_target(args)]
    targets = discover_form_targets(args.url, user_agent, args.timeout, args.verify_https, args.headers)
    if not targets:
        raise SystemExit("No testable query parameters or GET/POST forms were found on the target.")
    return targets

def parse_target_line(raw: str) -> tuple[str, str, str | None]:
    raw = raw.strip()
    if not raw:
        raise SystemExit("Target cannot be empty.")
    return "auto", normalize_input_url(raw.split()[0]), None

def build_request_target(target: ScanTarget, payload: str) -> tuple[str, str | None]:
    test_url = build_url(target.url, payload)
    test_body = build_body(target.data, payload, target.content_type) if target.method == "POST" else None
    return test_url, test_body
