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

def fuzzable_form_params(data: str | None) -> list[str]:
    if not data:
        return []
    pairs = urllib.parse.parse_qsl(data, keep_blank_values=True)
    return [name for name, value in pairs if value == "FUZZ"]

def body_has_fuzz(data: str | None) -> bool:
    return bool(data and "FUZZ" in data)

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
        form_params = fuzzable_form_params(target.data) if target.content_type == "application/x-www-form-urlencoded" else []
        if form_params:
            locations.extend(f"body:{name}" for name in form_params)
        elif body_has_fuzz(target.data):
            locations.append("body:raw")
    return locations

def form_data_template(fields: list[str]) -> str:
    return "&".join(f"{urllib.parse.quote_plus(name)}=FUZZ" for name in fields)

def form_candidate_to_target(form: FormCandidate) -> ScanTarget:
    if form.method == "POST":
        target = ScanTarget("POST", normalize_query_values_to_fuzz(form.action), form_data_template(form.fields), "application/x-www-form-urlencoded", [])
    else:
        separator = "&" if urllib.parse.urlsplit(form.action).query else "?"
        url = form.action + separator + form_data_template(form.fields)
        target = ScanTarget("GET", url, None, "application/x-www-form-urlencoded", [])
    target.fuzz_locations = target_fuzz_locations(target)
    return target

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

def sane_parameter_name(name: str) -> bool:
    if not 1 <= len(name) <= 48:
        return False
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_.:-]*$", name):
        return False
    blocked = {"viewport", "description", "keywords", "charset", "content", "robots", "author"}
    return name.lower() not in blocked

def extract_candidate_params_from_text(text: str) -> list[str]:
    candidates: list[str] = []
    patterns = [
        re.compile(r"(?:searchParams|get|set|append|delete)\(\s*['\"]([A-Za-z_][A-Za-z0-9_.:-]{0,47})['\"]", re.I),
        re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_.:-]{0,47})=", re.I),
        re.compile(r"['\"]([A-Za-z_][A-Za-z0-9_.:-]{0,47})['\"]\s*:\s*(?:['\"]|\d|true|false|null|\{)", re.I),
        re.compile(r"\b(?:name|field|param|key)\s*[:=]\s*['\"]([A-Za-z_][A-Za-z0-9_.:-]{0,47})['\"]", re.I),
    ]
    for pattern in patterns:
        candidates.extend(match.group(1) for match in pattern.finditer(text))
    common_hints = {
        "search": ["q", "search", "keyword", "query"],
        "filter": ["filter", "category", "type"],
        "page": ["page", "offset", "limit"],
        "login": ["username", "email", "password"],
        "id": ["id"],
    }
    lowered = text.lower()
    for hint, names in common_hints.items():
        if hint in lowered:
            candidates.extend(names)
    return [name for name in unique_lines(candidates) if sane_parameter_name(name)]

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
    get_targets: list[ScanTarget] = []  # Store GET targets separately

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
        target = form_candidate_to_target(form)
        target.source = "high-value-form" if is_high_value else "form"
        if is_high_value:
            high_value_forms.append(target)
        else:
            other_forms.append(target)

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
    # PHASE 2: GET endpoints - LOWER PRIORITY (only if no POST)
    # =========================================================
    # Only discover GET endpoints if no POST forms found
    if not targets:
        # Phase 2a: GET query parameters from links
        for link in parser.links:
            target = query_link_to_target(link)
            if target:
                target.source = "link"
                get_targets.append(target)

        # Phase 2b: Standalone HTML fields
        standalone_target = field_names_to_get_target(url, parser.standalone_fields)
        if standalone_target:
            standalone_target.source = "html-standalone"
            get_targets.append(standalone_target)

        # Gather discovery text for JS analysis
        page_structure = extract_page_structure(body, url)
        discovery_text = "\n".join(parser.meta_text + page_structure.inline_scripts)

        for source in fetch_discovery_scripts(page_structure.external_scripts, url, user_agent, timeout, verify_https, extra_headers or {}):
            discovery_text += "\n" + source

        # Phase 2c: JS-discovered parameters
        js_candidates = extract_candidate_params_from_text(discovery_text)

        # Single JS targets
        for candidate_name in js_candidates[:12]:
            js_target = field_names_to_get_target(url, [candidate_name])
            if js_target:
                js_target.source = "js-single"
                get_targets.append(js_target)

        # Grouped JS candidates
        grouped_js_target = field_names_to_get_target(url, js_candidates)
        if grouped_js_target:
            grouped_js_target.source = "grouped"
            get_targets.append(grouped_js_target)

        # Fallback: Common parameters
        if not get_targets:
            fallback = fallback_common_target(url, discovery_text or body[:30000])
            if fallback:
                fallback.source = "fallback"
                get_targets.append(fallback)

        targets = get_targets
    # If POST forms exist, GET endpoints from discovery are NOT added
    # This ensures POST forms are always prioritized

    targets = dedupe_targets(targets)

    # Final smart sort: high-value POST > other POST > GET links > discovered
    def priority_key(t: ScanTarget) -> int:
        source = getattr(t, 'source', 'unknown')
        method_order = 0 if t.method == "POST" else 1
        source_order = {
            "high-value-form": 0,
            "form": 1,
            "html-standalone": 2,
            "link": 3,
            "js-single": 4,
            "grouped": 5,
            "fallback": 6,
            "unknown": 7,
        }.get(source, 8)
        return (method_order, source_order)

    targets.sort(key=priority_key)
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
            return normalize_query_values_to_fuzz(candidate)
    return url

def make_scan_target(args: argparse.Namespace) -> ScanTarget:
    content_type = detect_content_type(args.data, args.content_type)
    method = args.method.upper()
    args.url = normalize_query_values_to_fuzz(args.url)
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

def make_scan_targets(args: argparse.Namespace, user_agent: str) -> list[ScanTarget]:
    args.url = normalize_input_url(args.url)
    args.url = normalize_query_values_to_fuzz(args.url)
    if query_params(args.url) or body_has_fuzz(args.data):
        if query_params(args.url):
            args.url = resolve_scan_url_candidate(args.url, user_agent, args.timeout, args.verify_https, args.headers)
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
