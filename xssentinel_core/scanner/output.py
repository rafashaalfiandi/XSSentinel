"""Terminal output rendering."""

from .settings import *
from .models import *
from .utils import *
from .http_client import normalize_request_error

def rendered_error(finding: Finding) -> str | None:
    return normalize_request_error(finding.error, finding.url)

def rendered_network_error(error: str | None) -> bool:
    if not error:
        return False
    lowered = error.lower()
    return any(
        marker in lowered
        for marker in (
            "dns lookup failed",
            "no address associated",
            "name or service not known",
            "connection timed out",
            "timed out",
            "connection refused",
            "connection reset",
            "network is unreachable",
        )
    )

def rendered_status(finding: Finding) -> str:
    error = rendered_error(finding)
    if finding.http_status is None and not error:
        return finding.status
    if finding.http_status is None and rendered_network_error(error):
        return "NETWORK_ERROR"
    return finding.status

def color_info(message: str) -> str:
    return f"{BLUE}{BOLD}{message}{RESET}"

def info_tag() -> str:
    return f"{BLUE}{BOLD}[INFO]{RESET}"

def start_tag() -> str:
    return f"{BRIGHT_TOSCA}{BOLD}[START]{RESET}"

def info_key(name: str) -> str:
    return f"{CYAN}{name}={RESET}"

def status_value(value: str) -> str:
    if value == "on":
        return f"{GREEN}{value}{RESET}"
    if value == "off":
        return f"{RED}{value}{RESET}"
    if value in {"none", "strict"}:
        return f"{GREEN}{value}{RESET}"
    if value in {"weak"}:
        return f"{YELLOW}{value}{RESET}"
    return value

def info_field(name: str, value: object, status: bool = False) -> str:
    raw = str(value)
    rendered = status_value(raw) if status else raw
    return f"{info_key(name)}{rendered}"

def first_param_name(target: ScanTarget) -> str:
    params = [item.split(":", 1)[1] for item in target.fuzz_locations if ":" in item]
    return params[0] if params else "-"

def csp_label(csp: CSPAnalysis) -> str:
    if not csp.raw:
        return "none"
    weak = [issue for issue in csp.issues if issue != "CSP is relatively strict"]
    return "weak" if weak else "strict"

def waf_label(waf_signals: list[str]) -> str:
    if not waf_signals:
        return "none"
    labels = []
    for signal in waf_signals:
        if ":" in signal:
            labels.append(signal.rsplit(":", 1)[1].strip().replace(" ", "_"))
        else:
            labels.append(signal.replace(" ", "_"))
    return "+".join(labels[:2])

def display_target_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    parts = []
    for item in parsed.query.split("&") if parsed.query else []:
        key, sep, value = item.partition("=")
        if sep and urllib.parse.unquote_plus(value) == "FUZZ":
            parts.append(f"{key}=")
        else:
            parts.append(item)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "&".join(parts), parsed.fragment))

def source_priority_label(source: str) -> tuple[str, str]:
    """Return (plain marker, label) for source categorization."""
    labels = {
        "high-value-form": ("[HIGH]", f"{GREEN}HIGH-VALUE{RESET}"),
        "form": ("[FORM]", f"{YELLOW}FORM{RESET}"),
        "js-post-json": ("[POST-JS]", f"{MAGENTA}JS-POST-JSON{RESET}"),
        "js-post": ("[POST-JS]", f"{MAGENTA}JS-POST{RESET}"),
        "html-standalone": ("[HTML]", f"{BLUE}STANDALONE{RESET}"),
        "link": ("[GET]", f"{CYAN}LINK{RESET}"),
        "js-single": ("[JS]", f"{MAGENTA}JS-SINGLE{RESET}"),
        "grouped": ("[JS]", f"{MAGENTA}GROUPED{RESET}"),
        "fallback": ("[FALLBACK]", f"{DIM}FALLBACK{RESET}"),
        "unknown": ("?", f"{RED}UNKNOWN{RESET}"),
    }
    return labels.get(source, ("?", f"{RED}UNKNOWN{RESET}"))

def format_endpoint_number(index: int) -> str:
    """Format endpoint index with zero-padding."""
    return f"{index:02d}."

def format_method(method: str) -> str:
    """Format HTTP method with color."""
    if method == "POST":
        return f"{YELLOW}{BOLD}{method}{RESET}"
    return f"{CYAN}{method}{RESET}"

def format_path_params(target: ScanTarget) -> str:
    """Extract and format path and params from target."""
    parsed = urllib.parse.urlsplit(target.url)
    path = parsed.path or "/"

    # Get all parameter names from fuzz_locations
    params = []
    for loc in target.fuzz_locations:
        if ":" in loc:
            parts = loc.split(":", 1)
            param_type = parts[0]  # "query" or "body"
            param_name = parts[1] if len(parts) > 1 else ""
            params.append(param_name)

    # Dedupe while preserving order
    seen = set()
    unique_params = []
    for p in params:
        if p not in seen:
            seen.add(p)
            unique_params.append(p)

    if not unique_params:
        return f"{path} {DIM}(no params){RESET}"

    # Truncate long param lists
    if len(unique_params) <= 4:
        param_str = ", ".join(unique_params)
    else:
        param_str = f"{unique_params[0]}, {unique_params[1]}, {unique_params[2]}, ... (+{len(unique_params)-3})"

    # Add method indicator for POST
    method_indicator = ""
    if target.method == "POST":
        method_indicator = f"{YELLOW}~{RESET}"

    return f"{path} {method_indicator}{param_str}"

def print_endpoint_discovery_summary(
    targets: list[ScanTarget],
    all_payloads: list[str] | None = None,
    selected_payloads: list[str] | int | None = None,
) -> None:
    """Print discovered endpoints with smart, detailed categorization."""
    if not targets:
        return

    parsed_base = urllib.parse.urlsplit(targets[0].url)
    base = f"{parsed_base.scheme}://{parsed_base.netloc}"

    # Separate by method first
    post_targets = [t for t in targets if t.method == "POST"]
    get_targets = [t for t in targets if t.method == "GET"]

    # Categorize by source
    high_value = [t for t in post_targets if getattr(t, 'source', '') == "high-value-form"]
    other_forms = [t for t in post_targets if getattr(t, 'source', '') == "form"]
    js_post = [t for t in post_targets if getattr(t, 'source', '') in ("js-post", "js-post-json")]
    links = [t for t in get_targets if getattr(t, 'source', '') == "link"]
    standalone = [t for t in get_targets if getattr(t, 'source', '') in ("html-standalone", "js-single", "grouped")]
    fallback = [t for t in get_targets if getattr(t, 'source', '') == "fallback"]

    # Calculate totals
    total_fuzz = sum(len(t.fuzz_locations) for t in targets)

    # Format payloads info if provided
    payload_info = ""
    if all_payloads:
        total = len(all_payloads)
        if selected_payloads:
            payload_info = f" payloads={total:,}"
        else:
            payload_info = f" payloads={total:,}"

    print()
    print(f"{info_tag()} {BOLD}endpoints={len(targets)} mode=auto-discovery{payload_info}{RESET}")
    print(f"{info_tag()} {info_key('base')}{base}")

    if post_targets:
        print(f"{info_tag()} {YELLOW}priority=POST forms before GET endpoints{RESET}")
    else:
        print(f"{info_tag()} {CYAN}priority=GET endpoints only (no POST forms found){RESET}")

    # Build ordered list of all targets with metadata
    all_display_targets = []
    for t in targets:
        source = getattr(t, 'source', 'unknown')
        marker, label = source_priority_label(source)
        all_display_targets.append({
            'target': t,
            'source': source,
            'marker': marker,
            'label': label,
            'order': (0 if t.method == "POST" else 1,
                     {"high-value-form": 0, "form": 1, "js-post-json": 2, "js-post": 3, "html-standalone": 4, "link": 5, "js-single": 6, "grouped": 7, "fallback": 8, "unknown": 9}.get(source, 10))
        })

    # Sort by priority - POST first, then GET
    all_display_targets.sort(key=lambda x: (x['order'][0], x['order'][1]))

    # Print each endpoint with detailed info
    print()

    # Separate POST and GET sections
    post_display = [d for d in all_display_targets if d['target'].method == "POST"]
    get_display = [d for d in all_display_targets if d['target'].method == "GET"]

    idx = 1
    if post_display:
        for item in post_display:
            t = item['target']
            marker = item['marker']
            method_str = format_method(t.method)
            path_params = format_path_params(t)

            line = f"  {format_endpoint_number(idx)} {marker} {method_str} {path_params}"
            if item['source'] not in ("high-value-form",):
                line += f" {DIM}[{item['source']}]{RESET}"
            print(line)
            idx += 1

        # Separator if both POST and GET
        if get_display:
            print()

    if get_display:
        for item in get_display:
            t = item['target']
            marker = item['marker']
            method_str = format_method(t.method)
            path_params = format_path_params(t)

            line = f"  {format_endpoint_number(idx)} {marker} {method_str} {path_params}"
            if item['source'] not in ("high-value-form",):
                line += f" {DIM}[{item['source']}]{RESET}"
            print(line)
            idx += 1

    # Print summary statistics
    print()
    summary_parts = []
    if high_value:
        summary_parts.append(f"{GREEN}HIGH={len(high_value)}{RESET}")
    if other_forms:
        summary_parts.append(f"{YELLOW}POST={len(other_forms)}{RESET}")
    if js_post:
        summary_parts.append(f"{MAGENTA}JS-POST={len(js_post)}{RESET}")
    if links:
        summary_parts.append(f"{CYAN}LINK={len(links)}{RESET}")
    if standalone:
        summary_parts.append(f"{MAGENTA}JS={len(standalone)}{RESET}")
    if fallback:
        summary_parts.append(f"{DIM}FALLBACK={len(fallback)}{RESET}")

    summary_str = " | ".join(summary_parts) if summary_parts else f"{DIM}none{RESET}"
    print(f"  {info_key('breakdown')} {summary_str}")
    print(f"  {info_key('total-fuzz')} {total_fuzz} injection points in {len(targets)} endpoints")

    # Print intelligent insights
    insights = []

    # Special case: No POST forms found
    if not post_targets:
        insights.append(f"{CYAN}No POST forms found; using {len(get_targets)} GET endpoint(s){RESET}")

    # Check for high-value forms
    if high_value:
        insights.append(f"{GREEN}{len(high_value)} high-value POST form target(s) detected{RESET}")

    if js_post:
        insights.append(f"{MAGENTA}{len(js_post)} JavaScript POST endpoint(s) inferred{RESET}")

    # Check for forms with sensitive params
    sensitive_patterns = ['password', 'passwd', 'pwd', 'secret', 'token', 'key', 'auth', 'credential']
    for t in targets:
        params_lower = [p.lower() for p in t.fuzz_locations if ":" in p]
        if any(pat in " ".join(params_lower) for pat in sensitive_patterns):
            insights.append(f"{GREEN}Sensitive parameters found (auth/token fields){RESET}")
            break

    # Check for forms without CSRF (only if POST forms exist)
    csrf_detected = False
    for t in post_targets:
        params = [p.split(":", 1)[1] for p in t.fuzz_locations if ":" in p]
        has_csrf = any('csrf' in p.lower() for p in params)
        if has_csrf:
            csrf_detected = True
            break

    if post_targets and not csrf_detected:
        insights.append(f"{YELLOW}Forms without visible CSRF token detected{RESET}")
    elif post_targets and csrf_detected:
        insights.append(f"{GREEN}CSRF tokens detected in forms{RESET}")

    # Check for search functionality
    for t in targets:
        params = [p.split(":", 1)[1].lower() for p in t.fuzz_locations if ":" in p]
        if any(p in ['q', 'search', 'query', 'keyword'] for p in params):
            insights.append(f"{CYAN}Search functionality found{RESET}")
            break

    # Check for common vulnerable patterns
    for t in targets:
        params = [p.split(":", 1)[1].lower() for p in t.fuzz_locations if ":" in p]
        if 'id' in params or 'page' in params or 'offset' in params:
            insights.append(f"{MAGENTA}Pagination or ID parameters found (common XSS points){RESET}")
            break

    # Check for file upload or content submission
    file_patterns = ['file', 'upload', 'image', 'avatar', 'attachment', 'content']
    for t in targets:
        params = [p.lower() for p in t.fuzz_locations if ":" in p]
        if any(pat in " ".join(params) for pat in file_patterns):
            insights.append(f"{BLUE}File upload or content field detected{RESET}")
            break

    if insights:
        print()
        for insight in insights[:5]:  # Limit to 5 insights
            print(f"  {info_tag()} {insight}")

def print_scan_info(
    target: ScanTarget,
    all_payloads: list[str],
    selected_payloads: list[str],
    args: argparse.Namespace,
    intel: TargetIntelligence,
    contexts: set[str],
    endpoint_index: int | None = None,
    total_endpoints: int | None = None,
) -> None:
    dom_enabled = "on" if intel.script_analysis.suspicious_scripts or intel.script_analysis.inline_scripts or intel.script_analysis.external_scripts else "on"
    context_label = "+".join(sorted(contexts)) if contexts else "none"

    # Smart param display - show all params being tested
    params = [item.split(":", 1)[1] for item in target.fuzz_locations if ":" in item]
    if len(params) <= 3:
        param_display = ", ".join(params)
    else:
        param_display = f"{params[0]}, {params[1]}, ... (+{len(params)-2} more)"

    # Show endpoint index if in multi-endpoint mode
    endpoint_info = ""
    if endpoint_index is not None and total_endpoints is not None:
        endpoint_info = f"{BLUE}[{endpoint_index}/{total_endpoints}]{RESET} "

    fields = [
        info_field("target", display_target_url(target.url)),
        info_field("method", target.method),
        info_field("param", param_display),
        info_field("payloads", f"{len(all_payloads):,}"),
        info_field("selected", len(selected_payloads) if hasattr(selected_payloads, '__len__') else selected_payloads),
        info_field("chromium", "on" if args.browser else "off", True),
        info_field("dom", dom_enabled, True),
        info_field("csp", csp_label(intel.csp), True),
        info_field("waf", waf_label(intel.waf_signals), True),
        info_field("context", context_label),
    ]
    print(info_tag() + (f" {endpoint_info}" if endpoint_info else ""))
    for field in fields:
        print(f"  {field}")

def print_intelligence(intel: TargetIntelligence) -> None:
    print(f"CSP Analyzer: score={intel.csp.score}/100; {one_line('; '.join(intel.csp.issues), 110)}")
    waf_label = "; ".join(intel.waf_signals) if intel.waf_signals else "no strong fingerprint"
    print(f"WAF Detection: {one_line(waf_label, 110)}")
    sink_count = len(intel.script_analysis.suspicious_scripts)
    print(f"JavaScript Parser: inline={intel.script_analysis.inline_scripts}, external={len(intel.script_analysis.external_scripts)}, sink={sink_count}")
    if intel.script_analysis.suspicious_scripts:
        top_sink = intel.script_analysis.suspicious_scripts[0]
        print(f"Sink Analyzer: {top_sink.detail} severity={top_sink.severity}")
    print(f"Payload Recommendation: {one_line(intel.recommendations[0], 120)}")

def print_result(number: int, finding: Finding, agent: str | None = None) -> None:
    colors = {
        "CONFIRMED": GREEN,
        "DOWNLOAD_CONFIRMED": GREEN,
        "REFLECTED_RISK": YELLOW,
        "REFLECTED_LOW": CYAN,
        "NOT_CONFIRMED": DIM,
        "NETWORK_ERROR": YELLOW,
        "HTTP_SKIPPED": YELLOW,
    }
    markers = {
        "CONFIRMED": "VALID",
        "DOWNLOAD_CONFIRMED": "VALID",
        "REFLECTED_RISK": "RISK",
        "REFLECTED_LOW": "LOW",
        "NOT_CONFIRMED": "NO",
        "NETWORK_ERROR": "SKIP",
        "HTTP_SKIPPED": "SKIP",
    }
    status = rendered_status(finding)
    error = rendered_error(finding)
    color = colors.get(status, RED)
    marker = markers.get(status, "?")
    http_status = finding.http_status or "-"
    detail = ""
    if finding.reflections:
        strongest = max(finding.reflections, key=lambda item: item.severity)
        detail = f"DOM={strongest.context}:{strongest.detail}"
    elif status == "HTTP_SKIPPED":
        detail = "HTTP status indicates this parameter should be skipped"
    elif error and finding.http_status is None:
        detail = f"network={error}"
    elif error:
        detail = f"response={error}"
    else:
        detail = "DOM=no-reflection"
    if finding.browser_evidence and status != "CONFIRMED" and not error:
        detail = f"{detail} browser={finding.browser_evidence}"
    if status in {"CONFIRMED", "DOWNLOAD_CONFIRMED"}:
        target = f"payload=\"{one_line(finding.payload, 90)}\" evidence=\"{one_line(finding.browser_evidence or 'browser-confirmed', 80)}\""
    else:
        target = one_line(detail, 70)
    agent_label = f" {DIM}{agent}{RESET}" if agent else ""
    print(
        f"{color}{BOLD}[{marker:<5}]{RESET} "
        f"#{number:04d}{agent_label} {finding.method} HTTP={http_status} "
        f"{color}{status}{RESET} "
        f"{DIM}{target}{RESET}"
    )

def print_target_skipped(error: str | None) -> None:
    detail = one_line(error or "target is unreachable", 120)
    print(f"{YELLOW}{BOLD}[SKIP]{RESET} target skipped: {detail}")

def result_tag() -> str:
    return f"{GREEN}{BOLD}[FOUND]{RESET}"

def result_key(name: str) -> str:
    return f"{CYAN}{name}:{RESET}"

def print_summary(findings: list[Finding]) -> None:
    counts: dict[str, int] = {}
    for finding in findings:
        status = rendered_status(finding)
        counts[status] = counts.get(status, 0) + 1
    confirmed = [f for f in findings if rendered_status(f) in {"CONFIRMED", "DOWNLOAD_CONFIRMED"}]
    if confirmed:
        finding = confirmed[0]
        print()
        print(f"{result_tag()} confirmed XSS")
        print(f"  {result_key('method')} {finding.method}    {result_key('http')} {finding.http_status or '-'}    {result_key('tested')} {len(findings)}")
        print(
            f"  {result_key('stats')} confirmed={counts.get('CONFIRMED', 0) + counts.get('DOWNLOAD_CONFIRMED', 0)} "
            f"risk={counts.get('REFLECTED_RISK', 0)} low={counts.get('REFLECTED_LOW', 0)} "
            f"no={counts.get('NOT_CONFIRMED', 0)} skipped={counts.get('NETWORK_ERROR', 0) + counts.get('HTTP_SKIPPED', 0)}"
        )
        print(f"  {result_key('payload')} {finding.payload}")
        evidence_key = 'browser' if finding.status == 'CONFIRMED' else 'evidence'
        print(f"  {result_key(evidence_key)} {finding.browser_evidence or 'confirmed'}")
        print(f"  {result_key('url')} {finding.url}")
        if finding.body:
            print(f"  {result_key('body')} {one_line(finding.body, 180)}")
        return
    print()
    print(f"{YELLOW}{BOLD}[DONE]{RESET} no confirmed execution")
    print(
        f"  {result_key('stats')} confirmed={counts.get('CONFIRMED', 0) + counts.get('DOWNLOAD_CONFIRMED', 0)} "
        f"risk={counts.get('REFLECTED_RISK', 0)} low={counts.get('REFLECTED_LOW', 0)} "
        f"no={counts.get('NOT_CONFIRMED', 0)} skipped={counts.get('NETWORK_ERROR', 0) + counts.get('HTTP_SKIPPED', 0)}"
    )
