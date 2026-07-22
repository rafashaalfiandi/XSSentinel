"""CSP, WAF, JavaScript, and target intelligence analysis."""

from .settings import *
from .models import *
from .parsers import *
from .http_client import *
from .targets import *
from .utils import *

def parse_csp_policy(policy: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in policy.split(";"):
        tokens = part.strip().split()
        if not tokens:
            continue
        directives[tokens[0].lower()] = tokens[1:]
    return directives

def analyze_csp(headers: dict[str, str], body: str, base_url: str) -> CSPAnalysis:
    parser = PageStructureParser(base_url)
    try:
        parser.feed(body)
    except Exception:
        pass
    policies = []
    header_policy = header_value(headers, "Content-Security-Policy")
    report_only = header_value(headers, "Content-Security-Policy-Report-Only")
    if header_policy:
        policies.append(header_policy)
    if report_only:
        policies.append("report-only: " + report_only)
    policies.extend(parser.meta_csp)
    raw = " | ".join(policies)
    if not policies:
        return CSPAnalysis("", {}, ["CSP not found"], 0)
    directives: dict[str, list[str]] = {}
    for policy in policies:
        directives.update(parse_csp_policy(policy.removeprefix("report-only: ")))
    issues: list[str] = []
    script_src = directives.get("script-src") or directives.get("default-src") or []
    if not directives.get("script-src"):
        issues.append("script-src is not explicit")
    if "'unsafe-inline'" in script_src:
        issues.append("script-src allows unsafe-inline")
    if "'unsafe-eval'" in script_src:
        issues.append("script-src allows unsafe-eval")
    if "*" in script_src:
        issues.append("script-src wildcard")
    if any(item.startswith("data:") or item == "data:" for item in script_src):
        issues.append("script-src allows data:")
    if not directives.get("object-src"):
        issues.append("object-src is missing")
    if not directives.get("base-uri"):
        issues.append("base-uri is missing")
    if not issues:
        issues.append("CSP is relatively strict")
    score = max(0, 100 - (len([i for i in issues if i != "CSP is relatively strict"]) * 14))
    return CSPAnalysis(raw, directives, issues, score)

def detect_waf(headers: dict[str, str], body: str, status: int | None) -> list[str]:
    haystack = "\n".join(f"{key}: {value}" for key, value in headers.items())
    signals: list[str] = []
    for name, pattern in WAF_HEADER_PATTERNS:
        if pattern.search(haystack):
            signals.append(f"header fingerprint: {name}")
    if status in {403, 406, 419, 429, 503}:
        signals.append(f"blocking-like HTTP status: {status}")
    for pattern in WAF_BODY_PATTERNS:
        if pattern.search(body[:20000]):
            signals.append("body contains blocking/security wording")
            break
    return list(dict.fromkeys(signals))

def extract_page_structure(body: str, base_url: str) -> PageStructureParser:
    parser = PageStructureParser(base_url)
    try:
        parser.feed(body)
    except Exception:
        pass
    return parser

def fetch_external_scripts(urls: list[str], base_url: str, user_agent: str, timeout: float, verify_https: bool, extra_headers: dict[str, str]) -> list[tuple[str, str]]:
    base_host = urllib.parse.urlsplit(base_url).netloc
    scripts: list[tuple[str, str]] = []
    for script_url in urls[:MAX_EXTERNAL_SCRIPT_ANALYSIS]:
        parsed = urllib.parse.urlsplit(script_url)
        if parsed.scheme not in {"http", "https"} or parsed.netloc != base_host:
            continue
        result = request_detailed(script_url, user_agent, timeout, "GET", None, None, verify_https, extra_headers)
        if result.body:
            scripts.append((script_url, result.body[:500_000]))
    return scripts

def analyze_javascript(source: str, label: str) -> list[SinkFinding]:
    findings: list[SinkFinding] = []
    sources = [name for pattern, name in DOM_SOURCE_PATTERNS if pattern.search(source)]
    for pattern, sink_name, severity in DOM_SINK_PATTERNS:
        if pattern.search(source):
            source_note = f"; sources: {', '.join(sources)}" if sources else ""
            findings.append(SinkFinding("dom-sink", f"{label}: {sink_name}{source_note}", severity, text_snippet(source, pattern)))
    return findings

def analyze_scripts(body: str, base_url: str, user_agent: str, timeout: float, verify_https: bool, extra_headers: dict[str, str]) -> ScriptAnalysis:
    structure = extract_page_structure(body, base_url)
    suspicious: list[SinkFinding] = []
    for index, script in enumerate(structure.inline_scripts, start=1):
        suspicious.extend(analyze_javascript(script, f"inline script #{index}"))
    for script_url, source in fetch_external_scripts(structure.external_scripts, base_url, user_agent, timeout, verify_https, extra_headers):
        suspicious.extend(analyze_javascript(source, script_url))
    suspicious.sort(key=lambda item: item.severity, reverse=True)
    return ScriptAnalysis(len(structure.inline_scripts), structure.external_scripts, suspicious[:20])

def recommend_payload_strategy(contexts: set[str], csp: CSPAnalysis, scripts: ScriptAnalysis, waf_signals: list[str]) -> list[str]:
    recommendations: list[str] = []
    if "script-block" in contexts:
        recommendations.append("Prioritize script-context breakouts: </script>, quote breakouts, and JS expression payloads.")
    if "html-attribute" in contexts or "active-attribute" in contexts or "event-attribute" in contexts:
        recommendations.append("Prioritize attribute breakouts: quote + autofocus/onfocus/onmouseover and javascript: URLs.")
    if "html-text" in contexts or "raw-response" in contexts:
        recommendations.append("Prioritize HTML insertion: svg/img/details/iframe srcdoc and encoded parser differentials.")
    if "html-comment" in contexts:
        recommendations.append("Prioritize comment breakouts: --> followed by active HTML payloads.")
    if any("unsafe-inline" in issue for issue in csp.issues) or not csp.raw:
        recommendations.append("Weak or missing CSP: event-handler and inline SVG payloads are likely high-value.")
    elif csp.raw:
        recommendations.append("CSP detected: prioritize context breakouts that do not depend on external scripts.")
    if scripts.suspicious_scripts:
        recommendations.append("DOM sinks found: check location/hash/search parameters for DOM XSS in addition to reflected XSS.")
    if waf_signals:
        recommendations.append("WAF indicators detected: use encoding variants, whitespace variants, and short high-signal payloads.")
    return recommendations or ["No specific recommendation; continue with the default high-signal payloads."]

def html_context_snippets(body: str, payload: str, max_items: int = 4) -> list[str]:
    needles = [payload, urllib.parse.unquote_plus(payload), html.unescape(urllib.parse.unquote_plus(payload))]
    snippets: list[str] = []
    lowered_body = body.lower()
    for needle in unique_lines(needle for needle in needles if needle):
        index = lowered_body.find(needle.lower())
        if index < 0:
            continue
        start = max(0, index - 120)
        end = min(len(body), index + len(needle) + 120)
        snippets.append(one_line(body[start:end], 260))
        if len(snippets) >= max_items:
            break
    return snippets

def analyze_target_intelligence(target: ScanTarget, args: argparse.Namespace, user_agents: list[str], contexts: set[str]) -> TargetIntelligence:
    user_agent = random.choice(user_agents)
    url, body_data = build_request_target(target, "xss-intel")
    result = request_detailed(url, user_agent, args.timeout, target.method, body_data, target.content_type, args.verify_https, args.headers)
    csp = analyze_csp(result.headers, result.body, url)
    waf_signals = detect_waf(result.headers, result.body, result.status)
    scripts = analyze_scripts(result.body, url, user_agent, min(args.timeout, 5.0), args.verify_https, args.headers) if result.body else ScriptAnalysis(0, [], [])
    recommendations = recommend_payload_strategy(contexts, csp, scripts, waf_signals)
    return TargetIntelligence(target, result.status, csp, waf_signals, scripts, recommendations)
