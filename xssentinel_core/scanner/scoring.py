"""Rule-based confidence scoring for XSS evidence."""

from .models import BrowserValidation, Finding, Reflection, TargetIntelligence


def confidence_score(
    reflections: list[Reflection],
    browser: BrowserValidation | None,
    intel: TargetIntelligence | None,
    api_evidence: str = "",
    download_evidence: str = "",
    http_status: int | None = None,
) -> int:
    score = 0
    if browser and browser.confirmed:
        score += 86
    if browser and browser.taint_hits:
        score += min(18, 6 * len(browser.taint_hits))
    if browser and browser.dom_diff:
        score += min(12, 3 * len(browser.dom_diff))
    if reflections:
        strongest = max(item.severity for item in reflections)
        score += min(42, strongest // 2)
    if api_evidence or download_evidence:
        score += 18
    if intel:
        if intel.script_analysis.data_flows:
            score += min(20, 8 * len(intel.script_analysis.data_flows))
        elif intel.script_analysis.suspicious_scripts:
            score += 8
        if intel.csp.raw and not any("unsafe-inline" in issue or "unsafe-eval" in issue for issue in intel.csp.issues):
            score -= 8
        if intel.waf_signals:
            score -= 4
    if http_status and 200 <= http_status < 300:
        score += 4
    elif http_status and http_status >= 400:
        score -= 10
    return max(0, min(100, score))


def finding_evidence_bundle(finding: Finding) -> dict[str, object]:
    bundle = {
        "status": finding.status,
        "method": finding.method,
        "url": finding.url,
        "http_status": finding.http_status,
        "payload": finding.payload,
        "reflections": [item.__dict__ for item in finding.reflections],
        "browser_confirmed": finding.browser_confirmed,
        "browser_evidence": finding.browser_evidence,
        "context_snippets": finding.context_snippets,
        "confidence": finding.confidence,
        "strategy": finding.strategy,
        "error": finding.error,
    }
    if finding.diagnostics:
        bundle["diagnostics"] = {
            "batch": finding.diagnostics.batch,
            "payload_index": finding.diagnostics.payload_index,
            "rejected_status_streak": finding.diagnostics.rejected_status_streak,
            "browser_checked": finding.diagnostics.browser_checked,
            "browser_reason": finding.diagnostics.browser_reason,
            "skip_reason": finding.diagnostics.skip_reason,
            "evidence": [item.__dict__ for item in finding.diagnostics.evidence],
        }
    return bundle
