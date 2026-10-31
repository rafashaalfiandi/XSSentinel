"""Per-attempt scan decision logic.

This module keeps response classification and skip-policy state separate from
the threaded runner. The runner owns concurrency and output; this module owns
the deterministic decision for a single payload attempt.
"""

# Created by Rafasha Alfiandi Passage | github.com/rafashaalfiandi

from __future__ import annotations

import argparse
import hashlib
import html
import json
from collections.abc import Callable
from dataclasses import dataclass
from uuid import uuid4

from .contexts import analyze_response_context
from .browser import browser_run_context, is_loopback_url
from .http_client import normalize_request_error
from .models import BrowserValidation, EvidenceItem, Finding, HttpResult, Reflection, ResponseContext, ScanDiagnostics, ScanTarget, TargetIntelligence
from .pipeline import browser_validation_budget, classify_response, is_network_error, response_evidence_items, should_verify_with_browser
from .reflection import active_reflection, api_reflection_evidence, delivered_payload_evidence
from .scoring import confidence_score, finding_evidence_bundle
from .trace_intelligence import (
    analyze_transformations,
    attach_evidence_identity,
    classify_trace_status,
    create_attempt_trace,
    fingerprint_contexts,
    new_scan_id,
    validate_browser_confirmation,
)


HTTP_REJECTION_STREAK_LIMIT = 11
HTTP_REJECTION_STATUSES = {204, 304}

BrowserValidator = Callable[[str, str, int, str, str, str | None, str, bool, dict[str, str]], tuple[bool, str]]


def browser_validation_status(
    checked: bool,
    confirmed: bool,
    evidence: str,
    requested: bool = False,
    attempt_id: str | None = None,
) -> str:
    """Keep inability to run the verifier distinct from a completed negative check."""
    if not checked:
        return "INCONCLUSIVE" if requested else "NOT_TESTED"
    if confirmed:
        return "CONFIRMED"
    lowered = evidence.lower()
    failure_markers = (
        "browser verifier error:",
        "chromium cdp error:",
        "chromium error:",
        "chromium cdp was not ready before timeout",
        "local chromium/chrome binary was not found",
        "playwright is not available",
        "browser navigation blocked by configured scope policy",
        "browser validation is only accurate for",
        "timed out",
        "timeout",
    )
    if any(marker in lowered for marker in failure_markers):
        return "INCONCLUSIVE"
    if attempt_id:
        hits = [item.strip() for item in evidence.split(";")]
        for hit in hits:
            parts = hit.split(":", 3)
            if len(parts) != 4 or parts[0] != "attempt-popup" or parts[1] != attempt_id:
                continue
            kind = parts[2]
            source_prefix = f"attempt-popup-source:{attempt_id}:{kind}:"
            if not any(item.startswith(source_prefix) for item in hits):
                # The popup belongs to this browser run, but without a matching
                # source proof it cannot establish that the tested input caused it.
                return "INCONCLUSIVE"
    return "NOT_CONFIRMED"


@dataclass(frozen=True)
class AttemptState:
    """Mutable scan-loop state needed to classify one payload attempt."""

    browser_checks_done: int = 0
    rejected_status_streak: int = 0
    last_rejected_status: int | None = None


@dataclass(frozen=True)
class AttemptDecision:
    """Result of classifying one payload attempt."""

    finding: Finding
    state: AttemptState
    target_done: bool = False
    stop_all_targets: bool = False


def is_confirmed_status(status: str) -> bool:
    return status == "CONFIRMED"


def is_api_status(status: str) -> bool:
    return status in {"API_REFLECTED", "API_RISK"}


def should_stop_target_on_network_error(error: str | None) -> bool:
    return is_network_error(error)


def http_skip_streak_limit(http_status: int | None) -> int:
    return HTTP_REJECTION_STREAK_LIMIT


def should_skip_target_on_http_status(http_status: int | None, body: str, reflections: list[Reflection]) -> bool:
    if http_status is None or reflections:
        return False
    return http_status in HTTP_REJECTION_STATUSES


def status_skip_reason(http_status: int | None, error: str | None) -> str:
    if http_status is None:
        return error or "target is unreachable"
    labels = {
        204: "no content",
        304: "not modified",
    }
    return labels.get(http_status, "status rejected")


def skip_streak_detail(http_status: int | None, error: str | None, streak: int) -> str:
    return f"{status_skip_reason(http_status, error)} after {streak} consecutive rejected responses"


def response_context_for(result: HttpResult, payload: str, test_url: str) -> ResponseContext:
    if not result.body:
        return ResponseContext("", "empty", [], [])
    context = analyze_response_context(result.body, payload, result.headers, test_url)
    # Payloads that break out of an attribute split the response across tag
    # boundaries, so the HTML parser ends up with no context evidence beyond
    # the raw-body fallback. In that blind case, consult the active-reflection
    # check on the unescaped body so raw breakouts keep the same active signal
    # that context probing (analyze_reflection) already applies.
    # fix payload #7: breakout di attribute kelewat valid,
    # tambah fallback active_reflection biar kehitung - update by Ruyynn (github.com/ruyynn)
    if not context.reflections or all(item.context == "raw-response" for item in context.reflections):
        active = active_reflection(payload, html.unescape(result.body))
        if active:
            context.reflections.append(active)
    return context


def update_rejection_state(
    rejected_response: bool,
    http_status: int | None,
    previous_streak: int,
    last_rejected_status: int | None,
) -> tuple[int, int | None]:
    if rejected_response and http_status == last_rejected_status:
        return previous_streak + 1, last_rejected_status
    if rejected_response:
        return 1, http_status
    return 0, None


def network_error_finding(
    test_url: str,
    target: ScanTarget,
    payload: str,
    test_body: str | None,
    error: str,
    http_status: int | None,
    batch_name: str,
    payload_index: int,
    trace: dict[str, object] | None = None,
) -> Finding:
    diagnostics = ScanDiagnostics(batch_name, payload_index, 0, False, "", error)
    finding = Finding(
        "NETWORK_ERROR",
        test_url,
        target.method,
        test_body,
        payload,
        False,
        [],
        False,
        "",
        http_status,
        [],
        error,
    )
    finding.diagnostics = diagnostics
    if trace:
        trace["status"] = "BLOCKED_OR_UNREACHABLE"
        finding.attempt_id = str(trace["attempt_id"])
        finding.xti_status = "BLOCKED_OR_UNREACHABLE"
        finding.trace_intelligence = trace
    finding.evidence_bundle = finding_evidence_bundle(finding)
    return finding


def evaluate_scan_attempt(
    target: ScanTarget,
    payload: str,
    test_url: str,
    test_body: str | None,
    result: HttpResult,
    args: argparse.Namespace,
    user_agent: str,
    intel: TargetIntelligence,
    batch_name: str,
    payload_index: int,
    state: AttemptState,
    browser_validator: BrowserValidator,
    attempt_id: str | None = None,
) -> AttemptDecision:
    trace = create_attempt_trace(
        str(getattr(args, "_xti_scan_id", None) or new_scan_id()),
        target,
        payload,
        test_url,
        test_body,
        target.method,
        payload_index,
        batch_name,
        attempt_id or result.attempt_id,
    )
    attempt_id = str(trace["attempt_id"])
    http_status = result.status
    body = result.body
    error = normalize_request_error(result.error, test_url)
    lower_error = (error or "").lower()
    if not body and ("request budget exhausted" in lower_error or "outside configured scope" in lower_error):
        finding = network_error_finding(
            test_url,
            target,
            payload,
            test_body,
            error or "request blocked by scan policy",
            http_status,
            batch_name,
            payload_index,
            trace,
        )
        if "request budget exhausted" in lower_error:
            finding.xti_status = "INCONCLUSIVE"
            finding.trace_intelligence["status"] = "INCONCLUSIVE"
            finding.trace_intelligence["reason"] = "request budget exhausted"
            finding.evidence_bundle = finding_evidence_bundle(finding)
            return AttemptDecision(finding, state, target_done=True, stop_all_targets=True)
        finding.xti_status = "BLOCKED_OR_UNREACHABLE"
        finding.trace_intelligence["status"] = "BLOCKED_OR_UNREACHABLE"
        finding.trace_intelligence["reason"] = "target origin outside configured scope"
        finding.evidence_bundle = finding_evidence_bundle(finding)
        return AttemptDecision(finding, state, target_done=True)
    if http_status is None and not body and should_stop_target_on_network_error(error):
        finding = network_error_finding(test_url, target, payload, test_body, error or "network error", http_status, batch_name, payload_index, trace)
        return AttemptDecision(finding, state, target_done=True)

    response_context = response_context_for(result, payload, test_url)
    reflections = response_context.reflections
    api_evidence = api_reflection_evidence(payload, body, result.headers, test_url) if body else ""
    download_evidence = delivered_payload_evidence(payload, body, result.headers, test_url) if body else ""
    context_snippets = response_context.snippets if body and (reflections or api_evidence or download_evidence) else []

    browser_confirmed = False
    browser_checked = False
    browser_reason = "not-needed"
    browser_run_id = None
    delivery_evidence = download_evidence or api_evidence
    browser_evidence = delivery_evidence
    browser_needed = should_verify_with_browser(payload, reflections, args, api_evidence, download_evidence)
    next_browser_checks = state.browser_checks_done
    if browser_needed and state.browser_checks_done < browser_validation_budget(payload, reflections, args):
        browser_checked = True
        browser_reason = "browser-validation-requested"
        next_browser_checks += 1
        browser_run_id = uuid4().hex
        try:
            with browser_run_context(browser_run_id, attempt_id):
                browser_confirmed, browser_evidence = browser_validator(
                    test_url,
                    user_agent,
                    int(args.timeout * 1000),
                    payload,
                    target.method,
                    test_body,
                    target.content_type,
                    args.verify_https,
                    args.headers,
                )
        except Exception as exc:  # Browser failures are inconclusive, not scan-worker failures.
            browser_confirmed = False
            browser_evidence = f"Browser verifier error: {type(exc).__name__}"
        browser_confirmed = validate_browser_confirmation(
            payload,
            browser_confirmed,
            browser_evidence,
            attempt_id=attempt_id,
            allow_dom_signal=is_loopback_url(test_url),
            reflections=reflections,
        )
        if delivery_evidence and not browser_confirmed:
            browser_evidence = f"{delivery_evidence}; browser={browser_evidence}"
    elif browser_needed:
        browser_reason = "browser-budget-exhausted"

    browser_status = browser_validation_status(
        browser_checked,
        browser_confirmed,
        browser_evidence,
        requested=browser_needed,
        attempt_id=attempt_id,
    )
    if browser_checked:
        browser_reason = browser_status.lower().replace("_", "-")

    rejected_response = should_skip_target_on_http_status(http_status, body, reflections)
    rejected_status_streak, last_rejected_status = update_rejection_state(
        rejected_response,
        http_status,
        state.rejected_status_streak,
        state.last_rejected_status,
    )

    status = classify_response(reflections, browser_confirmed, error, http_status, body, api_evidence, download_evidence)
    if (
        not browser_confirmed
        and rejected_response
        and rejected_status_streak >= http_skip_streak_limit(http_status)
    ):
        status = "HTTP_SKIPPED"
    elif not browser_confirmed and browser_checked and browser_status == "INCONCLUSIVE":
        # Do not present failed or uncorrelated browser verification as a
        # completed negative result when response reflection was observed.
        status = "INCONCLUSIVE"
    evidence_items = response_evidence_items(
        reflections,
        browser_confirmed,
        browser_evidence,
        api_evidence,
        download_evidence,
        context_snippets,
        attempt_id,
    )
    if result.truncated:
        evidence_items.append(
            EvidenceItem(
                "response-truncated",
                "response body exceeded the transport read limit; analysis covers only the captured prefix",
                0,
                "response",
                "",
                attempt_id,
            )
        )
    contexts = fingerprint_contexts(reflections, response_context.parser)
    transformations = analyze_transformations(payload, body)
    for index, context in enumerate(contexts, start=1):
        context["attempt_id"] = attempt_id
        context["evidence_id"] = f"{attempt_id}:ctx{index:02d}"
    for index, transformation in enumerate(transformations, start=1):
        transformation["attempt_id"] = attempt_id
        transformation["evidence_id"] = f"{attempt_id}:tx{index:02d}"
    context_fingerprint = hashlib.sha256(
        json.dumps(contexts, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()[:20]
    response_content_type = next(
        (value for key, value in result.headers.items() if key.lower() == "content-type"),
        "",
    )
    response_fingerprint = hashlib.sha256(
        f"{http_status or ''}\0{response_content_type}\0".encode("utf-8") + body.encode("utf-8")
    ).hexdigest()[:20]
    trace["context_id"] = context_fingerprint
    trace["response_id"] = response_fingerprint
    trace["browser_run_id"] = browser_run_id
    trace["browser_evidence_correlated"] = browser_confirmed
    trace["browser_verification_status"] = browser_status
    trace["response_truncated"] = result.truncated
    trace["contexts"] = contexts
    trace["transformations"] = transformations
    trace_status = classify_trace_status(
        reflections,
        contexts,
        browser_checked=browser_checked,
        browser_confirmed=browser_confirmed,
        browser_evidence=browser_evidence,
        network_error=is_network_error(error),
        blocked=(
            not browser_confirmed
            and (status == "HTTP_SKIPPED" or http_status in {401, 403, 406, 429, 503})
        ),
        inconclusive=(
            not browser_confirmed
            and (
                not body
                or result.truncated
                or (http_status is not None and http_status >= 500)
                or browser_status == "INCONCLUSIVE"
            )
        ),
    )
    trace["status"] = trace_status
    trace["legacy_status"] = status
    trace["status_reason"] = (
        "current-attempt browser popup matched the payload call-site source"
        if trace_status == "CONFIRMED_XSS" and browser_evidence.startswith("dom-signal:") is False
        else "attempt-specific loopback fixture execution signal matched"
        if trace_status == "CONFIRMED_XSS"
        else "target request failed before a conclusive response"
        if trace_status == "BLOCKED_OR_UNREACHABLE" and is_network_error(error)
        else "HTTP scope or rejection policy prevented a conclusive result"
        if trace_status == "BLOCKED_OR_UNREACHABLE"
        else "browser verification or response analysis was inconclusive"
        if trace_status == "INCONCLUSIVE"
        else "high-severity reflected value occurred in a recognized executable attribute context"
        if trace_status == "POTENTIAL_XSS"
        else "response value was reflected in a parser-supported context"
        if trace_status == "CONTEXT_IDENTIFIED"
        else "response value was reflected without a supported context"
        if trace_status == "REFLECTED"
        else "no matching response reflection was found"
        if trace_status == "NOT_REFLECTED"
        else "browser execution-like event lacked sufficient attempt evidence"
    )
    trace["legacy_status_reason"] = (
        "browser execution evidence passed current-attempt validation"
        if status == "CONFIRMED"
        else "repeated HTTP response status met the skip threshold"
        if status == "HTTP_SKIPPED"
        else "network transport failed"
        if status == "NETWORK_ERROR"
        else "API or delivery response reflected the input; browser proof was not confirmed"
        if status in {"API_REFLECTED", "API_RISK"}
        else "high-severity reflection heuristic matched"
        if status == "REFLECTED_RISK"
        else "reflection was observed without a high-severity context heuristic"
        if status == "REFLECTED_LOW"
        else "no execution or reflection confirmation was obtained"
    )
    trace["evidence_ids"] = (
        attach_evidence_identity(evidence_items, attempt_id)
        + [str(item["evidence_id"]) for item in contexts]
        + [str(item["evidence_id"]) for item in transformations]
    )
    diagnostics = ScanDiagnostics(
        batch_name,
        payload_index,
        rejected_status_streak,
        browser_checked,
        browser_reason,
        skip_streak_detail(http_status, error, rejected_status_streak) if status == "HTTP_SKIPPED" else "",
        evidence_items,
    )
    browser_validation = BrowserValidation(browser_confirmed, browser_evidence) if browser_checked or browser_confirmed else None
    finding = Finding(
        status,
        test_url,
        target.method,
        test_body,
        payload,
        bool(reflections),
        reflections,
        browser_confirmed,
        browser_evidence,
        http_status,
        context_snippets,
        error,
    )
    finding.diagnostics = diagnostics
    finding.attempt_id = attempt_id
    finding.xti_status = trace_status
    finding.trace_intelligence = trace
    finding.confidence = confidence_score(reflections, browser_validation, intel, api_evidence, download_evidence, http_status)
    finding.evidence_bundle = finding_evidence_bundle(finding)

    next_state = AttemptState(next_browser_checks, rejected_status_streak, last_rejected_status)
    target_done = is_confirmed_status(status) or status == "HTTP_SKIPPED"
    stop_all_targets = is_confirmed_status(status) and bool(getattr(args, "stop_on_confirmed", False))
    return AttemptDecision(finding, next_state, target_done, stop_all_targets)
