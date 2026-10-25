"""Per-attempt scan decision logic.

This module keeps response classification and skip-policy state separate from
the threaded runner. The runner owns concurrency and output; this module owns
the deterministic decision for a single payload attempt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from uuid import uuid4

from .contexts import analyze_response_context
from .browser import browser_run_context
from .http_client import normalize_request_error
from .models import BrowserValidation, Finding, HttpResult, Reflection, ResponseContext, ScanDiagnostics, ScanTarget, TargetIntelligence
from .pipeline import browser_validation_budget, classify_response, is_network_error, response_evidence_items, should_verify_with_browser
from .reflection import api_reflection_evidence, delivered_payload_evidence
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
    return analyze_response_context(result.body, payload, result.headers, test_url)


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
        browser_reason = "popup-or-delivery-evidence"
        next_browser_checks += 1
        browser_run_id = uuid4().hex
        with browser_run_context(browser_run_id):
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
        browser_confirmed = validate_browser_confirmation(payload, browser_confirmed, browser_evidence)
        if delivery_evidence and not browser_confirmed:
            browser_evidence = f"{delivery_evidence}; browser={browser_evidence}"
    elif browser_needed:
        browser_reason = "browser-budget-exhausted"

    rejected_response = should_skip_target_on_http_status(http_status, body, reflections)
    rejected_status_streak, last_rejected_status = update_rejection_state(
        rejected_response,
        http_status,
        state.rejected_status_streak,
        state.last_rejected_status,
    )

    status = classify_response(reflections, browser_confirmed, error, http_status, body, api_evidence, download_evidence)
    if rejected_response and rejected_status_streak >= http_skip_streak_limit(http_status):
        status = "HTTP_SKIPPED"
    evidence_items = response_evidence_items(
        reflections,
        browser_confirmed,
        browser_evidence,
        api_evidence,
        download_evidence,
        context_snippets,
        attempt_id,
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
    trace["contexts"] = contexts
    trace["transformations"] = transformations
    trace_status = classify_trace_status(
        reflections,
        contexts,
        browser_checked=browser_checked,
        browser_confirmed=browser_confirmed,
        browser_evidence=browser_evidence,
        network_error=is_network_error(error),
        blocked=(status == "HTTP_SKIPPED" or http_status in {401, 403, 406, 429, 503}),
        inconclusive=(not body or (http_status is not None and http_status >= 500)),
    )
    trace["status"] = trace_status
    trace["legacy_status"] = status
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
    target_done = is_confirmed_status(status) or is_api_status(status) or status == "HTTP_SKIPPED"
    stop_all_targets = is_confirmed_status(status) and bool(getattr(args, "stop_on_confirmed", False))
    return AttemptDecision(finding, next_state, target_done, stop_all_targets)
