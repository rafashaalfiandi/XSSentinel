"""Opt-in, inert HTTP-header reflection diagnostics integrated with scan runs.

Only an explicit fixed allowlist of non-routing headers is supported. The
module sends a baseline plus unique inert-marker requests using the configured
HTTP service, so scope and request accounting remain on the standard path.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import uuid
from typing import Any

from .decisions import AttemptState
from .models import EvidenceItem, Finding, ScanTarget
from .scoring import finding_evidence_bundle
from .targets import build_request_target
from .utils import unique_lines

SUPPORTED_HEADER_NAMES = ("User-Agent", "Referer", "Accept-Language")
MAX_HEADER_TESTS_PER_SCAN = 3
CONTROL_VALUE = "XSSENTINEL_HEADER_CONTROL"


def validate_header_names(names: list[str] | None) -> list[str]:
    """Normalize explicit names and reject protocol, credential, and routing headers."""
    if names is None:
        return list(SUPPORTED_HEADER_NAMES)
    supported = {name.lower(): name for name in SUPPORTED_HEADER_NAMES}
    normalized: list[str] = []
    for raw_name in names:
        canonical = supported.get(str(raw_name).strip().lower())
        if canonical is None:
            raise ValueError("header diagnostics allow only User-Agent, Referer, and Accept-Language")
        normalized.append(canonical)
    return unique_lines(normalized)[:MAX_HEADER_TESTS_PER_SCAN]


def _fingerprint_response(result: Any) -> str:
    content_type = next(
        (value for key, value in result.headers.items() if key.lower() == "content-type"),
        "",
    )
    body = result.body or ""
    digest = hashlib.sha256(
        f"{result.status or ''}\0{content_type}\0".encode("utf-8") + body.encode("utf-8")
    ).hexdigest()[:20]
    return digest


def _replace_header(headers: dict[str, str], name: str, value: str) -> dict[str, str]:
    updated = {key: item for key, item in headers.items() if key.lower() != name.lower()}
    updated[name] = value
    return updated


def _append_header_evidence(finding: Finding, item: EvidenceItem) -> None:
    if finding.diagnostics is None:
        return
    item.attempt_id = finding.attempt_id
    item.evidence_id = f"{finding.attempt_id}:header"
    finding.diagnostics.evidence.append(item)
    trace = finding.trace_intelligence
    evidence_ids = list(trace.get("evidence_ids", []))
    if item.evidence_id not in evidence_ids:
        evidence_ids.append(item.evidence_id)
    trace["evidence_ids"] = evidence_ids
    old_bundle = finding.evidence_bundle
    finding.evidence_bundle = finding_evidence_bundle(finding)
    for key in ("agent_trace", "decision_explanation"):
        if key in old_bundle:
            finding.evidence_bundle[key] = old_bundle[key]


def run_header_analysis(
    args: argparse.Namespace,
    targets: list[ScanTarget],
    user_agent: str,
    services: Any,
    platform: Any,
) -> list[Finding]:
    """Run explicitly enabled passive marker checks through the normal scan transport."""
    requested_names = getattr(args, "test_headers", None)
    if not requested_names:
        return []
    header_names = validate_header_names(list(requested_names))
    if not header_names:
        return []

    # A GET target avoids writing application state. POST-only inputs are not used
    # as a header diagnostic surface in this implementation.
    target = next((item for item in targets if item.method.upper() == "GET"), None)
    if target is None:
        return []
    baseline_url, baseline_body = build_request_target(target, CONTROL_VALUE)
    baseline_attempt_id = uuid.uuid4().hex
    baseline = services.http.request(
        baseline_url,
        user_agent,
        args.timeout,
        "GET",
        baseline_body,
        target.content_type,
        args.verify_https,
        dict(getattr(args, "headers", {}) or {}),
    )
    baseline.attempt_id = baseline_attempt_id
    if baseline.status is None:
        return []
    baseline_id = _fingerprint_response(baseline)
    findings: list[Finding] = []

    for index, header_name in enumerate(header_names, start=1):
        marker_id = uuid.uuid4().hex
        marker = f"XSSENTINEL_HEADER_{marker_id}%END"
        attempt_id = uuid.uuid4().hex
        request_headers = _replace_header(dict(getattr(args, "headers", {}) or {}), header_name, marker)
        test_url, test_body = build_request_target(target, CONTROL_VALUE)
        result = services.http.request(
            test_url,
            user_agent,
            args.timeout,
            "GET",
            test_body,
            target.content_type,
            args.verify_https,
            request_headers,
        )
        result.attempt_id = attempt_id
        local_args = copy.copy(args)
        local_args.browser = False
        local_args.headers = request_headers
        attempt = platform.evaluate_attempt(
            target,
            marker,
            test_url,
            test_body,
            result,
            local_args,
            user_agent,
            None,
            "header-diagnostic",
            index,
            AttemptState(),
            services.browser.validate,
            attempt_id=attempt_id,
        )
        finding = attempt.finding
        trace = finding.trace_intelligence
        transformations = trace.get("transformations", [])
        transformed_marker_observed = bool(transformations)
        trace["marker_id"] = marker_id
        trace["input_location"] = [f"header:{header_name}"]
        trace["payload_id"] = hashlib.sha256(marker.encode("utf-8")).hexdigest()[:20]
        trace["response_id"] = _fingerprint_response(result)
        trace["header_analysis"] = {
            "header_name": header_name,
            "outcome": (
                "marker_reflected"
                if finding.reflected
                else "marker_transformed"
                if transformed_marker_observed
                else "marker_not_observed"
            ),
            "server_acceptance": "not_determined",
            "baseline_attempt_id": baseline_attempt_id,
            "baseline_response_id": baseline_id,
            "marker_fingerprint": trace["payload_id"],
            "request_method": "GET",
            "browser_validation": "not_run_for_inert_diagnostic_marker",
        }
        evidence_detail = (
            "unique inert marker from configured header observed in response"
            if finding.reflected
            else "known encoded representation of unique inert header marker observed"
            if transformed_marker_observed
            else "unique inert marker from configured header not observed; header handling is unknown"
        )
        if transformed_marker_observed and not finding.reflected:
            finding.xti_status = "REFLECTED"
            trace["status"] = finding.xti_status
            finding.evidence_bundle = finding_evidence_bundle(finding)
        _append_header_evidence(
            finding,
            EvidenceItem(
                "header-marker-observation",
                evidence_detail,
                20 if finding.reflected else 0,
                f"header:{header_name}",
            ),
        )
        findings.append(finding)
        if result.status is None:
            break
    return findings
