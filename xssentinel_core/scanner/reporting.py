"""Versioned, redacted JSON reporting for existing scanner findings.

The report is passive serialization: this module never sends requests or
changes scan behavior. Raw payloads, request bodies, response bodies, and
headers are deliberately excluded.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any
import urllib.parse

from .models import Finding
from .utils import redact_sensitive_text

REPORT_SCHEMA_VERSION = "1.0"
_SENSITIVE_KEY = re.compile(
    r"(?:authorization|cookie|credential|csrf|password|passwd|secret|session|token|api[_-]?key)",
    re.IGNORECASE,
)


def _safe_text(value: object) -> str:
    return redact_sensitive_text(str(value))


def _safe_location(value: object) -> str:
    text = str(value)
    return "[REDACTED]" if _SENSITIVE_KEY.search(text) else _safe_text(text)


def _report_origin(url: str) -> str:
    """Keep only scheme and host; arbitrary path/query values can be sensitive."""
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return "[URL OMITTED]"
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = parsed.port
        netloc = f"{host}:{port}" if port is not None else host
        return f"{parsed.scheme.lower()}://{netloc}/[PATH AND QUERY OMITTED]"
    except (TypeError, ValueError):
        return "[URL OMITTED]"


def _browser_evidence_summary(value: str, correlated: bool) -> dict[str, object]:
    event_kinds: set[str] = set()
    for event in value.split(";"):
        parts = event.strip().lower().split(":")
        if parts[0] == "attempt-popup" and len(parts) > 2 and parts[2] in {"alert", "confirm", "prompt"}:
            event_kinds.add(parts[2])
        elif parts[0] == "dialog" and len(parts) > 1 and parts[1] in {"alert", "confirm", "prompt"}:
            event_kinds.add(f"dialog:{parts[1]}")
        elif parts[0] in {"alert", "confirm", "prompt"}:
            event_kinds.add(parts[0])
        elif parts[0] == "dom-signal":
            event_kinds.add("dom-signal")
    return {
        "present": bool(value),
        "correlated": bool(correlated),
        "event_kinds": sorted(event_kinds),
        "message_included": False,
    }


def _safe_trace(trace: dict[str, object]) -> dict[str, object]:
    transformations = trace.get("transformations", [])
    contexts = trace.get("contexts", [])
    header_analysis = trace.get("header_analysis")
    return {
        "scan_id": _safe_text(trace.get("scan_id", "")),
        "target_id": _safe_text(trace.get("target_id", "")),
        "attempt_id": _safe_text(trace.get("attempt_id", "")),
        "marker_id": trace.get("marker_id"),
        "input_location": [_safe_location(item) for item in trace.get("input_location", [])],
        "request_method": _safe_text(trace.get("request_method", "")),
        "request_fingerprint": _safe_text(trace.get("request_fingerprint", "")),
        "payload_id": _safe_text(trace.get("payload_id", "")),
        "context_id": trace.get("context_id"),
        "response_id": trace.get("response_id"),
        "browser_run_id": trace.get("browser_run_id"),
        "evidence_ids": [_safe_text(item) for item in trace.get("evidence_ids", [])],
        "transformations": [
            {
                "kind": _safe_text(item.get("kind", "")),
                "observation": _safe_text(item.get("observation", "")),
                "evidence_id": item.get("evidence_id"),
            }
            for item in transformations
            if isinstance(item, dict)
        ],
        "contexts": [
            {
                "category": _safe_text(item.get("category", "UNKNOWN")),
                "source_context": _safe_text(item.get("source_context", "")),
                "output_location": _safe_location(item.get("output_location", "")),
                "confidence": _safe_text(item.get("confidence", "low")),
                "active_context": bool(item.get("active_context", False)),
                "evidence": _safe_text(item.get("evidence", "")),
                "evidence_id": item.get("evidence_id"),
            }
            for item in contexts
            if isinstance(item, dict)
        ],
        "status": _safe_text(trace.get("status", "INCONCLUSIVE")),
        "status_reason": _safe_text(trace.get("status_reason", "")),
        "legacy_status": _safe_text(trace.get("legacy_status", "")),
        "legacy_status_reason": _safe_text(trace.get("legacy_status_reason", "")),
        "browser_evidence_correlated": bool(trace.get("browser_evidence_correlated", False)),
        "browser_verification_status": _safe_text(trace.get("browser_verification_status", "NOT_TESTED")),
        "response_truncated": bool(trace.get("response_truncated", False)),
        "header_analysis": {
            "header_name": _safe_location(header_analysis.get("header_name", "")),
            "outcome": _safe_text(header_analysis.get("outcome", "")),
            "server_acceptance": _safe_text(header_analysis.get("server_acceptance", "not_determined")),
            "baseline_attempt_id": _safe_text(header_analysis.get("baseline_attempt_id", "")),
            "baseline_response_id": _safe_text(header_analysis.get("baseline_response_id", "")),
            "marker_fingerprint": _safe_text(header_analysis.get("marker_fingerprint", "")),
            "request_method": _safe_text(header_analysis.get("request_method", "")),
            "browser_validation": _safe_text(header_analysis.get("browser_validation", "")),
        } if isinstance(header_analysis, dict) else None,
    }


def _finding_report(finding: Finding) -> dict[str, Any]:
    trace = _safe_trace(finding.trace_intelligence)
    evidence_items = []
    if finding.diagnostics:
        for item in finding.diagnostics.evidence:
            evidence_items.append(
                {
                    "evidence_id": item.evidence_id,
                    "attempt_id": item.attempt_id,
                    "kind": _safe_text(item.kind),
                    "detail": _safe_text(item.detail),
                    "weight": item.weight,
                    "location": _safe_location(item.location),
                    "snippet_included": False,
                }
            )
    reflections = [
        {
            "context": _safe_text(item.context),
            "detail": _safe_text(item.detail),
            "severity": item.severity,
            "location": _safe_location(item.location),
            "snippet_included": False,
        }
        for item in finding.reflections
    ]
    status = _safe_text(finding.status)
    xti_status = _safe_text(finding.xti_status)
    return {
        "finding_id": _safe_text(finding.attempt_id or trace.get("attempt_id", "")),
        "attempt_id": _safe_text(finding.attempt_id or trace.get("attempt_id", "")),
        "target_id": trace.get("target_id"),
        "status": status,
        "xti_status": xti_status,
        "method": _safe_text(finding.method),
        "url": _report_origin(finding.url),
        "path_and_query_included": False,
        "http_status": finding.http_status,
        "confidence": finding.confidence,
        "reflected": bool(finding.reflected),
        "browser_confirmed": bool(finding.browser_confirmed),
        "browser_evidence": _browser_evidence_summary(
            finding.browser_evidence,
            bool(trace.get("browser_evidence_correlated", finding.browser_confirmed)),
        ),
        "error": _safe_text(finding.error) if finding.error else None,
        "reflections": reflections,
        "evidence": evidence_items,
        "trace": trace,
        "limitations": [
            "Report serialization does not independently validate exploitability.",
            "Browser evidence is limited to events collected by the configured verifier.",
        ],
    }


def build_json_report(
    findings: list[Finding],
    scan_id: str | None = None,
    request_metrics: dict[str, object] | None = None,
) -> dict[str, Any]:
    """Build the stable report object while excluding raw request/response data."""
    inferred_scan_ids = {
        str(finding.trace_intelligence.get("scan_id"))
        for finding in findings
        if finding.trace_intelligence.get("scan_id")
    }
    effective_scan_id = scan_id or (next(iter(inferred_scan_ids)) if len(inferred_scan_ids) == 1 else None)
    legacy_counts = Counter(_safe_text(finding.status) for finding in findings)
    xti_counts = Counter(_safe_text(finding.xti_status) for finding in findings)
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_id": _safe_text(effective_scan_id) if effective_scan_id else None,
        "completion": "partial_or_unknown",
        "summary": {
            "finding_count": len(findings),
            "legacy_status_counts": dict(sorted(legacy_counts.items())),
            "xti_status_counts": dict(sorted(xti_counts.items())),
            "http_transport_requests": {
                key: request_metrics.get(key)
                for key in ("used", "limit", "requests_per_second")
            } if request_metrics else None,
            "request_accounting": {
                key: request_metrics.get(key)
                for key in ("total_used", "browser_used", "browser_run_count", "by_channel")
            } if request_metrics else None,
        },
        "findings": [_finding_report(finding) for finding in findings],
        "redaction": {
            "applied": True,
            "policy": "Best-effort redaction; raw payloads, request bodies, response bodies, and headers are omitted.",
        },
    }


def write_json_report(
    path: str | Path,
    findings: list[Finding],
    scan_id: str | None = None,
    request_metrics: dict[str, object] | None = None,
) -> Path:
    """Create a new report file without overwriting an existing path."""
    destination = Path(path)
    report = build_json_report(findings, scan_id, request_metrics)
    with destination.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    return destination
