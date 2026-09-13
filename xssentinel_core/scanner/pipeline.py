"""Scan-stage orchestration helpers."""

import argparse

from .models import EvidenceItem, Reflection
from .reflection import payload_expects_popup


def is_network_error(error: str | None) -> bool:
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


def should_verify_with_browser(payload: str, reflections: list[Reflection], args: argparse.Namespace, api_evidence: str = "", download_evidence: str = "") -> bool:
    if not args.browser:
        return False
    if api_evidence or download_evidence:
        return True
    if not payload_expects_popup(payload):
        return False
    if args.browser_all:
        return True
    return bool(reflections)


def browser_validation_budget(payload: str, reflections: list[Reflection], args: argparse.Namespace) -> int:
    if args.browser_all or reflections:
        return 10**9
    if payload_expects_popup(payload):
        return args.browser_confirm_limit
    return max(1, args.browser_confirm_limit // 2)


def classify_response(
    reflections: list[Reflection],
    browser_confirmed: bool,
    error: str | None = None,
    http_status: int | None = None,
    body: str = "",
    api_evidence: str = "",
    download_evidence: str = "",
) -> str:
    if http_status is None and not body and is_network_error(error):
        return "NETWORK_ERROR"
    if browser_confirmed:
        return "CONFIRMED"
    if api_evidence or download_evidence:
        return "API_RISK" if reflections else "API_REFLECTED"
    if any(item.severity >= 75 for item in reflections):
        return "REFLECTED_RISK"
    if reflections:
        return "REFLECTED_LOW"
    return "NOT_CONFIRMED"


def response_evidence_items(
    reflections: list[Reflection],
    browser_confirmed: bool,
    browser_evidence: str,
    api_evidence: str,
    download_evidence: str,
    context_snippets: list[str],
) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    for reflection in reflections[:8]:
        items.append(
            EvidenceItem(
                kind=reflection.context,
                detail=reflection.detail,
                weight=reflection.severity,
                location=reflection.location,
                snippet=reflection.snippet,
            )
        )
    if browser_confirmed:
        items.append(EvidenceItem("browser-confirmed", browser_evidence, 100, "browser", browser_evidence))
    elif browser_evidence:
        items.append(EvidenceItem("browser-evidence", browser_evidence, 50, "browser", browser_evidence))
    if api_evidence:
        items.append(EvidenceItem("api-evidence", api_evidence, 45, "response", api_evidence))
    if download_evidence:
        items.append(EvidenceItem("delivery-evidence", download_evidence, 45, "response", download_evidence))
    for snippet in context_snippets[:4]:
        items.append(EvidenceItem("snippet", snippet, 5, "response", snippet))
    return items


def evidence_summary(items: list[EvidenceItem]) -> str:
    details: list[str] = []
    for item in items:
        if item.detail and item.detail not in details:
            details.append(item.detail)
        if len(details) >= 4:
            break
    return "; ".join(details)


def confirmation_signal_count(reflections: list[Reflection], browser_confirmed: bool, api_evidence: str, download_evidence: str) -> int:
    count = len(reflections)
    if browser_confirmed:
        count += 3
    if api_evidence:
        count += 1
    if download_evidence:
        count += 1
    return count
