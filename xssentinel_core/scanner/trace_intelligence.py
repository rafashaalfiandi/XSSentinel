"""Passive, per-attempt evidence correlation for XSSentinel.

This module analyzes the response already obtained by the scanner. It does not
create requests, inject diagnostic markers, or execute browser interactions.
"""

from __future__ import annotations

import hashlib
import html
import json
import re
import urllib.parse
import uuid
import base64
from typing import Iterable

from .models import Reflection, ScanTarget
from .reflection import (
    attempt_popup_evidence_is_valid,
    expected_popup_calls_for_function,
    normalize_browser_evidence,
    popup_source_fragments,
)


TRACE_STATUS = {
    "NOT_REFLECTED",
    "REFLECTED",
    "CONTEXT_IDENTIFIED",
    "POTENTIAL_XSS",
    "BROWSER_EVIDENCE",
    "CONFIRMED_XSS",
    "INCONCLUSIVE",
    "BLOCKED_OR_UNREACHABLE",
}

CONTEXT_LABELS = {
    "html-text": "HTML_TEXT",
    "html-attribute": "HTML_ATTRIBUTE",
    "active-attribute": "HTML_ATTRIBUTE",
    "event-attribute": "HTML_ATTRIBUTE",
    "style-attribute": "HTML_ATTRIBUTE",
    "html-comment": "HTML_COMMENT",
    "script-block": "JAVASCRIPT",
    "javascript-response": "JAVASCRIPT",
    "json-string": "JSON",
    "json-key": "JSON",
    "json-raw": "JSON",
    "raw-response": "UNKNOWN",
    "css-block": "UNKNOWN",
    "css-token": "UNKNOWN",
    "css-executable": "UNKNOWN",
}
URL_ATTRIBUTES = {"href", "src", "action", "formaction", "data", "srcdoc"}


def _digest(value: object, length: int = 20) -> str:
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:length]


def new_scan_id() -> str:
    """Return an opaque identifier for one scan invocation."""
    return uuid.uuid4().hex


def create_attempt_trace(
    scan_id: str,
    target: ScanTarget,
    payload: str,
    request_url: str,
    request_body: str | None,
    method: str,
    attempt_index: int,
    batch: str,
    attempt_id: str | None = None,
) -> dict[str, object]:
    """Create non-secret identity metadata; request values are only hashed."""
    target_id = _digest([target.method, target.url, target.data, target.content_type, target.fuzz_locations])
    request_fingerprint = _digest([method.upper(), request_url, request_body])
    attempt_id = attempt_id or uuid.uuid4().hex
    return {
        "scan_id": scan_id,
        "target_id": target_id,
        "attempt_id": attempt_id,
        # This is an identity reference only. No marker is injected into traffic.
        "marker_id": None,
        "input_location": list(target.fuzz_locations),
        "request_method": method.upper(),
        "request_fingerprint": request_fingerprint,
        "payload_id": _digest(payload),
        "context_id": None,
        "response_id": None,
        "browser_run_id": None,
        "evidence_ids": [],
        "batch": batch,
        "attempt_index": attempt_index,
        "transformations": [],
        "contexts": [],
        "status": "INCONCLUSIVE",
    }


def fingerprint_contexts(reflections: Iterable[Reflection], parser: str = "") -> list[dict[str, object]]:
    """Map parser evidence to conservative output-context fingerprints."""
    fingerprints: list[dict[str, object]] = []
    seen: set[tuple[str, str, str]] = set()
    for reflection in reflections:
        category = CONTEXT_LABELS.get(reflection.context, "UNKNOWN")
        if category == "HTML_ATTRIBUTE":
            attr_match = re.search(r"\[([^\]]+)\]$", reflection.location)
            attribute = attr_match.group(1).lower() if attr_match else ""
            if attribute in URL_ATTRIBUTES:
                category = "URL_RELATED"
        confidence = "high" if category not in {"UNKNOWN"} else "low"
        evidence = (category, reflection.location, reflection.context)
        if evidence in seen:
            continue
        seen.add(evidence)
        fingerprints.append(
            {
                "category": category,
                "source_context": reflection.context,
                "output_location": reflection.location,
                "confidence": confidence,
                "active_context": reflection.severity >= 75 and category in {"HTML_ATTRIBUTE", "URL_RELATED"},
                "evidence": reflection.detail,
            }
        )
    if not fingerprints and parser == "json":
        fingerprints.append(
            {
                "category": "JSON",
                "source_context": "json-response",
                "output_location": "response",
                "confidence": "medium",
                "active_context": False,
                "evidence": "response parser identified JSON; no reflected value was classified",
            }
        )
    return fingerprints


def analyze_transformations(payload: str, response_body: str) -> list[dict[str, str]]:
    """Report observed exact representations without inferring execution or safety."""
    if not payload or not response_body:
        return []
    candidates: list[tuple[str, str]] = [("identity", payload)]
    escaped = html.escape(payload, quote=True)
    if escaped != payload:
        candidates.append(("html_entity_encoding", escaped))
    escaped = html.escape(payload, quote=False)
    if escaped != payload:
        candidates.append(("html_entity_encoding", escaped))
    percent = urllib.parse.quote(payload, safe="")
    if percent != payload:
        candidates.append(("url_percent_encoding", percent))
    plus = urllib.parse.quote_plus(payload, safe="")
    if plus != payload:
        candidates.append(("url_plus_encoding", plus))
    js_escaped = json.dumps(payload, ensure_ascii=False)[1:-1]
    if js_escaped != payload:
        candidates.append(("javascript_string_escaping", js_escaped))

    decoded_url = urllib.parse.unquote(payload)
    if decoded_url != payload:
        candidates.append(("url_decoding", decoded_url))
    decoded_html = html.unescape(payload)
    if decoded_html != payload:
        candidates.append(("html_entity_decoding", decoded_html))

    observations: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for kind, representation in candidates:
        if representation and representation in response_body and (kind, representation) not in seen:
            seen.add((kind, representation))
            observations.append({"kind": kind, "observation": "representation_present"})

    # A prefix alone is weak evidence; expose it as such and never infer deletion
    # or truncation from an arbitrary short coincidence.
    if len(payload) >= 24 and payload not in response_body and payload[:24] in response_body:
        observations.append({"kind": "possible_truncation", "observation": "payload_prefix_present_only"})
    return observations


def classify_trace_status(
    reflections: list[Reflection],
    contexts: list[dict[str, object]],
    *,
    browser_checked: bool = False,
    browser_confirmed: bool = False,
    browser_evidence: str = "",
    network_error: bool = False,
    blocked: bool = False,
    inconclusive: bool = False,
) -> str:
    """Canonical evidence classification; legacy CLI statuses remain unchanged."""
    if browser_confirmed:
        return "CONFIRMED_XSS"
    if network_error or blocked:
        return "BLOCKED_OR_UNREACHABLE"
    if inconclusive:
        return "INCONCLUSIVE"
    hits = normalize_browser_evidence(browser_evidence.split(";"))
    if browser_checked and hits:
        return "BROWSER_EVIDENCE"
    if not reflections:
        return "NOT_REFLECTED"
    if any(
        item.severity >= 75 and context.get("category") in {"HTML_ATTRIBUTE", "URL_RELATED"}
        for item in reflections
        for context in contexts
        if context.get("source_context") == item.context
    ):
        return "POTENTIAL_XSS"
    if any(context.get("category") not in {"UNKNOWN"} for context in contexts):
        return "CONTEXT_IDENTIFIED"
    return "REFLECTED"


def validate_browser_confirmation(
    payload: str,
    confirmed: bool,
    evidence: str,
    *,
    attempt_id: str | None = None,
    allow_dom_signal: bool = False,
    reflections: list[Reflection] | None = None,
) -> bool:
    """Validate popup call-site/context evidence or a loopback fixture signal."""
    if not confirmed:
        return False
    hits = evidence.split(";")
    normalized_hits = normalize_browser_evidence(hits)
    if reflections and attempt_id:
        fragments = popup_source_fragments(payload)
        for item in normalized_hits:
            parts = item.split(":", 3)
            if len(parts) != 4 or parts[0] != "attempt-popup" or parts[1] != attempt_id:
                continue
            kind = parts[2]
            matching_source_proofs = [
                proof for proof in normalized_hits
                if proof.startswith(f"attempt-popup-source:{attempt_id}:{kind}:")
            ]
            if not attempt_popup_evidence_is_valid(payload, [item, *matching_source_proofs], attempt_id):
                continue

            if matching_source_proofs:
                for proof in matching_source_proofs:
                    source_parts = proof.split(":")
                    if len(source_parts) != 4:
                        continue
                    source_context = source_parts[3]
                    function_fragments = [
                        fragment for fragment in fragments
                        if (match := re.match(r"\s*(alert|confirm|prompt)\b", fragment, re.I))
                        and match.group(1).lower() == kind
                    ]
                    if source_context == "event":
                        relevant = [
                            reflection for reflection in reflections
                            if reflection.context in {"event-attribute", "raw-response"}
                        ]
                    elif source_context == "script":
                        relevant = [
                            reflection for reflection in reflections
                            if reflection.context in {"script-block", "javascript-response"}
                        ]
                    else:
                        continue
                    if any(
                        fragment.lower() in reflection.snippet.lower()
                        for fragment in function_fragments
                        for reflection in relevant
                    ):
                        return True
                continue

            # CDP and Playwright dialog events provide the exact prompt text and
            # are tagged with the active attempt, but may not expose a caller
            # stack/currentScript (notably for inline SVG event handlers).
            # Accept this narrower fallback only for an exact literal token and
            # matching call in a supported response context from that attempt.
            try:
                message = base64.urlsafe_b64decode(parts[3] + "=" * (-len(parts[3]) % 4)).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue
            matching_calls = [
                call for call, token in expected_popup_calls_for_function(payload, kind)
                if message == token
            ]
            relevant = [
                reflection for reflection in reflections
                if reflection.context in {
                    "event-attribute", "raw-response", "script-block", "javascript-response",
                }
            ]
            if any(
                call.lower() in reflection.snippet.lower()
                for call in matching_calls
                for reflection in relevant
            ):
                return True
    expected_signal = f"dom-signal:{attempt_id}" if attempt_id else ""
    return bool(allow_dom_signal and expected_signal in normalize_browser_evidence(hits))


def attach_evidence_identity(items: list[object], attempt_id: str) -> list[str]:
    """Attach stable-within-attempt evidence references and return their IDs."""
    evidence_ids: list[str] = []
    for index, item in enumerate(items, start=1):
        evidence_id = f"{attempt_id}:e{index:02d}"
        setattr(item, "attempt_id", attempt_id)
        setattr(item, "evidence_id", evidence_id)
        evidence_ids.append(evidence_id)
    return evidence_ids
