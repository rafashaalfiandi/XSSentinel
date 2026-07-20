"""Payload expansion, probing, and prioritization."""

from .settings import *
from .models import *
from .http_client import *
from .targets import build_request_target
from .reflection import *
from .utils import *

def payload_score(payload: str, contexts: set[str]) -> int:
    decoded = html.unescape(urllib.parse.unquote_plus(payload)).lower()
    score = 0
    if any(snippet in decoded for snippet in HIGH_SIGNAL_SNIPPETS):
        score += 30
    if expected_popup_tokens(payload):
        score += 18
    if len(payload) <= 120:
        score += 8
    if "script-block" in contexts:
        if "</script>" in decoded or re.search(r"^[\"'];", decoded):
            score += 35
        if re.search(r"\b(alert|confirm|prompt)\s*[(`]", decoded):
            score += 18
    if "html-attribute" in contexts or "active-attribute" in contexts:
        if decoded.startswith(('"', "'", "`")) or " on" in decoded or "autofocus" in decoded:
            score += 35
        if "javascript:" in decoded:
            score += 18
    if "html-text" in contexts or "raw-response" in contexts:
        if decoded.startswith("<") and any(tag in decoded for tag in ("<svg", "<img", "<details", "<iframe", "<math")):
            score += 35
    if "html-comment" in contexts:
        if "-->" in decoded or decoded.startswith("-->"):
            score += 24
    if "%" in payload:
        score += 6
    if re.search(r"<script\s+src\s*=|//host:port|brutelogic|3334957647", decoded):
        score -= 100
    return score

def payload_mutations(payload: str) -> list[str]:
    decoded = html.unescape(urllib.parse.unquote_plus(payload))
    variants = [payload]
    if decoded != payload:
        variants.append(decoded)
    if any(ch in decoded for ch in "<>'\""):
        variants.append(urllib.parse.quote(decoded, safe=""))
        variants.append(urllib.parse.quote_plus(decoded, safe=""))
        variants.append(html.escape(decoded, quote=True))
    if "alert(1)" in decoded:
        variants.extend(
            [
                decoded.replace("alert(1)", "confirm('xss-search')"),
                decoded.replace("alert(1)", "prompt(8)"),
                decoded.replace("alert(1)", "(alert)(1)"),
                decoded.replace("alert(1)", "top['alert'](1)"),
                decoded.replace("alert(1)", "alert`1`"),
            ]
        )
    if decoded.startswith("<"):
        variants.extend(
            [
                decoded.replace("<svg ", "<svg/", 1),
                decoded.replace("<img ", "<img/", 1),
                decoded.replace(" ", "/", 1),
                decoded.replace(" ", "%09", 1),
                decoded.replace(" ", "%0A", 1),
            ]
        )
    if not decoded.startswith(('"', "'")) and decoded.startswith("<"):
        variants.extend([f'">{decoded}', f"'>{decoded}"])
    return unique_lines(item for item in variants if item and len(item) <= 600)

def expand_payloads(payloads: list[str], smart: bool) -> list[str]:
    if not smart:
        return unique_lines(payloads)
    expanded: list[str] = []
    for payload in payloads:
        expanded.extend(payload_mutations(payload))
    return unique_lines(expanded)

def context_probe_targets(target: ScanTarget, payload: str) -> tuple[str, str | None]:
    return build_request_target(target, payload)

def infer_target_contexts(target: ScanTarget, args: argparse.Namespace, user_agents: list[str]) -> set[str]:
    contexts: set[str] = set()
    for probe in CONTEXT_PROBE_PAYLOADS:
        test_url, test_body = context_probe_targets(target, probe)
        http_status, body, error = request_url(
            test_url,
            random.choice(user_agents),
            args.timeout,
            target.method,
            test_body,
            target.content_type,
            args.verify_https,
            args.headers,
        )
        if error and not body:
            continue
        for reflection in analyze_reflection(body, probe) if body else []:
            contexts.add(reflection.context)
        if http_status and http_status >= 500:
            contexts.add("server-error-on-probe")
        if len(contexts) >= 4:
            break
    return contexts

def prioritize_payloads(payloads: list[str], contexts: set[str], limit: int | None) -> list[str]:
    scored = [(payload_score(payload, contexts), index, payload) for index, payload in enumerate(payloads)]
    scored.sort(key=lambda item: (-item[0], item[1]))
    ordered = [payload for _, _, payload in scored]
    for position, payload in FORCED_SMART_PAYLOAD_POSITIONS:
        ordered = [item for item in ordered if item != payload]
        ordered.insert(max(0, position - 1), payload)
    if limit:
        return ordered[:limit]
    if contexts:
        return ordered[:SMART_PAYLOAD_LIMIT]
    return ordered[:SMART_CONTEXT_LIMIT] + ordered[SMART_CONTEXT_LIMIT:SMART_PAYLOAD_LIMIT]

def prioritize_all_payloads(payloads: list[str], contexts: set[str]) -> list[str]:
    return prioritize_payloads(payloads, contexts, len(payloads))
