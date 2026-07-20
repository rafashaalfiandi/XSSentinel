"""Main scan orchestration."""

from .settings import *
from .models import *
from .utils import *
from .payloads import *
from .targets import *
from .http_client import *
from .reflection import *
from .browser import *
from .intelligence import *
from .output import *

def classify(reflections: list[Reflection], browser_confirmed: bool, error: str | None = None, http_status: int | None = None, body: str = "") -> str:
    if http_status is None and not body and is_network_error(error):
        return "NETWORK_ERROR"
    if browser_confirmed:
        return "CONFIRMED"
    if any(item.severity >= 75 for item in reflections):
        return "REFLECTED_RISK"
    if reflections:
        return "REFLECTED_LOW"
    return "NOT_CONFIRMED"

def should_verify_with_browser(payload: str, reflections: list[Reflection], args: argparse.Namespace) -> bool:
    if not args.browser:
        return False
    if not payload_expects_popup(payload):
        return False
    if args.browser_all:
        return True
    return bool(reflections)

def browser_validation_budget(payload: str, reflections: list[Reflection], args: argparse.Namespace) -> int:
    if args.browser_all:
        return 10**9
    if reflections:
        return 10**9
    return args.browser_confirm_limit

def iter_payloads(payloads: list[str], limit: int | None) -> Iterable[str]:
    for index, payload in enumerate(payloads, start=1):
        if limit and index > limit:
            break
        yield payload

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

def should_stop_target_on_network_error(error: str | None) -> bool:
    return is_network_error(error)

def scan(args: argparse.Namespace) -> tuple[list[Finding], list[TargetIntelligence]]:
    payload_path = Path(args.payloads)
    base_payloads = load_lines(payload_path)
    smart_selected = payload_path.name == "smart-selected-180-payloads.txt"
    payloads = unique_lines(base_payloads) if smart_selected else expand_payloads(base_payloads, args.smart)
    user_agents = load_lines(Path(args.user_agents))
    discovery_user_agent = random.choice(user_agents)
    targets = make_scan_targets(args, discovery_user_agent)

    if len(targets) > 1:
        # Calculate selected payloads count for smart mode
        selected_count = min(args.limit or len(payloads), len(payloads)) if args.smart else len(payloads)
        print_endpoint_discovery_summary(targets, payloads, selected_count)

    findings: list[Finding] = []
    intelligence: list[TargetIntelligence] = []
    number = 0
    is_multi_endpoint = len(targets) > 1
    for idx, target in enumerate(targets):
        browser_checks_done = 0
        contexts = infer_target_contexts(target, args, user_agents) if args.smart else set()
        intel = analyze_target_intelligence(target, args, user_agents, contexts)
        intelligence.append(intel)
        selected_payloads = prioritize_payloads(payloads, contexts, args.limit) if args.smart else payloads
        if args.smart and args.exhaustive_fallback:
            ordered_payloads = prioritize_all_payloads(payloads, contexts)
            selected_set = set(selected_payloads)
            fallback_payloads = [payload for payload in ordered_payloads if payload not in selected_set]
        else:
            fallback_payloads = []
        print_scan_info(
            target, payloads, selected_payloads, args, intel, contexts,
            endpoint_index=idx + 1 if is_multi_endpoint else None,
            total_endpoints=len(targets) if is_multi_endpoint else None,
        )
        print(f"{start_tag()} will proceed in 2 seconds...")
        time.sleep(2)
        batches = [("smart", selected_payloads), ("exhaustive", fallback_payloads)]
        target_unreachable = False
        for batch_name, batch_payloads in batches:
            if target_unreachable:
                break
            if not batch_payloads:
                continue
            if batch_name == "exhaustive":
                print(f"{start_tag()} no confirmed in smart batch; continuing remaining payloads={len(batch_payloads):,}")
            for payload in iter_payloads(batch_payloads, None if args.smart else args.limit):
                number += 1
                user_agent = random.choice(user_agents)
                test_url, test_body = build_request_target(target, payload)
                http_status, body, error = request_url(
                    test_url,
                    user_agent,
                    args.timeout,
                    target.method,
                    test_body,
                    target.content_type,
                    args.verify_https,
                    args.headers,
                )
                error = normalize_request_error(error, test_url)
                if http_status is None and not body and should_stop_target_on_network_error(error):
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
                    findings.append(finding)
                    print_target_skipped(error)
                    target_unreachable = True
                    break
                reflections = analyze_reflection(body, payload) if body else []
                context_snippets = html_context_snippets(body, payload) if body and reflections else []
                browser_confirmed = False
                browser_evidence = ""
                if should_verify_with_browser(payload, reflections, args) and browser_checks_done < browser_validation_budget(payload, reflections, args):
                    browser_checks_done += 1
                    browser_confirmed, browser_evidence = confirm_with_browser(
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
                error = normalize_request_error(error, test_url)
                status = classify(reflections, browser_confirmed, error, http_status, body)
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
                findings.append(finding)
                print_result(number, finding)
                if args.stop_on_confirmed and status == "CONFIRMED":
                    return findings, intelligence
                if args.delay:
                    time.sleep(args.delay)
    return findings, intelligence
