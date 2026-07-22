"""Main scan orchestration."""

from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

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

HTTP_REJECTION_STREAK_LIMIT = 11
HTTP_REJECTION_STATUSES = {204, 304}
DEFAULT_MAX_WORKERS = 10
DEFAULT_BROWSER_MAX_WORKERS = 4
PROGRESS_FRAMES = "|/-\\"

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

def is_confirmed_status(status: str) -> bool:
    return status == "CONFIRMED"

def is_api_status(status: str) -> bool:
    return status in {"API_REFLECTED", "API_RISK"}

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

def http_skip_streak_limit(http_status: int | None) -> int:
    return HTTP_REJECTION_STREAK_LIMIT

def should_skip_target_on_http_status(http_status: int | None, body: str, reflections: list[Reflection]) -> bool:
    if http_status is None or reflections:
        return False
    if http_status in HTTP_REJECTION_STATUSES:
        return True
    return False

def skip_streak_detail(http_status: int | None, error: str | None, streak: int) -> str:
    return f"{status_skip_reason(http_status, error)} after {streak} consecutive rejected responses"

def status_skip_reason(http_status: int | None, error: str | None) -> str:
    if http_status is None:
        return error or "target is unreachable"
    labels = {
        204: "no content",
        304: "not modified",
    }
    return labels.get(http_status, "status rejected")

def scan_worker_count(args: argparse.Namespace, target_count: int) -> int:
    requested = getattr(args, "workers", None)
    if requested:
        return max(1, min(int(requested), target_count))
    default_limit = DEFAULT_BROWSER_MAX_WORKERS if getattr(args, "browser", False) else DEFAULT_MAX_WORKERS
    return max(1, min(target_count, default_limit))

def next_result_number(counter: list[int], lock: threading.Lock) -> int:
    with lock:
        counter[0] += 1
        return counter[0]

def worker_label(target_index: int, total_targets: int) -> str:
    return f"agent={target_index:02d}/{total_targets:02d}"

class ScanProgress:
    def __init__(self, print_lock: threading.Lock, total_targets: int):
        self.print_lock = print_lock
        self.total_targets = total_targets
        self.states: dict[int, str] = {}
        self.done_count = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._line_active = False
        self._thread = threading.Thread(target=self._run, name="xssentinel-progress", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=1.0)
        self.clear()

    def update(self, target_index: int, state: str) -> None:
        with self._lock:
            self.states[target_index] = state

    def done(self, target_index: int) -> None:
        with self._lock:
            if self.states.get(target_index) != "done":
                self.done_count += 1
            self.states[target_index] = "done"

    def clear(self) -> None:
        with self.print_lock:
            self.clear_locked()

    def clear_locked(self) -> None:
        if self._line_active:
            sys.stdout.write("\r" + " " * 140 + "\r")
            sys.stdout.flush()
            self._line_active = False

    def _snapshot(self) -> tuple[int, int, str]:
        with self._lock:
            active = sum(1 for state in self.states.values() if state != "done")
            done = self.done_count
            state_counts: dict[str, int] = {}
            for state in self.states.values():
                if state == "done":
                    continue
                state_counts[state] = state_counts.get(state, 0) + 1
        if state_counts:
            phases = ", ".join(f"{name}:{count}" for name, count in sorted(state_counts.items())[:4])
        else:
            phases = "waiting"
        return active, done, phases

    def _run(self) -> None:
        frame_index = 0
        while not self._stop.is_set():
            frame = PROGRESS_FRAMES[frame_index % len(PROGRESS_FRAMES)]
            frame_index += 1
            active, done, phases = self._snapshot()
            line = f"{start_tag()} scanning {frame} active={active}/{self.total_targets} done={done}/{self.total_targets} phases={phases}"
            with self.print_lock:
                sys.stdout.write("\r" + line[:140].ljust(140))
                sys.stdout.flush()
                self._line_active = True
            self._stop.wait(0.25)

def clear_progress_locked(progress: ScanProgress | None) -> None:
    if progress:
        progress.clear_locked()

def scan_target_worker(
    target: ScanTarget,
    target_index: int,
    total_targets: int,
    payloads: list[str],
    args: argparse.Namespace,
    user_agents: list[str],
    stop_event: threading.Event,
    print_lock: threading.Lock,
    number_lock: threading.Lock,
    counter: list[int],
    progress: ScanProgress | None,
) -> tuple[list[Finding], list[TargetIntelligence]]:
    findings: list[Finding] = []
    intelligence: list[TargetIntelligence] = []
    browser_checks_done = 0
    rejected_status_streak = 0
    last_rejected_status: int | None = None
    agent = worker_label(target_index, total_targets)

    with print_lock:
        clear_progress_locked(progress)
        print(
            f"{start_tag()} {agent} state=assigned "
            f"source={getattr(target, 'source', 'unknown')} method={target.method} param={first_param_name(target)}"
        )
        print(f"{start_tag()} {agent} state=analyzing")
    if progress:
        progress.update(target_index, "analysis")

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

    with print_lock:
        clear_progress_locked(progress)
        context_label = "+".join(sorted(contexts)) if contexts else "none"
        print(f"{start_tag()} {agent} state=analysis-done context={context_label}")
        print_scan_info(
            target,
            payloads,
            selected_payloads,
            args,
            intel,
            contexts,
            endpoint_index=target_index,
            total_endpoints=total_targets,
        )
        print(f"{start_tag()} {agent} state=scan-start")
    if progress:
        progress.update(target_index, "scan")

    batches = [("smart", selected_payloads), ("exhaustive", fallback_payloads)]
    target_done = False
    for batch_name, batch_payloads in batches:
        if target_done or stop_event.is_set():
            break
        if not batch_payloads:
            continue
        if batch_name == "exhaustive":
            with print_lock:
                clear_progress_locked(progress)
                print(f"{start_tag()} {agent} state=batch name={batch_name} remaining={len(batch_payloads):,}")
        else:
            with print_lock:
                clear_progress_locked(progress)
                print(f"{start_tag()} {agent} state=batch name={batch_name} selected={len(batch_payloads):,}")
        if progress:
            progress.update(target_index, batch_name)
        for payload_index, payload in enumerate(iter_payloads(batch_payloads, None if args.smart else args.limit), start=1):
            if stop_event.is_set():
                target_done = True
                break
            if payload_index == 1 or payload_index % 10 == 0:
                with print_lock:
                    clear_progress_locked(progress)
                    print(f"{start_tag()} {agent} state=progress tested={payload_index} queue={len(batch_payloads):,}")
            user_agent = random.choice(user_agents)
            test_url, test_body = build_request_target(target, payload)
            result = request_detailed(
                test_url,
                user_agent,
                args.timeout,
                target.method,
                test_body,
                target.content_type,
                args.verify_https,
                args.headers,
            )
            http_status = result.status
            body = result.body
            error = normalize_request_error(result.error, test_url)
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
                number = next_result_number(counter, number_lock)
                with print_lock:
                    clear_progress_locked(progress)
                    print_result(number, finding, agent)
                    print_target_skipped(error)
                target_done = True
                break

            reflections = analyze_reflection(body, payload) if body else []
            api_evidence = api_reflection_evidence(payload, body, result.headers, test_url) if body else ""
            download_evidence = delivered_payload_evidence(payload, body, result.headers, test_url) if body else ""
            context_snippets = html_context_snippets(body, payload) if body and (reflections or api_evidence or download_evidence) else []
            browser_confirmed = False
            delivery_evidence = download_evidence or api_evidence
            browser_evidence = delivery_evidence
            browser_needed = should_verify_with_browser(payload, reflections, args) or bool(api_evidence or download_evidence)
            if browser_needed and browser_checks_done < browser_validation_budget(payload, reflections, args):
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
                if delivery_evidence and not browser_confirmed:
                    browser_evidence = f"{delivery_evidence}; browser={browser_evidence}"
            error = normalize_request_error(error, test_url)
            rejected_response = should_skip_target_on_http_status(http_status, body, reflections)
            if rejected_response and http_status == last_rejected_status:
                rejected_status_streak += 1
            elif rejected_response:
                rejected_status_streak = 1
                last_rejected_status = http_status
            else:
                rejected_status_streak = 0
                last_rejected_status = None

            status = classify(reflections, browser_confirmed, error, http_status, body)
            if api_evidence and not browser_confirmed:
                status = "API_RISK" if reflections else "API_REFLECTED"
            elif download_evidence and not browser_confirmed:
                status = "API_RISK" if reflections else "API_REFLECTED"
            skip_streak_limit = http_skip_streak_limit(http_status)
            if rejected_response and rejected_status_streak >= skip_streak_limit:
                status = "HTTP_SKIPPED"
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
            number = next_result_number(counter, number_lock)
            with print_lock:
                clear_progress_locked(progress)
                print_result(number, finding, agent)
                if is_confirmed_status(status):
                    print(f"{start_tag()} {agent} state=confirmed payload={one_line(payload, 60)}")
                elif is_api_status(status):
                    print(f"{start_tag()} {agent} state=api-evidence evidence={one_line(browser_evidence or api_evidence or download_evidence, 60)}")
                elif status == "HTTP_SKIPPED":
                    print(f"{start_tag()} {agent} state=skip-threshold streak={rejected_status_streak}")

            if is_confirmed_status(status):
                if args.stop_on_confirmed:
                    stop_event.set()
                target_done = True
                break
            if is_api_status(status):
                target_done = True
                break
            if status == "HTTP_SKIPPED":
                with print_lock:
                    clear_progress_locked(progress)
                    print_target_skipped(skip_streak_detail(http_status, error, rejected_status_streak))
                target_done = True
                break
            if args.delay:
                time.sleep(args.delay)

    with print_lock:
        clear_progress_locked(progress)
        print(f"{start_tag()} {agent} state=done findings={len(findings)}")
    if progress:
        progress.done(target_index)

    return findings, intelligence

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

    print_scan_mode_summary(targets, args)

    findings: list[Finding] = []
    intelligence: list[TargetIntelligence] = []
    worker_count = scan_worker_count(args, len(targets))
    print(f"{start_tag()} workers={worker_count} targets={len(targets)} parallel=on")
    print(f"{start_tag()} will proceed in 2 seconds...")
    time.sleep(2)

    stop_event = threading.Event()
    print_lock = threading.Lock()
    number_lock = threading.Lock()
    counter = [0]
    progress = ScanProgress(print_lock, len(targets))
    progress.start()

    try:
        with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="xssentinel") as executor:
            futures = [
                executor.submit(
                    scan_target_worker,
                    target,
                    idx,
                    len(targets),
                    payloads,
                    args,
                    user_agents,
                    stop_event,
                    print_lock,
                    number_lock,
                    counter,
                    progress,
                )
                for idx, target in enumerate(targets, start=1)
            ]
            for future in as_completed(futures):
                target_findings, target_intelligence = future.result()
                findings.extend(target_findings)
                intelligence.extend(target_intelligence)
    finally:
        progress.stop()
    return findings, intelligence
