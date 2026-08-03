"""Main scan orchestration."""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import re
import shutil
import sys
import threading
import time
from pathlib import Path
from typing import Iterable

from .agents import AgentPlatform, ExecutionTask
from .decisions import AttemptState, is_api_status, is_confirmed_status
from .models import Finding, ScanTarget, TargetIntelligence
from .output import (
    first_param_name,
    print_endpoint_discovery_summary,
    print_result,
    print_scan_info,
    print_scan_mode_summary,
    print_target_skipped,
    start_tag,
)
from .payloads import expand_payloads
from .services import ScanServices
from .targets import build_request_target
from .utils import load_lines, one_line, unique_lines

DEFAULT_MAX_WORKERS = 10
DEFAULT_BROWSER_MAX_WORKERS = 4
PROGRESS_FRAMES = "|/-\\"
ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def terminal_content_width(fallback: int = 80) -> int:
    columns = shutil.get_terminal_size((fallback, 20)).columns
    return max(20, columns - 1)


def visible_len(text: str) -> int:
    return len(ANSI_RE.sub("", text))


def truncate_visible(text: str, width: int) -> str:
    if visible_len(text) <= width:
        return text
    output: list[str] = []
    visible = 0
    index = 0
    while index < len(text) and visible < width:
        match = ANSI_RE.match(text, index)
        if match:
            output.append(match.group(0))
            index = match.end()
            continue
        output.append(text[index])
        visible += 1
        index += 1
    return "".join(output)

def iter_payloads(payloads: list[str], limit: int | None) -> Iterable[str]:
    for index, payload in enumerate(payloads, start=1):
        if limit and index > limit:
            break
        yield payload

def scan_worker_count(args: argparse.Namespace, target_count: int) -> int:
    requested = getattr(args, "workers", None)
    if requested:
        return max(1, min(int(requested), target_count))
    default_limit = DEFAULT_BROWSER_MAX_WORKERS if getattr(args, "browser", False) else DEFAULT_MAX_WORKERS
    return max(1, min(target_count, default_limit))


def worker_count_from_plan(args: argparse.Namespace, target_count: int, platform: AgentPlatform | None = None) -> int:
    if platform and platform.plan:
        return platform.plan.worker_count
    return scan_worker_count(args, target_count)

def next_result_number(counter: list[int], lock: threading.Lock) -> int:
    with lock:
        counter[0] += 1
        return counter[0]

def worker_label(target_index: int, total_targets: int) -> str:
    return f"agent={target_index:02d}/{total_targets:02d}"


def load_payload_catalog(args: argparse.Namespace) -> list[str]:
    payload_path = Path(args.payloads)
    base_payloads = load_lines(payload_path)
    if payload_path.name == "smart-selected-180-payloads.txt":
        return unique_lines(base_payloads)
    return expand_payloads(base_payloads, args.smart)


def selected_payload_count(payloads: list[str], args: argparse.Namespace) -> int:
    if not args.smart:
        return len(payloads)
    return min(args.limit or len(payloads), len(payloads))


def print_discovery_summary(targets: list[ScanTarget], payloads: list[str], args: argparse.Namespace) -> None:
    if len(targets) > 1:
        print_endpoint_discovery_summary(targets, payloads, selected_payload_count(payloads, args))
    print_scan_mode_summary(targets, args)

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
            sys.stdout.write("\r\x1b[2K")
            sys.stdout.flush()
            self._line_active = False

    def finish_line_locked(self) -> None:
        if self._line_active:
            sys.stdout.write("\n")
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
            line = (
                f"{start_tag()} scanning {frame} active={active}/{self.total_targets} "
                f"done={done}/{self.total_targets} phases={phases}"
            )
            with self.print_lock:
                sys.stdout.write("\r\x1b[2K" + truncate_visible(line, terminal_content_width()))
                sys.stdout.flush()
                self._line_active = True
            self._stop.wait(0.25)

def clear_progress_locked(progress: ScanProgress | None) -> None:
    if progress:
        progress.clear_locked()


def finish_progress_line_locked(progress: ScanProgress | None) -> None:
    if progress:
        progress.finish_line_locked()


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
    services: ScanServices,
    platform: AgentPlatform,
) -> tuple[list[Finding], list[TargetIntelligence]]:
    findings: list[Finding] = []
    intelligence: list[TargetIntelligence] = []
    state = AttemptState()
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

    contexts = platform.infer_contexts(target, args, user_agents, services)
    services.lifecycle.before_target(target, contexts)
    intel = platform.analyze_target(target, args, user_agents, contexts, services)
    intelligence.append(intel)
    selected_payloads, fallback_payloads = platform.payload_batches(payloads, contexts, args, services)

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
            result = services.http.request(
                test_url,
                user_agent,
                args.timeout,
                target.method,
                test_body,
                target.content_type,
                args.verify_https,
                args.headers,
            )
            decision = platform.evaluate_attempt(
                target,
                payload,
                test_url,
                test_body,
                result,
                args,
                user_agent,
                intel,
                batch_name,
                payload_index,
                state,
                services.browser.validate,
            )
            state = decision.state
            finding = decision.finding
            findings.append(finding)
            services.lifecycle.after_finding(finding)
            number = next_result_number(counter, number_lock)
            with print_lock:
                clear_progress_locked(progress)
                print_result(number, finding, agent)
                status = finding.status
                if is_confirmed_status(status):
                    print(f"{start_tag()} {agent} state=confirmed payload={one_line(payload, 60)}")
                elif is_api_status(status):
                    print(f"{start_tag()} {agent} state=api-evidence evidence={one_line(finding.browser_evidence, 60)}")
                elif status == "HTTP_SKIPPED":
                    print(f"{start_tag()} {agent} state=skip-threshold streak={finding.diagnostics.rejected_status_streak if finding.diagnostics else 0}")
                elif status == "NETWORK_ERROR":
                    print_target_skipped(finding.error)

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
                    print_target_skipped(finding.diagnostics.skip_reason if finding.diagnostics else "")
                target_done = True
                break
            if decision.target_done:
                if decision.stop_all_targets:
                    stop_event.set()
                target_done = True
                break
            if args.delay:
                time.sleep(args.delay)

    with print_lock:
        clear_progress_locked(progress)
        print(f"{start_tag()} {agent} state=done findings={len(findings)}")
    if progress:
        progress.done(target_index)
    services.lifecycle.after_target(target, findings)
    platform.evaluate_stage(f"target-{target_index:02d}", findings)

    return findings, intelligence


def run_target_workers(
    targets: list[ScanTarget],
    payloads: list[str],
    args: argparse.Namespace,
    user_agents: list[str],
    services: ScanServices,
    progress: ScanProgress,
    print_lock: threading.Lock,
    platform: AgentPlatform,
) -> tuple[list[Finding], list[TargetIntelligence]]:
    findings: list[Finding] = []
    intelligence: list[TargetIntelligence] = []
    worker_count = worker_count_from_plan(args, len(targets), platform)
    with print_lock:
        finish_progress_line_locked(progress)
        print(f"{start_tag()} workers={worker_count} targets={len(targets)} parallel=on")
        print(f"{start_tag()} will proceed in 2 seconds...")
    time.sleep(2)

    stop_event = threading.Event()
    number_lock = threading.Lock()
    counter = [0]
    scheduled_tasks = platform.scheduled_targets() or [ExecutionTask(f"target-{idx:02d}", idx, target, 100, "legacy-order") for idx, target in enumerate(targets, start=1)]

    with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="xssentinel") as executor:
        futures = [
            executor.submit(
                scan_target_worker,
                task.target,
                task.target_index,
                len(targets),
                payloads,
                args,
                user_agents,
                stop_event,
                print_lock,
                number_lock,
                counter,
                progress,
                services,
                platform,
            )
            for task in scheduled_tasks
        ]
        for future in as_completed(futures):
            target_findings, target_intelligence = future.result()
            findings.extend(target_findings)
            intelligence.extend(target_intelligence)
    return findings, intelligence


def scan(args: argparse.Namespace, services: ScanServices | None = None) -> tuple[list[Finding], list[TargetIntelligence]]:
    services = services or ScanServices.defaults()
    platform = AgentPlatform()
    payloads = load_payload_catalog(args)
    user_agents = load_lines(Path(args.user_agents))
    discovery_user_agent = random.choice(user_agents)
    targets = services.target_discovery.discover(args, discovery_user_agent)
    platform.create_plan(targets, args, DEFAULT_MAX_WORKERS, DEFAULT_BROWSER_MAX_WORKERS, services.config)
    services.lifecycle.before_scan(args, targets)
    print_discovery_summary(targets, payloads, args)

    print_lock = threading.Lock()
    progress = ScanProgress(print_lock, len(targets))
    progress.start()
    try:
        findings, intelligence = run_target_workers(targets, payloads, args, user_agents, services, progress, print_lock, platform)
    finally:
        progress.stop()
    services.lifecycle.after_scan(findings, intelligence)
    platform.evaluate_stage("scan", findings)
    platform.complete(findings, args)
    return findings, intelligence
