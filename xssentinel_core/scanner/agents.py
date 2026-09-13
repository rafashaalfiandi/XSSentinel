"""Agent runtime for intelligent scan orchestration.

The scanner still exposes the same public CLI and service interfaces. This
module adds an internal multi-agent control plane around those services so scan
execution can be planned, traced, evaluated, and extended without hard-coding a
single procedural path through the runner.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from .decisions import AttemptDecision, AttemptState, BrowserValidator, evaluate_scan_attempt
from .models import Finding, HttpResult, ScanTarget, TargetIntelligence


def _now() -> float:
    return time.perf_counter()


def _stable_hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


@dataclass(frozen=True)
class AgentMessage:
    """Structured agent output emitted for traceability."""

    agent: str
    stage: str
    decision: str
    confidence: int
    rationale: str
    data: dict[str, object] = field(default_factory=dict)
    elapsed_ms: float = 0.0


@dataclass(frozen=True)
class AgentEvaluation:
    """Self-evaluation result after an important execution stage."""

    stage: str
    score: int
    passed: bool
    rationale: str
    recommendations: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ExecutionTask:
    """Schedulable unit of scanner work."""

    task_id: str
    target_index: int
    target: ScanTarget
    priority: int
    reason: str
    estimated_cost: int = 1


@dataclass(frozen=True)
class ExecutionPlan:
    """Dynamic scan plan created from runtime context."""

    plan_id: str
    mode: str
    tasks: list[ExecutionTask]
    worker_count: int
    retry_limit: int
    confidence_threshold: int
    rationale: str
    recommendations: list[str] = field(default_factory=list)


@dataclass
class RuntimeMetrics:
    """Mutable metrics collected by the agent runtime."""

    started_at: float = field(default_factory=_now)
    finished_at: float | None = None
    targets_total: int = 0
    attempts_total: int = 0
    findings_total: int = 0
    confirmed_total: int = 0
    api_signal_total: int = 0
    network_errors: int = 0
    retries: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    stage_ms: dict[str, float] = field(default_factory=dict)

    @property
    def elapsed_ms(self) -> float:
        end = self.finished_at or _now()
        return round((end - self.started_at) * 1000, 2)


@dataclass(frozen=True)
class ExecutionSummary:
    """Final structured summary produced by the reporting agent."""

    quality_score: int
    confidence: int
    metrics: RuntimeMetrics
    evaluations: list[AgentEvaluation]
    recommendations: list[str]


class Agent(Protocol):
    name: str


class TraceRecorder:
    """Thread-safe enough trace recorder for scanner worker callbacks."""

    def __init__(self) -> None:
        self.messages: list[AgentMessage] = []
        self.evaluations: list[AgentEvaluation] = []

    def emit(
        self,
        agent: str,
        stage: str,
        decision: str,
        confidence: int,
        rationale: str,
        data: dict[str, object] | None = None,
        elapsed_ms: float = 0.0,
    ) -> AgentMessage:
        message = AgentMessage(agent, stage, decision, max(0, min(100, confidence)), rationale, data or {}, elapsed_ms)
        self.messages.append(message)
        return message

    def evaluate(self, evaluation: AgentEvaluation) -> AgentEvaluation:
        self.evaluations.append(evaluation)
        return evaluation


class IntelligentCache:
    """Small reusable in-memory cache for expensive per-target analysis."""

    def __init__(self, metrics: RuntimeMetrics) -> None:
        self._values: dict[str, object] = {}
        self.metrics = metrics
        self.enabled = True

    def get_or_create(self, namespace: str, key_data: object, factory: Callable[[], object]) -> object:
        if not self.enabled:
            self.metrics.cache_misses += 1
            return factory()
        key = f"{namespace}:{_stable_hash(key_data)}"
        if key in self._values:
            self.metrics.cache_hits += 1
            return self._values[key]
        self.metrics.cache_misses += 1
        value = factory()
        self._values[key] = value
        return value


class RetryPolicy:
    """Resource-aware retry wrapper for recoverable internal operations."""

    def __init__(self, retries: int, metrics: RuntimeMetrics, trace: TraceRecorder) -> None:
        self.retries = max(0, retries)
        self.metrics = metrics
        self.trace = trace

    def run(self, label: str, action: Callable[[], object]) -> object:
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                return action()
            except Exception as exc:  # noqa: BLE001 - policy records and retries extension failures.
                last_error = exc
                if attempt >= self.retries:
                    break
                self.metrics.retries += 1
                self.trace.emit("Diagnostics Agent", label, "retry", 55, str(exc), {"attempt": attempt + 1})
        assert last_error is not None
        raise last_error


class ContextAnalyzerAgent:
    name = "Context Analyzer"

    def analyze(self, target: ScanTarget, args: argparse.Namespace, user_agents: list[str], services: Any, cache: IntelligentCache, trace: TraceRecorder) -> set[str]:
        started = _now()
        contexts = cache.get_or_create(
            "contexts",
            {"url": target.url, "method": target.method, "smart": getattr(args, "smart", False)},
            lambda: services.contexts.infer(target, args, user_agents),
        )
        result = set(contexts)
        confidence = 80 if result else 55
        trace.emit(self.name, "context", "contexts-inferred", confidence, "target context selected for payload planning", {"contexts": sorted(result)}, (_now() - started) * 1000)
        return result


class DataInterpreterAgent:
    name = "Data Interpreter"

    def analyze(self, target: ScanTarget, args: argparse.Namespace, user_agents: list[str], contexts: set[str], services: Any, cache: IntelligentCache, trace: TraceRecorder) -> TargetIntelligence:
        started = _now()
        intel = cache.get_or_create(
            "intelligence",
            {"url": target.url, "method": target.method, "contexts": sorted(contexts)},
            lambda: services.intelligence.analyze(target, args, user_agents, contexts),
        )
        assert isinstance(intel, TargetIntelligence)
        signals = len(intel.waf_signals) + len(intel.recommendations) + len(intel.script_analysis.suspicious_scripts)
        trace.emit(self.name, "intelligence", "target-profiled", min(95, 60 + signals * 5), "CSP, WAF, script, and fingerprint signals interpreted", {"signals": signals}, (_now() - started) * 1000)
        return intel


class ResourceManagerAgent:
    name = "Resource Manager"

    def workers(self, args: argparse.Namespace, target_count: int, default_workers: int, browser_workers: int) -> int:
        requested = getattr(args, "workers", None)
        if requested:
            return max(1, min(int(requested), target_count))
        default_limit = browser_workers if getattr(args, "browser", False) else default_workers
        return max(1, min(target_count, default_limit))

    def retry_limit(self, args: argparse.Namespace, runtime_config: Any | None = None) -> int:
        configured = getattr(getattr(runtime_config, "agent", None), "retry_limit", None)
        if configured is not None:
            return max(0, int(configured))
        if getattr(args, "browser", False):
            return 1
        return 0

    def confidence_threshold(self, runtime_config: Any | None = None) -> int:
        configured = getattr(getattr(runtime_config, "agent", None), "confidence_threshold", 70)
        return max(1, min(100, int(configured)))


class PlanningAgent:
    name = "Planning Agent"

    def plan(self, targets: list[ScanTarget], args: argparse.Namespace, worker_count: int, retry_limit: int, confidence_threshold: int, trace: TraceRecorder) -> ExecutionPlan:
        started = _now()
        tasks: list[ExecutionTask] = []
        for index, target in enumerate(targets, start=1):
            source = getattr(target, "source", "unknown")
            priority = 100
            if target.method == "POST":
                priority += 25
            if source in {"high-value-form", "graphql", "fetch", "xhr", "axios"}:
                priority += 20
            if getattr(target, "discovery_confidence", 0):
                priority += int(target.discovery_confidence / 5)
            task_id = f"target-{index:02d}-{_stable_hash([target.method, target.url, target.data])}"
            tasks.append(ExecutionTask(task_id, index, target, priority, f"source={source} method={target.method}"))
        mode = "adaptive-browser" if getattr(args, "browser", False) else "adaptive-http"
        plan = ExecutionPlan(
            _stable_hash([task.task_id for task in tasks]),
            mode,
            tasks,
            worker_count,
            retry_limit,
            confidence_threshold,
            "prioritized targets by method, discovery signal, and available validation resources",
        )
        trace.emit(self.name, "planning", "plan-created", 85 if tasks else 20, plan.rationale, {"tasks": len(tasks), "workers": worker_count, "mode": mode}, (_now() - started) * 1000)
        return plan


class TaskSchedulerAgent:
    name = "Task Scheduler"

    def schedule(self, plan: ExecutionPlan, trace: TraceRecorder) -> list[ExecutionTask]:
        tasks = sorted(plan.tasks, key=lambda task: (-task.priority, task.target_index))
        trace.emit(self.name, "scheduling", "tasks-scheduled", 82, "highest-value targets are scheduled first while preserving stable tie ordering", {"task_ids": [task.task_id for task in tasks[:8]]})
        return tasks


class StrategyManagerAgent:
    name = "Strategy Manager"

    def batches(self, payloads: list[str], contexts: set[str], args: argparse.Namespace, services: Any, trace: TraceRecorder) -> tuple[list[str], list[str]]:
        selected, fallback = services.payloads.batches(payloads, contexts, args)
        rationale = "smart contextual payload selection" if getattr(args, "smart", False) else "explicit payload catalog order"
        trace.emit(self.name, "strategy", "payload-batches-selected", 78 if selected else 25, rationale, {"selected": len(selected), "fallback": len(fallback), "contexts": sorted(contexts)})
        return selected, fallback


class DecisionEngineAgent:
    name = "Decision Engine"

    def evaluate(
        self,
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
        trace: TraceRecorder,
    ) -> AttemptDecision:
        started = _now()
        decision = evaluate_scan_attempt(target, payload, test_url, test_body, result, args, user_agent, intel, batch_name, payload_index, state, browser_validator)
        finding = decision.finding
        rationale = "classified response from reflection, browser, API, delivery, HTTP, and error evidence"
        trace.emit(self.name, "decision", finding.status, finding.confidence or 50, rationale, {"batch": batch_name, "payload_index": payload_index, "target_done": decision.target_done}, (_now() - started) * 1000)
        return decision


class EvidenceManagerAgent:
    name = "Evidence Manager"

    def attach_trace(self, finding: Finding, trace: TraceRecorder) -> None:
        recent = trace.messages[-12:]
        bundle = dict(finding.evidence_bundle or {})
        bundle["agent_trace"] = [message.__dict__ for message in recent]
        bundle["decision_explanation"] = next((message.rationale for message in reversed(recent) if message.agent == "Decision Engine"), "")
        finding.evidence_bundle = bundle


class ValidationAgent:
    name = "Validation Agent"

    def evaluate_stage(self, stage: str, findings: list[Finding], trace: TraceRecorder) -> AgentEvaluation:
        meaningful = sum(1 for finding in findings if finding.status not in {"NOT_CONFIRMED", "NETWORK_ERROR"})
        errors = sum(1 for finding in findings if finding.status == "NETWORK_ERROR")
        score = max(0, min(100, 70 + meaningful * 5 - errors * 10))
        evaluation = AgentEvaluation(stage, score, score >= 60, "stage quality scored from signal yield and recoverable error rate")
        return trace.evaluate(evaluation)


class QualityAssuranceAgent:
    name = "Quality Assurance Agent"

    def quality_score(self, findings: list[Finding], evaluations: list[AgentEvaluation]) -> int:
        if not findings and not evaluations:
            return 0
        confidence = [finding.confidence for finding in findings if finding.confidence]
        base = int(sum(confidence) / len(confidence)) if confidence else 55
        eval_score = int(sum(item.score for item in evaluations) / len(evaluations)) if evaluations else 60
        return max(0, min(100, int(base * 0.6 + eval_score * 0.4)))


class DiagnosticsAgent:
    name = "Diagnostics Agent"

    def diagnose(self, findings: list[Finding], trace: TraceRecorder) -> list[str]:
        recommendations: list[str] = []
        network_errors = sum(1 for finding in findings if finding.status == "NETWORK_ERROR")
        skipped = sum(1 for finding in findings if finding.status == "HTTP_SKIPPED")
        if network_errors:
            recommendations.append("Review target reachability, DNS, proxy, timeout, and HTTPS verification settings.")
        if skipped:
            recommendations.append("Reduce rejected responses by validating cache-control headers or choosing a more interactive endpoint.")
        trace.emit(self.name, "diagnostics", "diagnostics-complete", 75, "automatic diagnostics generated from terminal finding states", {"network_errors": network_errors, "http_skipped": skipped})
        return recommendations


class PerformanceOptimizerAgent:
    name = "Performance Optimizer"

    def recommendations(self, metrics: RuntimeMetrics, plan: ExecutionPlan, trace: TraceRecorder) -> list[str]:
        recommendations: list[str] = []
        if metrics.cache_hits > metrics.cache_misses:
            recommendations.append("Current target mix benefits from analysis caching; preserve shared context reuse.")
        if plan.worker_count <= 1 and metrics.targets_total > 1:
            recommendations.append("Increase workers for multi-target scans when target rate limits permit it.")
        if metrics.elapsed_ms > 0 and metrics.attempts_total:
            rate = round(metrics.attempts_total / max(metrics.elapsed_ms / 1000, 0.001), 2)
            trace.emit(self.name, "performance", "metrics-collected", 80, "attempt throughput and worker plan measured", {"attempts_per_second": rate, "elapsed_ms": metrics.elapsed_ms})
        return recommendations


class ConfigurationAdvisorAgent:
    name = "Configuration Advisor"

    def recommendations(self, args: argparse.Namespace, plan: ExecutionPlan, trace: TraceRecorder) -> list[str]:
        recommendations: list[str] = []
        if not getattr(args, "browser", False):
            recommendations.append("Enable browser validation when executable XSS proof is required.")
        if getattr(args, "smart", False) and not getattr(args, "exhaustive_fallback", False):
            recommendations.append("Enable exhaustive fallback for higher coverage on low-confidence targets.")
        trace.emit(self.name, "configuration", "configuration-reviewed", 72, "runtime options reviewed against plan and validation goals", {"recommendations": len(recommendations), "plan": plan.mode})
        return recommendations


class LearningFeedbackAgent:
    name = "Learning & Feedback Agent"

    def record(self, summary: ExecutionSummary, trace: TraceRecorder) -> None:
        trace.emit(self.name, "learning", "history-recorded", summary.confidence, "execution history retained in runtime trace for future plugin persistence", {"quality_score": summary.quality_score})


class ReportingAgent:
    name = "Reporting Agent"

    def summarize(self, findings: list[Finding], metrics: RuntimeMetrics, evaluations: list[AgentEvaluation], recommendations: list[str], qa: QualityAssuranceAgent, trace: TraceRecorder) -> ExecutionSummary:
        quality = qa.quality_score(findings, evaluations)
        confidence = max(0, min(100, int((quality + (evaluations[-1].score if evaluations else 60)) / 2)))
        summary = ExecutionSummary(quality, confidence, metrics, list(evaluations), recommendations)
        trace.emit(self.name, "reporting", "summary-created", confidence, "final execution summary assembled from metrics, evaluations, and diagnostics", {"quality_score": quality, "recommendations": len(recommendations)})
        return summary


class AgentPlatform:
    """Facade used by the runner to coordinate specialized agents."""

    def __init__(self) -> None:
        self.trace = TraceRecorder()
        self.metrics = RuntimeMetrics()
        self.cache = IntelligentCache(self.metrics)
        self.context_analyzer = ContextAnalyzerAgent()
        self.data_interpreter = DataInterpreterAgent()
        self.resource_manager = ResourceManagerAgent()
        self.planning = PlanningAgent()
        self.scheduler = TaskSchedulerAgent()
        self.strategy = StrategyManagerAgent()
        self.decision_engine = DecisionEngineAgent()
        self.evidence = EvidenceManagerAgent()
        self.validation = ValidationAgent()
        self.qa = QualityAssuranceAgent()
        self.diagnostics = DiagnosticsAgent()
        self.performance = PerformanceOptimizerAgent()
        self.config_advisor = ConfigurationAdvisorAgent()
        self.learning = LearningFeedbackAgent()
        self.reporting = ReportingAgent()
        self.plan: ExecutionPlan | None = None
        self.retry_policy = RetryPolicy(0, self.metrics, self.trace)

    def create_plan(self, targets: list[ScanTarget], args: argparse.Namespace, default_workers: int, browser_workers: int, runtime_config: Any | None = None) -> ExecutionPlan:
        self.metrics.targets_total = len(targets)
        worker_count = self.resource_manager.workers(args, len(targets), default_workers, browser_workers)
        retry_limit = self.resource_manager.retry_limit(args, runtime_config)
        confidence_threshold = self.resource_manager.confidence_threshold(runtime_config)
        self.cache.enabled = bool(getattr(getattr(runtime_config, "agent", None), "enable_cache", True))
        self.retry_policy = RetryPolicy(retry_limit, self.metrics, self.trace)
        self.plan = self.planning.plan(targets, args, worker_count, retry_limit, confidence_threshold, self.trace)
        return self.plan

    def scheduled_targets(self) -> list[ExecutionTask]:
        if self.plan is None:
            return []
        return self.scheduler.schedule(self.plan, self.trace)

    def infer_contexts(self, target: ScanTarget, args: argparse.Namespace, user_agents: list[str], services: Any) -> set[str]:
        return self.context_analyzer.analyze(target, args, user_agents, services, self.cache, self.trace)

    def analyze_target(self, target: ScanTarget, args: argparse.Namespace, user_agents: list[str], contexts: set[str], services: Any) -> TargetIntelligence:
        return self.data_interpreter.analyze(target, args, user_agents, contexts, services, self.cache, self.trace)

    def payload_batches(self, payloads: list[str], contexts: set[str], args: argparse.Namespace, services: Any) -> tuple[list[str], list[str]]:
        return self.strategy.batches(payloads, contexts, args, services, self.trace)

    def evaluate_attempt(self, *args: Any, **kwargs: Any) -> AttemptDecision:
        self.metrics.attempts_total += 1
        browser_validator = args[-1]
        if callable(browser_validator):
            def retriable_validator(*validator_args: Any, **validator_kwargs: Any) -> tuple[bool, str]:
                return self.retry_policy.run(
                    "browser-validation",
                    lambda: browser_validator(*validator_args, **validator_kwargs),
                )  # type: ignore[return-value]

            args = (*args[:-1], retriable_validator)
        decision = self.decision_engine.evaluate(*args, trace=self.trace, **kwargs)
        finding = decision.finding
        self.metrics.findings_total += 1
        if finding.status == "CONFIRMED":
            self.metrics.confirmed_total += 1
        if finding.status in {"API_REFLECTED", "API_RISK"}:
            self.metrics.api_signal_total += 1
        if finding.status == "NETWORK_ERROR":
            self.metrics.network_errors += 1
        self.evidence.attach_trace(finding, self.trace)
        return decision

    def evaluate_stage(self, stage: str, findings: list[Finding]) -> AgentEvaluation:
        return self.validation.evaluate_stage(stage, findings, self.trace)

    def complete(self, findings: list[Finding], args: argparse.Namespace) -> ExecutionSummary:
        self.metrics.finished_at = _now()
        if self.plan is None:
            self.plan = ExecutionPlan("none", "unplanned", [], 1, 0, 70, "scan completed without explicit plan")
        recommendations = []
        recommendations.extend(self.diagnostics.diagnose(findings, self.trace))
        recommendations.extend(self.performance.recommendations(self.metrics, self.plan, self.trace))
        recommendations.extend(self.config_advisor.recommendations(args, self.plan, self.trace))
        summary = self.reporting.summarize(findings, self.metrics, self.trace.evaluations, recommendations, self.qa, self.trace)
        self.learning.record(summary, self.trace)
        return summary
