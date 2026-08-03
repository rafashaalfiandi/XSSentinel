import argparse
import unittest

from xssentinel_core.scanner.agents import AgentPlatform
from xssentinel_core.scanner.decisions import AttemptState
from xssentinel_core.scanner.models import HttpResult, ScanTarget


def agent_args(**overrides):
    values = {
        "browser": False,
        "workers": None,
        "smart": True,
        "exhaustive_fallback": True,
        "timeout": 1.0,
        "verify_https": False,
        "headers": {},
        "stop_on_confirmed": False,
        "browser_confirm_limit": 4,
        "delay": 0.0,
        "limit": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class StubServices:
    class Contexts:
        def infer(self, _target, _args, _user_agents):
            return {"html-text"}

    class Intelligence:
        def analyze(self, target, _args, _user_agents, _contexts):
            from xssentinel_core.scanner.models import CSPAnalysis, FingerprintAnalysis, ScriptAnalysis, TargetIntelligence

            return TargetIntelligence(target, 200, CSPAnalysis("", {}, [], 0), [], ScriptAnalysis(0, [], []), [], FingerprintAnalysis([], []))

    class Payloads:
        def batches(self, payloads, _contexts, _args):
            return payloads[:2], payloads[2:]

    def __init__(self):
        self.contexts = self.Contexts()
        self.intelligence = self.Intelligence()
        self.payloads = self.Payloads()


class AgentPlatformTests(unittest.TestCase):
    def test_scheduler_prioritizes_post_targets(self) -> None:
        platform = AgentPlatform()
        targets = [
            ScanTarget("GET", "https://example.test/a?x=FUZZ", None, "application/x-www-form-urlencoded", ["query:x"], "direct", 10),
            ScanTarget("POST", "https://example.test/b", "x=FUZZ", "application/x-www-form-urlencoded", ["body:x"], "high-value-form", 90),
        ]

        platform.create_plan(targets, agent_args(), 4, 2)
        scheduled = platform.scheduled_targets()

        self.assertEqual(scheduled[0].target.method, "POST")
        self.assertGreater(scheduled[0].priority, scheduled[1].priority)

    def test_decision_attaches_trace_and_updates_metrics(self) -> None:
        platform = AgentPlatform()
        target = ScanTarget("GET", "https://example.test/search?q=FUZZ", None, "application/x-www-form-urlencoded", ["query:q"], "direct", 30)
        services = StubServices()
        args = agent_args()
        platform.create_plan([target], args, 2, 1)
        contexts = platform.infer_contexts(target, args, ["unit-agent"], services)
        intel = platform.analyze_target(target, args, ["unit-agent"], contexts, services)

        decision = platform.evaluate_attempt(
            target,
            "plain",
            "https://example.test/search?q=plain",
            None,
            HttpResult(200, "no match", {"Content-Type": "text/html"}, None),
            args,
            "unit-agent",
            intel,
            "smart",
            1,
            AttemptState(),
            lambda *_args: (False, "no popup"),
        )

        self.assertEqual(decision.finding.status, "NOT_CONFIRMED")
        self.assertIn("agent_trace", decision.finding.evidence_bundle)
        self.assertGreaterEqual(platform.metrics.attempts_total, 1)

    def test_summary_records_quality_and_recommendations(self) -> None:
        platform = AgentPlatform()
        target = ScanTarget("GET", "https://example.test/search?q=FUZZ", None, "application/x-www-form-urlencoded", ["query:q"], "direct", 30)
        services = StubServices()
        args = agent_args()
        platform.create_plan([target], args, 2, 1)
        contexts = platform.infer_contexts(target, args, ["unit-agent"], services)
        intel = platform.analyze_target(target, args, ["unit-agent"], contexts, services)
        decision = platform.evaluate_attempt(
            target,
            "plain",
            "https://example.test/search?q=plain",
            None,
            HttpResult(200, "no match", {"Content-Type": "text/html"}, None),
            args,
            "unit-agent",
            intel,
            "smart",
            1,
            AttemptState(),
            lambda *_args: (False, "no popup"),
        )
        summary = platform.complete([decision.finding], args)

        self.assertGreaterEqual(summary.quality_score, 0)
        self.assertIs(summary.metrics, platform.metrics)
        self.assertTrue(summary.recommendations)


if __name__ == "__main__":
    unittest.main()
