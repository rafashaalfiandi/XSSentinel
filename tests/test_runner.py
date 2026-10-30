import os
from concurrent.futures import Future
import unittest
from unittest.mock import patch

from xssentinel_core.scanner import runner
from xssentinel_core.scanner.models import ScanTarget


class RunnerProgressTests(unittest.TestCase):
    def test_worker_limits_are_environment_configurable_and_clamped(self) -> None:
        args = type("Args", (), {"workers": None, "browser": False})()
        with patch.dict(os.environ, {"XSSENTINEL_MAX_WORKERS": "1000"}, clear=False):
            self.assertEqual(runner.scan_worker_count(args, 50), 32)
        args.browser = True
        with patch.dict(os.environ, {"XSSENTINEL_BROWSER_WORKERS": "2"}, clear=False):
            self.assertEqual(runner.scan_worker_count(args, 50), 2)

    def test_worker_exception_isolated_as_sanitized_inconclusive_finding(self) -> None:
        target = ScanTarget("GET", "https://fixture.test/?q=FUZZ", None, "application/x-www-form-urlencoded", ["query:q"])

        finding = runner.worker_exception_finding(target, RuntimeError("Authorization: Bearer secret-value"))

        self.assertEqual(finding.status, "NETWORK_ERROR")
        self.assertEqual(finding.xti_status, "INCONCLUSIVE")
        self.assertIn("RuntimeError", finding.error)
        self.assertNotIn("secret-value", finding.error)

    def test_failed_worker_future_is_returned_as_partial_result(self) -> None:
        target = ScanTarget("GET", "https://fixture.test/?q=FUZZ", None, "application/x-www-form-urlencoded", ["query:q"])
        future = Future()
        future.set_exception(RuntimeError("private exception detail"))

        findings, intelligence = runner.resolve_target_future(future, target)

        self.assertEqual(len(findings), 1)
        self.assertEqual(intelligence, [])
        self.assertNotIn("private exception detail", findings[0].error)

    def test_progress_line_uses_terminal_width_without_padding_wrap(self) -> None:
        line = f"{runner.start_tag()} scanning | active=1/1 done=0/1 phases=analysis:1"

        with patch.object(runner.shutil, "get_terminal_size", return_value=os.terminal_size((40, 20))):
            rendered = "\r\x1b[2K" + runner.truncate_visible(line, runner.terminal_content_width())

        visible = runner.ANSI_RE.sub("", rendered.replace("\r", ""))
        self.assertLessEqual(len(visible), 39)
        self.assertNotIn(" " * 20, rendered)

    def test_clear_progress_uses_terminal_clear_sequence(self) -> None:
        progress = runner.ScanProgress.__new__(runner.ScanProgress)
        progress._line_active = True
        writes: list[str] = []

        class Stdout:
            def write(self, value: str) -> None:
                writes.append(value)

            def flush(self) -> None:
                return None

        with patch.object(runner.sys, "stdout", Stdout()):
            runner.ScanProgress.clear_locked(progress)

        self.assertEqual(writes, ["\r\x1b[2K"])
        self.assertFalse(progress._line_active)

    def test_finish_progress_line_adds_newline(self) -> None:
        progress = runner.ScanProgress.__new__(runner.ScanProgress)
        progress._line_active = True
        writes: list[str] = []

        class Stdout:
            def write(self, value: str) -> None:
                writes.append(value)

            def flush(self) -> None:
                return None

        with patch.object(runner.sys, "stdout", Stdout()):
            runner.ScanProgress.finish_line_locked(progress)

        self.assertEqual(writes, ["\n"])
        self.assertFalse(progress._line_active)


if __name__ == "__main__":
    unittest.main()
