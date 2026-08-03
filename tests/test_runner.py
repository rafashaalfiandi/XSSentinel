import os
import unittest
from unittest.mock import patch

from xssentinel_core.scanner import runner


class RunnerProgressTests(unittest.TestCase):
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
