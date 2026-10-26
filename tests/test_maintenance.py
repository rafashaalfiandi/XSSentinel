import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from xssentinel_core.scanner import maintenance


class MaintenanceTests(unittest.TestCase):
    def test_update_preservation_skips_clean_source(self) -> None:
        source = Path("/tmp/xssentinel-source")

        with patch.object(maintenance, "run_git", return_value="") as run_git:
            stash_commit = maintenance.preserve_local_update_changes(source)

        self.assertIsNone(stash_commit)
        run_git.assert_called_once_with(["status", "--porcelain", "--untracked-files=all"], source)

    def test_update_preservation_stashes_local_edits_and_untracked_files(self) -> None:
        source = Path("/tmp/xssentinel-source")
        outputs = iter([" M main.py\n?? notes.txt", ""])
        calls = []
        marker = ""

        def fake_run_git(args, cwd=None):
            nonlocal marker
            calls.append((args, cwd))
            if args[:2] == ["stash", "push"]:
                marker = args[-1]
                return "Saved working directory and index state"
            if args[:2] == ["stash", "list"]:
                return "a" * 40 + "\t" + marker
            return next(outputs)

        with patch.object(maintenance, "run_git", side_effect=fake_run_git):
            stash_commit = maintenance.preserve_local_update_changes(source)

        self.assertEqual(stash_commit, "a" * 40)
        self.assertEqual(calls[0], (["status", "--porcelain", "--untracked-files=all"], source))
        self.assertEqual(calls[1][0][:3], ["stash", "push", "--include-untracked"])
        self.assertIn(maintenance.AUTO_STASH_PREFIX, calls[1][0][-1])
        self.assertEqual(calls[2], (["status", "--porcelain", "--untracked-files=all"], source))
        self.assertEqual(calls[3], (["stash", "list", "--format=%H%x09%gs", "-1"], source))

    def test_update_preservation_stops_if_changes_remain_after_stash(self) -> None:
        source = Path("/tmp/xssentinel-source")
        outputs = iter([" M main.py", " M main.py"])

        def fake_run_git(args, _cwd=None):
            if args[0] == "stash":
                return "saved"
            return next(outputs)

        with patch.object(maintenance, "run_git", side_effect=fake_run_git):
            with self.assertRaises(SystemExit) as raised:
                maintenance.preserve_local_update_changes(source)

        self.assertIn("Could not safely update", str(raised.exception))

    def test_git_sync_preserves_changes_before_fetch_and_pull(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp)
            (source / ".git").mkdir()
            (source / "main.py").write_text("# fixture\n", encoding="utf-8")
            (source / "xssentinel_core").mkdir()
            git_calls = []

            def fake_run_git(args, cwd=None):
                git_calls.append((args, cwd))
                return ""

            with (
                patch.dict(os.environ, {"XSSENTINEL_UPDATE_DIR": str(source)}, clear=False),
                patch.object(maintenance, "git_current_branch", return_value="main"),
                patch.object(maintenance, "preserve_local_update_changes", return_value="a" * 40) as preserve,
                patch.object(maintenance, "run_git", side_effect=fake_run_git),
            ):
                output = StringIO()
                with redirect_stdout(output):
                    resolved = maintenance.sync_git_source()

            self.assertEqual(resolved, source)
            preserve.assert_called_once_with(source)
            self.assertEqual([call[0] for call in git_calls], [
                ["fetch", "--prune", "origin"],
                ["checkout", "main"],
                ["pull", "--ff-only", "origin", "main"],
            ])
            self.assertIn("git stash apply", output.getvalue())

    def test_clean_pycache_removes_nested_cache_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a" / "__pycache__").mkdir(parents=True)
            (root / "b" / "__pycache__").mkdir(parents=True)

            removed = maintenance.clean_pycache(root)

            self.assertEqual(removed, 2)
            self.assertFalse((root / "a" / "__pycache__").exists())
            self.assertFalse((root / "b" / "__pycache__").exists())

    def test_resolve_update_source_prefers_marker_when_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            (source / "main.py").write_text("print('ok')\n", encoding="utf-8")
            (source / "xssentinel_core").mkdir()
            marker = root / "marker"
            marker.write_text(str(source) + "\n", encoding="utf-8")

            with patch.object(maintenance, "SOURCE_MARKER", marker), patch.dict(os.environ, {}, clear=True):
                resolved = maintenance.resolve_update_source()

            self.assertEqual(resolved, source)


if __name__ == "__main__":
    unittest.main()
