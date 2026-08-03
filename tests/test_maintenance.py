import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from xssentinel_core.scanner import maintenance


class MaintenanceTests(unittest.TestCase):
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
