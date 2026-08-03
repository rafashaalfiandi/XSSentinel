import contextlib
import io
import unittest
from unittest.mock import patch

from xssentinel_core.scanner import cli


class CliTests(unittest.TestCase):
    def test_parse_args_exits_when_chromium_is_missing(self) -> None:
        with patch.object(cli, "local_chromium_binary", return_value=None), \
             patch.object(cli, "print_banner"), \
             patch.object(cli.sys, "argv", ["xssentinel", "https://example.test/"]):
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as ctx:
                    cli.parse_args()

        self.assertIn("Chromium was not detected", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
