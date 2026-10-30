import contextlib
import io
import unittest
from types import SimpleNamespace
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

    def test_parse_args_accepts_json_report_path_without_changing_target(self) -> None:
        with patch.object(cli, "local_chromium_binary", return_value="/fixture/chromium"), \
             patch.object(cli, "print_banner"), \
             patch.object(cli, "print_ready"), \
             patch.object(cli.sys, "argv", ["xssentinel", "--json-report", "out.json", "https://example.test/?q=x"]):
            args = cli.parse_args()

        self.assertEqual(args.json_report, "out.json")
        self.assertEqual(args.url, "https://example.test/?q=x")
        self.assertTrue(args.verify_https)

    def test_parse_args_accepts_inline_json_report_path(self) -> None:
        with patch.object(cli, "local_chromium_binary", return_value="/fixture/chromium"), \
             patch.object(cli, "print_banner"), \
             patch.object(cli, "print_ready"), \
             patch.object(cli.sys, "argv", ["xssentinel", "--json-report=out.json", "https://example.test/?q=x"]):
            args = cli.parse_args()

        self.assertEqual(args.json_report, "out.json")

    def test_parse_args_header_diagnostics_are_opt_in_and_allowlisted(self) -> None:
        common_patches = (
            patch.object(cli, "local_chromium_binary", return_value="/fixture/chromium"),
            patch.object(cli, "print_banner"),
            patch.object(cli, "print_ready"),
        )
        with common_patches[0], common_patches[1], common_patches[2], patch.object(
            cli.sys, "argv", ["xssentinel", "--test-headers=Referer,User-Agent", "https://example.test/?q=x"]
        ):
            args = cli.parse_args()
        self.assertEqual(args.test_headers, ["Referer", "User-Agent"])

        with common_patches[0], common_patches[1], common_patches[2], patch.object(
            cli.sys, "argv", ["xssentinel", "--test-headers", "https://example.test/?q=x"]
        ):
            default_header_args = cli.parse_args()
        self.assertEqual(default_header_args.test_headers, list(cli.SUPPORTED_HEADER_NAMES))

        with common_patches[0], common_patches[1], common_patches[2], patch.object(
            cli.sys, "argv", ["xssentinel", "https://example.test/?q=x"]
        ):
            default_args = cli.parse_args()
        self.assertEqual(default_args.test_headers, [])

        with common_patches[0], common_patches[1], common_patches[2], patch.object(
            cli.sys, "argv", ["xssentinel", "--test-headers=Host", "https://example.test/?q=x"]
        ):
            with self.assertRaises(SystemExit):
                cli.parse_args()

    def test_main_writes_json_report_after_existing_scan_flow(self) -> None:
        args = SimpleNamespace(
            help_only=False,
            maintenance_command=None,
            json_report="findings.json",
            _xti_scan_id="scan-fixture",
        )
        findings = [object()]
        with patch.object(cli, "parse_args", return_value=args), \
             patch.object(cli, "scan", return_value=(findings, [])), \
             patch.object(cli, "print_summary"), \
             patch.object(cli, "request_governor_snapshot", return_value={"used": 3, "limit": 5000, "requests_per_second": 5.0}), \
             patch.object(cli, "write_json_report", return_value="findings.json") as writer, \
             contextlib.redirect_stdout(io.StringIO()):
            result = cli.main()

        self.assertEqual(result, 0)
        writer.assert_called_once_with(
            "findings.json",
            findings,
            "scan-fixture",
            {"used": 3, "limit": 5000, "requests_per_second": 5.0},
        )


if __name__ == "__main__":
    unittest.main()
