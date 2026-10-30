"""Command-line entrypoint for XSSentinel."""

# Updated by ell GITHUB: https://github.com/ruyynn

from .settings import *
from .targets import *
from .browser import *
from .runner import *
from .output import *
from .fileinput import MAX_FUZZ_FIELDS
from .maintenance import print_banner, run_restart, run_update
from .reporting import write_json_report
from .utils import redact_sensitive_text
from .http_client import request_governor_snapshot
from .header_analysis import SUPPORTED_HEADER_NAMES, validate_header_names

def parse_extra_headers(header_values: list[str], cookie: str | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw in header_values:
        name, sep, value = raw.partition(":")
        if not sep or not name.strip():
            raise SystemExit(f"Invalid header: {raw!r}. Format: 'Name: value'")
        headers[name.strip()] = value.strip()
    if cookie:
        headers["Cookie"] = cookie.strip()
    return headers

def print_ready() -> None:
    print(f"{GREEN}{BOLD}[READY]{RESET} Enter target URL to begin.")
    print()

def print_help() -> None:
    print("Usage:")
    print("  xssentinel <url>")
    print("  xssentinel --all-params <url>")
    print("  xssentinel --stop-on-confirmed <url>")
    print("  xssentinel -f <file>")
    print("  xssentinel -r <request-file>")
    print("  xssentinel")
    print("  xssentinel -update")
    print("  xssentinel -restart")
    print("  xssentinel -h")
    print()
    print("Commands:")
    print("  <url>       Scan a target URL. If no URL is provided, the tool prompts interactively.")
    print("  --all-params  Fuzz all query parameters in one request for the target URL.")
    print("  --stop-on-confirmed  Stop once the first confirmed result is found.")
    print("  -f, --file  Load targets from a file. Each line is a URL that already has parameters.")
    print("  -r, --request  Load a raw HTTP request file, then test its GET or POST parameters.")
    print("  --max-fields N  Override the default 8-field cap.")
    print("  --json-report PATH  Write a redacted JSON report without overwriting an existing file.")
    print("  --test-headers[=NAMES]  Opt in to inert reflection checks for User-Agent, Referer, and Accept-Language.")
    print("  Header diagnostics use GET requests only; allowed names: User-Agent, Referer, Accept-Language.")
    print("  -update     Clone/pull the latest XSSentinel source from git, then install the runtime.")
    print("  -restart    Clean cache and reinstall the runtime from the saved/local source project.")
    print("  -h, -help   Show this help information.")
    print()
    print("Runtime behavior:")
    print("  Default mode tests one parameter per request for clearer evidence.")
    print("  --all-params sends the same payload to every query parameter in one request.")
    print("  --stop-on-confirmed keeps the old fast-stop behavior after the first confirmed result.")
    print("  By default, confirmed payloads stop the current target but scanning continues on other targets.")
    print("  Discovered parameters are tested in parallel with an automatic worker pool.")
    print("  File modes (-f, -r) test the parameters already present in the file instead of crawling, POST first.")
    print("  File modes fuzz at most 8 fields per form or JSON body; --max-fields N raises that cap.")
    print("  HTTP requests share a scan-wide budget and global start-rate limit.")
    print("  HTTP redirects and browser resources are restricted to the initial target origin.")
    print("  XSSENTINEL_SCOPE_ORIGINS optionally restricts initial targets to comma-separated exact origins.")
    print("  XSSENTINEL_REQUEST_BUDGET defaults to 5000; XSSENTINEL_REQUESTS_PER_SECOND defaults to 5.")
    print("  Header diagnostics are GET-only, bounded, and report reflection rather than XSS confirmation.")
    print()
    print("Examples:")
    print("  xssentinel https://site.test/search?q=test&id=1")
    print("  xssentinel --all-params https://site.test/search?q=test&id=1")
    print("  xssentinel -f urls.txt")
    print("  xssentinel -r request.txt")
    print("  xssentinel -update")
    print("  xssentinel -restart")

def maintenance_command(value: str) -> str | None:
    lowered = value.lower()
    if lowered in {"-h", "--help", "-help", "help"}:
        return "help"
    if lowered in {"-update", "--update", "update"}:
        return "update"
    if lowered in {"-restart", "--restart", "restart"}:
        return "restart"
    return None

def extract_file_inputs(cleaned_args: list[str]) -> tuple[str | None, str | None]:
    if not cleaned_args:
        return None, None
    first = cleaned_args[0]
    if first in {"-r", "--request"}:
        if len(cleaned_args) != 2:
            raise SystemExit("-r/--request expects exactly one request file path, for example: xssentinel -r request.txt")
        return None, cleaned_args[1]
    if first in {"-f", "--file", "f"}:
        if len(cleaned_args) != 2:
            raise SystemExit("-f/--file expects exactly one URL list file path, for example: xssentinel -f urls.txt")
        return cleaned_args[1], None
    return None, None

def parse_args() -> argparse.Namespace:
    if len(sys.argv) > 1 and maintenance_command(sys.argv[1]) == "help":
        print_banner()
        print_help()
        return argparse.Namespace(help_only=True)

    command = maintenance_command(sys.argv[1]) if len(sys.argv) > 1 else None
    if command in {"update", "restart"}:
        print_banner()
        return argparse.Namespace(maintenance_command=command)

    print_banner()

    chromium = local_chromium_binary()
    if not chromium:
        raise SystemExit(
            "Chromium was not detected. Install Chromium before running XSSentinel."
        )

    print_ready()

    raw_args = sys.argv[1:] if len(sys.argv) > 1 else []
    all_params = False
    stop_on_confirmed = False
    max_fields = MAX_FUZZ_FIELDS
    json_report_path: str | None = None
    test_header_names: list[str] = []
    cleaned_args: list[str] = []
    index = 0
    while index < len(raw_args):
        item = raw_args[index]
        if item in {"--all-params", "--all-query-params", "--fuzz-all-params"}:
            all_params = True
            index += 1
            continue
        if item in {"--stop-on-confirmed", "--stop-after-confirmed"}:
            stop_on_confirmed = True
            index += 1
            continue
        if item == "--max-fields" or item.startswith("--max-fields="):
            separator, inline = item.partition("=")[1:]
            if not separator:
                index += 1
                inline = raw_args[index] if index < len(raw_args) else ""
            if not inline.lstrip("-").isdigit():
                raise SystemExit("--max-fields expects a positive integer, for example: --max-fields 12")
            max_fields = int(inline)
            index += 1
            continue
        if item == "--json-report" or item.startswith("--json-report="):
            separator, inline = item.partition("=")[1:]
            if not separator:
                index += 1
                inline = raw_args[index] if index < len(raw_args) else ""
            if not inline or inline.startswith("-"):
                raise SystemExit("--json-report expects a file path")
            json_report_path = inline
            index += 1
            continue
        if item == "--test-headers" or item.startswith("--test-headers="):
            separator, inline = item.partition("=")[1:]
            selected = [name.strip() for name in inline.split(",") if name.strip()] if separator else list(SUPPORTED_HEADER_NAMES)
            try:
                test_header_names = validate_header_names(selected)
            except ValueError as exc:
                raise SystemExit(f"Invalid header diagnostic selection: {exc}") from exc
            index += 1
            continue
        cleaned_args.append(item)
        index += 1

    url_file, request_file = extract_file_inputs(cleaned_args)
    if url_file or request_file:
        method, url, data = "AUTO", "", None
    else:
        raw_target = " ".join(cleaned_args).strip() if cleaned_args else ""
        if not raw_target:
            raw_target = input("URL > ").strip()
        method, url, data = parse_target_line(raw_target)

    args = argparse.Namespace(
        url=url,
        method=method.upper(),
        data=data,
        content_type="auto",
        payloads=str(PAYLOAD_FILE),
        user_agents=str(USER_AGENT_FILE),
        headers={},
        browser=True,
        browser_all=False,
        smart=True,
        verify_https=True,
        timeout=5.0,
        delay=0.0,
        limit=None,
        browser_confirm_limit=max(30, SMART_CONFIRM_LIMIT * 5),
        workers=None,
        exhaustive_fallback=True,
        stop_on_confirmed=stop_on_confirmed,
        i_am_authorized=True,
        all_params=all_params,
        max_fields=max_fields,
        json_report=json_report_path,
        test_headers=test_header_names,
        help_only=False,
        maintenance_command=None,
        url_file=url_file,
        request_file=request_file,
    )
    if url_file or request_file:
        return args
    args.url = normalize_input_url(args.url)
    return args

def main() -> int:
    args = parse_args()
    if getattr(args, "help_only", False):
        return 0
    if getattr(args, "maintenance_command", None) == "update":
        return run_update()
    if getattr(args, "maintenance_command", None) == "restart":
        return run_restart()
    findings, intelligence = scan(args)
    print_summary(findings)
    if getattr(args, "json_report", None):
        try:
            destination = write_json_report(
                args.json_report,
                findings,
                getattr(args, "_xti_scan_id", None),
                request_governor_snapshot(),
            )
        except FileExistsError as exc:
            safe_path = redact_sensitive_text(str(exc.filename or args.json_report))
            raise SystemExit(f"JSON report already exists; refusing to overwrite: {safe_path}") from exc
        except OSError as exc:
            raise SystemExit(f"Could not write JSON report: {redact_sensitive_text(str(exc))}") from exc
        print(f"JSON report written: {redact_sensitive_text(str(destination))}")
    return 0
