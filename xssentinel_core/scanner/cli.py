"""Command-line entrypoint for XSSentinel."""

from .settings import *
from .targets import *
from .browser import *
from .runner import *
from .output import *
from .maintenance import print_banner, run_restart, run_update

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
    print("  xssentinel")
    print("  xssentinel -update")
    print("  xssentinel -restart")
    print("  xssentinel -h")
    print()
    print("Commands:")
    print("  <url>       Scan a target URL. If no URL is provided, the tool prompts interactively.")
    print("  --all-params  Fuzz all query parameters in one request for the target URL.")
    print("  --stop-on-confirmed  Stop once the first confirmed result is found.")
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
    print()
    print("Examples:")
    print("  xssentinel https://site.test/search?q=test&id=1")
    print("  xssentinel --all-params https://site.test/search?q=test&id=1")
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
    cleaned_args: list[str] = []
    for item in raw_args:
        if item in {"--all-params", "--all-query-params", "--fuzz-all-params"}:
            all_params = True
            continue
        if item in {"--stop-on-confirmed", "--stop-after-confirmed"}:
            stop_on_confirmed = True
            continue
        cleaned_args.append(item)

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
        verify_https=False,
        timeout=5.0,
        delay=0.0,
        limit=None,
        browser_confirm_limit=max(30, SMART_CONFIRM_LIMIT * 5),
        workers=None,
        exhaustive_fallback=True,
        stop_on_confirmed=stop_on_confirmed,
        i_am_authorized=True,
        all_params=all_params,
        help_only=False,
        maintenance_command=None,
    )
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
    return 0
