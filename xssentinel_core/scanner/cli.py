"""Command-line entrypoint for XSSentinel."""

from .settings import *
from .targets import *
from .browser import *
from .runner import *
from .output import *

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

def print_banner() -> None:
    try:
        verify_identity(sys.argv[0])
    except RuntimeError as exc:
        raise SystemExit(f"{RED}{BOLD}[LOCKED]{RESET} {exc}") from exc
    identity = rafashacodeid()
    print(BANNER)
    print(f"{BRIGHT_TOSCA}Author: {identity['author']}{RESET}")
    print()

def print_ready() -> None:
    print(f"{GREEN}{BOLD}[READY]{RESET} Enter target URL to begin.")
    print()

def parse_args() -> argparse.Namespace:
    if len(sys.argv) > 1 and sys.argv[1] in {"-h", "--help", "help"}:
        print_banner()
        print_ready()
        print("Example: https://site.test/search?q=test&id=1")
        return argparse.Namespace(help_only=True)

    print_banner()
    print_ready()

    raw_target = " ".join(sys.argv[1:]).strip() if len(sys.argv) > 1 else ""
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
        browser=bool(local_chromium_binary() or playwright_available()),
        browser_all=False,
        smart=True,
        verify_https=False,
        timeout=5.0,
        delay=0.0,
        limit=None,
        browser_confirm_limit=max(30, SMART_CONFIRM_LIMIT * 5),
        exhaustive_fallback=True,
        stop_on_confirmed=True,
        i_am_authorized=True,
        help_only=False,
    )
    args.url = normalize_input_url(args.url)
    return args

def main() -> int:
    args = parse_args()
    if getattr(args, "help_only", False):
        return 0
    if args.browser and not local_chromium_binary() and not playwright_available():
        print("Note: Chromium/Playwright was not found; the scanner will continue with response and DOM analysis.")
    findings, intelligence = scan(args)
    print_summary(findings)
    return 0
