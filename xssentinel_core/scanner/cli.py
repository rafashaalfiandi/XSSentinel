"""Command-line entrypoint for XSSentinel."""

from .settings import *
from .targets import *
from .browser import *
from .runner import *
from .output import *

APP_NAME = "xssentinel"
INSTALL_DIR = Path.home() / ".local" / "share" / APP_NAME
BIN_DIR = Path.home() / ".local" / "bin"
BIN_PATH = BIN_DIR / APP_NAME
SOURCE_MARKER = INSTALL_DIR / ".source-dir"

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

def print_help() -> None:
    print("Usage:")
    print("  xssentinel <url>")
    print("  xssentinel")
    print("  xssentinel -update")
    print("  xssentinel -restart")
    print("  xssentinel -h")
    print()
    print("Commands:")
    print("  <url>       Scan a target URL. If no URL is provided, the tool prompts interactively.")
    print("  -update     Clean XSSentinel cache and reinstall the runtime from the saved source project.")
    print("  -restart    Alias for -update. Use after editing source files so the installed command uses the latest code.")
    print("  -h, -help   Show this help information.")
    print()
    print("Runtime behavior:")
    print("  Discovered parameters are tested in parallel with an automatic worker pool.")
    print()
    print("Examples:")
    print("  xssentinel https://site.test/search?q=test&id=1")
    print("  xssentinel -update")

def maintenance_command(value: str) -> str | None:
    lowered = value.lower()
    if lowered in {"-h", "--help", "-help", "help"}:
        return "help"
    if lowered in {"-update", "--update", "update", "-restart", "--restart", "restart"}:
        return "update"
    return None

def clean_pycache(root: Path) -> int:
    removed = 0
    if not root.exists():
        return removed
    for path in list(root.rglob("__pycache__")):
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
            removed += 1
    return removed

def resolve_update_source() -> Path:
    candidates: list[Path] = []
    if SOURCE_MARKER.exists():
        marker = SOURCE_MARKER.read_text(encoding="utf-8", errors="ignore").strip()
        if marker:
            candidates.append(Path(marker).expanduser())
    env_source = os.environ.get("XSSENTINEL_SOURCE_DIR", "").strip()
    if env_source:
        candidates.append(Path(env_source).expanduser())
    candidates.append(BASE_DIR)

    for candidate in candidates:
        candidate = candidate.resolve()
        if (candidate / "main.py").exists() and (candidate / "xssentinel_core").is_dir():
            return candidate
    raise SystemExit(f"{RED}{BOLD}[ERROR]{RESET} Could not find a valid XSSentinel source directory for update.")

def copy_runtime_file(source_dir: Path, filename: str) -> None:
    source = source_dir / filename
    if not source.exists():
        raise SystemExit(f"{RED}{BOLD}[ERROR]{RESET} Missing required source file: {source}")
    shutil.copy2(source, INSTALL_DIR / filename)

def reinstall_from_source(source_dir: Path) -> None:
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    BIN_DIR.mkdir(parents=True, exist_ok=True)

    legacy = INSTALL_DIR / "xss_fuzz_scanner.py"
    if legacy.exists():
        legacy.unlink()

    for filename in ("main.py", "xss-payloads.txt", "smart-selected-180-payloads.txt", "useragents.txt"):
        copy_runtime_file(source_dir, filename)

    core_source = source_dir / "xssentinel_core"
    core_target = INSTALL_DIR / "xssentinel_core"
    if core_target.exists():
        shutil.rmtree(core_target)
    shutil.copytree(core_source, core_target)
    SOURCE_MARKER.write_text(str(source_dir) + "\n", encoding="utf-8")

    main_path = INSTALL_DIR / "main.py"
    main_path.chmod(main_path.stat().st_mode | 0o111)
    BIN_PATH.write_text(
        f'#!/usr/bin/env bash\nexec -a "{APP_NAME}" "{main_path}" "$@"\n',
        encoding="utf-8",
    )
    BIN_PATH.chmod(0o755)

def run_update() -> int:
    source_dir = resolve_update_source()
    cache_dir = Path.home() / ".cache" / APP_NAME

    print(f"{info_tag()} action=update")
    print(f"  {info_key('source')}{source_dir}")
    print(f"  {info_key('install')}{INSTALL_DIR}")

    removed = clean_pycache(source_dir) + clean_pycache(INSTALL_DIR)
    if cache_dir.exists():
        shutil.rmtree(cache_dir, ignore_errors=True)
        print(f"  {info_key('cache')}removed {cache_dir}")
    else:
        print(f"  {info_key('cache')}none")
    print(f"  {info_key('pycache')}removed {removed} directorie(s)")

    reinstall_from_source(source_dir)
    print(f"{GREEN}{BOLD}[DONE]{RESET} updated {APP_NAME} -> {BIN_PATH}")
    print(f"  {info_key('run')}xssentinel")
    return 0

def parse_args() -> argparse.Namespace:
    if len(sys.argv) > 1 and maintenance_command(sys.argv[1]) == "help":
        print_banner()
        print_help()
        return argparse.Namespace(help_only=True)

    if len(sys.argv) > 1 and maintenance_command(sys.argv[1]) == "update":
        print_banner()
        return argparse.Namespace(update_only=True)

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
        workers=None,
        exhaustive_fallback=True,
        stop_on_confirmed=True,
        i_am_authorized=True,
        help_only=False,
        update_only=False,
    )
    args.url = normalize_input_url(args.url)
    return args

def main() -> int:
    args = parse_args()
    if getattr(args, "help_only", False):
        return 0
    if getattr(args, "update_only", False):
        return run_update()
    if args.browser and not local_chromium_binary() and not playwright_available():
        print("Note: Chromium/Playwright was not found; the scanner will continue with response and DOM analysis.")
    findings, intelligence = scan(args)
    print_summary(findings)
    return 0
