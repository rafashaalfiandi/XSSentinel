"""Command-line entrypoint for XSSentinel."""

from .settings import *
from .targets import *
from .browser import *
from .runner import *
from .output import *

APP_NAME = "xssentinel"
INSTALL_DIR = Path.home() / ".local" / "share" / APP_NAME
UPDATE_SOURCE_DIR = Path.home() / ".local" / "share" / f"{APP_NAME}-source"
BIN_DIR = Path.home() / ".local" / "bin"
BIN_PATH = BIN_DIR / APP_NAME
SOURCE_MARKER = INSTALL_DIR / ".source-dir"
DEFAULT_REPO_URL = "https://github.com/rafashaalfiandi/XSSentinel.git"

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

def run_git(args: list[str], cwd: Path | None = None) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=str(cwd) if cwd else None,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError as exc:
        raise SystemExit(f"{RED}{BOLD}[ERROR]{RESET} git is not installed or not available in PATH.") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "git command failed").strip()
        raise SystemExit(f"{RED}{BOLD}[ERROR]{RESET} git {' '.join(args)} failed: {detail}")
    return result.stdout.strip()

def git_current_branch(source_dir: Path) -> str:
    branch = run_git(["rev-parse", "--abbrev-ref", "HEAD"], source_dir).strip()
    if branch and branch != "HEAD":
        return branch
    return "main"

def sync_git_source() -> Path:
    repo_url = os.environ.get("XSSENTINEL_REPO_URL", DEFAULT_REPO_URL).strip() or DEFAULT_REPO_URL
    branch = os.environ.get("XSSENTINEL_REPO_BRANCH", "").strip()
    source_dir = Path(os.environ.get("XSSENTINEL_UPDATE_DIR", str(UPDATE_SOURCE_DIR))).expanduser()

    print(f"{info_tag()} action=git-update")
    print(f"  {info_key('repo')}{repo_url}")
    print(f"  {info_key('source')}{source_dir}")

    if (source_dir / ".git").is_dir():
        current_branch = branch or git_current_branch(source_dir)
        print(f"  {info_key('mode')}pull")
        print(f"  {info_key('branch')}{current_branch}")
        run_git(["fetch", "--prune", "origin"], source_dir)
        run_git(["checkout", current_branch], source_dir)
        run_git(["pull", "--ff-only", "origin", current_branch], source_dir)
    else:
        if source_dir.exists() and any(source_dir.iterdir()):
            raise SystemExit(
                f"{RED}{BOLD}[ERROR]{RESET} update source exists but is not a git repository: {source_dir}\n"
                f"Move it away or set XSSENTINEL_UPDATE_DIR to another path."
            )
        source_dir.parent.mkdir(parents=True, exist_ok=True)
        clone_args = ["clone", "--depth", "1"]
        if branch:
            clone_args.extend(["--branch", branch])
        clone_args.extend([repo_url, str(source_dir)])
        print(f"  {info_key('mode')}clone")
        if branch:
            print(f"  {info_key('branch')}{branch}")
        run_git(clone_args)

    if not (source_dir / "main.py").exists() or not (source_dir / "xssentinel_core").is_dir():
        raise SystemExit(f"{RED}{BOLD}[ERROR]{RESET} git source is not a valid XSSentinel project: {source_dir}")
    return source_dir

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

def run_restart() -> int:
    source_dir = resolve_update_source()
    cache_dir = Path.home() / ".cache" / APP_NAME

    print(f"{info_tag()} action=restart")
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
    print(f"{GREEN}{BOLD}[DONE]{RESET} restarted {APP_NAME} -> {BIN_PATH}")
    print(f"  {info_key('run')}xssentinel")
    return 0

def run_update() -> int:
    source_dir = sync_git_source()
    cache_dir = Path.home() / ".cache" / APP_NAME

    print(f"{info_tag()} action=install-update")
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
    print(f"{GREEN}{BOLD}[DONE]{RESET} updated {APP_NAME} from git -> {BIN_PATH}")
    print(f"  {info_key('run')}xssentinel")
    return 0

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
    if args.browser and not local_chromium_binary() and not playwright_available():
        print("Note: Chromium/Playwright was not found; the scanner will continue with response and DOM analysis.")
    findings, intelligence = scan(args)
    print_summary(findings)
    return 0
