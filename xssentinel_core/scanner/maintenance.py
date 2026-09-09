"""Update and reinstall helpers for the installed runtime."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from .output import BOLD, GREEN, RED, RESET, info_key, info_tag


APP_NAME = "xssentinel"
INSTALL_DIR = Path.home() / ".local" / "share" / APP_NAME
UPDATE_SOURCE_DIR = Path.home() / ".local" / "share" / f"{APP_NAME}-source"
BIN_DIR = Path.home() / ".local" / "bin"
BIN_PATH = BIN_DIR / APP_NAME
SOURCE_MARKER = INSTALL_DIR / ".source-dir"
DEFAULT_REPO_URL = "https://github.com/rafashaalfiandi/XSSentinel.git"


def print_banner() -> None:
    from xssentinel_core.runtime.engine import BANNER, verify_identity

    try:
        verify_identity(sys.argv[0])
    except RuntimeError as exc:  # pragma: no cover - defensive entrypoint guard.
        raise SystemExit(f"{RED}{BOLD}[LOCKED]{RESET} {exc}") from exc
    white = "\033[37m"
    print(BANNER)
    dark_red = "\033[31m"
    print(f"                 {white}rafashacode.id{RESET}  \u2022  XSS {BOLD}{dark_red}Scanner{RESET}")
    print()


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
    return branch if branch and branch != "HEAD" else "main"


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
    candidates.append(Path(__file__).resolve().parents[2])

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
    for legacy_payload in ("xss-payloads.txt", "smart-selected-180-payloads.txt"):
        legacy_path = INSTALL_DIR / legacy_payload
        if legacy_path.exists():
            legacy_path.unlink()

    for filename in ("main.py", "useragents.txt"):
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
