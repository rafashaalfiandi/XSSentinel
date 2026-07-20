"""Small shared scanner utilities."""

from .settings import *

def one_line(value: str, limit: int) -> str:
    value = re.sub(r"\s+", " ", str(value)).strip()
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 3)] + "..."

def text_snippet(value: str, pattern: re.Pattern[str] | str, radius: int = 90) -> str:
    if isinstance(pattern, str):
        index = value.lower().find(pattern.lower())
        if index < 0:
            return ""
        start = max(0, index - radius)
        end = min(len(value), index + len(pattern) + radius)
    else:
        match = pattern.search(value)
        if not match:
            return ""
        start = max(0, match.start() - radius)
        end = min(len(value), match.end() + radius)
    return one_line(value[start:end], radius * 2)

def load_lines(path: Path) -> list[str]:
    if not path.exists():
        raise SystemExit(f"File not found: {path}")
    lines = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    if not lines:
        raise SystemExit(f"File is empty: {path}")
    return lines

def unique_lines(lines: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for line in lines:
        if line not in seen:
            seen.add(line)
            result.append(line)
    return result
