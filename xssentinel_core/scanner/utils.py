"""Small shared scanner utilities."""

import re
import urllib.parse
from pathlib import Path
from typing import Iterable


_SENSITIVE_COMPONENTS = {
    "auth",
    "authorization",
    "cookie",
    "credential",
    "csrf",
    "passwd",
    "password",
    "secret",
    "session",
    "token",
}
_SENSITIVE_COMPOUNDS = {
    "accesskey",
    "apikey",
    "clientkey",
    "clientsecret",
    "csrftoken",
    "privatekey",
    "proxyauthorization",
    "refreshkey",
    "sessionid",
    "setcookie",
}
_SENSITIVE_COMPONENT_PAIRS = {
    frozenset(("access", "key")),
    frozenset(("api", "key")),
    frozenset(("client", "key")),
    frozenset(("private", "key")),
    frozenset(("refresh", "key")),
}
_SENSITIVE_HEADER = re.compile(
    r"(?im)(\b(?:cookie|set-cookie|authorization|proxy-authorization)\s*:\s*)[^\r\n]*"
)
_SENSITIVE_ASSIGNMENT = re.compile(
    r'''(?i)(["']?(?:authorization|proxy-authorization|cookie|set-cookie|password|passwd|token|api[_-]?key|secret|session(?:[_-]?id)?|csrf(?:[_-]?token)?)["']?\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^&\s,;}]+)'''
)


def redact_sensitive_text(value: str) -> str:
    """Best-effort redaction for secrets in text rendered to users."""
    value = _SENSITIVE_HEADER.sub(r"\1[REDACTED]", str(value))
    return _SENSITIVE_ASSIGNMENT.sub(r"\1[REDACTED]", value)


def redact_sensitive_url(url: str) -> str:
    """Redact credential-like URL components without changing other values."""
    try:
        parsed = urllib.parse.urlsplit(url)
        netloc = parsed.netloc.rsplit("@", 1)[-1] if parsed.username is not None else parsed.netloc
        safe_query = []
        for item in parsed.query.split("&") if parsed.query else []:
            key = item.partition("=")[0]
            decoded_key = urllib.parse.unquote_plus(key)
            components = re.findall(
                r"[a-z0-9]+",
                re.sub(r"([a-z])([A-Z])", r"\1 \2", decoded_key),
                flags=re.IGNORECASE,
            )
            compact_key = "".join(components).lower()
            component_set = set(component.lower() for component in components)
            pair_match = any(pair.issubset(component_set) for pair in _SENSITIVE_COMPONENT_PAIRS)
            if _SENSITIVE_COMPONENTS.intersection(component_set) or compact_key in _SENSITIVE_COMPOUNDS or pair_match:
                safe_query.append(f"{key}=[REDACTED]")
            else:
                safe_query.append(item)
        fragment = redact_sensitive_text(parsed.fragment)
        return urllib.parse.urlunsplit(
            (parsed.scheme, netloc, parsed.path, "&".join(safe_query), fragment)
        )
    except (TypeError, ValueError):
        return "[URL REDACTED: invalid URL]"

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
