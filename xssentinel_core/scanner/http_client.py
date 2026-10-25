"""HTTP request helpers."""

import re
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from .models import HttpResult
from .settings import INSECURE_SSL_CONTEXT


class RequestBudgetExceeded(RuntimeError):
    """Raised when the scan-wide HTTP request budget has been consumed."""


class RedirectScopeError(RuntimeError):
    """Raised before following a redirect to a different origin."""


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    try:
        port = parsed.port
    except ValueError:
        return "", "", None
    if port is None:
        port = 443 if scheme == "https" else 80 if scheme == "http" else None
    return scheme, host, port


class SameOriginRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow normal redirects only when the destination preserves origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        destination = urllib.parse.urljoin(req.full_url, newurl)
        if _origin(req.full_url) != _origin(destination):
            raise RedirectScopeError("redirect blocked by same-origin scope policy")
        if not is_url_in_scope(destination):
            raise RedirectScopeError("redirect blocked by configured scope allowlist")
        REQUEST_GOVERNOR.acquire()
        return super().redirect_request(req, fp, code, msg, headers, destination)


class RequestGovernor:
    """Shared thread-safe scan request budget and request-start rate limiter."""

    def __init__(self, max_requests: int = 5000, requests_per_second: float = 5.0) -> None:
        self._lock = threading.Lock()
        self.configure(max_requests, requests_per_second)

    def configure(self, max_requests: int, requests_per_second: float) -> None:
        with self._lock:
            self.max_requests = max(1, min(int(max_requests), 100_000))
            self.requests_per_second = max(0.1, min(float(requests_per_second), 100.0))
            self.interval = 1.0 / self.requests_per_second
            self.used = 0
            self.by_channel: dict[str, int] = {"http": 0, "browser": 0}
            self.browser_run_used: dict[str, int] = {}
            self.browser_run_limits: dict[str, int] = {}
            self.next_start = 0.0

    def acquire(
        self,
        channel: str = "http",
        *,
        run_id: str | None = None,
        run_limit: int | None = None,
        channel_rate: float | None = None,
    ) -> None:
        if channel not in {"http", "browser"}:
            raise ValueError(f"unsupported request accounting channel: {channel}")
        with self._lock:
            total_used = sum(self.by_channel.values())
            if total_used >= self.max_requests:
                raise RequestBudgetExceeded("scan-wide HTTP request budget exhausted")
            if channel == "browser" and run_id:
                limit = max(1, int(run_limit or self.max_requests))
                previous_limit = self.browser_run_limits.setdefault(run_id, limit)
                if self.browser_run_used.get(run_id, 0) >= previous_limit:
                    raise RequestBudgetExceeded("browser validation request budget exhausted")
            now = time.monotonic()
            rate = self.requests_per_second
            if channel_rate is not None:
                rate = min(rate, max(0.1, min(float(channel_rate), 100.0)))
            interval = max(self.interval, 1.0 / rate)
            wait = max(0.0, self.next_start - now)
            start_at = max(now, self.next_start)
            self.next_start = start_at + interval
            self.by_channel[channel] = self.by_channel.get(channel, 0) + 1
            if channel == "http":
                self.used += 1
            if channel == "browser" and run_id:
                self.browser_run_used[run_id] = self.browser_run_used.get(run_id, 0) + 1
        if wait:
            time.sleep(wait)

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            python_used = self.used
            browser_used = self.by_channel.get("browser", 0)
            return {
                # Keep the old Python-transport key and meaning for report consumers.
                "used": python_used,
                "limit": self.max_requests,
                "requests_per_second": round(self.requests_per_second, 2),
                "total_used": python_used + browser_used,
                "browser_used": browser_used,
                "browser_run_count": len(self.browser_run_used),
                "by_channel": dict(self.by_channel),
            }

    def browser_run_count(self, run_id: str) -> int:
        with self._lock:
            return self.browser_run_used.get(run_id, 0)


REQUEST_GOVERNOR = RequestGovernor()
_SCOPE_LOCK = threading.Lock()
_SCOPE_ORIGINS: set[tuple[str, str, int | None]] | None = None


def configure_scope_origins(origins: list[str] | None = None) -> None:
    """Set exact allowed origins; None reads XSSENTINEL_SCOPE_ORIGINS."""
    raw_origins = origins
    if raw_origins is None:
        raw = os.environ.get("XSSENTINEL_SCOPE_ORIGINS", "").strip()
        raw_origins = [value.strip() for value in raw.split(",") if value.strip()] if raw else []
    normalized: set[tuple[str, str, int | None]] = set()
    for value in raw_origins:
        parsed = urllib.parse.urlsplit(value if "://" in value else f"https://{value}")
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"invalid scope origin: {value}")
        try:
            parsed.port
        except ValueError as exc:
            raise ValueError(f"invalid port in scope origin: {value}") from exc
        if parsed.username is not None or parsed.password is not None or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("scope entries must be origins only (scheme, host, optional port)")
        normalized.add(_origin(urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))))
    global _SCOPE_ORIGINS
    with _SCOPE_LOCK:
        _SCOPE_ORIGINS = normalized or None


def is_url_in_scope(url: str, initial_origin: tuple[str, str, int | None] | None = None) -> bool:
    origin = _origin(url)
    if origin[0] not in {"http", "https"} or not origin[1]:
        return False
    with _SCOPE_LOCK:
        configured = None if _SCOPE_ORIGINS is None else set(_SCOPE_ORIGINS)
    if configured is not None and origin not in configured:
        return False
    return initial_origin is None or origin == initial_origin


def configure_request_governor(max_requests: int | None = None, requests_per_second: float | None = None) -> None:
    """Reset scan-wide request controls from explicit args or environment."""
    try:
        budget = int(os.environ.get("XSSENTINEL_REQUEST_BUDGET", "5000")) if max_requests is None else int(max_requests)
    except ValueError:
        budget = 5000
    try:
        rate = float(os.environ.get("XSSENTINEL_REQUESTS_PER_SECOND", "5")) if requests_per_second is None else float(requests_per_second)
    except ValueError:
        rate = 5.0
    REQUEST_GOVERNOR.configure(budget, rate)


def request_governor_snapshot() -> dict[str, object]:
    """Return shared scan request accounting; `used` remains Python HTTP only."""
    return REQUEST_GOVERNOR.snapshot()

def request_url(
    url: str,
    user_agent: str,
    timeout: float,
    method: str = "GET",
    data: str | None = None,
    content_type: str | None = None,
    verify_https: bool = True,
    extra_headers: dict[str, str] | None = None,
) -> tuple[int | None, str, str | None]:
    result = request_detailed(url, user_agent, timeout, method, data, content_type, verify_https, extra_headers)
    return result.status, result.body, result.error

def request_detailed(
    url: str,
    user_agent: str,
    timeout: float,
    method: str = "GET",
    data: str | None = None,
    content_type: str | None = None,
    verify_https: bool = True,
    extra_headers: dict[str, str] | None = None,
) -> HttpResult:
    if not is_url_in_scope(url):
        return HttpResult(None, "", {}, "target origin is outside configured scope")
    attempts = 3 if method.upper() == "GET" else 1
    last_result: HttpResult | None = None
    for attempt in range(attempts):
        try:
            REQUEST_GOVERNOR.acquire()
        except RequestBudgetExceeded as exc:
            return HttpResult(None, "", {}, str(exc))
        current_timeout = timeout if attempt == 0 else max(timeout * 1.75, timeout + 2.0)
        result = _request_once(url, user_agent, current_timeout, method, data, content_type, verify_https, extra_headers)
        result.error = normalize_request_error(result.error, url)
        if not is_retryable_network_error(result.error):
            return result
        last_result = result
        if attempt + 1 < attempts:
            time.sleep(min(0.25 * (attempt + 1), 0.75))
    if last_result and last_result.error:
        last_result.error = f"{last_result.error} after {attempts} attempts"
    return last_result or HttpResult(None, "", {}, "request failed")

def _request_once(
    url: str,
    user_agent: str,
    timeout: float,
    method: str = "GET",
    data: str | None = None,
    content_type: str | None = None,
    verify_https: bool = True,
    extra_headers: dict[str, str] | None = None,
) -> HttpResult:
    headers = {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    if extra_headers:
        headers.update(extra_headers)
    body_bytes = None
    if method.upper() == "POST" and data is not None:
        headers["Content-Type"] = content_type or "application/x-www-form-urlencoded"
        body_bytes = data.encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body_bytes,
        headers=headers,
        method=method.upper(),
    )
    if not is_url_in_scope(url):
        return HttpResult(None, "", {}, "target origin is outside configured scope")
    try:
        context = None if verify_https else INSECURE_SSL_CONTEXT
        handlers: list[urllib.request.BaseHandler] = [SameOriginRedirectHandler()]
        if context is not None:
            handlers.append(urllib.request.HTTPSHandler(context=context))
        opener = urllib.request.build_opener(*handlers)
        with opener.open(req, timeout=timeout) as response:
            charset = response.headers.get_content_charset() or "utf-8"
            body = response.read(2_000_000).decode(charset, errors="replace")
            return HttpResult(response.status, body, dict(response.headers.items()), None)
    except RedirectScopeError as exc:
        return HttpResult(None, "", {}, str(exc))
    except RequestBudgetExceeded as exc:
        return HttpResult(None, "", {}, str(exc))
    except urllib.error.HTTPError as exc:
        body = exc.read(500_000).decode("utf-8", errors="replace")
        return HttpResult(exc.code, body, dict(exc.headers.items()), f"HTTP {exc.code}")
    except urllib.error.URLError as exc:
        return HttpResult(None, "", {}, format_url_error(url, exc))
    except Exception as exc:  # noqa: BLE001 - shown to the operator as scan evidence.
        return HttpResult(None, "", {}, format_request_exception(url, exc))

def format_url_error(url: str, exc: urllib.error.URLError) -> str:
    return format_request_exception(url, getattr(exc, "reason", exc))

def normalize_request_error(error: str | None, url: str) -> str | None:
    if not error:
        return error
    lowered = error.lower()
    if lowered.startswith((
        "dns lookup failed",
        "connection timed out",
        "connection refused",
        "connection reset",
        "network is unreachable",
        "url request failed",
    )):
        return error
    if (
        "<urlopen error " in error
        or "No address associated" in error
        or "Name or service not known" in error
        or "timed out" in lowered
        or "connection reset" in lowered
        or "connection refused" in lowered
        or "network is unreachable" in lowered
    ):
        return format_request_exception(url, Exception(error))
    return error

def is_retryable_network_error(error: str | None) -> bool:
    if not error:
        return False
    lowered = error.lower()
    return any(
        marker in lowered
        for marker in (
            "dns lookup failed",
            "temporary failure",
            "connection timed out",
            "timed out",
            "connection reset",
            "network is unreachable",
        )
    )

def is_timeout_error(error: str | None) -> bool:
    return bool(error and "timed out" in error.lower())

def format_request_exception(url: str, exc: object) -> str:
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or "unknown-host"
    text = str(exc)
    match = re.search(r"<urlopen error (.*?)>", text)
    if match:
        text = match.group(1)
    elif text.startswith("<urlopen error ") and text.endswith(">"):
        text = text[len("<urlopen error ") : -1]
    errno = getattr(exc, "errno", None)
    if errno in {-2, -3, -5} or "Name or service not known" in text or "No address associated" in text:
        return f"DNS lookup failed for host '{host}' ({text})"
    lowered = text.lower()
    if isinstance(exc, TimeoutError) or "timed out" in lowered:
        return f"Connection timed out for host '{host}'"
    if "connection refused" in lowered:
        return f"Connection refused by host '{host}'"
    if "connection reset" in lowered:
        return f"Connection reset by host '{host}'"
    if "network is unreachable" in lowered:
        return f"Network is unreachable for host '{host}'"
    return f"URL request failed for host '{host}': {text}"

def header_value(headers: dict[str, str], name: str) -> str:
    wanted = name.lower()
    for key, value in headers.items():
        if key.lower() == wanted:
            return value
    return ""
