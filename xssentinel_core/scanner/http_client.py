"""HTTP request helpers."""

from .settings import *
from .models import *

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
    attempts = 3 if method.upper() == "GET" else 2
    last_result: HttpResult | None = None
    for attempt in range(attempts):
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
    try:
        context = None if verify_https else INSECURE_SSL_CONTEXT
        with urllib.request.urlopen(req, timeout=timeout, context=context) as response:
            charset = response.headers.get_content_charset() or "utf-8"
            body = response.read(2_000_000).decode(charset, errors="replace")
            return HttpResult(response.status, body, dict(response.headers.items()), None)
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
