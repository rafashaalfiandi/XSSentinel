"""Browser-based XSS confirmation helpers."""

from contextlib import suppress
from functools import lru_cache
import logging

from .config import BrowserRuntimeConfig
from .settings import *
from .reflection import *

LOGGER = logging.getLogger(__name__)
NO_POPUP_EVIDENCE = "no alert/confirm/prompt popup detected"


def browser_runtime_config() -> BrowserRuntimeConfig:
    return BrowserRuntimeConfig.from_env()


def browser_timeout_seconds(timeout_ms: int, config: BrowserRuntimeConfig) -> float:
    return max(timeout_ms / 1000, config.launch_timeout_s)


def _now() -> float:
    return time.monotonic()


def _remaining(deadline: float, fallback: float) -> float:
    return max(0.01, min(fallback, deadline - _now()))


def _extend_hits(evidence: list[str], hits: Iterable[object]) -> None:
    evidence.extend(str(hit) for hit in hits if hit)


def _safe_close(label: str, callback) -> None:
    try:
        callback()
    except Exception as exc:  # noqa: BLE001 - cleanup must be best effort.
        LOGGER.debug("browser cleanup failed label=%s error=%s", label, exc)


def _return_browser_evidence(payload: str, hits: Iterable[str]) -> tuple[bool, str]:
    evidence = normalize_browser_hits(hits)
    confirmed = popup_evidence_is_valid(payload, evidence)
    return confirmed, "; ".join(evidence) if evidence else NO_POPUP_EVIDENCE

def run_with_suppressed_stdio(callback):
    stdout_fd = os.dup(1)
    stderr_fd = os.dup(2)
    try:
        with open(os.devnull, "w") as devnull:
            os.dup2(devnull.fileno(), 1)
            os.dup2(devnull.fileno(), 2)
            return callback()
    finally:
        os.dup2(stdout_fd, 1)
        os.dup2(stderr_fd, 2)
        os.close(stdout_fd)
        os.close(stderr_fd)


@lru_cache(maxsize=1)
def playwright_available() -> bool:
    def check() -> bool:
        try:
            from playwright._impl._driver import compute_driver_executable  # type: ignore
            from playwright.sync_api import sync_playwright  # type: ignore

            executable = compute_driver_executable()
            if isinstance(executable, tuple) and len(executable) >= 2 and not Path(executable[1]).exists():
                return False
            with sync_playwright() as p:
                return bool(p.chromium)
        except Exception:
            return False

    return bool(run_with_suppressed_stdio(check))


class CDPClient:
    def __init__(self, websocket_url: str, timeout: float):
        parsed = urllib.parse.urlsplit(websocket_url)
        self.host = parsed.hostname or "127.0.0.1"
        self.port = parsed.port or 80
        self.path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self.next_id = 1

    def __enter__(self) -> "CDPClient":
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.settimeout(self.timeout)
        request = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(request.encode("ascii"))
        response = self.sock.recv(4096)
        status_line = response.split(b"\r\n", 1)[0]
        if b" 101 " not in status_line:
            _safe_close("cdp-handshake", self.sock.close)
            self.sock = None
            raise RuntimeError(f"CDP websocket handshake failed: {status_line.decode('latin1', errors='replace')}")
        return self

    def __exit__(self, *_: object) -> None:
        if self.sock:
            _safe_close("cdp-socket", self.sock.close)
            self.sock = None

    def send(self, method: str, params: dict | None = None) -> int:
        message_id = self.next_id
        self.next_id += 1
        payload = json.dumps({"id": message_id, "method": method, "params": params or {}}).encode("utf-8")
        self._send_frame(payload)
        return message_id

    def recv_until(self, wanted_id: int | None = None, seconds: float = 1.0) -> list[dict]:
        return collect_cdp_events(self, wanted_id, seconds, handle_dialogs=False)

    def call(self, method: str, params: dict | None = None, seconds: float = 2.0) -> list[dict]:
        return self.recv_until(self.send(method, params), seconds)

    def set_timeout(self, seconds: float) -> None:
        if self.sock:
            self.sock.settimeout(seconds)

    def _send_frame(self, payload: bytes) -> None:
        if not self.sock:
            raise RuntimeError("CDP socket is not active")
        header = bytearray([0x81])
        length = len(payload)
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.extend([0x80 | 126, *struct.pack("!H", length)])
        else:
            header.extend([0x80 | 127, *struct.pack("!Q", length)])
        mask = os.urandom(4)
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.sock.sendall(bytes(header) + mask + masked)

    def _recv_frame(self) -> bytes:
        if not self.sock:
            raise RuntimeError("CDP socket is not active")
        first = self._recv_exact(2)
        if not first:
            return b""
        opcode = first[0] & 0x0F
        length = first[1] & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._recv_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._recv_exact(8))[0]
        if first[1] & 0x80:
            mask = self._recv_exact(4)
            data = self._recv_exact(length)
            data = bytes(byte ^ mask[index % 4] for index, byte in enumerate(data))
        else:
            data = self._recv_exact(length)
        if opcode == 0x8:
            return b""
        return data

    def _recv_exact(self, length: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < length:
            chunk = self.sock.recv(length - len(chunks)) if self.sock else b""
            if not chunk:
                break
            chunks.extend(chunk)
        return bytes(chunks)



@lru_cache(maxsize=1)
def local_chromium_binary() -> str | None:
    for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        path = shutil.which(name)
        if path:
            return path
    return None

def cdp_dialog_hits(events: list[dict]) -> list[str]:
    hits = []
    for event in events:
        if event.get("method") == "Page.javascriptDialogOpening":
            params = event.get("params", {})
            hits.append(f"dialog:{params.get('type', 'unknown')}:{params.get('message', '')}")
    return hits

def cdp_returned_list(events: list[dict]) -> list[str]:
    for event in events:
        value = event.get("result", {}).get("result", {}).get("value")
        if isinstance(value, list):
            return [str(item) for item in value]
    return []


def collect_cdp_events(
    cdp: CDPClient,
    wanted_id: int | None = None,
    seconds: float = 1.0,
    handle_dialogs: bool = True,
) -> list[dict]:
    deadline = _now() + seconds
    events: list[dict] = []
    while _now() < deadline:
        try:
            cdp.set_timeout(_remaining(deadline, cdp.timeout))
            raw = cdp._recv_frame()
        except socket.timeout:
            break
        if not raw:
            break
        try:
            event = json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            continue
        events.append(event)
        if handle_dialogs and event.get("method") == "Page.javascriptDialogOpening":
            handle_cdp_dialogs(cdp, [event])
        if wanted_id is not None and event.get("id") == wanted_id:
            break
    return events

def cdp_call_collect(cdp: CDPClient, method: str, params: dict | None = None, seconds: float = 2.0) -> list[dict]:
    return collect_cdp_events(cdp, cdp.send(method, params), seconds)

def handle_cdp_dialogs(cdp: CDPClient, events: list[dict]) -> None:
    if any(event.get("method") == "Page.javascriptDialogOpening" for event in events):
        with suppress(Exception):
            cdp.call("Page.handleJavaScriptDialog", {"accept": False}, 1)

def post_form_data_url(url: str, data: str) -> str:
    inputs = []
    for name, value in urllib.parse.parse_qsl(data, keep_blank_values=True):
        inputs.append(
            "<input type=\"hidden\" name=\"{}\" value=\"{}\">".format(
                html.escape(name, quote=True),
                html.escape(value, quote=True),
            )
        )
    document = "".join(
        [
            "<!doctype html><meta charset=\"utf-8\">",
            f"<form method=\"POST\" enctype=\"application/x-www-form-urlencoded\" action=\"{html.escape(url, quote=True)}\">",
            *inputs,
            "</form><script>document.forms[0].submit()</script>",
        ]
    )
    return "data:text/html;charset=utf-8," + urllib.parse.quote(document)


def _chromium_command(chromium: str, tmpdir: str, verify_https: bool) -> list[str]:
    cmd = [
        chromium,
        "--headless=new",
        "--no-sandbox",
        "--disable-gpu",
        "--disable-crash-reporter",
        "--disable-crashpad",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "--disable-dev-shm-usage",
        "--remote-debugging-port=0",
        f"--user-data-dir={tmpdir}",
        "about:blank",
    ]
    if not verify_https:
        cmd.insert(-1, "--ignore-certificate-errors")
    return cmd


def _shutdown_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=2)
        return
    except subprocess.TimeoutExpired:
        LOGGER.debug("browser process did not exit after terminate; killing pid=%s", process.pid)
    process.kill()
    with suppress(subprocess.TimeoutExpired):
        process.wait(timeout=2)


def _wait_for_devtools_port(tmpdir: str, timeout: float, config: BrowserRuntimeConfig) -> str | None:
    active_port = Path(tmpdir) / "DevToolsActivePort"
    deadline = _now() + timeout
    while _now() < deadline:
        if active_port.exists():
            lines = active_port.read_text(encoding="utf-8", errors="ignore").splitlines()
            if lines and lines[0].strip():
                return lines[0].strip()
        time.sleep(min(config.poll_interval_s, _remaining(deadline, config.poll_interval_s)))
    return None


def _json_get_with_retries(url: str, timeout: float, config: BrowserRuntimeConfig, phase: str) -> object:
    deadline = _now() + timeout
    last_error: Exception | None = None
    attempts = max(1, config.launch_retries + 1)
    for attempt in range(1, attempts + 1):
        try:
            LOGGER.debug("browser cdp http phase=%s attempt=%d url=%s", phase, attempt, url)
            with urllib.request.urlopen(url, timeout=_remaining(deadline, timeout)) as response:
                return json.loads(response.read())
        except Exception as exc:  # noqa: BLE001 - reported as diagnostics.
            last_error = exc
            if attempt >= attempts or _now() >= deadline:
                break
            time.sleep(min(config.poll_interval_s, _remaining(deadline, config.poll_interval_s)))
    raise RuntimeError(f"{phase} failed after {attempts} attempt(s): {last_error}")


def _target_websocket_url(port: str, target_id: str | None, timeout: float, config: BrowserRuntimeConfig) -> str:
    targets = _json_get_with_retries(f"http://127.0.0.1:{port}/json", timeout, config, "target-list")
    if not isinstance(targets, list) or not targets:
        raise RuntimeError("target-list returned no debuggable pages")
    if target_id:
        for item in targets:
            if item.get("id") == target_id and item.get("webSocketDebuggerUrl"):
                return item["webSocketDebuggerUrl"]
    for item in targets:
        if item.get("webSocketDebuggerUrl"):
            return item["webSocketDebuggerUrl"]
    raise RuntimeError("target-list did not include a websocket URL")


def _create_blank_cdp_target(port: str, timeout: float, config: BrowserRuntimeConfig) -> str | None:
    version = _json_get_with_retries(f"http://127.0.0.1:{port}/json/version", timeout, config, "browser-version")
    if not isinstance(version, dict) or not version.get("webSocketDebuggerUrl"):
        raise RuntimeError("browser-version did not include a websocket URL")
    with CDPClient(version["webSocketDebuggerUrl"], timeout) as browser_cdp:
        events = browser_cdp.call("Target.createTarget", {"url": "about:blank"}, timeout)
    return next((e.get("result", {}).get("targetId") for e in events if e.get("result")), None)


def _navigate_cdp(cdp: CDPClient, url: str, timeout: float, method: str, data: str | None, content_type: str | None) -> tuple[bool, str | None]:
    if method.upper() == "POST" and data is not None:
        if content_type != "application/x-www-form-urlencoded":
            return False, "Chromium CDP POST browser validation is only accurate for application/x-www-form-urlencoded"
        cdp.call("Page.navigate", {"url": post_form_data_url(url, data)}, timeout)
    else:
        cdp.call("Page.navigate", {"url": url}, timeout)
    return True, None


def _setup_cdp_page(cdp: CDPClient, user_agent: str, extra_headers: dict[str, str] | None) -> None:
    cdp.call("Runtime.enable")
    cdp.call("Page.enable")
    cdp.call("Network.enable")
    cdp.call("Network.setUserAgentOverride", {"userAgent": user_agent})
    if extra_headers:
        cdp.call("Network.setExtraHTTPHeaders", {"headers": extra_headers})
    cdp.call("Page.addScriptToEvaluateOnNewDocument", {"source": BROWSER_INIT_SCRIPT})


def _collect_cdp_hits(cdp: CDPClient, timeout: float, config: BrowserRuntimeConfig) -> list[str]:
    hits: list[str] = []
    load_events = collect_cdp_events(cdp, seconds=min(timeout, config.load_window_s))
    hits.extend(cdp_dialog_hits(load_events))
    trigger_events = cdp_call_collect(
        cdp,
        "Runtime.evaluate",
        {"expression": BROWSER_TRIGGER_SCRIPT, "returnByValue": True},
        min(timeout, config.trigger_window_s),
    )
    hits.extend(cdp_dialog_hits(trigger_events))
    hits.extend(cdp_returned_list(trigger_events))
    for _ in range(config.followup_rounds):
        if config.followup_delay_s:
            time.sleep(config.followup_delay_s)
        result_events = cdp_call_collect(cdp, "Runtime.evaluate", {"expression": "window.__xssScannerHits || []", "returnByValue": True}, 1.0)
        new_hits = cdp_dialog_hits(result_events)
        if not new_hits:
            break
        hits.extend(new_hits)
        hits.extend(cdp_returned_list(result_events))
    return hits


def _confirm_with_local_chromium_once(
    chromium: str,
    url: str,
    user_agent: str,
    timeout: float,
    payload: str,
    method: str,
    data: str | None,
    content_type: str | None,
    verify_https: bool,
    extra_headers: dict[str, str] | None,
    config: BrowserRuntimeConfig,
) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory(prefix="xss-cdp-", ignore_cleanup_errors=True) as tmpdir:
        process = subprocess.Popen(_chromium_command(chromium, tmpdir, verify_https), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            LOGGER.debug("browser cdp launch pid=%s", process.pid)
            port = _wait_for_devtools_port(tmpdir, timeout, config)
            if not port:
                return False, "Chromium CDP was not ready before timeout"
            target_id = _create_blank_cdp_target(port, timeout, config)
            page_ws = _target_websocket_url(port, target_id, timeout, config)
            with CDPClient(page_ws, timeout) as cdp:
                _setup_cdp_page(cdp, user_agent, extra_headers)
                navigated, reason = _navigate_cdp(cdp, url, timeout, method, data, content_type)
                if not navigated:
                    return False, reason or NO_POPUP_EVIDENCE
                return _return_browser_evidence(payload, _collect_cdp_hits(cdp, timeout, config))
        finally:
            _shutdown_process(process)


def _retryable_cdp_evidence(evidence: str) -> bool:
    return evidence.startswith("Chromium CDP error:") or evidence == "Chromium CDP was not ready before timeout"

def confirm_with_local_chromium(
    url: str,
    user_agent: str,
    timeout_ms: int,
    payload: str,
    method: str = "GET",
    data: str | None = None,
    content_type: str | None = None,
    verify_https: bool = True,
    extra_headers: dict[str, str] | None = None,
) -> tuple[bool, str]:
    config = browser_runtime_config()
    chromium = local_chromium_binary()
    if not chromium:
        return False, "local Chromium/Chrome binary was not found"
    timeout = browser_timeout_seconds(timeout_ms, config)
    last_evidence = ""
    for attempt in range(config.launch_retries + 1):
        try:
            confirmed, evidence = _confirm_with_local_chromium_once(
                chromium,
                url,
                user_agent,
                timeout,
                payload,
                method,
                data,
                content_type,
                verify_https,
                extra_headers,
                config,
            )
            if confirmed or not _retryable_cdp_evidence(evidence) or attempt >= config.launch_retries:
                return confirmed, evidence
            last_evidence = evidence
            LOGGER.debug("browser cdp retry attempt=%d evidence=%s", attempt + 1, evidence)
        except Exception as exc:  # noqa: BLE001 - evidence for operator.
            evidence = f"Chromium CDP error: {exc}"
            if attempt >= config.launch_retries:
                return False, evidence
            last_evidence = evidence
            LOGGER.debug("browser cdp retry attempt=%d error=%s", attempt + 1, exc)
    return False, last_evidence or "Chromium CDP error: validation failed"


def _record_playwright_dialog(evidence: list[str], dialog) -> None:
    evidence.append(f"dialog:{dialog.type}:{dialog.message}")
    with suppress(Exception):
        dialog.dismiss()


def _submit_playwright_post(page, url: str, data: str, content_type: str | None, timeout_ms: int) -> None:
    page.goto("about:blank", wait_until="domcontentloaded", timeout=timeout_ms)
    page.set_content("<html><body></body></html>")
    page.evaluate(
        """
        ({url, data, contentType}) => {
          if (contentType === 'application/x-www-form-urlencoded') {
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = url;
            form.enctype = contentType;
            form.style.display = 'none';
            for (const [name, value] of new URLSearchParams(data)) {
              const input = document.createElement('input');
              input.type = 'hidden';
              input.name = name;
              input.value = value;
              form.appendChild(input);
            }
            document.body.appendChild(form);
            form.submit();
            return;
          }
          fetch(url, {method: 'POST', headers: {'Content-Type': contentType}, body: data})
            .then((response) => response.text())
            .then((text) => { document.open(); document.write(text); document.close(); })
            .catch(() => {});
        }
        """,
        {"url": url, "data": data, "contentType": content_type or "application/x-www-form-urlencoded"},
    )


def _navigate_playwright(page, url: str, timeout_ms: int, method: str, data: str | None, content_type: str | None) -> None:
    if method.upper() == "POST" and data is not None:
        _submit_playwright_post(page, url, data, content_type, timeout_ms)
    else:
        page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)


def _collect_playwright_frame_hits(page, evidence: list[str]) -> None:
    for frame in page.frames:
        with suppress(Exception):
            hits = frame.evaluate(BROWSER_TRIGGER_SCRIPT)
            if hits:
                _extend_hits(evidence, hits)


def _collect_playwright_window_hits(page, evidence: list[str]) -> None:
    with suppress(Exception):
        hits = page.evaluate("window.__xssScannerHits || []")
        if hits:
            _extend_hits(evidence, hits)


def _run_playwright_interactions(page, evidence: list[str], config: BrowserRuntimeConfig) -> None:
    page.wait_for_timeout(config.playwright_initial_wait_ms)
    for iteration in range(config.playwright_interaction_rounds):
        with suppress(Exception):
            _collect_playwright_frame_hits(page, evidence)
            coordinate = 20 + iteration * 10
            page.mouse.move(coordinate, coordinate)
            page.mouse.click(coordinate, coordinate)
            for key in ["Tab", "Enter", "Space"]:
                page.keyboard.press(key)
            page.wait_for_timeout(config.playwright_interaction_wait_ms)
        _collect_playwright_window_hits(page, evidence)
    _collect_playwright_window_hits(page, evidence)


def _confirm_with_playwright(
    sync_playwright,
    url: str,
    user_agent: str,
    timeout_ms: int,
    payload: str,
    method: str,
    data: str | None,
    content_type: str | None,
    verify_https: bool,
    extra_headers: dict[str, str] | None,
    config: BrowserRuntimeConfig,
) -> tuple[bool, str]:
    evidence: list[str] = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            context = browser.new_context(user_agent=user_agent, ignore_https_errors=not verify_https, extra_http_headers=extra_headers or None)
            try:
                page = context.new_page()
                page.on("dialog", lambda dialog: _record_playwright_dialog(evidence, dialog))
                page.add_init_script(BROWSER_INIT_SCRIPT)
                _navigate_playwright(page, url, timeout_ms, method, data, content_type)
                _run_playwright_interactions(page, evidence, config)
            finally:
                _safe_close("playwright-context", context.close)
        finally:
            _safe_close("playwright-browser", browser.close)
    return _return_browser_evidence(payload, evidence)

def confirm_with_browser(
    url: str,
    user_agent: str,
    timeout_ms: int,
    payload: str,
    method: str = "GET",
    data: str | None = None,
    content_type: str | None = None,
    verify_https: bool = True,
    extra_headers: dict[str, str] | None = None,
) -> tuple[bool, str]:
    config = browser_runtime_config()
    confirmed, evidence = confirm_with_local_chromium(url, user_agent, timeout_ms, payload, method, data, content_type, verify_https, extra_headers)
    if confirmed or evidence == NO_POPUP_EVIDENCE or re.search(r"\b(alert|confirm|prompt|dialog):", evidence):
        return confirmed, evidence

    if not playwright_available():
        return False, evidence + " | Playwright is not available"

    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except Exception as exc:
        LOGGER.debug("playwright import failed error=%s", exc)
        return False, evidence + " | Playwright is not available"

    try:
        return _confirm_with_playwright(sync_playwright, url, user_agent, timeout_ms, payload, method, data, content_type, verify_https, extra_headers, config)
    except Exception as exc:  # noqa: BLE001 - evidence for operator.
        return False, f"Chromium error: {exc}"
