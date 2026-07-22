"""Browser-based XSS confirmation helpers."""

from .settings import *
from .reflection import *

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
        self.path = urllib.parse.urlunsplit(("", "", parsed.path, parsed.query, ""))
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
        if b" 101 " not in response.split(b"\r\n", 1)[0]:
            raise RuntimeError("CDP websocket handshake failed")
        return self

    def __exit__(self, *_: object) -> None:
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass

    def send(self, method: str, params: dict | None = None) -> int:
        message_id = self.next_id
        self.next_id += 1
        payload = json.dumps({"id": message_id, "method": method, "params": params or {}}).encode("utf-8")
        self._send_frame(payload)
        return message_id

    def recv_until(self, wanted_id: int | None = None, seconds: float = 1.0) -> list[dict]:
        deadline = time.time() + seconds
        events = []
        while time.time() < deadline:
            try:
                raw = self._recv_frame()
            except socket.timeout:
                break
            if not raw:
                break
            try:
                event = json.loads(raw.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                continue
            events.append(event)
            if wanted_id is not None and event.get("id") == wanted_id:
                break
        return events

    def call(self, method: str, params: dict | None = None, seconds: float = 2.0) -> list[dict]:
        return self.recv_until(self.send(method, params), seconds)

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


def collect_cdp_events(cdp: CDPClient, wanted_id: int | None = None, seconds: float = 1.0) -> list[dict]:
    deadline = time.time() + seconds
    events: list[dict] = []
    while time.time() < deadline:
        try:
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
        if event.get("method") == "Page.javascriptDialogOpening":
            handle_cdp_dialogs(cdp, [event])
        if wanted_id is not None and event.get("id") == wanted_id:
            break
    return events

def cdp_call_collect(cdp: CDPClient, method: str, params: dict | None = None, seconds: float = 2.0) -> list[dict]:
    return collect_cdp_events(cdp, cdp.send(method, params), seconds)

def handle_cdp_dialogs(cdp: CDPClient, events: list[dict]) -> None:
    if any(event.get("method") == "Page.javascriptDialogOpening" for event in events):
        try:
            cdp.call("Page.handleJavaScriptDialog", {"accept": False}, 1)
        except Exception:
            pass

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
    chromium = local_chromium_binary()
    if not chromium:
        return False, "local Chromium/Chrome binary was not found"
    timeout = max(timeout_ms / 1000, 3)
    with tempfile.TemporaryDirectory(prefix="xss-cdp-", ignore_cleanup_errors=True) as tmpdir:
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
            cmd.insert(-3, "--ignore-certificate-errors")
        process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            active_port = Path(tmpdir) / "DevToolsActivePort"
            deadline = time.time() + timeout
            while time.time() < deadline and not active_port.exists():
                time.sleep(0.05)
            if not active_port.exists():
                return False, "Chromium CDP was not ready before timeout"
            port = active_port.read_text(encoding="utf-8", errors="ignore").splitlines()[0].strip()
            version = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=timeout).read())
            browser_ws = version["webSocketDebuggerUrl"]
            with CDPClient(browser_ws, timeout) as browser_cdp:
                events = browser_cdp.call("Target.createTarget", {"url": "about:blank"}, timeout)
                target_id = next((e.get("result", {}).get("targetId") for e in events if e.get("result")), None)
            targets = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{port}/json", timeout=timeout).read())
            page_ws = next((item["webSocketDebuggerUrl"] for item in targets if item.get("id") == target_id), targets[0]["webSocketDebuggerUrl"])
            with CDPClient(page_ws, timeout) as cdp:
                cdp.call("Runtime.enable")
                cdp.call("Page.enable")
                cdp.call("Network.enable")
                cdp.call("Network.setUserAgentOverride", {"userAgent": user_agent})
                if extra_headers:
                    cdp.call("Network.setExtraHTTPHeaders", {"headers": extra_headers})
                cdp.call("Page.addScriptToEvaluateOnNewDocument", {"source": BROWSER_INIT_SCRIPT})
                if method.upper() == "POST" and data is not None:
                    if content_type != "application/x-www-form-urlencoded":
                        return False, "Chromium CDP POST browser validation is only accurate for application/x-www-form-urlencoded"
                    cdp.call("Page.navigate", {"url": post_form_data_url(url, data)}, timeout)
                else:
                    cdp.call("Page.navigate", {"url": url}, timeout)
                # Collect events during initial page load (longer window for slow pages)
                load_events = collect_cdp_events(cdp, seconds=min(timeout, 5.0))
                hits = cdp_dialog_hits(load_events)
                # Trigger user interaction events to fire onerror/onfocus/etc handlers
                trigger_events = cdp_call_collect(cdp, "Runtime.evaluate", {"expression": BROWSER_TRIGGER_SCRIPT, "returnByValue": True}, min(timeout, 4.0))
                hits.extend(cdp_dialog_hits(trigger_events))
                hits.extend(cdp_returned_list(trigger_events))
                # Multiple collection passes to catch async XSS (e.g., img onerror after network delay)
                for _ in range(3):
                    time.sleep(0.5)
                    result_events = cdp_call_collect(cdp, "Runtime.evaluate", {"expression": "window.__xssScannerHits || []", "returnByValue": True}, 1.0)
                    new_hits = cdp_dialog_hits(result_events)
                    if not new_hits:
                        break
                    hits.extend(new_hits)
                    hits.extend(cdp_returned_list(result_events))
            hits = normalize_browser_hits(hits)
            confirmed = popup_evidence_is_valid(payload, hits)
            return confirmed, "; ".join(hits) if hits else "no alert/confirm/prompt popup detected"
        except Exception as exc:  # noqa: BLE001 - evidence for operator.
            return False, f"Chromium CDP error: {exc}"
        finally:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass

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
    confirmed, evidence = confirm_with_local_chromium(url, user_agent, timeout_ms, payload, method, data, content_type, verify_https, extra_headers)
    if confirmed or evidence == "no alert/confirm/prompt popup detected" or re.search(r"\b(alert|confirm|prompt|dialog):", evidence):
        return confirmed, evidence

    if not playwright_available():
        return False, evidence + " | Playwright is not available"

    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except Exception:
        return False, evidence + " | Playwright is not available"

    evidence: list[str] = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(user_agent=user_agent, ignore_https_errors=not verify_https, extra_http_headers=extra_headers or None)
            page = context.new_page()
            page.on("dialog", lambda dialog: (evidence.append(f"dialog:{dialog.type}:{dialog.message}"), dialog.dismiss()))
            page.add_init_script(BROWSER_INIT_SCRIPT)
            if method.upper() == "POST" and data is not None:
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
            else:
                page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            # Wait longer for page to fully load and async XSS to trigger
            page.wait_for_timeout(1500)
            # Trigger user interactions multiple times to catch various XSS patterns
            for iteration in range(3):
                try:
                    for frame in page.frames:
                        try:
                            hits = frame.evaluate(BROWSER_TRIGGER_SCRIPT)
                            if hits:
                                evidence.extend(str(hit) for hit in hits)
                        except Exception:
                            pass
                    page.mouse.move(20 + iteration * 10, 20 + iteration * 10)
                    page.mouse.click(20 + iteration * 10, 20 + iteration * 10)
                    for key in ["Tab", "Enter", "Space"]:
                        page.keyboard.press(key)
                    page.wait_for_timeout(300)
                except Exception:
                    pass
                # Check for new hits after each interaction pass
                try:
                    hits = page.evaluate("window.__xssScannerHits || []")
                    if hits:
                        evidence.extend(str(hit) for hit in hits)
                except Exception:
                    pass
            # Final check after all interactions
            try:
                hits = page.evaluate("window.__xssScannerHits || []")
                if hits:
                    evidence.extend(str(hit) for hit in hits)
            except Exception:
                pass
            context.close()
            browser.close()
    except Exception as exc:  # noqa: BLE001 - evidence for operator.
        return False, f"Chromium error: {exc}"
    evidence = normalize_browser_hits(evidence)
    confirmed = popup_evidence_is_valid(payload, evidence)
    return confirmed, "; ".join(evidence) if evidence else "no alert/confirm/prompt popup detected"
