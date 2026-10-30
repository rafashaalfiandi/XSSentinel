import concurrent.futures
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import unittest
from unittest.mock import patch
from threading import Thread
from urllib.request import Request

from xssentinel_core.scanner import browser
from xssentinel_core.scanner.http_client import (
    REQUEST_GOVERNOR,
    REQUEST_GOVERNOR,
    RedirectScopeError,
    RESPONSE_BODY_LIMIT,
    RequestBudgetExceeded,
    RequestGovernor,
    SameOriginRedirectHandler,
    configure_scope_origins,
    is_url_in_scope,
    request_detailed,
)
from xssentinel_core.scanner.models import HttpResult


class RedirectScopeTests(unittest.TestCase):
    def setUp(self):
        self.handler = SameOriginRedirectHandler()
        self.request = Request("https://fixture.test:443/path")

    def test_same_origin_redirect_is_allowed(self):
        redirect = self.handler.redirect_request(
            self.request, None, 302, "Found", {}, "/next",
        )
        self.assertIsNotNone(redirect)
        self.assertEqual(redirect.full_url, "https://fixture.test:443/next")

    def test_scheme_host_and_port_changes_are_blocked(self):
        for destination in (
            "http://fixture.test/path",
            "https://other.test/path",
            "https://fixture.test:444/path",
        ):
            with self.subTest(destination=destination):
                with self.assertRaises(RedirectScopeError):
                    self.handler.redirect_request(
                        self.request, None, 302, "Found", {}, destination,
                    )

    def test_local_transport_follows_same_origin_and_blocks_other_host(self):
        hits = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                if self.path == "/same":
                    self.send_response(302)
                    self.send_header("Location", "/ok")
                    self.end_headers()
                    return
                if self.path == "/other":
                    self.send_response(302)
                    self.send_header("Location", f"http://localhost:{self.server.server_port}/must-not-hit")
                    self.end_headers()
                    return
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"fixture")

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        REQUEST_GOVERNOR.configure(max_requests=10, requests_per_second=100)
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            same_origin = request_detailed(f"{base}/same", "fixture", 1.0)
            before_offscope = len(hits)
            cross_origin = request_detailed(f"{base}/other", "fixture", 1.0)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)
            REQUEST_GOVERNOR.configure(max_requests=5000, requests_per_second=100)

        self.assertEqual(same_origin.status, 200)
        self.assertEqual(same_origin.body, "fixture")
        self.assertIsNone(cross_origin.status)
        self.assertIn("same-origin scope policy", cross_origin.error)
        self.assertEqual(hits[before_offscope:], ["/other"])

    def test_redirect_hop_consumes_global_budget(self):
        hits = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                self.send_response(302)
                self.send_header("Location", "/must-not-follow")
                self.end_headers()

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        REQUEST_GOVERNOR.configure(max_requests=1, requests_per_second=100)
        try:
            result = request_detailed(f"http://127.0.0.1:{server.server_port}/start", "fixture", 1.0)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)
            REQUEST_GOVERNOR.configure(max_requests=5000, requests_per_second=100)

        self.assertIsNone(result.status)
        self.assertIn("request budget exhausted", result.error)
        self.assertEqual(hits, ["/start"])

    def test_large_http_response_is_marked_truncated(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"x" * (RESPONSE_BODY_LIMIT + 1)
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        REQUEST_GOVERNOR.configure(max_requests=10, requests_per_second=100)
        try:
            result = request_detailed(f"http://127.0.0.1:{server.server_port}/large", "fixture", 2.0)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)
            REQUEST_GOVERNOR.configure(max_requests=5000, requests_per_second=5)

        self.assertEqual(result.status, 200)
        self.assertEqual(len(result.body), RESPONSE_BODY_LIMIT)
        self.assertTrue(result.truncated)


class RequestGovernorTests(unittest.TestCase):
    def test_browser_and_python_http_share_one_scan_wide_budget(self):
        REQUEST_GOVERNOR.configure(max_requests=1, requests_per_second=100)
        browser_governor = browser.BrowserRequestGovernor(10, 30, run_id="shared-test-run")
        try:
            self.assertTrue(browser_governor.acquire())
            with patch("xssentinel_core.scanner.http_client._request_once") as transport:
                result = request_detailed("https://fixture.test/", "ua", 0.1)
            snapshot = REQUEST_GOVERNOR.snapshot()
        finally:
            REQUEST_GOVERNOR.configure(max_requests=5000, requests_per_second=100)

        self.assertIsNone(result.status)
        self.assertIn("request budget exhausted", result.error)
        transport.assert_not_called()
        self.assertEqual(snapshot["total_used"], 1)
        self.assertEqual(snapshot["browser_used"], 1)
        self.assertEqual(snapshot["used"], 0)

    def test_mixed_browser_and_http_concurrency_obeys_one_global_budget(self):
        REQUEST_GOVERNOR.configure(max_requests=17, requests_per_second=100)
        browser_governor = browser.BrowserRequestGovernor(100, 30, run_id="mixed-channel-run")
        accepted = []
        rejected = []
        lock = threading.Lock()

        def acquire(index):
            try:
                if index % 2:
                    REQUEST_GOVERNOR.acquire("http")
                elif not browser_governor.acquire():
                    raise RequestBudgetExceeded("browser reservation denied")
                with lock:
                    accepted.append(index)
            except RequestBudgetExceeded:
                with lock:
                    rejected.append(index)

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=30) as pool:
                list(pool.map(acquire, range(60)))
            snapshot = REQUEST_GOVERNOR.snapshot()
        finally:
            REQUEST_GOVERNOR.configure(max_requests=5000, requests_per_second=5)

        self.assertEqual(len(accepted), 17)
        self.assertEqual(len(rejected), 43)
        self.assertEqual(snapshot["total_used"], 17)
        self.assertEqual(snapshot["by_channel"]["http"] + snapshot["by_channel"]["browser"], 17)

    def test_python_http_request_consumes_shared_budget_before_browser(self):
        REQUEST_GOVERNOR.configure(max_requests=1, requests_per_second=100)
        browser_governor = browser.BrowserRequestGovernor(10, 30, run_id="shared-test-run-2")
        try:
            with patch("xssentinel_core.scanner.http_client._request_once", return_value=HttpResult(200, "ok", {}, None)):
                result = request_detailed("https://fixture.test/", "ua", 0.1)
            allowed_browser_request = browser_governor.acquire()
            snapshot = REQUEST_GOVERNOR.snapshot()
        finally:
            REQUEST_GOVERNOR.configure(max_requests=5000, requests_per_second=100)

        self.assertEqual(result.status, 200)
        self.assertFalse(allowed_browser_request)
        self.assertEqual(snapshot["total_used"], 1)
        self.assertEqual(snapshot["used"], 1)
        self.assertEqual(snapshot["browser_used"], 0)

    def test_rate_limit_reserves_global_request_start_intervals(self):
        governor = RequestGovernor(max_requests=4, requests_per_second=2)
        with patch("xssentinel_core.scanner.http_client.time.monotonic", side_effect=[10.0, 10.1]), \
             patch("xssentinel_core.scanner.http_client.time.sleep") as sleep:
            governor.acquire()
            governor.acquire()

        sleep.assert_called_once()
        self.assertAlmostEqual(sleep.call_args.args[0], 0.4)

    def test_budget_is_shared_under_concurrency(self):
        governor = RequestGovernor(max_requests=9, requests_per_second=100)
        accepted = []
        rejected = []
        lock = threading.Lock()

        def acquire():
            try:
                governor.acquire()
                with lock:
                    accepted.append(1)
            except RequestBudgetExceeded:
                with lock:
                    rejected.append(1)

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            list(pool.map(lambda _: acquire(), range(30)))

        self.assertEqual(len(accepted), 9)
        self.assertEqual(len(rejected), 21)
        self.assertEqual(governor.snapshot()["used"], 9)

    def test_request_budget_exhaustion_returns_result_without_retry(self):
        REQUEST_GOVERNOR.configure(max_requests=1, requests_per_second=100)
        calls = []
        try:
            with patch("xssentinel_core.scanner.http_client._request_once", return_value=HttpResult(200, "ok", {}, None)) as request_once:
                first = request_detailed("https://fixture.test/", "ua", 0.1)
                second = request_detailed("https://fixture.test/", "ua", 0.1)
                calls.append(request_once.call_count)
        finally:
            REQUEST_GOVERNOR.configure(max_requests=5000, requests_per_second=100)

        self.assertEqual(first.status, 200)
        self.assertIsNone(second.status)
        self.assertIn("request budget exhausted", second.error)
        self.assertEqual(calls, [1])

    def test_timeout_exception_is_converted_to_http_result(self):
        class BrokenOpener:
            def open(self, *_args, **_kwargs):
                raise TimeoutError("timed out")

        REQUEST_GOVERNOR.configure(max_requests=3, requests_per_second=100)
        try:
            with patch("xssentinel_core.scanner.http_client.urllib.request.build_opener", return_value=BrokenOpener()):
                result = request_detailed("https://fixture.test/", "ua", 0.1)
        finally:
            REQUEST_GOVERNOR.configure(max_requests=5000, requests_per_second=100)

        self.assertIsNone(result.status)
        self.assertIn("timed out", result.error.lower())

    def test_post_timeout_is_not_retried(self):
        REQUEST_GOVERNOR.configure(max_requests=10, requests_per_second=100)
        try:
            with patch(
                "xssentinel_core.scanner.http_client._request_once",
                return_value=HttpResult(None, "", {}, "Connection timed out for host 'fixture.test'"),
            ) as transport:
                result = request_detailed(
                    "https://fixture.test/submit", "ua", 0.1,
                    method="POST", data="field=value",
                )
        finally:
            REQUEST_GOVERNOR.configure(max_requests=5000, requests_per_second=100)

        self.assertIsNone(result.status)
        transport.assert_called_once()


class ConfiguredScopeTests(unittest.TestCase):
    def tearDown(self):
        configure_scope_origins([])

    def test_allowlist_blocks_request_before_transport(self):
        configure_scope_origins(["https://allowed.fixture.test"])
        REQUEST_GOVERNOR.configure(max_requests=20, requests_per_second=100)

        try:
            with patch("xssentinel_core.scanner.http_client._request_once") as transport:
                result = request_detailed("https://other.fixture.test/", "ua", 0.1)
            snapshot = REQUEST_GOVERNOR.snapshot()
        finally:
            REQUEST_GOVERNOR.configure(max_requests=5000, requests_per_second=5)

        self.assertIsNone(result.status)
        self.assertIn("outside configured scope", result.error)
        transport.assert_not_called()
        self.assertEqual(snapshot["total_used"], 0)
        self.assertTrue(is_url_in_scope("https://allowed.fixture.test/path"))
        self.assertFalse(is_url_in_scope("https://allowed.fixture.test:444/path"))

    def test_invalid_scope_port_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid port"):
            configure_scope_origins(["https://fixture.test:not-a-port"])

    def test_second_local_origin_is_blocked_before_dispatch(self):
        hits = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"local fixture")

            def log_message(self, *_args):
                pass

        servers = [ThreadingHTTPServer(("127.0.0.1", 0), Handler) for _ in range(2)]
        threads = [Thread(target=server.serve_forever, daemon=True) for server in servers]
        for thread in threads:
            thread.start()
        first_origin = f"http://127.0.0.1:{servers[0].server_port}"
        second_origin = f"http://127.0.0.1:{servers[1].server_port}"
        REQUEST_GOVERNOR.configure(max_requests=10, requests_per_second=100)
        configure_scope_origins([first_origin])
        try:
            allowed = request_detailed(first_origin + "/allowed", "fixture", 1.0)
            blocked = request_detailed(second_origin + "/blocked", "fixture", 1.0)
        finally:
            for server in servers:
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join(timeout=1)
            REQUEST_GOVERNOR.configure(max_requests=5000, requests_per_second=5)

        self.assertEqual(allowed.status, 200)
        self.assertIsNone(blocked.status)
        self.assertIn("outside configured scope", blocked.error)
        self.assertEqual(hits, ["/allowed"])


if __name__ == "__main__":
    unittest.main()
