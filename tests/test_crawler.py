import unittest

from xssentinel_core.scanner.config import CrawlerRuntimeConfig
from xssentinel_core.scanner.crawler import (
    EndpointCandidate,
    RecursiveCrawler,
    axios_endpoints,
    canonical_url,
    fetch_endpoints,
    graphql_endpoints,
    script_endpoints,
    spa_route_endpoints,
    websocket_endpoints,
)
from xssentinel_core.scanner.http_client import HttpResult
from xssentinel_core.scanner.targets import candidate_to_scan_targets


class CrawlerExtractionTests(unittest.TestCase):
    def test_canonical_url_sorts_query_and_drops_fragment(self) -> None:
        self.assertEqual(
            canonical_url("HTTPS://Example.test/path?b=2&a=1#frag"),
            "https://example.test/path?a=1&b=2",
        )

    def test_fetch_endpoint_extracts_method_and_json_params(self) -> None:
        text = "fetch('/api/search', {method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({query: q, page: 1})})"
        endpoints = fetch_endpoints(text, "https://example.test/", 1)
        self.assertEqual(endpoints[0].method, "POST")
        self.assertEqual(endpoints[0].content_type, "application/json")
        self.assertIn("query", endpoints[0].parameters)

    def test_axios_and_xhr_are_discovered_through_script_endpoint_scan(self) -> None:
        text = "axios.post('/api/comment', {message: body}); var x=new XMLHttpRequest(); x.open('GET','/api/items?q=1');"
        sources = {endpoint.source for endpoint in script_endpoints(text, "https://example.test/", 1)}
        self.assertIn("axios", sources)
        self.assertIn("xhr", sources)

    def test_spa_graphql_and_websocket_detection(self) -> None:
        text = "const r={path:'/users/:id'}; gql`query Search { viewer { id } }`; new WebSocket('/socket')"
        self.assertTrue(spa_route_endpoints(text, "https://example.test/", 1))
        self.assertTrue(graphql_endpoints(text, "https://example.test/", 1))
        self.assertTrue(websocket_endpoints(text, "https://example.test/"))

    def test_candidate_to_scan_targets_preserves_confidence_metadata(self) -> None:
        candidate = EndpointCandidate("POST", "https://example.test/api", ["message"], "application/json", "fetch", 77, ["fetch() call"], 2)
        targets = candidate_to_scan_targets(candidate)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].source, "fetch")
        self.assertEqual(targets[0].discovery_confidence, 77)
        self.assertEqual(targets[0].crawl_depth, 2)


class RecursiveCrawlerTests(unittest.TestCase):
    def test_recursive_same_origin_crawl_uses_cache_and_discovers_forms(self) -> None:
        responses = {
            "https://example.test/": HttpResult(200, '<a href="/search"><span>Search</span></a><script src="/app.js"></script>', {}, None),
            "https://example.test/search": HttpResult(200, '<form method="POST" action="/comment"><input name="message"></form>', {}, None),
            "https://example.test/app.js": HttpResult(200, "fetch('/api/search', {method:'POST', body: JSON.stringify({query: q})})", {}, None),
        }

        def fetcher(url, *_args):
            return responses.get(canonical_url(url), HttpResult(404, "", {}, "HTTP 404"))

        crawler = RecursiveCrawler(
            "ua",
            1.0,
            False,
            {},
            CrawlerRuntimeConfig(max_depth=2, max_pages=5, max_workers=2, max_scripts=3),
            fetcher,
        )
        result = crawler.crawl("https://example.test/", responses["https://example.test/"])
        sources = {endpoint.source for endpoint in result.endpoints}
        self.assertTrue({"form", "high-value-form"} & sources)
        self.assertIn("fetch", sources)
        self.assertGreaterEqual(result.diagnostics.pages_fetched, 2)
        self.assertGreaterEqual(result.diagnostics.cache_hits, 0)


if __name__ == "__main__":
    unittest.main()
