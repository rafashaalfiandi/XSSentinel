"""Recursive same-origin crawler for endpoint discovery.

The crawler discovers candidate attack surfaces only. Conversion into concrete
`ScanTarget` templates remains in `targets.py`, which preserves the existing
scanner pipeline and CLI behavior.
"""

from concurrent.futures import Future, ThreadPoolExecutor, as_completed
import functools
import threading

from .settings import *
from .config import CrawlerRuntimeConfig
from .models import FormCandidate, HttpResult
from .parsers import FormDiscoveryParser, extract_page_structure
from .http_client import request_detailed, normalize_request_error
from .utils import unique_lines


STATIC_ROUTE_EXTENSIONS = {
    ".7z", ".avi", ".bmp", ".css", ".eot", ".gif", ".gz", ".ico", ".jpeg", ".jpg",
    ".map", ".mov", ".mp3", ".mp4", ".mpeg", ".ogg", ".otf", ".pdf", ".png",
    ".rar", ".svg", ".tar", ".ttf", ".webm", ".woff", ".woff2", ".zip",
}

HIGH_VALUE_ENDPOINT_KEYWORDS = (
    "login", "signin", "auth", "search", "comment", "contact", "register", "signup",
    "reset", "password", "subscribe", "submit", "send", "message", "graphql", "api",
)

OBJECT_BLOCK_PATTERN = re.compile(r"\{([\s\S]{0,1400}?)\}")
OBJECT_KEY_PATTERN = re.compile(r"(?:^|[,\{\s])['\"]?([A-Za-z_][A-Za-z0-9_.:-]{0,47})['\"]?\s*:")
PARAMETER_PATTERNS = (
    re.compile(r"(?:searchParams|get|set|append|delete)\(\s*['\"]([A-Za-z_][A-Za-z0-9_.:-]{0,47})['\"]", re.I),
    re.compile(r"(?:FormData|URLSearchParams)[\s\S]{0,350}?\.(?:append|set)\(\s*['\"]([A-Za-z_][A-Za-z0-9_.:-]{0,47})['\"]", re.I),
    re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_.:-]{0,47})=", re.I),
    re.compile(r"\b(?:name|field|param|key)\s*[:=]\s*['\"]([A-Za-z_][A-Za-z0-9_.:-]{0,47})['\"]", re.I),
    re.compile(r"\b(?:useSearchParams|router\.push|router\.replace|createSearchParams|useForm|register)\b[\s\S]{0,300}?['\"]([A-Za-z_][A-Za-z0-9_.:-]{0,47})['\"]", re.I),
)
ROUTE_LITERAL_PATTERN = re.compile(r"['\"](?P<route>/(?!/)[^'\"`\s<>]{1,220})['\"]")
FETCH_PATTERN = re.compile(r"\bfetch\s*\(\s*(['\"])(?P<url>[^'\"]{1,260})\1(?P<tail>[\s\S]{0,900})", re.I)
AXIOS_DIRECT_PATTERN = re.compile(r"\baxios(?:\.(?P<method>get|post|put|patch|delete))?\s*\(\s*(['\"])(?P<url>[^'\"]{1,260})\2", re.I)
AXIOS_CONFIG_PATTERN = re.compile(r"\baxios\s*\(\s*\{(?P<body>[\s\S]{0,1600}?)\}\s*\)", re.I)
AXIOS_URL_PATTERN = re.compile(r"\b(?:url|endpoint)\s*:\s*(['\"])(?P<url>[^'\"]{1,260})\1", re.I)
XHR_PATTERN = re.compile(r"\.open\s*\(\s*(['\"])(?P<method>GET|POST|PUT|PATCH|DELETE)\1\s*,\s*(['\"])(?P<url>[^'\"]{1,260})\3", re.I)
GRAPHQL_SIGNAL_PATTERN = re.compile(r"\b(graphql|gql`|query\s+\w*\s*\{|mutation\s+\w*\s*\{)", re.I)
GRAPHQL_URL_PATTERN = re.compile(r"['\"](?P<url>[^'\"]*graphql[^'\"]*)['\"]", re.I)
WEBSOCKET_PATTERN = re.compile(r"\b(?:new\s+)?WebSocket\s*\(\s*(['\"])(?P<url>[^'\"]{1,260})\1", re.I)
SPA_ROUTE_PATTERNS = (
    re.compile(r"\bpath\s*:\s*(['\"])(?P<path>/[^'\"]{1,220})\1", re.I),
    re.compile(r"<Route\b[^>]*\bpath=\{?(['\"])(?P<path>/[^'\"]{1,220})\1", re.I),
    re.compile(r"\brouter\.(?:push|replace)\s*\(\s*(['\"])(?P<path>/[^'\"]{1,220})\1", re.I),
)
ROUTE_PARAM_PATTERN = re.compile(r":([A-Za-z_][A-Za-z0-9_:-]{0,47})")
METHOD_PATTERN = re.compile(r"\bmethod\s*[:=]\s*(['\"])(GET|POST|PUT|PATCH|DELETE)\1", re.I)
JSON_BODY_PATTERN = re.compile(r"application/json|JSON\.stringify\s*\(|\b(?:body|data|variables)\s*:\s*\{", re.I)


@dataclass(frozen=True)
class EndpointCandidate:
    """Potential scan surface found during crawling."""

    method: str
    url: str
    parameters: list[str]
    content_type: str = "application/x-www-form-urlencoded"
    source: str = "crawler"
    confidence: int = 0
    evidence: list[str] = field(default_factory=list)
    depth: int = 1


@dataclass(frozen=True)
class WebSocketCandidate:
    """WebSocket endpoint discovered for operator diagnostics."""

    url: str
    source: str
    confidence: int
    evidence: list[str] = field(default_factory=list)


@dataclass
class CrawlPage:
    """Fetched page or script body retained for extraction diagnostics."""

    url: str
    depth: int
    status: int | None
    body: str
    headers: dict[str, str]
    error: str | None = None
    source: str = "page"


@dataclass
class CrawlDiagnostics:
    pages_seen: int = 0
    pages_fetched: int = 0
    cache_hits: int = 0
    endpoints_seen: int = 0
    websockets_seen: int = 0
    skipped_by_robots: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass
class CrawlResult:
    start_url: str
    pages: list[CrawlPage]
    endpoints: list[EndpointCandidate]
    websockets: list[WebSocketCandidate]
    diagnostics: CrawlDiagnostics


class CrawlCache:
    """Small in-memory response cache shared by page and script fetches."""

    def __init__(self) -> None:
        self._items: dict[str, HttpResult] = {}
        self.hits = 0
        self._lock = threading.Lock()

    def get(self, url: str) -> HttpResult | None:
        key = canonical_url(url)
        with self._lock:
            result = self._items.get(key)
            if result:
                self.hits += 1
            return result

    def set(self, url: str, result: HttpResult) -> None:
        with self._lock:
            self._items[canonical_url(url)] = result


class RobotsPolicy:
    """Minimal robots.txt policy for optional crawl awareness."""

    def __init__(self, base_url: str, fetcher, user_agent: str, timeout: float, verify_https: bool, extra_headers: dict[str, str]) -> None:
        self.disallow: list[str] = []
        parsed = urllib.parse.urlsplit(base_url)
        robots_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "/robots.txt", "", ""))
        try:
            result = fetcher(robots_url, user_agent, min(timeout, 3.0), "GET", None, None, verify_https, extra_headers)
        except Exception:
            return
        if not result.body:
            return
        active = False
        for raw_line in result.body.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line or ":" not in line:
                continue
            name, value = [part.strip() for part in line.split(":", 1)]
            if name.lower() == "user-agent":
                active = value in {"*", user_agent}
            elif active and name.lower() == "disallow" and value:
                self.disallow.append(value)

    def allowed(self, url: str) -> bool:
        path = urllib.parse.urlsplit(url).path or "/"
        return not any(path.startswith(rule) for rule in self.disallow)


class RecursiveCrawler:
    """Discover same-origin pages, scripts, forms, and request endpoints."""

    def __init__(
        self,
        user_agent: str,
        timeout: float,
        verify_https: bool,
        extra_headers: dict[str, str] | None = None,
        config: CrawlerRuntimeConfig | None = None,
        fetcher=request_detailed,
    ) -> None:
        self.user_agent = user_agent
        self.timeout = timeout
        self.verify_https = verify_https
        self.extra_headers = extra_headers or {}
        self.config = config or CrawlerRuntimeConfig.from_env()
        self.fetcher = fetcher
        self.cache = CrawlCache()

    def crawl(self, start_url: str, seed_result: HttpResult | None = None) -> CrawlResult:
        diagnostics = CrawlDiagnostics()
        robots = RobotsPolicy(start_url, self.fetcher, self.user_agent, self.timeout, self.verify_https, self.extra_headers) if self.config.respect_robots else None
        pages: list[CrawlPage] = []
        endpoints: list[EndpointCandidate] = []
        websockets: list[WebSocketCandidate] = []
        seen_pages: set[str] = set()
        frontier = [canonical_url(start_url)]

        if seed_result:
            self.cache.set(start_url, seed_result)

        with ThreadPoolExecutor(max_workers=self.config.max_workers, thread_name_prefix="xssentinel-crawl") as executor:
            for depth in range(1, self.config.max_depth + 1):
                if not frontier or len(seen_pages) >= self.config.max_pages:
                    break
                current = []
                for url in frontier:
                    key = canonical_url(url)
                    if key not in seen_pages and same_origin(start_url, url) and probably_html_route(url):
                        current.append(url)
                frontier = []
                diagnostics.pages_seen += len(current)
                fetched = self._fetch_pages(current[: max(0, self.config.max_pages - len(seen_pages))], depth, robots, diagnostics, executor)
                for page in fetched:
                    seen_pages.add(canonical_url(page.url))
                    pages.append(page)
                    page_endpoints, page_websockets, links = self._extract_from_page(page, start_url, executor)
                    endpoints.extend(page_endpoints)
                    websockets.extend(page_websockets)
                    if depth < self.config.max_depth:
                        for link in links:
                            key = canonical_url(link)
                            if key not in seen_pages and same_origin(start_url, link) and probably_html_route(link):
                                frontier.append(link)
                frontier = unique_lines(frontier)

        endpoints = dedupe_endpoint_candidates(endpoints)
        websockets = dedupe_websocket_candidates(websockets)
        endpoints.sort(key=endpoint_priority_key)
        diagnostics.cache_hits = self.cache.hits
        diagnostics.endpoints_seen = len(endpoints)
        diagnostics.websockets_seen = len(websockets)
        return CrawlResult(start_url, pages, endpoints, websockets, diagnostics)

    def _fetch_pages(self, urls: list[str], depth: int, robots: RobotsPolicy | None, diagnostics: CrawlDiagnostics, executor: ThreadPoolExecutor) -> list[CrawlPage]:
        pages: list[CrawlPage] = []

        def fetch(url: str) -> CrawlPage | None:
            result = self._fetch_url(url)
            return CrawlPage(url, depth, result.status, result.body, result.headers, result.error, "page")

        scheduled: list[Future[CrawlPage | None]] = []
        for url in unique_lines(urls):
            if robots and not robots.allowed(url):
                diagnostics.skipped_by_robots += 1
                continue
            scheduled.append(executor.submit(fetch, url))
        diagnostics.pages_fetched += len(scheduled)
        for future in as_completed(scheduled):
            page = future.result()
            if page:
                if page.error and not page.body:
                    diagnostics.errors.append(f"{page.url}: {page.error}")
                pages.append(page)
        return pages

    def _fetch_url(self, url: str) -> HttpResult:
        cached = self.cache.get(url)
        if cached:
            return cached
        try:
            result = self.fetcher(url, self.user_agent, self.timeout, "GET", None, None, self.verify_https, self.extra_headers)
        except Exception as exc:  # noqa: BLE001 - retained in crawl diagnostics.
            result = HttpResult(None, "", {}, normalize_request_error(str(exc), url))
        self.cache.set(url, result)
        return result

    def _extract_from_page(self, page: CrawlPage, base_url: str, executor: ThreadPoolExecutor) -> tuple[list[EndpointCandidate], list[WebSocketCandidate], list[str]]:
        if not page.body:
            return [], [], []
        form_parser = FormDiscoveryParser(page.url)
        try:
            form_parser.feed(page.body)
        except Exception as exc:  # noqa: BLE001 - page extraction should continue with structure parser.
            form_parser.diagnostics.parse_error = str(exc)
        structure = extract_page_structure(page.body, page.url)

        endpoints = form_endpoints(form_parser.forms, page.depth)
        links = same_origin_links(page.url, form_parser.links)
        endpoints.extend(query_link_endpoints(links, page.depth))
        if form_parser.standalone_fields:
            endpoints.append(scored_endpoint("GET", page.url, form_parser.standalone_fields, "html-standalone", ["standalone input fields"], page.depth))

        script_sources = list(structure.inline_scripts)
        external_scripts = self._fetch_scripts(structure.external_scripts, base_url, executor)
        script_sources.extend(source for _, source in external_scripts)
        discovery_text = "\n".join(form_parser.meta_text + script_sources)
        endpoints.extend(script_endpoints(discovery_text, page.url, page.depth))
        websockets = websocket_endpoints(discovery_text, page.url)

        for script_url, _ in external_scripts:
            links.append(script_url)
        links.extend(route_links_from_text(discovery_text, page.url))
        return endpoints, websockets, unique_lines(links)

    def _fetch_scripts(self, script_urls: list[str], base_url: str, executor: ThreadPoolExecutor) -> list[tuple[str, str]]:
        same_origin_scripts = unique_lines(url for url in script_urls if same_origin(base_url, url))[: self.config.max_scripts]
        results: list[tuple[str, str]] = []

        def fetch(script_url: str) -> tuple[str, str] | None:
            result = self._fetch_url(script_url)
            if result.body:
                return script_url, result.body[:700_000]
            return None

        futures = [executor.submit(fetch, url) for url in same_origin_scripts]
        for future in as_completed(futures):
            item = future.result()
            if item:
                results.append(item)
        return results


@functools.lru_cache(maxsize=8192)
def canonical_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.urlencode(sorted(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)), doseq=True)
    path = parsed.path or "/"
    return urllib.parse.urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, query, ""))


@functools.lru_cache(maxsize=8192)
def same_origin(base_url: str, candidate: str) -> bool:
    base = urllib.parse.urlsplit(base_url)
    parsed = urllib.parse.urlsplit(candidate)
    return parsed.scheme in {"http", "https"} and parsed.netloc == base.netloc


def resolve_same_origin(base_url: str, candidate: str) -> str | None:
    candidate = html.unescape(candidate.strip())
    if not candidate or candidate.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
        return None
    resolved = urllib.parse.urljoin(base_url, candidate)
    parsed = urllib.parse.urlsplit(resolved)
    if parsed.scheme not in {"http", "https"}:
        return None
    if not same_origin(base_url, resolved):
        return None
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def probably_html_route(url: str) -> bool:
    path = urllib.parse.urlsplit(url).path.lower()
    return not any(path.endswith(ext) for ext in STATIC_ROUTE_EXTENSIONS)


def parameter_names_from_url(url: str) -> list[str]:
    parsed = urllib.parse.urlsplit(url)
    return [name for name, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True) if sane_parameter_name(name)]


def sane_parameter_name(name: str) -> bool:
    return bool(1 <= len(name) <= 48 and re.match(r"^[A-Za-z_][A-Za-z0-9_.:-]*$", name))


def extract_object_keys(text: str) -> list[str]:
    keys: list[str] = []
    for match in OBJECT_BLOCK_PATTERN.finditer(text):
        keys.extend(item.group(1) for item in OBJECT_KEY_PATTERN.finditer(match.group(1)))
    return [key for key in unique_lines(keys) if sane_parameter_name(key)]


def extract_parameter_names(text: str) -> list[str]:
    candidates: list[str] = []
    for pattern in PARAMETER_PATTERNS:
        candidates.extend(match.group(1) for match in pattern.finditer(text))
    candidates.extend(extract_object_keys(text))
    return [name for name in unique_lines(candidates) if sane_parameter_name(name)]


def scored_endpoint(method: str, url: str, params: list[str], source: str, evidence: list[str], depth: int, content_type: str = "application/x-www-form-urlencoded") -> EndpointCandidate:
    params = [param for param in unique_lines(params) if sane_parameter_name(param)]
    confidence = endpoint_confidence(method, url, params, source, evidence)
    return EndpointCandidate(method.upper(), canonical_url(url), params, content_type, source, confidence, evidence, depth)


def endpoint_confidence(method: str, url: str, params: list[str], source: str, evidence: list[str]) -> int:
    score = 10
    source_weights = {
        "high-value-form": 56,
        "form": 48,
        "fetch": 44,
        "axios": 44,
        "xhr": 42,
        "graphql": 54,
        "link": 34,
        "html-standalone": 30,
        "spa-route": 24,
        "js-route": 18,
    }
    score += source_weights.get(source, 20)
    if method.upper() == "POST":
        score += 10
    if params:
        score += min(22, 4 * len(params))
    lowered = url.lower()
    if any(keyword in lowered for keyword in HIGH_VALUE_ENDPOINT_KEYWORDS):
        score += 10
    score += min(8, 2 * len(evidence))
    return max(0, min(100, score))


def form_endpoints(forms: list[FormCandidate], depth: int) -> list[EndpointCandidate]:
    endpoints: list[EndpointCandidate] = []
    for form in forms:
        source = "high-value-form" if any(keyword in form.action.lower() or any(keyword in field.lower() for field in form.fields) for keyword in HIGH_VALUE_ENDPOINT_KEYWORDS) else "form"
        endpoints.append(scored_endpoint(form.method, form.action, form.fields, source, ["html form"], depth))
    return endpoints


def same_origin_links(base_url: str, links: list[str]) -> list[str]:
    resolved = [resolve_same_origin(base_url, link) for link in links]
    return unique_lines(item for item in resolved if item)


def query_link_endpoints(links: list[str], depth: int) -> list[EndpointCandidate]:
    endpoints = []
    for link in links:
        params = parameter_names_from_url(link)
        if params:
            endpoints.append(scored_endpoint("GET", link, params, "link", ["query link"], depth))
    return endpoints


def route_links_from_text(text: str, base_url: str) -> list[str]:
    routes: list[str] = []
    for match in ROUTE_LITERAL_PATTERN.finditer(text):
        route = match.group("route")
        if route.startswith(("/static/", "/assets/", "/cdn/")):
            continue
        resolved = resolve_same_origin(base_url, route)
        if resolved and probably_html_route(resolved):
            routes.append(resolved)
    return unique_lines(routes)


def script_endpoints(text: str, base_url: str, depth: int) -> list[EndpointCandidate]:
    endpoints: list[EndpointCandidate] = []
    endpoints.extend(fetch_endpoints(text, base_url, depth))
    endpoints.extend(axios_endpoints(text, base_url, depth))
    endpoints.extend(xhr_endpoints(text, base_url, depth))
    endpoints.extend(graphql_endpoints(text, base_url, depth))
    endpoints.extend(spa_route_endpoints(text, base_url, depth))
    endpoints.extend(js_route_endpoints(text, base_url, depth))
    return dedupe_endpoint_candidates(endpoints)


def nearby_text(text: str, start: int, end: int, radius: int = 900) -> str:
    return text[max(0, start - radius): min(len(text), end + radius)]


def fetch_endpoints(text: str, base_url: str, depth: int) -> list[EndpointCandidate]:
    endpoints: list[EndpointCandidate] = []
    for match in FETCH_PATTERN.finditer(text):
        url = resolve_same_origin(base_url, match.group("url"))
        if not url:
            continue
        context = nearby_text(text, match.start(), match.end())
        method = method_from_context(context, "GET")
        content_type = "application/json" if looks_like_json_body(context) else "application/x-www-form-urlencoded"
        params = parameter_names_from_url(url) + extract_parameter_names(context)
        endpoints.append(scored_endpoint(method, url, params, "fetch", ["fetch() call"], depth, content_type))
    return endpoints


def axios_endpoints(text: str, base_url: str, depth: int) -> list[EndpointCandidate]:
    endpoints: list[EndpointCandidate] = []
    for match in AXIOS_DIRECT_PATTERN.finditer(text):
        url = resolve_same_origin(base_url, match.group("url"))
        if not url:
            continue
        context = nearby_text(text, match.start(), match.end())
        method = (match.group("method") or method_from_context(context, "GET")).upper()
        content_type = "application/json" if looks_like_json_body(context) else "application/x-www-form-urlencoded"
        params = parameter_names_from_url(url) + extract_parameter_names(context)
        endpoints.append(scored_endpoint(method, url, params, "axios", ["axios call"], depth, content_type))
    for match in AXIOS_CONFIG_PATTERN.finditer(text):
        body = match.group("body")
        url_match = AXIOS_URL_PATTERN.search(body)
        if not url_match:
            continue
        url = resolve_same_origin(base_url, url_match.group("url"))
        if not url:
            continue
        method = method_from_context(body, "GET")
        content_type = "application/json" if looks_like_json_body(body) else "application/x-www-form-urlencoded"
        endpoints.append(scored_endpoint(method, url, parameter_names_from_url(url) + extract_parameter_names(body), "axios", ["axios config call"], depth, content_type))
    return endpoints


def xhr_endpoints(text: str, base_url: str, depth: int) -> list[EndpointCandidate]:
    endpoints: list[EndpointCandidate] = []
    for match in XHR_PATTERN.finditer(text):
        url = resolve_same_origin(base_url, match.group("url"))
        if not url:
            continue
        context = nearby_text(text, match.start(), match.end())
        content_type = "application/json" if looks_like_json_body(context) else "application/x-www-form-urlencoded"
        params = parameter_names_from_url(url) + extract_parameter_names(context)
        endpoints.append(scored_endpoint(match.group("method"), url, params, "xhr", ["XMLHttpRequest.open()"], depth, content_type))
    return endpoints


def graphql_endpoints(text: str, base_url: str, depth: int) -> list[EndpointCandidate]:
    endpoints: list[EndpointCandidate] = []
    has_graphql = bool(GRAPHQL_SIGNAL_PATTERN.search(text))
    for match in GRAPHQL_URL_PATTERN.finditer(text):
        url = resolve_same_origin(base_url, match.group("url"))
        if url:
            endpoints.append(scored_endpoint("POST", url, ["query", "variables", "operationName"], "graphql", ["GraphQL URL"], depth, "application/json"))
    if has_graphql:
        parsed = urllib.parse.urlsplit(base_url)
        url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "/graphql", "", ""))
        endpoints.append(scored_endpoint("POST", url, ["query", "variables", "operationName"], "graphql", ["GraphQL operation text"], depth, "application/json"))
    return endpoints


def websocket_endpoints(text: str, base_url: str) -> list[WebSocketCandidate]:
    sockets: list[WebSocketCandidate] = []
    base = urllib.parse.urlsplit(base_url)
    for match in WEBSOCKET_PATTERN.finditer(text):
        raw = match.group("url")
        if raw.startswith("/"):
            scheme = "wss" if base.scheme == "https" else "ws"
            url = urllib.parse.urlunsplit((scheme, base.netloc, raw, "", ""))
        else:
            url = raw
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme in {"ws", "wss"} and parsed.netloc == base.netloc:
            sockets.append(WebSocketCandidate(url, "websocket", 70, ["WebSocket constructor"]))
    return sockets


def spa_route_endpoints(text: str, base_url: str, depth: int) -> list[EndpointCandidate]:
    endpoints: list[EndpointCandidate] = []
    for pattern in SPA_ROUTE_PATTERNS:
        for match in pattern.finditer(text):
            url = resolve_same_origin(base_url, route_template_to_url(match.group("path")))
            if not url:
                continue
            route_params = ROUTE_PARAM_PATTERN.findall(match.group("path"))
            endpoints.append(scored_endpoint("GET", url, route_params, "spa-route", ["SPA route"], depth))
    return endpoints


def js_route_endpoints(text: str, base_url: str, depth: int) -> list[EndpointCandidate]:
    endpoints: list[EndpointCandidate] = []
    for route in route_links_from_text(text, base_url):
        params = parameter_names_from_url(route)
        if params:
            endpoints.append(scored_endpoint("GET", route, params, "js-route", ["JavaScript route string"], depth))
    return endpoints


def route_template_to_url(route: str) -> str:
    route = ROUTE_PARAM_PATTERN.sub(r"\1", route)
    route = route.replace("*", "")
    return route or "/"


def method_from_context(context: str, default: str) -> str:
    match = METHOD_PATTERN.search(context)
    return match.group(2).upper() if match else default.upper()


def looks_like_json_body(context: str) -> bool:
    return bool(JSON_BODY_PATTERN.search(context))


def dedupe_endpoint_candidates(endpoints: list[EndpointCandidate]) -> list[EndpointCandidate]:
    by_key: dict[tuple[str, str, tuple[str, ...], str], EndpointCandidate] = {}
    for endpoint in endpoints:
        if not endpoint.parameters and endpoint.method != "GET":
            continue
        key = (endpoint.method, canonical_url(endpoint.url), tuple(sorted(endpoint.parameters)), endpoint.content_type)
        previous = by_key.get(key)
        if previous is None or endpoint.confidence > previous.confidence:
            by_key[key] = endpoint
    return list(by_key.values())


def dedupe_websocket_candidates(sockets: list[WebSocketCandidate]) -> list[WebSocketCandidate]:
    seen: set[str] = set()
    result: list[WebSocketCandidate] = []
    for socket_candidate in sockets:
        if socket_candidate.url not in seen:
            seen.add(socket_candidate.url)
            result.append(socket_candidate)
    return result


def endpoint_priority_key(endpoint: EndpointCandidate) -> tuple[int, int, int, str]:
    source_order = {
        "high-value-form": 0,
        "form": 1,
        "graphql": 2,
        "fetch": 3,
        "axios": 4,
        "xhr": 5,
        "link": 6,
        "html-standalone": 7,
        "spa-route": 8,
        "js-route": 9,
    }.get(endpoint.source, 10)
    return (0 if endpoint.method == "POST" else 1, source_order, -endpoint.confidence, endpoint.url)
