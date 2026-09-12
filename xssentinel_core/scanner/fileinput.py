# Created by ell GITHUB: https://github.com/ruyynn
"""File-based target input: URL list files and raw HTTP request files."""

from __future__ import annotations

import argparse
import json
import re
import urllib.parse
from pathlib import Path

from .http_client import header_value
from .models import ScanTarget
from .targets import (
    dedupe_targets,
    detect_content_type,
    fuzz_candidate_fields,
    normalize_input_url,
    normalize_query_values_to_fuzz,
    query_fuzz_urls_by_parameter,
    target_fuzz_locations,
    target_priority_key,
)
from .utils import unique_lines

POSTDATA_SPLIT_RE = re.compile(r"\[POSTDATA(?:-JSON)?\]", re.IGNORECASE)
REQUEST_LINE_RE = re.compile(r"^(GET|POST)\s+(/\S*)(?:\s+HTTP/[\d.]+)?\s*$", re.IGNORECASE)
METHOD_PREFIX_RE = re.compile(r"^(GET|POST)\s+(\S+)$", re.IGNORECASE)
URL_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
LOCAL_HOST_PREFIXES = ("localhost", "127.", "[::1]")
LOCAL_HOST_SUFFIXES = (":80", ".local", ".test", ".localhost")
SKIPPED_REQUEST_HEADERS = {"host", "content-length", "content-type", "accept-encoding", "user-agent", "connection"}
MAX_FUZZ_FIELDS = 8

def file_scan_targets(args: argparse.Namespace) -> list[ScanTarget] | None:
    input_path = getattr(args, "request_file", None) or getattr(args, "url_file", None)
    if not input_path:
        return None
    path = Path(input_path)
    raw = read_input_file(path)
    request = parse_raw_request(raw)
    if request:
        method, request_target, headers, body = request
        apply_request_headers(args, headers)
        targets = raw_request_to_targets(method, request_target, headers, body, args)
    else:
        targets = url_list_targets(raw, args)
    targets = dedupe_targets(targets)
    targets.sort(key=target_priority_key)
    if not targets:
        raise SystemExit(f"No testable GET or POST parameters were found in file: {path}")
    return targets

def read_input_file(path: Path) -> str:
    if not path.exists():
        raise SystemExit(f"File not found: {path}")
    raw = path.read_text(encoding="utf-8", errors="ignore")
    if not raw.strip():
        raise SystemExit(f"File is empty: {path}")
    return raw

def url_list_targets(raw: str, args: argparse.Namespace) -> list[ScanTarget]:
    targets: list[ScanTarget] = []
    for raw_line in raw.splitlines():
        line = strip_method_prefix(raw_line.strip())
        if not line or line.startswith("#"):
            continue
        targets.extend(url_line_to_targets(line, args))
    return targets

def strip_method_prefix(line: str) -> str:
    match = METHOD_PREFIX_RE.match(line)
    return match.group(2) if match else line

def url_line_to_targets(line: str, args: argparse.Namespace) -> list[ScanTarget]:
    url_part, body = split_postdata(line)
    url = url_part.strip()
    if not is_valid_target_url(url):
        return []
    if body is not None:
        return post_targets_for(normalize_input_url(url), body, detect_content_type(body, "auto"), args)
    return get_line_targets(normalize_input_url(url), args)

def split_postdata(line: str) -> tuple[str, str | None]:
    parts = POSTDATA_SPLIT_RE.split(line, maxsplit=1)
    if len(parts) == 2:
        return parts[0], parts[1].strip()
    return line, None

def is_valid_target_url(url: str) -> bool:
    if not url:
        return False
    candidate = url if URL_SCHEME_RE.match(url) else "https://" + url
    parsed = urllib.parse.urlsplit(candidate)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)

def get_line_targets(url: str, args: argparse.Namespace) -> list[ScanTarget]:
    if getattr(args, "all_params", False):
        candidates = [normalize_query_values_to_fuzz(url)]
    else:
        candidates = query_fuzz_urls_by_parameter(url)
    targets = (build_target("GET", candidate, None, "application/x-www-form-urlencoded", "file-url") for candidate in candidates)
    return [target for target in targets if target]

def post_targets_for(url: str, body: str | None, content_type: str, args: argparse.Namespace) -> list[ScanTarget]:
    targets: list[ScanTarget] = []
    if body:
        if content_type == "application/json":
            targets.extend(json_body_targets(url, body, args))
        else:
            targets.extend(form_body_targets(url, body, args))
    if getattr(args, "all_params", False):
        if not body:
            targets.append(build_target("POST", normalize_query_values_to_fuzz(url), None, content_type, "file-post"))
    else:
        targets.extend(post_query_targets(url, body, content_type))
    return [target for target in targets if target]

def post_query_targets(url: str, body: str | None, content_type: str) -> list[ScanTarget]:
    targets = (build_target("POST", fuzz_url, body, content_type, "file-post") for fuzz_url in query_fuzz_urls_by_parameter(url))
    return [target for target in targets if target]

def max_fuzz_fields(args: argparse.Namespace) -> int:
    try:
        limit = int(getattr(args, "max_fields", None))
    except (TypeError, ValueError):
        limit = MAX_FUZZ_FIELDS
    return max(1, limit)

def form_body_targets(url: str, body: str, args: argparse.Namespace) -> list[ScanTarget]:
    pairs = urllib.parse.parse_qsl(body, keep_blank_values=True)
    if not pairs:
        return []
    fields = unique_lines(name for name, _ in pairs)
    fuzz_fields = fuzz_candidate_fields(fields)[:max_fuzz_fields(args)]
    plans = [set(fuzz_fields)] if getattr(args, "all_params", False) else [{name} for name in fuzz_fields]
    targets = (build_target("POST", url, form_body_for(pairs, plan), "application/x-www-form-urlencoded", "file-post") for plan in plans)
    return [target for target in targets if target]

def form_body_for(pairs: list[tuple[str, str]], fuzz_names: set[str]) -> str:
    return "&".join(
        f"{urllib.parse.quote_plus(name)}={urllib.parse.quote_plus('FUZZ' if name in fuzz_names else value)}"
        for name, value in pairs
    )

def json_body_targets(url: str, body: str, args: argparse.Namespace) -> list[ScanTarget]:
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return []
    fields = unique_lines(json_leaf_fields(parsed))
    if not fields:
        return []
    fuzz_fields = fuzz_candidate_fields(fields)[:max_fuzz_fields(args)]
    plans = [set(fuzz_fields)] if getattr(args, "all_params", False) else [{name} for name in fuzz_fields]
    targets = (
        build_target(
            "POST",
            url,
            json.dumps(rebuild_json_body(parsed, plan), ensure_ascii=False, separators=(",", ":")),
            "application/json",
            "file-post",
        )
        for plan in plans
    )
    return [target for target in targets if target]

def json_leaf_fields(value: object, field: str = "") -> list[str]:
    if isinstance(value, dict):
        return [sub for key, item in value.items() for sub in json_leaf_fields(item, key)]
    if isinstance(value, list):
        return [sub for item in value for sub in json_leaf_fields(item, field)]
    if isinstance(value, str) and field:
        return [field]
    return []

def rebuild_json_body(value: object, fuzz_names: set[str], field: str = "") -> object:
    if isinstance(value, dict):
        return {key: rebuild_json_body(item, fuzz_names, key) for key, item in value.items()}
    if isinstance(value, list):
        return [rebuild_json_body(item, fuzz_names, field) for item in value]
    if isinstance(value, str) and field in fuzz_names:
        return "FUZZ"
    return value

def build_target(method: str, url: str, data: str | None, content_type: str, source: str) -> ScanTarget | None:
    target = ScanTarget(method, url, data, content_type, [], source)
    target.fuzz_locations = target_fuzz_locations(target)
    return target if target.fuzz_locations else None

def parse_raw_request(raw: str) -> tuple[str, str, dict[str, str], str | None] | None:
    lines = raw.replace("\r\n", "\n").split("\n")
    match = REQUEST_LINE_RE.match(lines[0].strip()) if lines else None
    if not match:
        return None
    headers: dict[str, str] = {}
    index = 1
    while index < len(lines) and lines[index].strip():
        name, separator, value = lines[index].partition(":")
        if separator and name.strip():
            headers[name.strip()] = value.strip()
        index += 1
    body = "\n".join(lines[index + 1:]).strip() if index < len(lines) else ""
    return match.group(1).upper(), match.group(2), headers, body or None

def raw_request_to_targets(
    method: str,
    request_target: str,
    headers: dict[str, str],
    body: str | None,
    args: argparse.Namespace,
) -> list[ScanTarget]:
    if method not in {"GET", "POST"}:
        raise SystemExit(f"Unsupported request method '{method}' in the request file. XSSentinel tests GET and POST parameters.")
    url = normalize_input_url(request_base_url(request_target, headers))
    if method == "POST" and body:
        return post_targets_for(url, body, request_content_type(headers, body), args)
    return get_line_targets(url, args)

def request_base_url(request_target: str, headers: dict[str, str]) -> str:
    host = header_value(headers, "host")
    if not host:
        raise SystemExit("Request file is missing the Host header. Add 'Host: example.com' below the request line.")
    return f"{request_scheme(host)}://{host}{request_target}"

def request_scheme(host: str) -> str:
    lowered = host.strip().lower()
    if lowered.startswith(LOCAL_HOST_PREFIXES) or lowered.endswith(LOCAL_HOST_SUFFIXES):
        return "http"
    return "https"

def request_content_type(headers: dict[str, str], body: str) -> str:
    media_type = header_value(headers, "content-type").split(";", 1)[0].strip().lower()
    if media_type in {"application/json", "application/x-www-form-urlencoded"}:
        return media_type
    return detect_content_type(body, "auto")

def apply_request_headers(args: argparse.Namespace, headers: dict[str, str]) -> None:
    extra = dict(getattr(args, "headers", None) or {})
    for name, value in headers.items():
        if name.lower() not in SKIPPED_REQUEST_HEADERS:
            extra[name] = value
    args.headers = extra
