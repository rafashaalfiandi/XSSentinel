"""Scanner data models."""

from dataclasses import dataclass, field

@dataclass
class ScanTarget:
    method: str
    url: str
    data: str | None
    content_type: str
    fuzz_locations: list[str]
    source: str = "unknown"
    discovery_confidence: int = 0
    discovery_evidence: list[str] = field(default_factory=list)
    crawl_depth: int = 0

@dataclass
class Reflection:
    context: str
    detail: str
    severity: int
    signal: str = "reflection"
    location: str = "body"
    snippet: str = ""

@dataclass
class EvidenceItem:
    kind: str
    detail: str
    weight: int
    location: str = "body"
    snippet: str = ""

@dataclass
class ResponseContext:
    content_type: str
    parser: str
    reflections: list[Reflection]
    snippets: list[str]
    is_structured: bool = False
    parse_error: str | None = None
    diagnostics: object | None = None

@dataclass
class ScanAttempt:
    payload: str
    url: str
    method: str
    body: str | None
    user_agent: str
    batch: str = "smart"
    index: int = 0

@dataclass
class ScanDiagnostics:
    batch: str
    payload_index: int
    rejected_status_streak: int = 0
    browser_checked: bool = False
    browser_reason: str = ""
    skip_reason: str = ""
    evidence: list[EvidenceItem] = field(default_factory=list)

@dataclass
class Finding:
    status: str
    url: str
    method: str
    body: str | None
    payload: str
    reflected: bool
    reflections: list[Reflection]
    browser_confirmed: bool
    browser_evidence: str
    http_status: int | None
    context_snippets: list[str] = field(default_factory=list)
    error: str | None = None
    confidence: int = 0
    evidence_bundle: dict[str, object] = field(default_factory=dict)
    strategy: str = "default"
    diagnostics: ScanDiagnostics | None = None

@dataclass
class FormCandidate:
    method: str
    action: str
    fields: list[str]

@dataclass
class HttpResult:
    status: int | None
    body: str
    headers: dict[str, str]
    error: str | None = None

@dataclass
class CSPAnalysis:
    raw: str
    directives: dict[str, list[str]]
    issues: list[str]
    score: int

@dataclass
class SinkFinding:
    kind: str
    detail: str
    severity: int
    snippet: str

@dataclass
class ScriptAnalysis:
    inline_scripts: int
    external_scripts: list[str]
    suspicious_scripts: list[SinkFinding]
    data_flows: list[SinkFinding] = field(default_factory=list)

@dataclass
class FingerprintAnalysis:
    frameworks: list[str]
    sanitizers: list[str]
    headers: list[str] = field(default_factory=list)

@dataclass
class TargetIntelligence:
    target: ScanTarget
    status: int | None
    csp: CSPAnalysis
    waf_signals: list[str]
    script_analysis: ScriptAnalysis
    recommendations: list[str]
    fingerprints: FingerprintAnalysis = field(default_factory=lambda: FingerprintAnalysis([], []))

@dataclass
class BrowserValidation:
    confirmed: bool
    evidence: str
    taint_hits: list[str] = field(default_factory=list)
    dom_diff: list[str] = field(default_factory=list)
    console: list[str] = field(default_factory=list)
    snapshot_before: str = ""
    snapshot_after: str = ""

@dataclass
class ScanStrategy:
    name: str
    selected_payloads: list[str]
    fallback_payloads: list[str] = field(default_factory=list)
    browser_all: bool = False
    reason: str = ""
