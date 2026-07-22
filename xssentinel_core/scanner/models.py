"""Scanner data models."""

from .settings import *

@dataclass
class ScanTarget:
    method: str
    url: str
    data: str | None
    content_type: str
    fuzz_locations: list[str]
    source: str = "unknown"

@dataclass
class Reflection:
    context: str
    detail: str
    severity: int

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

@dataclass
class TargetIntelligence:
    target: ScanTarget
    status: int | None
    csp: CSPAnalysis
    waf_signals: list[str]
    script_analysis: ScriptAnalysis
    recommendations: list[str]
