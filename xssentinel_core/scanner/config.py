"""Internal configuration loading helpers.

The public CLI intentionally stays small. Internal subsystems use this module to
read typed defaults from environment variables while preserving command-line
backward compatibility.
"""

import os
from dataclasses import dataclass, field


def env_int(name: str, default: int, minimum: int | None = None, maximum: int | None = None) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        value = default
    else:
        try:
            value = int(raw)
        except ValueError:
            value = default
    if minimum is not None:
        value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on", "y"}


def env_float(name: str, default: float, minimum: float | None = None, maximum: float | None = None) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        value = default
    else:
        try:
            value = float(raw)
        except ValueError:
            value = default
    if minimum is not None:
        value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


@dataclass(frozen=True)
class CrawlerRuntimeConfig:
    """Runtime limits for endpoint discovery.

    `max_depth=1` means the start page is analyzed, which matches the legacy
    discovery behavior. Higher values enable recursive same-origin crawling.
    """

    max_depth: int = 1
    max_pages: int = 12
    max_workers: int = 4
    max_scripts: int = 12
    respect_robots: bool = False

    @classmethod
    def from_env(cls) -> "CrawlerRuntimeConfig":
        return cls(
            max_depth=env_int("XSSENTINEL_CRAWL_DEPTH", 1, 1, 5),
            max_pages=env_int("XSSENTINEL_CRAWL_MAX_PAGES", 12, 1, 100),
            max_workers=env_int("XSSENTINEL_CRAWL_WORKERS", 4, 1, 16),
            max_scripts=env_int("XSSENTINEL_CRAWL_MAX_SCRIPTS", 12, 0, 100),
            respect_robots=env_bool("XSSENTINEL_RESPECT_ROBOTS", False),
        )


@dataclass(frozen=True)
class BrowserRuntimeConfig:
    """Timing and retry defaults for browser-based confirmation."""

    launch_timeout_s: float = 3.0
    poll_interval_s: float = 0.05
    launch_retries: int = 2
    load_window_s: float = 5.0
    trigger_window_s: float = 4.0
    followup_rounds: int = 3
    followup_delay_s: float = 0.5
    playwright_initial_wait_ms: int = 1500
    playwright_interaction_rounds: int = 3
    playwright_interaction_wait_ms: int = 300

    @classmethod
    def from_env(cls) -> "BrowserRuntimeConfig":
        return cls(
            launch_timeout_s=env_float("XSSENTINEL_BROWSER_LAUNCH_TIMEOUT", 3.0, 0.5, 30.0),
            poll_interval_s=env_float("XSSENTINEL_BROWSER_POLL_INTERVAL", 0.05, 0.01, 1.0),
            launch_retries=env_int("XSSENTINEL_BROWSER_LAUNCH_RETRIES", 2, 0, 10),
            load_window_s=env_float("XSSENTINEL_BROWSER_LOAD_WINDOW", 5.0, 0.5, 30.0),
            trigger_window_s=env_float("XSSENTINEL_BROWSER_TRIGGER_WINDOW", 4.0, 0.5, 30.0),
            followup_rounds=env_int("XSSENTINEL_BROWSER_FOLLOWUP_ROUNDS", 3, 0, 10),
            followup_delay_s=env_float("XSSENTINEL_BROWSER_FOLLOWUP_DELAY", 0.5, 0.0, 5.0),
            playwright_initial_wait_ms=env_int("XSSENTINEL_BROWSER_PLAYWRIGHT_INITIAL_WAIT", 1500, 0, 10000),
            playwright_interaction_rounds=env_int("XSSENTINEL_BROWSER_PLAYWRIGHT_ROUNDS", 3, 0, 10),
            playwright_interaction_wait_ms=env_int("XSSENTINEL_BROWSER_PLAYWRIGHT_WAIT", 300, 0, 5000),
        )


@dataclass(frozen=True)
class AgentRuntimeConfig:
    """Runtime policy for the internal agent control plane."""

    confidence_threshold: int = 70
    retry_limit: int = 1
    enable_cache: bool = True

    @classmethod
    def from_env(cls) -> "AgentRuntimeConfig":
        return cls(
            confidence_threshold=env_int("XSSENTINEL_AGENT_CONFIDENCE_THRESHOLD", 70, 1, 100),
            retry_limit=env_int("XSSENTINEL_AGENT_RETRY_LIMIT", 1, 0, 5),
            enable_cache=env_bool("XSSENTINEL_AGENT_CACHE", True),
        )


@dataclass(frozen=True)
class ScannerRuntimeConfig:
    """Aggregate runtime configuration for injectable scanner services."""

    crawler: CrawlerRuntimeConfig = field(default_factory=CrawlerRuntimeConfig.from_env)
    browser: BrowserRuntimeConfig = field(default_factory=BrowserRuntimeConfig.from_env)
    agent: AgentRuntimeConfig = field(default_factory=AgentRuntimeConfig.from_env)

    @classmethod
    def from_env(cls) -> "ScannerRuntimeConfig":
        return cls(CrawlerRuntimeConfig.from_env(), BrowserRuntimeConfig.from_env(), AgentRuntimeConfig.from_env())
