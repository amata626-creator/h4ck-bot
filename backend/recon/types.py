"""
Data types produced by the recon phase.

These are the raw material for the semantic model and the hypothesis
generator. Nothing here is a finding - findings are still Finding
objects from core.schema. Recon output is an *inventory* of what the
target exposes, which downstream components reason over.

Everything is JSON-serializable via dataclasses.asdict(), so a recon
result can be cached to disk and reloaded without re-crawling.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class HttpTrace:
    """One request/response pair captured during recon."""
    method: str
    url: str
    request_headers: dict = field(default_factory=dict)
    request_body: str = ""
    status: int = 0
    response_headers: dict = field(default_factory=dict)
    response_body: str = ""             # truncated to MAX_BODY_CHARS
    elapsed_ms: int = 0
    error: Optional[str] = None

    def body_excerpt(self, n: int = 800) -> str:
        return self.response_body[:n]


@dataclass
class Endpoint:
    """A single callable thing the app exposes."""
    path: str                            # "/api/v2/orders/{id}"
    methods: list[str] = field(default_factory=list)   # ["GET", "POST"]
    discovered_from: str = ""            # "openapi" | "js_bundle" | "crawl" | "form" | "guess"
    params: list[str] = field(default_factory=list)
    auth_required: Optional[bool] = None # None = unknown, not tested
    content_type: str = ""               # "application/json" | "text/html"
    sample_response_keys: list[str] = field(default_factory=list)  # top-level JSON keys
    notes: str = ""

    @property
    def signature(self) -> str:
        """Stable identity for dedup: method set + normalized path."""
        m = ",".join(sorted(self.methods)) or "ANY"
        return f"{m} {self.path}"


@dataclass
class AuthHints:
    """Everything recon learned that bears on authentication."""
    login_paths: list[str] = field(default_factory=list)
    cookie_names: list[str] = field(default_factory=list)
    auth_header_names: list[str] = field(default_factory=list)  # e.g. "authorization"
    token_endpoint: Optional[str] = None
    csrf_param_names: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class TechStack:
    """Fingerprint of what's running."""
    server: str = ""                     # Server: header
    powered_by: str = ""                 # X-Powered-By: header
    framework: str = ""                  # inferred: "express" | "django" | ...
    language: str = ""                   # inferred: "python" | "java" | ...
    cms: str = ""                        # inferred: "wordpress" | "drupal" | ...
    detected_products: list[str] = field(default_factory=list)  # raw matches
    notes: str = ""

    def is_empty(self) -> bool:
        return not any([
            self.server, self.powered_by, self.framework,
            self.language, self.cms, self.detected_products,
        ])


@dataclass
class ReconResult:
    """Complete output of the recon phase for one target."""
    target: str
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None

    base_urls: list[str] = field(default_factory=list)          # reachable http(s) bases
    tech: TechStack = field(default_factory=TechStack)
    auth: AuthHints = field(default_factory=AuthHints)
    endpoints: list[Endpoint] = field(default_factory=list)
    js_bundles: list[str] = field(default_factory=list)
    openapi_spec: Optional[dict] = None
    robots_txt: Optional[str] = None
    sitemap_xml: Optional[str] = None

    # Raw traces, capped so this stays bounded. The LLM step reads
    # these as context; keeping more than ~20 causes prompt bloat.
    http_traces: list[HttpTrace] = field(default_factory=list)

    # Anything the recon phase explicitly could not determine.
    unknowns: list[str] = field(default_factory=list)

    def add_endpoint(self, ep: Endpoint) -> None:
        """Dedup by signature. If a path is found by two sources, keep
        the first discovery source and merge methods/params."""
        for existing in self.endpoints:
            if existing.path == ep.path:
                for m in ep.methods:
                    if m not in existing.methods:
                        existing.methods.append(m)
                for p in ep.params:
                    if p not in existing.params:
                        existing.params.append(p)
                if ep.sample_response_keys and not existing.sample_response_keys:
                    existing.sample_response_keys = ep.sample_response_keys
                return
        self.endpoints.append(ep)

    def summary(self) -> dict:
        return {
            "target": self.target,
            "base_urls": self.base_urls,
            "endpoint_count": len(self.endpoints),
            "js_bundle_count": len(self.js_bundles),
            "has_openapi": self.openapi_spec is not None,
            "has_robots": self.robots_txt is not None,
            "login_paths": self.auth.login_paths,
            "tech": {
                "server": self.tech.server,
                "framework": self.tech.framework,
                "language": self.tech.language,
            },
            "unknowns": self.unknowns,
        }
