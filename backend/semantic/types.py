"""
The semantic model: an LLM-produced description of what an application
is, expressed in a form the hypothesis generator can reason over.

This is deliberately a *small, focused* schema. The LLM's job is to
answer a handful of specific questions about the app, not to write
prose. Everything here is either a resource the app manages, a
workflow a user can go through, or a hint about roles/trust boundaries.

Anything the LLM cannot determine must be left null or empty. Hallucination
is the failure mode we design against most carefully, so the schema
makes absence expressible and the prompt tells the model to prefer
"unknown" over a guess.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class Resource:
    """A noun the app manages. 'orders', 'users', 'invitations', ..."""
    name: str                             # singular, lowercase: "order"
    endpoints: list[str] = field(default_factory=list)   # paths that operate on it
    identifier_field: str = ""            # "order_id" | "id" | ...
    owner_field: str = ""                 # field in the response that names the owner, e.g. "user_id"
    sensitivity: str = "unknown"          # "low" | "medium" | "high" | "unknown"
    notes: str = ""

    def has_ownership_signal(self) -> bool:
        """If we know a resource has an owner field, it's a BOLA candidate."""
        return bool(self.owner_field) or any(
            kw in self.name.lower()
            for kw in ("user", "account", "order", "invoice", "invitation",
                       "message", "document", "file", "payment", "profile")
        )


@dataclass
class Workflow:
    """A multi-step thing a user does. 'checkout', 'signup', ..."""
    name: str
    steps: list[str] = field(default_factory=list)     # endpoint paths in order
    involves_payment: bool = False
    notes: str = ""


@dataclass
class RoleHint:
    name: str                             # "anonymous" | "user" | "admin" | ...
    evidence: str = ""                    # why the LLM thinks this role exists


@dataclass
class SemanticModel:
    target: str
    app_purpose: str = ""                 # one paragraph: what does this app do?
    product_category: str = ""            # "e-commerce" | "SaaS" | "social" | ...

    roles: list[RoleHint] = field(default_factory=list)
    resources: list[Resource] = field(default_factory=list)
    workflows: list[Workflow] = field(default_factory=list)
    trust_boundaries: list[str] = field(default_factory=list)   # plain strings

    auth_flow_notes: str = ""

    # What the LLM could not determine. Populated by the model itself,
    # so its unknowns are explicit and don't get silently dropped.
    unknowns: list[str] = field(default_factory=list)

    # Metadata for audit and prompt-iteration
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    model_name: str = ""
    prompt_tokens_estimate: int = 0

    # Raw LLM output, kept for debugging. Not used downstream.
    raw_response: str = ""

    def resources_with_ownership(self) -> list[Resource]:
        return [r for r in self.resources if r.has_ownership_signal()]

    def summary(self) -> dict:
        return {
            "target": self.target,
            "product_category": self.product_category,
            "app_purpose": self.app_purpose[:200],
            "resource_count": len(self.resources),
            "resources_with_ownership": [r.name for r in self.resources_with_ownership()],
            "workflow_count": len(self.workflows),
            "roles": [r.name for r in self.roles],
            "trust_boundaries": self.trust_boundaries,
            "unknowns": self.unknowns,
        }
