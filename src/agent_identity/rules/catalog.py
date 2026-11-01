"""The rule registry and the context each rule sees.

A rule returns a list of hits, an empty list when it passes, or None when the data it needs isn't
available. None is what makes "not assessed" different from "passed".
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from agent_identity.models import (
    AccessLevel,
    Agent,
    DataGrant,
    DataStore,
    Domain,
    Identity,
    Secret,
    SecretGrant,
    Sensitivity,
    Severity,
    Snapshot,
    Trifecta,
)

SENSITIVE = {Sensitivity.RESTRICTED, Sensitivity.CONFIDENTIAL}
WRITE_LEVELS = {AccessLevel.WRITE, AccessLevel.DELETE, AccessLevel.ADMIN}


@dataclass
class Hit:
    evidence: str
    subject: str = ""
    severity: Severity | None = None


@dataclass
class Context:
    agent: Agent
    snapshot: Snapshot
    now: datetime
    identity: Identity | None
    identities: dict[str, Identity]
    stores: dict[str, DataStore]
    secrets: dict[str, Secret]
    grants: list[DataGrant]
    secret_grants: list[SecretGrant]
    all_grants: list[DataGrant]
    all_secret_grants: list[SecretGrant]
    trifecta: Trifecta
    autonomy_scope: int | None
    admin_equivalent: bool
    privesc_paths: list[str]
    indirect_admin: list[str] = field(default_factory=list)
    shared_with: list[Agent] = field(default_factory=list)
    unknown_domains: list[str] = field(default_factory=list)
    agents_by_id: dict[str, Agent] = field(default_factory=dict)


RuleFn = Callable[[Context], list[Hit] | None]


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    domain: Domain
    remediation: str
    nhi: tuple[str, ...]
    asi: tuple[str, ...]
    aws: tuple[str, ...]
    fn: RuleFn


RULES: list[Rule] = []


def rule(
    rule_id: str,
    title: str,
    severity: Severity,
    domain: Domain,
    remediation: str,
    nhi: tuple[str, ...] = (),
    asi: tuple[str, ...] = (),
    aws: tuple[str, ...] = (),
) -> Callable[[RuleFn], RuleFn]:
    def register(fn: RuleFn) -> RuleFn:
        RULES.append(Rule(rule_id, title, severity, domain, remediation, nhi, asi, aws, fn))
        return fn

    return register


NHI_NAMES = {
    "NHI1": "Improper offboarding",
    "NHI2": "Secret leakage",
    "NHI3": "Vulnerable third-party NHI",
    "NHI4": "Insecure authentication",
    "NHI5": "Overprivileged NHI",
    "NHI6": "Insecure cloud deployment configurations",
    "NHI7": "Long-lived secrets",
    "NHI8": "Environment isolation",
    "NHI9": "NHI reuse",
    "NHI10": "Human use of NHI",
}
ASI_NAMES = {
    "ASI01": "Agent goal hijack",
    "ASI02": "Tool misuse and exploitation",
    "ASI03": "Identity and privilege abuse",
    "ASI04": "Agentic supply chain vulnerabilities",
    "ASI05": "Unexpected code execution",
    "ASI06": "Context management and retrieval manipulation",
    "ASI07": "Insecure inter-agent communication",
    "ASI08": "Cascading failures",
    "ASI09": "Human-agent trust exploitation",
    "ASI10": "Rogue agents",
}
AWS_DIMENSIONS = (
    "Identity context",
    "Data, memory and state protection",
    "Audit and logging",
    "Agent and LLM controls",
    "Agency perimeters and policies",
    "Orchestration",
)
