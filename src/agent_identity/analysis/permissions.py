"""A local evaluator for IAM identity policies.

It narrows the candidates that `SimulatePrincipalPolicy` then confirms, and it is the only source
of answers when simulation is unavailable, such as in demo mode. It does not model SCPs, session
policies or the contents of conditions: anything behind a condition is reported as conditional.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from agent_identity.models import Identity, Policy, Statement


@lru_cache(maxsize=4096)
def _compile(pattern: str) -> re.Pattern[str]:
    # IAM treats * as any run and ? as any single character. ${aws:...} variables match anything.
    pattern = re.sub(r"\$\{[^}]*\}", "*", pattern)
    return re.compile(fnmatch.translate(pattern.lower()))


def matches(pattern: str, value: str) -> bool:
    return _compile(pattern).fullmatch(value.lower()) is not None


def _any_match(patterns: list[str], value: str) -> bool:
    return any(matches(p, value) for p in patterns)


def _statement_applies(stmt: Statement, action: str, resource: str) -> bool:
    if stmt.actions and not _any_match(stmt.actions, action):
        return False
    if stmt.not_actions and _any_match(stmt.not_actions, action):
        return False
    if stmt.resources and not _any_match(stmt.resources, resource):
        return False
    if stmt.not_resources and _any_match(stmt.not_resources, resource):
        return False
    return True


@dataclass(frozen=True)
class Decision:
    allowed: bool
    conditional: bool = False
    policy: str | None = None


def _evaluate_policies(policies: list[Policy], action: str, resource: str) -> Decision:
    allow: Decision | None = None
    conditional_deny = False
    for policy in policies:
        for stmt in policy.statements:
            if not _statement_applies(stmt, action, resource):
                continue
            if stmt.effect == "Deny":
                if not stmt.conditional:
                    return Decision(False, policy=policy.name)
                conditional_deny = True
            elif allow is None or (allow.conditional and not stmt.conditional):
                allow = Decision(True, stmt.conditional, policy.name)
    if allow is None:
        return Decision(False)
    return Decision(True, allow.conditional or conditional_deny, allow.policy)


def evaluate(
    identity: Identity,
    action: str,
    resource: str,
    resource_policy: Policy | None = None,
) -> Decision:
    decision = _evaluate_policies(identity.policies, action, resource)
    if resource_policy is not None:
        by_resource = _evaluate_policies([resource_policy], action, resource)
        denied = any(
            stmt.effect == "Deny"
            and not stmt.conditional
            and _statement_applies(stmt, action, resource)
            for stmt in resource_policy.statements
        )
        if denied:
            return Decision(False, policy=resource_policy.name)
        if not decision.allowed and by_resource.allowed:
            decision = by_resource
    if decision.allowed and identity.boundary is not None:
        bounded = _evaluate_policies([identity.boundary], action, resource)
        if not bounded.allowed:
            return Decision(False, policy=identity.boundary.name)
        if bounded.conditional:
            decision = Decision(True, True, decision.policy)
    return decision


def is_admin_equivalent(identity: Identity) -> bool:
    """True if an identity can do anything, tested with actions from unrelated services."""
    probes = ("iam:PassRole", "iam:CreateUser", "s3:DeleteBucket", "kms:ScheduleKeyDeletion")
    return all(
        (d := evaluate(identity, action, "*")).allowed and not d.conditional for action in probes
    )


PRIVILEGE_ESCALATION: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Attach an admin policy to itself", ("iam:AttachRolePolicy",)),
    ("Write an inline policy on itself", ("iam:PutRolePolicy",)),
    ("Create a new version of an attached policy", ("iam:CreatePolicyVersion",)),
    ("Create access keys for another user", ("iam:CreateAccessKey",)),
    ("Pass a stronger role to a new Lambda", ("iam:PassRole", "lambda:CreateFunction")),
    ("Pass a stronger role to an ECS task", ("iam:PassRole", "ecs:RunTask")),
    ("Pass a stronger role to a new Bedrock agent", ("iam:PassRole", "bedrock:CreateAgent")),
    ("Change another role's trust policy", ("iam:UpdateAssumeRolePolicy",)),
)


def allows_action_on_any_resource(identity: Identity, action: str) -> bool:
    """True if some statement allows the action on at least one resource, however narrow."""
    for policy in identity.policies:
        for stmt in policy.statements:
            if stmt.effect != "Allow":
                continue
            if stmt.actions and not _any_match(stmt.actions, action):
                continue
            if stmt.not_actions and _any_match(stmt.not_actions, action):
                continue
            if identity.boundary is None or _boundary_allows(identity.boundary, action):
                return True
    return False


def _boundary_allows(boundary: Policy, action: str) -> bool:
    for stmt in boundary.statements:
        if stmt.effect == "Deny" and not stmt.conditional and "*" in stmt.resources:
            if _any_match(stmt.actions, action):
                return False
    return any(
        stmt.effect == "Allow" and _any_match(stmt.actions, action) for stmt in boundary.statements
    )


def explicitly_allows_service(identity: Identity, service: str, action: str) -> bool:
    """True if a statement names the service. A bare "*" doesn't count."""
    for policy in identity.policies:
        for stmt in policy.statements:
            if stmt.effect == "Allow" and any(
                p.lower().startswith(f"{service}:") and matches(p, action) for p in stmt.actions
            ):
                return True
    return False


def privilege_escalation_paths(identity: Identity) -> list[str]:
    return [
        label
        for label, actions in PRIVILEGE_ESCALATION
        if all(allows_action_on_any_resource(identity, action) for action in actions)
    ]


def assumable_roles(identity: Identity, all_identities: list[Identity]) -> list[Identity]:
    return [
        target
        for target in all_identities
        if target.kind == "role"
        and target.arn != identity.arn
        and evaluate(identity, "sts:AssumeRole", target.arn).allowed
        and (identity.arn in target.trusted_principals or target.trust_is_broad)
    ]


# ---- Parsing raw IAM JSON ---------------------------------------------------------------------


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


def parse_policy(name: str, document: dict[str, Any] | None, **kwargs: Any) -> Policy:
    statements = []
    raw = (document or {}).get("Statement", [])
    for stmt in [raw] if isinstance(raw, dict) else raw:
        statements.append(
            Statement(
                effect=stmt.get("Effect", "Deny"),
                actions=_as_list(stmt.get("Action")),
                not_actions=_as_list(stmt.get("NotAction")),
                resources=_as_list(stmt.get("Resource")),
                not_resources=_as_list(stmt.get("NotResource")),
                conditional=bool(stmt.get("Condition")),
            )
        )
    return Policy(name=name, statements=statements, **kwargs)
