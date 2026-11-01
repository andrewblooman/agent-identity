"""A local evaluator for IAM identity policies.

It narrows the candidates that `SimulatePrincipalPolicy` then confirms, and it is the only source
of answers when simulation is unavailable, such as in demo mode. It does not model SCPs, session
policies or the contents of conditions: anything behind a condition is reported as conditional.

Action names are case-insensitive in IAM. Resource names, such as S3 object keys, are not.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from agent_identity.models import Identity, Policy, Statement

_VARIABLE = re.compile(r"\$\{[^}]*\}")


@lru_cache(maxsize=4096)
def _compile(pattern: str) -> re.Pattern[str]:
    # IAM treats * as any run and ? as any single character. ${aws:...} variables match anything.
    # Unlike fnmatch, it has no character classes, so [ is only ever a literal.
    return re.compile(fnmatch.translate(_VARIABLE.sub("*", pattern).replace("[", "[[]")))


def matches(pattern: str, action: str) -> bool:
    return _compile(pattern.lower()).fullmatch(action.lower()) is not None


def matches_resource(pattern: str, resource: str) -> bool:
    return _compile(pattern).fullmatch(resource) is not None


def _any_match(patterns: list[str], action: str) -> bool:
    return any(matches(p, action) for p in patterns)


def _any_resource_match(patterns: list[str], resource: str) -> bool:
    return any(matches_resource(p, resource) for p in patterns)


def patterns_overlap(first: str, second: str) -> bool:
    """True if some string matches both patterns, such as data/* and */private/*."""
    a, b = _VARIABLE.sub("*", first), _VARIABLE.sub("*", second)
    seen: set[tuple[int, int]] = set()
    stack = [(0, 0)]
    while stack:
        i, j = stack.pop()
        if (i, j) in seen:
            continue
        seen.add((i, j))
        if i == len(a) and j == len(b):
            return True
        a_more, b_more = i < len(a), j < len(b)
        if a_more and a[i] == "*":
            stack.append((i + 1, j))
            if b_more:
                stack.append((i, j + 1))
        if b_more and b[j] == "*":
            stack.append((i, j + 1))
            if a_more:
                stack.append((i + 1, j))
        if a_more and b_more and "*" not in (a[i], b[j]) and (a[i] == b[j] or "?" in (a[i], b[j])):
            stack.append((i + 1, j + 1))
    return False


def _statement_applies(stmt: Statement, action: str, resource: str) -> bool:
    if stmt.actions and not _any_match(stmt.actions, action):
        return False
    if stmt.not_actions and _any_match(stmt.not_actions, action):
        return False
    if stmt.resources and not _any_resource_match(stmt.resources, resource):
        return False
    if stmt.not_resources and _any_resource_match(stmt.not_resources, resource):
        return False
    return True


@dataclass(frozen=True)
class Decision:
    allowed: bool
    conditional: bool = False
    policy: str | None = None
    denied: bool = False  # An explicit deny, which no allow anywhere can overcome


def _evaluate_policies(policies: list[Policy], action: str, resource: str) -> Decision:
    allow: Decision | None = None
    conditional_deny = False
    for policy in policies:
        for stmt in policy.statements:
            if not _statement_applies(stmt, action, resource):
                continue
            if stmt.effect == "Deny":
                if not stmt.conditional:
                    return Decision(False, policy=policy.name, denied=True)
                conditional_deny = True
            elif allow is None or (allow.conditional and not stmt.conditional):
                allow = Decision(True, stmt.conditional, policy.name)
    if allow is None:
        return Decision(False)
    return Decision(True, allow.conditional or conditional_deny, allow.policy)


def _statement_covers(stmt: Statement, identity: Identity) -> str | None:
    if stmt.not_principals:
        return "named" if _names_identity(stmt.not_principals, identity) is None else None
    if stmt.principals:
        return _names_identity(stmt.principals, identity)
    return "named"


def _names_identity(principals: list[str], identity: Identity) -> str | None:
    """How a principal list covers an identity: "named", its "account" as a whole, or None."""
    assumed = f"arn:aws:sts::{identity.account_id}:assumed-role/{identity.name}/"
    account = None
    for principal in principals:
        if principal in ("*", identity.arn) or principal.startswith(assumed):
            return "named"
        if principal in (identity.account_id, f"arn:aws:iam::{identity.account_id}:root"):
            account = "account"
    return account


def _evaluate_resource_policy(
    policy: Policy, identity: Identity, action: str, resource: str
) -> Decision:
    allow: Decision | None = None
    conditional_deny = False
    for stmt in policy.statements:
        if not _statement_applies(stmt, action, resource):
            continue
        covers = _statement_covers(stmt, identity)
        if covers is None:
            continue
        if stmt.effect == "Deny":
            if not stmt.conditional:
                return Decision(False, policy=policy.name, denied=True)
            conditional_deny = True
        # Naming the account only delegates to its IAM policies, so it grants nothing by itself.
        elif covers == "named" and (allow is None or (allow.conditional and not stmt.conditional)):
            allow = Decision(True, stmt.conditional, policy.name)
    if allow is None:
        return Decision(False, conditional_deny)
    return Decision(True, allow.conditional or conditional_deny, allow.policy)


def evaluate(
    identity: Identity,
    action: str,
    resource: str,
    resource_policy: Policy | None = None,
) -> Decision:
    decision = _evaluate_policies(identity.policies, action, resource)
    if decision.denied:
        return decision
    if resource_policy is not None:
        by_resource = _evaluate_resource_policy(resource_policy, identity, action, resource)
        if by_resource.denied:
            return by_resource
        if by_resource.allowed and not decision.allowed:
            decision = by_resource
        elif by_resource.conditional and decision.allowed:
            decision = Decision(True, True, decision.policy)
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


def _action_may_apply(stmt: Statement, action: str) -> bool:
    if stmt.actions and not any(patterns_overlap(p.lower(), action.lower()) for p in stmt.actions):
        return False
    return not (stmt.not_actions and _any_match(stmt.not_actions, action))


def _resource_may_apply(stmt: Statement, resource: str) -> bool:
    if stmt.resources and not any(patterns_overlap(p, resource) for p in stmt.resources):
        return False
    return not (stmt.not_resources and _any_resource_match(stmt.not_resources, resource))


def _denied_outright(policies: list[Policy], action: str, resource: str) -> bool:
    return any(
        stmt.effect == "Deny"
        and not stmt.conditional
        and _statement_applies(stmt, action, resource)
        for policy in policies
        for stmt in policy.statements
    )


def _boundary_permits(boundary: Policy, action: str, resource: str) -> bool:
    if _denied_outright([boundary], action, resource):
        return False
    return any(
        stmt.effect == "Allow"
        and _action_may_apply(stmt, action)
        and _resource_may_apply(stmt, resource)
        for stmt in boundary.statements
    )


def allows_action_on_any_resource(identity: Identity, action: str) -> bool:
    """True if the action survives denies and the boundary on some resource, however narrow.

    `action` may be a pattern such as s3:Put*, which counts if any action it covers is allowed.
    """
    for policy in identity.policies:
        for stmt in policy.statements:
            if stmt.effect != "Allow" or not _action_may_apply(stmt, action):
                continue
            for resource in stmt.resources or ["*"]:
                if _denied_outright(identity.policies, action, resource):
                    continue
                if identity.boundary is None or _boundary_permits(
                    identity.boundary, action, resource
                ):
                    return True
    return False


def narrower_resources(
    identity: Identity, action: str, whole: str, resource_policy: Policy | None = None
) -> list[str]:
    """Resource patterns granting the action on part of `whole`, such as one S3 prefix."""
    statements = [stmt for policy in identity.policies for stmt in policy.statements]
    if resource_policy is not None:
        statements += [
            stmt for stmt in resource_policy.statements if _statement_covers(stmt, identity)
        ]
    found = {
        pattern
        for stmt in statements
        if stmt.effect == "Allow" and _action_may_apply(stmt, action)
        for pattern in stmt.resources
        if patterns_overlap(pattern, whole) and not matches_resource(pattern, whole)
    }
    return sorted(found)


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
        and _names_identity(target.trusted_principals, identity) is not None
    ]


# ---- Parsing raw IAM JSON ---------------------------------------------------------------------


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


def _principals(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [p for values in value.values() for p in _as_list(values)]
    return _as_list(value)


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
                principals=_principals(stmt.get("Principal")),
                not_principals=_principals(stmt.get("NotPrincipal")),
            )
        )
    return Policy(name=name, statements=statements, **kwargs)
