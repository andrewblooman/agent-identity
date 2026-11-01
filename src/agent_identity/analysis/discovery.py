"""Decide what each discovered workload is, and how sure we are.

Workloads arrive with evidence attached. A workload is only called an agent if it can use a model
and can also act on something, so a summariser Lambda doesn't inflate the count.
"""

from __future__ import annotations

import re

from agent_identity.analysis import permissions
from agent_identity.models import Agent, AgentKind, Confidence, Identity, Platform, Policy

_WRITE_VERB = re.compile(
    r"^(?:\*|Put|Create|Update|Delete|Send|Publish|Write|Start|Run|Modify|Attach|Pass|Batch.*Write"
    r"|Invoke(?:Function)|Execute|Terminate|Stop|Reboot|Remove|Add|Tag)",
    re.IGNORECASE,
)
# Writing to these is how a workload runs at all, so it doesn't count as being able to act.
_PLUMBING = {"logs", "xray", "cloudwatch", "ec2messages", "ssmmessages", "kms", "sts"}
# A NotAction allow names no write action, so test it with some common ones.
_WRITE_PROBES = ("s3:PutObject", "dynamodb:PutItem", "lambda:InvokeFunction", "sns:Publish")
_MODEL_ACTIONS = (
    "bedrock:InvokeModel",
    "bedrock:InvokeModelWithResponseStream",
    "bedrock:Converse",
)
_MANAGED_PLATFORMS = {Platform.BEDROCK_AGENT, Platform.AGENTCORE}
MODEL_SIGNALS = {"managed", "behaviour", "config"}


def _is_write_action(action: str) -> bool:
    if action == "*":
        return True
    service, _, verb = action.partition(":")
    if service.lower() in _PLUMBING:
        return False
    if service.lower() == "ec2" and "NetworkInterface" in verb:
        return False
    return bool(_WRITE_VERB.match(verb))


def _write_actions(policies: list[Policy]) -> list[str]:
    found: list[str] = []
    for policy in policies:
        for stmt in policy.statements:
            if stmt.effect == "Allow":
                found += [a for a in stmt.actions if _is_write_action(a)]
                if stmt.not_actions:
                    found += _WRITE_PROBES
    return found


def can_act(identity: Identity | None) -> bool | None:
    """True if a write action survives explicit denies and the permission boundary."""
    if identity is None:
        return None
    actions = _write_actions(identity.policies)
    if identity.boundary is not None:
        # s3:* under a read-only boundary can't write, so a write must be in both.
        limits = _write_actions([identity.boundary])
        actions = [
            limit if permissions.matches(action, limit) else action
            for action in actions
            for limit in limits
            if permissions.patterns_overlap(action.lower(), limit.lower())
        ]
    return any(permissions.allows_action_on_any_resource(identity, a) for a in actions)


def has_explicit_model_access(identity: Identity) -> bool:
    return any(
        permissions.explicitly_allows_service(identity, "bedrock", action)
        for action in _MODEL_ACTIONS
    )


def classify(agent: Agent, identity: Identity | None) -> None:
    signals = {e.signal for e in agent.evidence}
    if signals & {"managed", "behaviour"}:
        agent.confidence = Confidence.CONFIRMED
    elif "config" in signals:
        agent.confidence = Confidence.LIKELY
    else:
        agent.confidence = Confidence.POSSIBLE

    if agent.platform in _MANAGED_PLATFORMS:
        agent.kind = AgentKind.AGENT
        return
    if agent.tools:
        agent.kind = AgentKind.AGENT
        return
    if signals <= {"iam"}:
        # A permission alone doesn't show that anything is using the model.
        agent.kind = AgentKind.UNKNOWN
        return
    acts = can_act(identity)
    if signals & MODEL_SIGNALS or (identity is not None and has_explicit_model_access(identity)):
        if acts is None:
            agent.kind = AgentKind.UNKNOWN
        elif acts:
            agent.kind = AgentKind.AGENT
        else:
            agent.kind = AgentKind.MODEL_CONSUMER
    else:
        agent.kind = AgentKind.UNKNOWN
