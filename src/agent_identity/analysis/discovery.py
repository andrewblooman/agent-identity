"""Decide what each discovered workload is, and how sure we are.

Workloads arrive with evidence attached. A workload is only called an agent if it can use a model
and can also act on something, so a summariser Lambda doesn't inflate the count.
"""

from __future__ import annotations

import re

from agent_identity.analysis import permissions
from agent_identity.models import Agent, AgentKind, Confidence, Identity, Platform

_WRITE_VERB = re.compile(
    r"^(?:\*|Put|Create|Update|Delete|Send|Publish|Write|Start|Run|Modify|Attach|Pass|Batch.*Write"
    r"|Invoke(?:Function)|Execute|Terminate|Stop|Reboot|Remove|Add|Tag)",
    re.IGNORECASE,
)
# Writing to these is how a workload runs at all, so it doesn't count as being able to act.
_PLUMBING = {"logs", "xray", "cloudwatch", "ec2messages", "ssmmessages", "kms", "sts"}
_MODEL_ACTIONS = (
    "bedrock:InvokeModel",
    "bedrock:InvokeModelWithResponseStream",
    "bedrock:Converse",
)
_MANAGED_PLATFORMS = {Platform.BEDROCK_AGENT, Platform.AGENTCORE}
MODEL_SIGNALS = {"managed", "behaviour", "config"}


def can_act(identity: Identity | None) -> bool | None:
    if identity is None:
        return None
    for policy in identity.policies:
        for stmt in policy.statements:
            if stmt.effect != "Allow":
                continue
            for action in stmt.actions:
                service, _, verb = action.partition(":")
                if action == "*":
                    return True
                if service.lower() in _PLUMBING:
                    continue
                if service.lower() == "ec2" and "NetworkInterface" in verb:
                    continue
                if _WRITE_VERB.match(verb or ""):
                    return True
    return False


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
