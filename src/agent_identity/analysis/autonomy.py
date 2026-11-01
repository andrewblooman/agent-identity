"""Estimate an agent's scope on the AWS Agentic AI Security Scoping Matrix.

AWS defines the scopes by human oversight, which configuration can't fully show, so this is an
estimate from triggers, write capability and approval settings.
"""

from __future__ import annotations

from agent_identity.models import AccessLevel, Agent, DataGrant

_AUTONOMOUS_TRIGGERS = {"schedule", "event", "queue"}


def estimate_scope(agent: Agent, grants: list[DataGrant]) -> tuple[int | None, list[str]]:
    reasons: list[str] = []
    write_grants = [
        g
        for g in grants
        if {AccessLevel.WRITE, AccessLevel.DELETE, AccessLevel.ADMIN} & set(g.levels)
        and g.store_arn not in agent.memory_arns
    ]
    write_tools = [t for t in agent.tools if t.writes]
    saas_writes = [s for s in agent.saas if s.can_write]
    if write_grants:
        reasons.append(f"Can change {len(write_grants)} data store(s)")
    if write_tools:
        reasons.append(f"{len(write_tools)} tool(s) can make changes")
    if saas_writes:
        reasons.append(f"Can write to {', '.join(s.vendor for s in saas_writes)}")
    can_write = bool(write_grants or write_tools or saas_writes)

    if agent.triggers is None and not can_write:
        return None, ["Triggers and write capability could not be determined"]
    triggers = set(agent.triggers or [])
    autonomous = sorted(triggers & _AUTONOMOUS_TRIGGERS)

    if autonomous and can_write:
        reasons.append(f"Starts on its own: {', '.join(autonomous)}")
        return 4, reasons
    if not can_write:
        return 1, ["No write capability found", *reasons]
    all_approved = (
        not write_grants and write_tools and all(t.requires_approval for t in write_tools)
    )
    if all_approved:
        reasons.append("Every change-making tool requires human approval")
        return 2, reasons
    reasons.append("Started by a person or request, then acts without per-change approval")
    return 3, reasons
