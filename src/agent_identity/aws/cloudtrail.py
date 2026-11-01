"""Find who actually called a model.

InvokeModel and Converse are management events, so LookupEvents sees them with no extra setup.
InvokeAgent and Retrieve are data events, which it can't see. Calls to the bedrock-mantle endpoint
are logged differently and aren't covered either. Streaming calls add a second AwsServiceEvent
record, which isn't a call and is left out of the count.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from agent_identity.aws.base import CoverageLog, attempt
from agent_identity.aws.session import client

MODEL_EVENTS = ("InvokeModel", "InvokeModelWithResponseStream", "Converse", "ConverseStream")
_MAX_PAGES_PER_EVENT = 6


@dataclass
class ModelUse:
    calls: int = 0
    last_call: datetime | None = None
    human_agents: set[str] = field(default_factory=set)


def _principal(event: dict[str, Any]) -> str | None:
    identity = event.get("userIdentity") or {}
    issuer = (identity.get("sessionContext") or {}).get("sessionIssuer") or {}
    return issuer.get("arn") or identity.get("arn")


def _looks_human(user_agent: str) -> str | None:
    lowered = user_agent.lower()
    if lowered.startswith("mozilla") or "console.amazonaws.com" in lowered:
        return "AWS console"
    if lowered.startswith("aws-cli"):
        return "AWS CLI"
    return None


def collect_model_use(
    session: Any, region: str, now: datetime, lookback_days: int, coverage: CoverageLog
) -> dict[str, ModelUse]:
    api = client(session, "cloudtrail", region)
    start = now - timedelta(days=lookback_days)

    def scan() -> dict[str, ModelUse]:
        usage: dict[str, ModelUse] = {}
        for name in MODEL_EVENTS:
            pages = api.get_paginator("lookup_events").paginate(
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": name}],
                StartTime=start,
                EndTime=now,
                PaginationConfig={"MaxItems": _MAX_PAGES_PER_EVENT * 50, "PageSize": 50},
            )
            for page in pages:
                for record in page.get("Events", []):
                    _record(record, usage)
        return usage

    usage, ok = attempt(coverage, "CloudTrail", region, scan, {})
    return usage if ok else {}


def _record(record: dict[str, Any], usage: dict[str, ModelUse]) -> None:
    """Keep only who, when and which client. Request details stay out of the snapshot."""
    event = json.loads(record.get("CloudTrailEvent") or "{}")
    if event.get("eventType") != "AwsApiCall":
        return
    principal = _principal(event)
    if not principal:
        return
    entry = usage.setdefault(principal, ModelUse())
    entry.calls += 1
    when = record.get("EventTime")
    if when and (entry.last_call is None or when > entry.last_call):
        entry.last_call = when
    human = _looks_human(event.get("userAgent") or "")
    if human:
        entry.human_agents.add(human)


def data_event_buckets(session: Any, region: str, coverage: CoverageLog) -> set[str] | None:
    """Bucket ARNs with S3 data events on. "*" means every bucket. None means not known."""
    api = client(session, "cloudtrail", region)

    def scan() -> set[str]:
        found: set[str] = set()
        for trail in api.describe_trails(includeShadowTrails=False).get("trailList", []):
            selectors = api.get_event_selectors(TrailName=trail["TrailARN"])
            for selector in selectors.get("EventSelectors", []):
                for resource in selector.get("DataResources", []):
                    if resource.get("Type") == "AWS::S3::Object":
                        for value in resource.get("Values", []):
                            found.add("*" if value == "arn:aws:s3" else value.rstrip("/"))
            for selector in selectors.get("AdvancedEventSelectors", []):
                fields = {f["Field"]: f for f in selector.get("FieldSelectors", [])}
                if "AWS::S3::Object" not in fields.get("resources.type", {}).get("Equals", []):
                    continue
                prefixes = fields.get("resources.ARN", {}).get("StartsWith")
                if prefixes:
                    found.update(p.rstrip("/") for p in prefixes)
                else:
                    found.add("*")
        return found

    found, ok = attempt(coverage, "CloudTrail data events", region, scan, set(), record_ok=False)
    return found if ok else None
