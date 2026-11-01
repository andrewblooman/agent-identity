"""Security services that may be switched off. The scanner reads them and never enables them."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from agent_identity.aws.base import CoverageLog, attempt, quiet
from agent_identity.aws.session import client
from agent_identity.models import Agent, CoverageStatus, DataStore, Domain, Sensitivity


def access_analyzers(
    session: Any, region: str, coverage: CoverageLog
) -> tuple[bool | None, bool | None]:
    api = client(session, "accessanalyzer", region)
    analyzers, ok = attempt(
        coverage,
        "Access Analyzer",
        region,
        lambda: api.list_analyzers().get("analyzers", []),
        [],
        record_ok=False,
    )
    if not ok:
        return None, None
    kinds = {a.get("type", "") for a in analyzers if a.get("status") == "ACTIVE"}
    unused = any("UNUSED" in k for k in kinds)
    internal = any("INTERNAL" in k for k in kinds)
    if unused:
        coverage.ok("Access Analyzer (unused access)", region)
    else:
        coverage.gap(
            "Access Analyzer (unused access)",
            region,
            CoverageStatus.NOT_ENABLED,
            "Using IAM last-accessed data instead",
            [Domain.IDENTITY],
        )
    return unused, internal


def apply_macie(
    session: Any, region: str, stores: list[DataStore], coverage: CoverageLog
) -> bool | None:
    api = client(session, "macie2", region)
    session_info, ok = attempt(
        coverage, "Macie", region, api.get_macie_session, None, [Domain.DATA], record_ok=False
    )
    if not ok or session_info is None:
        return False if coverage.entries[-1].status == CoverageStatus.NOT_ENABLED else None
    if session_info.get("status") != "ENABLED":
        coverage.gap(
            "Macie",
            region,
            CoverageStatus.NOT_ENABLED,
            "Sensitivity comes from tags and names instead",
            [Domain.DATA],
        )
        return False
    buckets, ok = attempt(
        coverage,
        "Macie",
        region,
        lambda: [
            b
            for page in api.get_paginator("describe_buckets").paginate()
            for b in page.get("buckets", [])
        ],
        [],
        [Domain.DATA],
    )
    by_name = {b["bucketName"]: b for b in buckets}
    for store in stores:
        bucket = by_name.get(store.name)
        if store.type != "S3" or bucket is None:
            continue
        score = bucket.get("sensitivityScore")
        if score is None or score < 0:  # Macie uses -1 when it can't score a bucket.
            continue
        if store.sensitivity_source == "classification tag":
            continue  # A person's explicit label outranks a statistical score.
        store.sensitivity = (
            Sensitivity.RESTRICTED
            if score >= 70
            else Sensitivity.CONFIDENTIAL
            if score >= 40
            else Sensitivity.INTERNAL
        )
        store.sensitivity_source = f"Macie score {score}"
    return True


def apply_dns_logs(
    session: Any, region: str, agents: list[Agent], now: datetime, coverage: CoverageLog
) -> None:
    """Mark configured domains as observed if they're in existing Resolver query logs."""
    api = client(session, "route53resolver", region)
    configs, ok = attempt(
        coverage,
        "Route 53 Resolver query logs",
        region,
        lambda: api.list_resolver_query_log_configs().get("ResolverQueryLogConfigs", []),
        [],
        [Domain.NETWORK],
        record_ok=False,
    )
    if not ok:
        return
    log_groups = [
        c["DestinationArn"].split(":log-group:")[-1].split(":")[0]
        for c in configs
        if ":log-group:" in c.get("DestinationArn", "")
    ]
    if not log_groups:
        coverage.gap(
            "Route 53 Resolver query logs",
            region,
            CoverageStatus.NOT_ENABLED,
            "Domains show what's configured, not what was contacted",
            [Domain.NETWORK],
        )
        return
    coverage.ok("Route 53 Resolver query logs", region)
    logs = client(session, "logs", region)
    start = int((now - timedelta(days=7)).timestamp() * 1000)
    for agent in agents:
        for ref in agent.domains:
            for group in log_groups:
                found = quiet(
                    lambda g=group, h=ref.hostname: logs.filter_log_events(
                        logGroupName=g, startTime=start, limit=1, filterPattern=f'"{h}"'
                    ).get("events", []),
                    [],
                )
                if found:
                    ref.observed = True
                    break
