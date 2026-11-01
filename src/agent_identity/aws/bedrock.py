"""Bedrock Agents and knowledge bases, plus model invocation logging."""

from __future__ import annotations

from typing import Any

from agent_identity.analysis.redaction import fingerprint_instructions, hostnames_in
from agent_identity.aws.base import CoverageLog, attempt, quiet
from agent_identity.aws.session import client
from agent_identity.models import (
    Agent,
    AgentKind,
    Confidence,
    DataStore,
    DomainRef,
    Evidence,
    Platform,
    RuntimeProfile,
    Tool,
)

DRAFT = "DRAFT"


def collect_knowledge_bases(session: Any, region: str, coverage: CoverageLog) -> list[DataStore]:
    api = client(session, "bedrock-agent", region)

    def list_all() -> list[dict]:
        return [
            k
            for page in api.get_paginator("list_knowledge_bases").paginate()
            for k in page.get("knowledgeBaseSummaries", [])
        ]

    stores = []
    summaries, _ = attempt(coverage, "Bedrock knowledge bases", region, list_all, [])
    for summary in summaries:
        kb_id = summary["knowledgeBaseId"]
        kb = quiet(lambda k=kb_id: api.get_knowledge_base(knowledgeBaseId=k)["knowledgeBase"], {})
        sources = []
        for item in quiet(
            lambda k=kb_id: api.list_data_sources(knowledgeBaseId=k).get("dataSourceSummaries", []),
            [],
        ):
            detail = quiet(
                lambda k=kb_id, d=item["dataSourceId"]: api.get_data_source(
                    knowledgeBaseId=k, dataSourceId=d
                )["dataSource"],
                {},
            )
            s3_config = (detail.get("dataSourceConfiguration") or {}).get("s3Configuration") or {}
            if s3_config.get("bucketArn"):
                sources.append(s3_config["bucketArn"])
        stores.append(
            DataStore(
                arn=kb.get("knowledgeBaseArn", f"arn:aws:bedrock:{region}::knowledge-base/{kb_id}"),
                name=summary.get("name", kb_id),
                type="Knowledge base",
                region=region,
                source_store_arns=sources,
            )
        )
    return stores


def _tool(api: Any, agent_id: str, summary: dict) -> Tool | None:
    if summary.get("actionGroupState") == "DISABLED":
        return None
    group = quiet(
        lambda: api.get_agent_action_group(
            agentId=agent_id, agentVersion=DRAFT, actionGroupId=summary["actionGroupId"]
        )["agentActionGroup"]
    )
    if group is None:
        return Tool(name=summary.get("actionGroupName", "unknown"), type="action group")
    if group.get("parentActionSignature"):
        code_interpreter = group["parentActionSignature"] == "AMAZON.CodeInterpreter"
        return Tool(
            name=group["parentActionSignature"],
            type="code interpreter" if code_interpreter else "built-in action",
            target="AWS managed",
            writes=False if not code_interpreter else None,
        )
    executor = group.get("actionGroupExecutor") or {}
    functions = (group.get("functionSchema") or {}).get("functions") or []
    # RETURN_CONTROL hands the call to the app, which may run it unattended, so it isn't approval.
    approval = (
        all(f.get("requireConfirmation") == "ENABLED" for f in functions) if functions else None
    )
    return Tool(
        name=group.get("actionGroupName", "unknown"),
        type="action group",
        target=executor.get("lambda", "returned to the calling app"),
        requires_approval=approval,
    )


def collect_agents(
    session: Any, region: str, account_id: str, coverage: CoverageLog
) -> list[Agent]:
    api = client(session, "bedrock-agent", region)

    def list_all() -> list[dict]:
        return [
            a
            for page in api.get_paginator("list_agents").paginate()
            for a in page.get("agentSummaries", [])
        ]

    agents = []
    summaries, _ = attempt(coverage, "Bedrock Agents", region, list_all, [])
    for summary in summaries:
        agent_id = summary["agentId"]
        detail = quiet(lambda a=agent_id: api.get_agent(agentId=a)["agent"], {})
        digest, length = fingerprint_instructions(detail.get("instruction"))
        groups = quiet(
            lambda a=agent_id: api.list_agent_action_groups(agentId=a, agentVersion=DRAFT).get(
                "actionGroupSummaries", []
            ),
            [],
        )
        tools = [t for t in (_tool(api, agent_id, g) for g in groups) if t is not None]
        code_exec = any(t.type == "code interpreter" for t in tools)
        kbs = quiet(
            lambda a=agent_id: api.list_agent_knowledge_bases(agentId=a, agentVersion=DRAFT).get(
                "agentKnowledgeBaseSummaries", []
            ),
            [],
        )
        domains = []
        for group in groups:
            schema = quiet(
                lambda g=group, a=agent_id: (
                    api.get_agent_action_group(
                        agentId=a, agentVersion=DRAFT, actionGroupId=g["actionGroupId"]
                    )["agentActionGroup"]
                    .get("apiSchema", {})
                    .get("payload")
                )
            )
            domains += [
                DomainRef(hostname=host, source="action group schema")
                for host in hostnames_in(schema or "")
            ]
        agents.append(
            Agent(
                id=f"bedrock-{region}-{agent_id}",
                name=summary.get("agentName", agent_id),
                account_id=account_id,
                region=region,
                platform=Platform.BEDROCK_AGENT,
                kind=AgentKind.AGENT,
                confidence=Confidence.CONFIRMED,
                resource_arn=detail.get(
                    "agentArn", f"arn:aws:bedrock:{region}:{account_id}:agent/{agent_id}"
                ),
                description=(detail.get("description") or "")[:200],
                evidence=[
                    Evidence(signal="managed", source="Bedrock Agents", detail="Registered agent")
                ],
                identity_arn=detail.get("agentResourceRoleArn"),
                tools=tools,
                domains=domains,
                knowledge_base_arns=[
                    f"arn:aws:bedrock:{region}:{account_id}:knowledge-base/{k['knowledgeBaseId']}"
                    for k in kbs
                ],
                guardrail=bool(detail.get("guardrailConfiguration")) if detail else None,
                model_ids=[detail["foundationModel"]] if detail.get("foundationModel") else [],
                instructions_sha256=digest,
                instructions_length=length,
                runtime=RuntimeProfile(
                    platform_detail="Bedrock managed runtime",
                    code_execution_tool=code_exec,
                    vulns_source="Managed by AWS",
                ),
            )
        )
    return agents


def invocation_logging(session: Any, region: str, coverage: CoverageLog) -> bool | None:
    api = client(session, "bedrock", region)
    response, ok = attempt(
        coverage,
        "Bedrock model invocation logging",
        region,
        api.get_model_invocation_logging_configuration,
        None,
        record_ok=False,
    )
    return bool(response.get("loggingConfig")) if ok and response is not None else None
