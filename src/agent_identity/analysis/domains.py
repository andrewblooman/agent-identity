"""Classify hostnames an agent is configured to talk to."""

from __future__ import annotations

from agent_identity.models import Agent, DomainInfo

_KNOWN: tuple[tuple[str, str, str], ...] = (
    ("anthropic.com", "LLM provider", "Anthropic"),
    ("openai.com", "LLM provider", "OpenAI"),
    ("openai.azure.com", "LLM provider", "Azure OpenAI"),
    ("generativelanguage.googleapis.com", "LLM provider", "Google Gemini"),
    ("mistral.ai", "LLM provider", "Mistral"),
    ("cohere.com", "LLM provider", "Cohere"),
    ("cohere.ai", "LLM provider", "Cohere"),
    ("groq.com", "LLM provider", "Groq"),
    ("langchain.com", "LLM tooling", "LangSmith"),
    ("github.com", "Code hosting", "GitHub"),
    ("githubusercontent.com", "Code hosting", "GitHub"),
    ("gitlab.com", "Code hosting", "GitLab"),
    ("bitbucket.org", "Code hosting", "Bitbucket"),
    ("pypi.org", "Package registry", "PyPI"),
    ("npmjs.org", "Package registry", "npm"),
    ("salesforce.com", "SaaS", "Salesforce"),
    ("force.com", "SaaS", "Salesforce"),
    ("slack.com", "SaaS", "Slack"),
    ("zendesk.com", "SaaS", "Zendesk"),
    ("atlassian.net", "SaaS", "Atlassian"),
    ("atlassian.com", "SaaS", "Atlassian"),
    ("googleapis.com", "SaaS", "Google"),
    ("graph.microsoft.com", "SaaS", "Microsoft 365"),
    ("hubapi.com", "SaaS", "HubSpot"),
    ("notion.com", "SaaS", "Notion"),
    ("notion.so", "SaaS", "Notion"),
    ("stripe.com", "SaaS", "Stripe"),
    ("amazonaws.com", "AWS", "AWS"),
)


def classify_hostname(hostname: str) -> tuple[str, str | None]:
    host = hostname.lower().rstrip(".")
    for suffix, category, vendor in _KNOWN:
        if host == suffix or host.endswith(f".{suffix}"):
            return category, vendor
    if host.endswith((".internal", ".local", ".corp")):
        return "Internal", None
    return "Unknown", None


def build_domains(agents: list[Agent]) -> list[DomainInfo]:
    found: dict[str, DomainInfo] = {}
    for agent in agents:
        for ref in agent.domains:
            category, vendor = classify_hostname(ref.hostname)
            info = found.setdefault(
                ref.hostname, DomainInfo(hostname=ref.hostname, category=category, vendor=vendor)
            )
            info.observed = info.observed or ref.observed
            if ref.source not in info.sources:
                info.sources.append(ref.source)
            if agent.id not in info.agent_ids:
                info.agent_ids.append(agent.id)
    return sorted(found.values(), key=lambda d: (d.category != "Unknown", d.category, d.hostname))
