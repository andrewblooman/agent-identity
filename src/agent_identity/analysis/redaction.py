"""Inspect config values in memory and return only what is safe to keep.

Lambda, ECS and AgentCore APIs return environment variable values. Those values must never reach
the snapshot, the database or a log line. `inspect_env` is the only code that reads them.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from agent_identity.models import DomainRef, PlaintextSecret

_VALUE_DETECTORS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{16,}")),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}")),
    ("Stripe key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{16,}")),
    ("Private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("JSON web token", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.")),
)

_SENSITIVE_NAME = re.compile(
    r"(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIAL|AUTH_?KEY)", re.IGNORECASE
)
_REFERENCE = re.compile(r"^(?:arn:|ssm:|\{\{resolve:|\$\{|/)", re.IGNORECASE)
_URL = re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s\"'<>,;]+", re.IGNORECASE)
_NAME_NOT_SECRET = re.compile(r"(?:_ARN|_NAME|_ID|_URL|_PATH|_TTL|_EXPIRY|_LIMIT)$", re.IGNORECASE)

_LLM_VARIABLES: dict[str, str] = {
    "ANTHROPIC_API_KEY": "Anthropic",
    "OPENAI_API_KEY": "OpenAI",
    "OPENAI_BASE_URL": "OpenAI",
    "AZURE_OPENAI_ENDPOINT": "Azure OpenAI",
    "AZURE_OPENAI_API_KEY": "Azure OpenAI",
    "GEMINI_API_KEY": "Google Gemini",
    "GOOGLE_API_KEY": "Google",
    "MISTRAL_API_KEY": "Mistral",
    "COHERE_API_KEY": "Cohere",
    "GROQ_API_KEY": "Groq",
    "BEDROCK_MODEL_ID": "Amazon Bedrock",
    "BEDROCK_AGENT_ID": "Amazon Bedrock",
    "BEDROCK_KNOWLEDGE_BASE_ID": "Amazon Bedrock",
    "AWS_BEDROCK_MODEL_ID": "Amazon Bedrock",
    "MODEL_ID": "Unspecified model",
    "LANGCHAIN_API_KEY": "LangSmith",
    "LANGSMITH_API_KEY": "LangSmith",
}
_FRAMEWORK_VARIABLES: dict[str, str] = {
    "LANGCHAIN_TRACING_V2": "LangChain",
    "LANGGRAPH_API_URL": "LangGraph",
    "CREWAI_TRACING_ENABLED": "CrewAI",
    "MCP_SERVER_URL": "MCP",
    "MCP_SERVERS": "MCP",
}


@dataclass
class EnvSignals:
    plaintext: list[PlaintextSecret] = field(default_factory=list)
    domains: list[DomainRef] = field(default_factory=list)
    llm_vendors: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    variable_names: list[str] = field(default_factory=list)
    secret_refs: list[str] = field(default_factory=list)


def _entropy(value: str) -> float:
    counts = {c: value.count(c) for c in set(value)}
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def _detect(name: str, value: str) -> str | None:
    for label, pattern in _VALUE_DETECTORS:
        if pattern.search(value):
            return label
    for match in _URL.finditer(value):
        if _url_has_credentials(match.group()):
            return "Password in URL"
    if _SENSITIVE_NAME.search(name) and not _NAME_NOT_SECRET.search(name):
        if _REFERENCE.match(value) or len(value) < 8:
            return None
        if value.lower() in {"true", "false", "changeme", "placeholder", "disabled"}:
            return None
        if _entropy(value) >= 3.0:
            return "Credential-like value"
    return None


def _url_has_credentials(url: str) -> bool:
    try:
        return urlsplit(url).password is not None
    except ValueError:
        return False


def hostnames_in(value: str) -> list[str]:
    """Return hostnames only. Paths, queries and user info can hold secrets, so they are dropped."""
    hosts = []
    for match in _URL.finditer(value):
        try:
            host = urlsplit(match.group()).hostname
        except ValueError:
            continue
        if host and "." in host and not host.replace(".", "").isdigit():
            hosts.append(host.lower())
    return hosts


def endpoint_origin(url: str) -> str:
    """Keep only the scheme and host. User info, paths and queries can all hold credentials."""
    try:
        parts = urlsplit(url)
        host, port = parts.hostname, parts.port
    except ValueError:
        return "external endpoint"
    if not parts.scheme or not host:
        return "external endpoint"
    return f"{parts.scheme}://{host}" + (f":{port}" if port else "")


def inspect_env(location: str, env: Mapping[str, str] | None) -> EnvSignals:
    signals = EnvSignals()
    for name, value in (env or {}).items():
        text = str(value)
        signals.variable_names.append(name)
        if text.startswith(("arn:aws:secretsmanager:", "arn:aws:ssm:")):
            signals.secret_refs.append(text)
        if detector := _detect(name, text):
            signals.plaintext.append(
                PlaintextSecret(location=location, variable=name, detector=detector)
            )
        for host in hostnames_in(text):
            signals.domains.append(DomainRef(hostname=host, source=f"env var {name}"))
        upper = name.upper()
        if vendor := _LLM_VARIABLES.get(upper):
            signals.llm_vendors.append(vendor)
        if framework := _FRAMEWORK_VARIABLES.get(upper):
            signals.frameworks.append(framework)
    return signals


def fingerprint_instructions(instructions: str | None) -> tuple[str | None, int | None]:
    """Agent instructions may hold secrets or business logic, so keep only a hash and a length."""
    if instructions is None:
        return None, None
    return hashlib.sha256(instructions.encode()).hexdigest(), len(instructions)


def mask_key_id(key_id: str) -> str:
    return f"{key_id[:4]}…{key_id[-4:]}" if len(key_id) >= 8 else "…"
