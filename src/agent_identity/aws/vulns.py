"""Vulnerabilities from Inspector when it's on, and from Trivy for images it doesn't cover."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess  # noqa: S404  (runs the pinned Trivy binary with an argv list and no shell)
from typing import Any

from agent_identity.aws.base import CoverageLog, attempt
from agent_identity.aws.session import client
from agent_identity.config import Settings
from agent_identity.models import Agent, CoverageStatus, Severity, Vulnerability

log = logging.getLogger(__name__)

_ECR_IMAGE = re.compile(
    r"^\d{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com/[a-z0-9._/-]+"
    r"(?::[A-Za-z0-9_.-]+|@sha256:[a-f0-9]{64})?$"
)
_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}
_FRAMEWORK_PACKAGES = {
    "langchain": "LangChain",
    "langchain-core": "LangChain",
    "langgraph": "LangGraph",
    "crewai": "CrewAI",
    "autogen-agentchat": "AutoGen",
    "pyautogen": "AutoGen",
    "llama-index": "LlamaIndex",
    "llama-index-core": "LlamaIndex",
    "strands-agents": "Strands",
    "mcp": "MCP",
    "openai": "OpenAI SDK",
    "anthropic": "Anthropic SDK",
    "claude-agent-sdk": "Claude Agent SDK",
}
_SAFE_ENV = (
    "PATH",
    "HOME",
    "AWS_PROFILE",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_CONFIG_FILE",
    "TRIVY_CACHE_DIR",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
)


def inspector_enabled(session: Any, region: str, coverage: CoverageLog) -> bool | None:
    api = client(session, "inspector2", region)
    response, ok = attempt(
        coverage, "Inspector", region, lambda: api.batch_get_account_status(), None, record_ok=False
    )
    if not ok or response is None:
        return None
    accounts = response.get("accounts", [])
    return any((a.get("state") or {}).get("status") == "ENABLED" for a in accounts)


def _resource_key(resource: dict) -> list[str]:
    details = resource.get("details") or {}
    keys = [resource.get("id", "")]
    image = details.get("awsEcrContainerImage") or {}
    if image.get("repositoryName"):
        keys.append(f"ecr:{image['repositoryName']}")
    fn = details.get("awsLambdaFunction") or {}
    if fn.get("functionName"):
        keys.append(f"lambda:{fn['functionName']}")
    return keys


def apply_inspector(session: Any, region: str, agents: list[Agent], coverage: CoverageLog) -> None:
    api = client(session, "inspector2", region)

    def load() -> dict[str, list[Vulnerability]]:
        found: dict[str, list[Vulnerability]] = {}
        pages = api.get_paginator("list_findings").paginate(
            filterCriteria={
                "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
                "findingType": [{"comparison": "EQUALS", "value": "PACKAGE_VULNERABILITY"}],
            },
            PaginationConfig={"MaxItems": 2000},
        )
        for page in pages:
            for finding in page.get("findings", []):
                vuln = _inspector_vuln(finding)
                if vuln is None:
                    continue
                for resource in finding.get("resources", []):
                    for key in _resource_key(resource):
                        if key:
                            found.setdefault(key, []).append(vuln)
        return found

    found, ok = attempt(coverage, "Inspector", region, load, {})
    if not ok:
        return
    for agent in agents:
        keys = [agent.resource_arn, f"lambda:{agent.name}", agent.resource_arn.rsplit("/", 1)[-1]]
        if agent.runtime.image and "/" in agent.runtime.image:
            repository = re.split(r"[:@]", agent.runtime.image.split("/", 1)[1])[0]
            keys.append(f"ecr:{repository}")
        matches = [v for key in keys for v in found.get(key, [])]
        if matches or agent.runtime.image or agent.platform.value in ("Lambda", "EC2"):
            agent.runtime.vulnerabilities = _dedupe(matches)
            agent.runtime.vulns_assessed = True
            agent.runtime.vulns_source = "Inspector"


def _dedupe(vulns: list[Vulnerability]) -> list[Vulnerability]:
    return list({(v.cve, v.package): v for v in vulns}.values())


def _inspector_vuln(finding: dict) -> Vulnerability | None:
    severity = _SEVERITY.get(finding.get("severity", ""))
    details = finding.get("packageVulnerabilityDetails") or {}
    if severity is None or not details:
        return None
    packages = details.get("vulnerablePackages") or [{}]
    package = packages[0]
    exploit = finding.get("exploitAvailable")
    return Vulnerability(
        cve=details.get("vulnerabilityId", "unknown"),
        severity=severity,
        package=f"{package.get('name', 'unknown')} {package.get('version', '')}".strip(),
        fixed_in=package.get("fixedInVersion"),
        exploit_available=exploit == "YES" if exploit else None,
        source="Inspector",
    )


def scan_with_trivy(
    agents: list[Agent], settings: Settings, coverage: CoverageLog, region: str
) -> None:
    pending = [a for a in agents if a.runtime.image and not a.runtime.vulns_assessed]
    if not settings.trivy_enabled or not pending:
        return
    binary = shutil.which("trivy")
    if binary is None:
        coverage.gap(
            "Trivy",
            region,
            CoverageStatus.ERROR,
            "Trivy isn't installed, so images weren't scanned",
        )
        return
    env = {k: os.environ[k] for k in _SAFE_ENV if k in os.environ}
    results: dict[str, list[Vulnerability]] = {}
    frameworks: dict[str, list[str]] = {}
    images = sorted({a.runtime.image for a in pending if _ECR_IMAGE.match(a.runtime.image)})
    for image in images[: settings.max_images_to_scan]:
        report = _run_trivy(binary, image, env, settings.trivy_timeout_seconds)
        if report is not None:
            results[image], frameworks[image] = _parse_trivy(report)
    skipped = len(images) - len(results)
    if skipped > 0:
        coverage.gap(
            "Trivy", region, CoverageStatus.ERROR, f"{skipped} image(s) couldn't be scanned"
        )
    for agent in pending:
        image = agent.runtime.image
        if image in results:
            agent.runtime.vulnerabilities = results[image]
            agent.runtime.vulns_assessed = True
            agent.runtime.vulns_source = "Trivy"
            agent.runtime.frameworks = sorted({*agent.runtime.frameworks, *frameworks[image]})
        elif not _ECR_IMAGE.match(image or ""):
            agent.runtime.vulns_source = "Only images in ECR are scanned"


def _run_trivy(binary: str, image: str, env: dict[str, str], timeout: int) -> dict | None:
    command = [
        binary,
        "image",
        "--quiet",
        "--format",
        "json",
        "--scanners",
        "vuln",
        "--list-all-pkgs",
        "--timeout",
        f"{timeout}s",
        image,
    ]
    try:
        done = subprocess.run(  # noqa: S603  (image matches _ECR_IMAGE, no shell)
            command, env=env, capture_output=True, timeout=timeout + 30, check=False
        )
    except subprocess.TimeoutExpired:
        log.warning("Trivy timed out on %s", image)
        return None
    if done.returncode != 0:
        log.warning("Trivy exited with %s on %s", done.returncode, image)
        return None
    try:
        return json.loads(done.stdout)
    except json.JSONDecodeError:
        log.warning("Trivy returned output that isn't JSON for %s", image)
        return None


def _parse_trivy(report: dict) -> tuple[list[Vulnerability], list[str]]:
    vulns, frameworks = [], set()
    for result in report.get("Results") or []:
        for package in result.get("Packages") or []:
            if name := _FRAMEWORK_PACKAGES.get(package.get("Name", "").lower()):
                frameworks.add(name)
        for item in result.get("Vulnerabilities") or []:
            severity = _SEVERITY.get(item.get("Severity", ""))
            if severity is None:
                continue
            vulns.append(
                Vulnerability(
                    cve=item.get("VulnerabilityID", "unknown"),
                    severity=severity,
                    package=" ".join(
                        filter(None, (item.get("PkgName", "unknown"), item.get("InstalledVersion")))
                    ),
                    fixed_in=item.get("FixedVersion") or None,
                    source="Trivy",
                )
            )
    return _dedupe(vulns), sorted(frameworks)
