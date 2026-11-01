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
from agent_identity.models import (
    Agent,
    CoverageStatus,
    Domain,
    Platform,
    Severity,
    Vulnerability,
)

log = logging.getLogger(__name__)

_ECR_IMAGE = re.compile(
    r"^\d{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com/[a-z0-9._/-]+"
    r"(?::[A-Za-z0-9_.-]+|@sha256:[a-f0-9]{64})?$"
)
_DEPLOYED_IMAGE = re.compile(
    r"^(?P<registry>\d{12})\.dkr\.ecr\.(?P<region>[a-z0-9-]+)\.amazonaws\.com/"
    r"(?P<repository>[a-z0-9._/-]+)(?::(?P<tag>[A-Za-z0-9_.-]+)|@(?P<digest>sha256:[a-f0-9]{64}))?$"
)
_COVERED_IMAGE = re.compile(
    r"^arn:aws[a-z-]*:ecr:[a-z0-9-]+:(?P<registry>\d{12}):repository/"
    r"(?P<repository>[a-z0-9._/-]+)/(?P<digest>sha256:[a-f0-9]+)$"
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
    return any(
        state.get("status") == "ENABLED"
        for account in response.get("accounts", [])
        for state in (
            account.get("state") or {},
            *(account.get("resourceState") or {}).values(),
        )
    )


def _ecr_keys(registry: str, repository: str, digest: str | None, tags: list[str]) -> list[str]:
    """The same repository can hold a patched image and a vulnerable one, so keys name the image."""
    keys = [f"ecr:{registry}/{repository}:{tag}" for tag in tags]
    if digest:
        keys.append(f"ecr:{registry}/{repository}@{digest}")
    return keys


def _resource_key(resource: dict) -> list[str]:
    details = resource.get("details") or {}
    keys = [resource.get("id", "")]
    image = details.get("awsEcrContainerImage") or {}
    if image.get("repositoryName") and image.get("registry"):
        keys += _ecr_keys(
            image["registry"],
            image["repositoryName"],
            image.get("imageHash"),
            image.get("imageTags") or [],
        )
    fn = details.get("awsLambdaFunction") or {}
    if fn.get("functionName"):
        keys.append(f"lambda:{fn['functionName']}")
    return keys


def _covered_keys(item: dict) -> list[str]:
    """How to recognise a resource from ListCoverage, if Inspector is actively scanning it."""
    if (item.get("scanStatus") or {}).get("statusCode") != "ACTIVE":
        return []
    resource_id = item.get("resourceId", "")
    metadata = item.get("resourceMetadata") or {}
    image = _COVERED_IMAGE.match(resource_id)
    if image:
        tags = (metadata.get("ecrImage") or {}).get("imageTags") or []
        return _ecr_keys(image["registry"], image["repository"], image["digest"], tags)
    if item.get("resourceType") == "ECR_REPOSITORY":
        return []  # Scanning a repository doesn't show that any one image has been scanned.
    function = (metadata.get("lambdaFunction") or {}).get("functionName")
    return [resource_id, *([f"lambda:{function}"] if function else [])]


def _agent_keys(agent: Agent, region: str) -> list[str]:
    if agent.runtime.image:
        image = _DEPLOYED_IMAGE.match(agent.runtime.image)
        if image is None or image["region"] != region:
            return []
        tags = [] if image["digest"] else [image["tag"] or "latest"]
        return _ecr_keys(image["registry"], image["repository"], image["digest"], tags)
    if agent.platform == Platform.LAMBDA:
        return [agent.resource_arn, f"lambda:{agent.name}"]
    if agent.platform == Platform.EC2:
        return [agent.resource_arn.rsplit("/", 1)[-1]]
    return []


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

    def load_coverage() -> set[str]:
        pages = api.get_paginator("list_coverage").paginate(PaginationConfig={"MaxItems": 5000})
        return {
            key
            for page in pages
            for item in page.get("coveredResources", [])
            for key in _covered_keys(item)
        }

    found, ok = attempt(coverage, "Inspector", region, load, {})
    if not ok:
        return
    covered, _ = attempt(
        coverage, "Inspector coverage", region, load_coverage, set(), [Domain.RUNTIME], False
    )
    for agent in agents:
        keys = _agent_keys(agent, region)
        matches = [v for key in keys for v in found.get(key, [])]
        # No findings only means something if Inspector is actually scanning this resource.
        if matches or covered.intersection(keys):
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
