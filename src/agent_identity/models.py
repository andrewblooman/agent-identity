"""The normalised snapshot of an AWS estate, plus the results computed from it.

Collectors and the demo estate both produce a `Snapshot`; analysis never touches AWS directly.
`None` on a field means "we could not find out", which is different from False or empty.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class Confidence(StrEnum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"


class AgentKind(StrEnum):
    AGENT = "agent"
    MODEL_CONSUMER = "model consumer"
    UNKNOWN = "unknown"


class Platform(StrEnum):
    BEDROCK_AGENT = "Bedrock agent"
    AGENTCORE = "AgentCore runtime"
    LAMBDA = "Lambda"
    ECS = "ECS"
    EKS = "EKS"
    EC2 = "EC2"
    IAM_ONLY = "IAM role only"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Domain(StrEnum):
    IDENTITY = "identity"
    SECRETS = "secrets"
    DATA = "data"
    NETWORK = "network"
    RUNTIME = "runtime"
    GOVERNANCE = "governance"


class Sensitivity(StrEnum):
    RESTRICTED = "restricted"
    CONFIDENTIAL = "confidential"
    INTERNAL = "internal"
    PUBLIC = "public"
    UNKNOWN = "unknown"


class AccessLevel(StrEnum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"


class CoverageStatus(StrEnum):
    OK = "ok"
    NOT_ENABLED = "not enabled"
    ACCESS_DENIED = "access denied"
    THROTTLED = "throttled"
    ERROR = "error"
    NOT_AVAILABLE = "not visible"


class Evidence(BaseModel):
    signal: str  # managed, behaviour, config or iam
    source: str
    detail: str


class Coverage(BaseModel):
    source: str
    region: str = "global"
    status: CoverageStatus
    detail: str = ""
    affects: list[Domain] = Field(default_factory=list)


class Statement(BaseModel):
    effect: str
    actions: list[str] = Field(default_factory=list)
    not_actions: list[str] = Field(default_factory=list)
    resources: list[str] = Field(default_factory=list)
    not_resources: list[str] = Field(default_factory=list)
    conditional: bool = False


class Policy(BaseModel):
    name: str
    arn: str | None = None
    managed_by_aws: bool = False
    statements: list[Statement] = Field(default_factory=list)


class AccessKey(BaseModel):
    key_id: str  # masked: AKIA...WXYZ
    status: str
    created: datetime | None = None
    last_used: datetime | None = None
    last_service: str | None = None
    last_region: str | None = None
    human_use_signal: str | None = None


class Identity(BaseModel):
    arn: str
    name: str
    kind: str  # role or user
    account_id: str
    created: datetime | None = None
    last_used: datetime | None = None
    trusted_principals: list[str] = Field(default_factory=list)
    trust_is_broad: bool = False
    policies: list[Policy] = Field(default_factory=list)
    boundary: Policy | None = None
    access_keys: list[AccessKey] = Field(default_factory=list)
    # Service namespace -> last use. None means last-accessed data is not available.
    service_last_used: dict[str, datetime | None] | None = None
    human_session_signal: str | None = None


class DataStore(BaseModel):
    arn: str
    name: str
    type: str  # S3, DynamoDB, RDS, Knowledge base, Agent memory
    region: str
    sensitivity: Sensitivity = Sensitivity.UNKNOWN
    sensitivity_source: str = "not classified"
    encrypted: bool | None = None
    kms_key_arn: str | None = None
    public: bool | None = None
    cross_account_principals: list[str] | None = None
    resource_policy: Policy | None = None
    source_store_arns: list[str] = Field(default_factory=list)  # e.g. KB -> bucket
    logs_data_access: bool | None = None


class Secret(BaseModel):
    arn: str
    name: str
    kind: str  # Secrets Manager, SSM SecureString, API key provider, OAuth provider
    region: str
    vendor: str | None = None
    rotation_enabled: bool | None = None
    last_rotated: datetime | None = None
    last_accessed: datetime | None = None
    created: datetime | None = None
    kms_key_arn: str | None = None
    resource_policy: Policy | None = None


class PlaintextSecret(BaseModel):
    """A credential seen in config. The value itself is never kept."""

    location: str
    variable: str
    detector: str


class Exposure(BaseModel):
    kind: str
    detail: str
    internet: bool
    authenticated: bool | None = None
    auth_detail: str = ""


class NetworkProfile(BaseModel):
    inbound: list[Exposure] | None = None
    internet_egress: bool | None = None
    egress_detail: str = ""
    vpc_id: str | None = None
    in_vpc: bool | None = None
    open_security_groups: list[str] = Field(default_factory=list)
    vpc_endpoints: list[str] | None = None


class Vulnerability(BaseModel):
    cve: str
    severity: Severity
    package: str
    fixed_in: str | None = None
    exploit_available: bool | None = None
    source: str = ""


class RuntimeProfile(BaseModel):
    platform_detail: str = ""
    image: str | None = None
    image_pinned: bool | None = None
    language_runtime: str | None = None
    runtime_deprecated: bool | None = None
    privileged: bool | None = None
    runs_as_root: bool | None = None
    read_only_root: bool | None = None
    imdsv2_required: bool | None = None
    code_execution_tool: bool = False
    vulns_assessed: bool = False
    vulns_source: str = ""
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)


class Tool(BaseModel):
    name: str
    type: str  # action group, gateway target, code interpreter, browser, MCP server
    target: str = ""
    role_arn: str | None = None
    requires_approval: bool | None = None
    external: bool = False
    writes: bool | None = None


class SaasConnection(BaseModel):
    vendor: str
    source: str
    credential_ref: str | None = None
    credential_type: str = "unknown"
    scopes: list[str] | None = None
    can_write: bool | None = None


class DomainRef(BaseModel):
    hostname: str
    source: str
    observed: bool = False


class Agent(BaseModel):
    id: str
    name: str
    account_id: str
    region: str
    platform: Platform
    resource_arn: str
    kind: AgentKind = AgentKind.UNKNOWN
    confidence: Confidence = Confidence.POSSIBLE
    evidence: list[Evidence] = Field(default_factory=list)
    identity_arn: str | None = None
    extra_identity_arns: list[str] = Field(default_factory=list)
    owner: str | None = None
    environment: str | None = None
    description: str = ""
    triggers: list[str] | None = None  # e.g. "schedule", "http", "human", "event"
    untrusted_inputs: list[str] | None = None
    tools: list[Tool] = Field(default_factory=list)
    knowledge_base_arns: list[str] = Field(default_factory=list)
    memory_arns: list[str] = Field(default_factory=list)
    secret_arns: list[str] = Field(default_factory=list)  # referenced in config
    plaintext_secrets: list[PlaintextSecret] = Field(default_factory=list)
    domains: list[DomainRef] = Field(default_factory=list)
    saas: list[SaasConnection] = Field(default_factory=list)
    network: NetworkProfile = Field(default_factory=NetworkProfile)
    runtime: RuntimeProfile = Field(default_factory=RuntimeProfile)
    guardrail: bool | None = None
    model_ids: list[str] = Field(default_factory=list)
    instructions_sha256: str | None = None
    instructions_length: int | None = None
    last_model_call: datetime | None = None


class AccountSignals(BaseModel):
    model_invocation_logging: dict[str, bool | None] = Field(default_factory=dict)  # by region
    access_analyzer_unused: bool | None = None
    access_analyzer_internal: bool | None = None
    macie_enabled: bool | None = None
    inspector_enabled: bool | None = None
    cloudtrail_data_events: bool | None = None


class Snapshot(BaseModel):
    mode: str  # demo or live
    account_id: str
    regions: list[str]
    taken_at: datetime
    agents: list[Agent] = Field(default_factory=list)
    identities: list[Identity] = Field(default_factory=list)
    stores: list[DataStore] = Field(default_factory=list)
    secrets: list[Secret] = Field(default_factory=list)
    coverage: list[Coverage] = Field(default_factory=list)
    signals: AccountSignals = Field(default_factory=AccountSignals)
    # store ARN -> identity ARN -> last use seen in data events
    observed_data_use: dict[str, dict[str, datetime]] = Field(default_factory=dict)
    # Exact allow/deny answers from SimulatePrincipalPolicy: "identity|action|resource" -> allowed
    simulated: dict[str, bool] = Field(default_factory=dict)


# ---- Computed results -------------------------------------------------------------------------


class AccessPath(BaseModel):
    steps: list[str]
    indirect: bool = False


class DataGrant(BaseModel):
    agent_id: str
    identity_arn: str
    store_arn: str
    levels: list[AccessLevel]
    conditional: bool = False
    verified: bool = False  # confirmed by SimulatePrincipalPolicy
    blocked_by_kms: bool = False
    indirect: bool = False
    path: list[str] = Field(default_factory=list)
    use: str = "unknown"  # used, unused or unknown
    use_detail: str = ""


class SecretGrant(BaseModel):
    agent_id: str
    identity_arn: str
    secret_arn: str
    conditional: bool = False
    indirect: bool = False
    referenced: bool = False
    path: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    domain: Domain
    agent_id: str | None = None
    subject: str = ""
    evidence: str
    remediation: str
    nhi: list[str] = Field(default_factory=list)
    asi: list[str] = Field(default_factory=list)
    aws_dimension: list[str] = Field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.rule_id}|{self.agent_id}|{self.subject}"


class TrifectaLeg(BaseModel):
    state: bool | None  # True, False or None for not assessed
    reasons: list[str] = Field(default_factory=list)


class Trifecta(BaseModel):
    sensitive_data: TrifectaLeg
    untrusted_input: TrifectaLeg
    outbound_path: TrifectaLeg

    @property
    def complete(self) -> bool:
        return all(
            leg.state is True
            for leg in (self.sensitive_data, self.untrusted_input, self.outbound_path)
        )

    @property
    def possible(self) -> bool:
        legs = (self.sensitive_data, self.untrusted_input, self.outbound_path)
        return not self.complete and all(leg.state is not False for leg in legs)


class DomainScore(BaseModel):
    domain: Domain
    score: int | None  # None when nothing in the domain could be assessed
    assessed: int
    total: int


class AgentResult(BaseModel):
    agent_id: str
    score: int | None
    uncapped_score: int | None = None
    cap_reason: str = ""
    coverage_pct: int
    domains: list[DomainScore]
    autonomy_scope: int | None
    autonomy_reasons: list[str] = Field(default_factory=list)
    trifecta: Trifecta
    admin_equivalent: bool = False
    privesc_paths: list[str] = Field(default_factory=list)
    shared_identity_with: list[str] = Field(default_factory=list)


class DomainInfo(BaseModel):
    hostname: str
    category: str
    vendor: str | None = None
    observed: bool = False
    sources: list[str] = Field(default_factory=list)
    agent_ids: list[str] = Field(default_factory=list)


class Result(BaseModel):
    score: int | None
    coverage_pct: int
    agents: list[AgentResult]
    grants: list[DataGrant]
    secret_grants: list[SecretGrant]
    findings: list[Finding]
    domains: list[DomainInfo]
    not_assessed: list[dict[str, str]] = Field(default_factory=list)
