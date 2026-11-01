"""Permissions, discovery and scoring, driven by real policy documents."""

from datetime import UTC, datetime

from agent_identity.analysis.autonomy import estimate_scope
from agent_identity.analysis.data_access import build_data_grants, build_secret_grants
from agent_identity.analysis.discovery import can_act
from agent_identity.analysis.engine import analyse, estate_score
from agent_identity.analysis.permissions import (
    assumable_roles,
    evaluate,
    is_admin_equivalent,
    parse_policy,
    patterns_overlap,
    privilege_escalation_paths,
)
from agent_identity.demo.estate import build_snapshot
from agent_identity.models import (
    AccessLevel,
    Agent,
    AgentKind,
    Confidence,
    Coverage,
    CoverageStatus,
    DataStore,
    Evidence,
    Identity,
    NetworkProfile,
    Platform,
    SaasConnection,
    Secret,
    Sensitivity,
    Snapshot,
    Tool,
)

NOW = datetime(2026, 11, 1, tzinfo=UTC)
BUCKET = "arn:aws:s3:::data"


def _identity(*statements, boundary=None, **kwargs):
    return Identity(
        arn="arn:aws:iam::1:role/r",
        name="r",
        kind="role",
        account_id="1",
        policies=[parse_policy("p", {"Statement": list(statements)})],
        boundary=parse_policy("b", {"Statement": boundary}) if boundary else None,
        **kwargs,
    )


def allow(action, resource="*", **extra):
    return {"Effect": "Allow", "Action": action, "Resource": resource, **extra}


def test_allow_and_wildcards():
    identity = _identity(allow("s3:Get*", f"{BUCKET}/*"))
    assert evaluate(identity, "s3:GetObject", f"{BUCKET}/k").allowed
    assert not evaluate(identity, "s3:PutObject", f"{BUCKET}/k").allowed
    assert not evaluate(identity, "s3:GetObject", "arn:aws:s3:::other/k").allowed


def test_iam_action_matching_ignores_case():
    assert evaluate(_identity(allow("S3:getobject")), "s3:GetObject", BUCKET).allowed


def test_explicit_deny_wins():
    identity = _identity(
        allow("s3:*"), {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"}
    )
    assert not evaluate(identity, "s3:DeleteObject", BUCKET).allowed
    assert evaluate(identity, "s3:GetObject", BUCKET).allowed


def test_not_action_grants_everything_else():
    identity = _identity({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"})
    assert evaluate(identity, "s3:GetObject", BUCKET).allowed
    assert not evaluate(identity, "iam:CreateUser", "*").allowed


def test_not_resource_excludes_it():
    identity = _identity({"Effect": "Allow", "Action": "s3:*", "NotResource": BUCKET})
    assert not evaluate(identity, "s3:GetObject", BUCKET).allowed
    assert evaluate(identity, "s3:GetObject", "arn:aws:s3:::other").allowed


def test_conditions_are_reported_not_assumed():
    identity = _identity(allow("s3:GetObject", Condition={"Bool": {"aws:SecureTransport": "true"}}))
    decision = evaluate(identity, "s3:GetObject", BUCKET)
    assert decision.allowed and decision.conditional


def test_permission_boundary_limits_access():
    identity = _identity(allow("s3:*"), boundary=[allow("s3:GetObject")])
    assert evaluate(identity, "s3:GetObject", BUCKET).allowed
    assert not evaluate(identity, "s3:PutObject", BUCKET).allowed


def test_resource_policy_can_grant_and_deny():
    grant = parse_policy("bp", {"Statement": [allow("s3:GetObject", BUCKET)]})
    deny = parse_policy(
        "bp", {"Statement": [{"Effect": "Deny", "Action": "s3:*", "Resource": "*"}]}
    )
    assert evaluate(_identity(), "s3:GetObject", BUCKET, grant).allowed
    assert not evaluate(_identity(allow("s3:*")), "s3:GetObject", BUCKET, deny).allowed


def test_admin_detection():
    assert is_admin_equivalent(_identity(allow("*")))
    assert not is_admin_equivalent(_identity(allow("s3:*")))
    conditional = allow("*", Condition={"StringEquals": {"aws:RequestedRegion": "eu-west-1"}})
    assert not is_admin_equivalent(_identity(conditional))


def test_privilege_escalation_finds_resource_scoped_pass_role():
    identity = _identity(
        allow("iam:PassRole", "arn:aws:iam::1:role/x"), allow("lambda:CreateFunction")
    )
    assert "Pass a stronger role to a new Lambda" in privilege_escalation_paths(identity)
    assert privilege_escalation_paths(_identity(allow("iam:PassRole"))) == []


def test_assuming_a_role_needs_both_permission_and_trust():
    caller = _identity(allow("sts:AssumeRole"))
    trusting = Identity(
        arn="arn:aws:iam::1:role/t",
        name="t",
        kind="role",
        account_id="1",
        trusted_principals=[caller.arn],
    )
    distrusting = Identity(
        arn="arn:aws:iam::1:role/d",
        name="d",
        kind="role",
        account_id="1",
        trusted_principals=["lambda.amazonaws.com"],
    )
    assert assumable_roles(caller, [trusting, distrusting]) == [trusting]


def _role(name, *statements, **kwargs):
    return Identity(
        arn=f"arn:aws:iam::1:role/{name}",
        name=name,
        kind="role",
        account_id="1",
        policies=[parse_policy("p", {"Statement": list(statements)})],
        **kwargs,
    )


def deny(action, resource="*", **extra):
    return {"Effect": "Deny", "Action": action, "Resource": resource, **extra}


def test_resource_patterns_are_case_sensitive():
    identity = _identity(allow("s3:GetObject", f"{BUCKET}/Private/*"))
    assert evaluate(identity, "s3:GetObject", f"{BUCKET}/Private/k").allowed
    assert not evaluate(identity, "s3:GetObject", f"{BUCKET}/private/k").allowed


def test_square_brackets_in_a_resource_are_literal():
    identity = _identity(allow("s3:GetObject", f"{BUCKET}/[ab]/*"))
    assert evaluate(identity, "s3:GetObject", f"{BUCKET}/[ab]/k").allowed
    assert not evaluate(identity, "s3:GetObject", f"{BUCKET}/a/k").allowed


def test_patterns_overlap():
    assert patterns_overlap("data/*", "*/private/*")
    assert patterns_overlap("a?c", "abc")
    assert not patterns_overlap("data/*", "logs/*")


def test_resource_policy_allow_does_not_beat_an_identity_deny():
    grant = parse_policy("bp", {"Statement": [allow("s3:GetObject", f"{BUCKET}/*")]})
    identity = _identity(deny("s3:GetObject"))
    assert not evaluate(identity, "s3:GetObject", f"{BUCKET}/k", grant).allowed
    assert evaluate(_identity(), "s3:GetObject", f"{BUCKET}/k", grant).allowed


def test_resource_policy_only_applies_to_the_principals_it_names():
    me, other = _identity(), _role("other")
    bucket_policy = {
        "Statement": [
            allow("s3:GetObject", f"{BUCKET}/*", Principal={"AWS": me.arn}),
            deny("s3:PutObject", f"{BUCKET}/*", Principal={"AWS": other.arn}),
        ]
    }
    grant = parse_policy("bp", bucket_policy)
    assert evaluate(me, "s3:GetObject", f"{BUCKET}/k", grant).allowed
    assert not evaluate(other, "s3:GetObject", f"{BUCKET}/k", grant).allowed
    writer = _identity(allow("s3:PutObject"))
    assert evaluate(writer, "s3:PutObject", f"{BUCKET}/k", grant).allowed


def test_not_principal_and_account_principals_in_a_resource_policy():
    me = _identity()
    everyone_else = parse_policy(
        "bp", {"Statement": [{**deny("s3:*"), "NotPrincipal": {"AWS": me.arn}}]}
    )
    assert not evaluate(
        _role("other", allow("s3:*")), "s3:GetObject", BUCKET, everyone_else
    ).allowed
    assert evaluate(_identity(allow("s3:*")), "s3:GetObject", BUCKET, everyone_else).allowed
    # Naming the account delegates to IAM policies. It doesn't grant anything itself.
    delegated = parse_policy(
        "bp", {"Statement": [allow("s3:GetObject", Principal={"AWS": "arn:aws:iam::1:root"})]}
    )
    assert not evaluate(me, "s3:GetObject", BUCKET, delegated).allowed
    assert evaluate(_identity(allow("s3:GetObject")), "s3:GetObject", BUCKET, delegated).allowed


def test_pass_role_that_is_denied_is_not_an_escalation_path():
    identity = _identity(
        allow("iam:PassRole", "arn:aws:iam::1:role/x"),
        allow("lambda:CreateFunction"),
        deny("iam:PassRole"),
    )
    assert privilege_escalation_paths(identity) == []


def test_pass_role_outside_the_boundary_resources_is_not_an_escalation_path():
    identity = _identity(
        allow("iam:PassRole", "arn:aws:iam::1:role/x"),
        allow("lambda:CreateFunction"),
        boundary=[allow("iam:PassRole", "arn:aws:iam::1:role/y"), allow("lambda:*")],
    )
    assert privilege_escalation_paths(identity) == []


def test_root_trust_from_another_account_does_not_let_this_caller_assume_the_role():
    caller = _identity(allow("sts:AssumeRole"))
    foreign = _role("foreign", trusted_principals=["arn:aws:iam::2:root"], trust_is_broad=True)
    local = _role("local", trusted_principals=["arn:aws:iam::1:root"], trust_is_broad=True)
    assert assumable_roles(caller, [foreign, local]) == [local]


def test_read_only_boundary_stops_a_workload_counting_as_able_to_act():
    limited = _identity(
        allow("bedrock:InvokeModel"), allow("s3:PutObject"), boundary=[allow("s3:Get*")]
    )
    assert can_act(limited) is False
    wildcard = _identity(allow("*"), boundary=[allow("s3:GetObject")])
    assert can_act(wildcard) is False
    assert can_act(_identity(allow("s3:Put*"), boundary=[allow("s3:PutObject")])) is True
    assert can_act(_identity(allow("s3:PutObject"), deny("s3:*"))) is False
    assert can_act(_identity({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"})) is True


def test_approved_tool_does_not_cover_a_directly_writable_saas_connection():
    tool = Tool(name="t", type="action group", writes=True, requires_approval=True)
    agent = Agent(
        id="a",
        name="a",
        account_id="1",
        region="eu-west-1",
        platform=Platform.LAMBDA,
        resource_arn="arn:a",
        triggers=["human"],
        tools=[tool],
    )
    assert estimate_scope(agent, [])[0] == 2
    agent.saas = [SaasConnection(vendor="Slack", source="s", can_write=True)]
    assert estimate_scope(agent, [])[0] == 3


def _snapshot(identity, signal="config", **agent_kwargs):
    agent = Agent(
        id="a",
        name="a",
        account_id="1",
        region="eu-west-1",
        platform=Platform.LAMBDA,
        resource_arn="arn:a",
        identity_arn=identity.arn,
        evidence=[Evidence(signal=signal, source="s", detail="d")],
        **agent_kwargs,
    )
    store = DataStore(
        arn=BUCKET, name="data", type="S3", region="eu-west-1", sensitivity=Sensitivity.RESTRICTED
    )
    return Snapshot(
        mode="demo",
        account_id="1",
        regions=["eu-west-1"],
        taken_at=NOW,
        agents=[agent],
        identities=[identity],
        stores=[store],
    )


def test_grant_on_one_s3_prefix_is_found_and_labelled():
    prefix = f"{BUCKET}/private/*"
    grants = build_data_grants(_snapshot(_identity(allow("s3:GetObject", prefix))))
    assert grants[0].levels == [AccessLevel.READ]
    assert grants[0].limited_to == [prefix]


def test_whole_bucket_grant_is_not_labelled_as_limited():
    grants = build_data_grants(_snapshot(_identity(allow("s3:GetObject", f"{BUCKET}/*"))))
    assert grants[0].limited_to == []


def test_object_action_on_the_bucket_arn_alone_grants_nothing():
    assert build_data_grants(_snapshot(_identity(allow("s3:GetObject", BUCKET)))) == []


def test_each_level_keeps_the_route_that_allows_it():
    caller = _identity(
        allow("s3:GetObject", f"{BUCKET}/*"), allow("sts:AssumeRole", "arn:aws:iam::1:role/writer")
    )
    writer = _role("writer", allow("s3:PutObject", f"{BUCKET}/*"), trusted_principals=[caller.arn])
    snapshot = _snapshot(caller)
    snapshot.identities.append(writer)
    grant = build_data_grants(snapshot)[0]
    assert grant.levels == [AccessLevel.READ, AccessLevel.WRITE]
    assert not grant.indirect
    assert grant.indirect_levels == [AccessLevel.WRITE]
    by_identity = {r.identity_arn: r for r in grant.routes}
    assert by_identity[caller.arn].levels == [AccessLevel.READ]
    assert by_identity[writer.arn].levels == [AccessLevel.WRITE]
    assert by_identity[writer.arn].indirect


def _rds_snapshot(identity):
    snapshot = _snapshot(identity)
    snapshot.stores = [
        DataStore(
            arn="arn:aws:rds:eu-west-1:1:db:prod",
            name="prod",
            type="RDS",
            region="eu-west-1",
            db_resource_id="db-ABC",
        )
    ]
    return snapshot


def test_rds_connect_is_checked_against_the_database_user_resource():
    dbuser = "arn:aws:rds-db:eu-west-1:1:dbuser:db-ABC/app"
    grants = build_data_grants(_rds_snapshot(_identity(allow("rds-db:connect", dbuser))))
    assert grants[0].levels == [AccessLevel.READ]
    assert grants[0].limited_to == [dbuser]
    other = "arn:aws:rds-db:eu-west-1:1:dbuser:db-XYZ/app"
    assert build_data_grants(_rds_snapshot(_identity(allow("rds-db:connect", other)))) == []


SECRET_ARN = "arn:aws:secretsmanager:eu-west-1:1:secret:s-AbCdEf"


def _secret_snapshot(identity, **agent_kwargs):
    snapshot = _snapshot(identity, secret_arns=[SECRET_ARN], **agent_kwargs)
    snapshot.secrets = [
        Secret(
            arn=SECRET_ARN,
            name="s",
            kind="Secrets Manager",
            region="eu-west-1",
            rotation_enabled=False,
        )
    ]
    return snapshot


def test_naming_a_secret_in_config_is_not_permission_to_read_it():
    snapshot = _secret_snapshot(_identity())
    assert build_secret_grants(snapshot)[0].authorized is False
    result = analyse(snapshot, NOW)
    assert not [f for f in result.findings if f.rule_id == "AIP-303"]


def test_a_role_that_fetches_secrets_for_the_agent_counts_as_access():
    fetcher = _role("exec", allow("secretsmanager:GetSecretValue", SECRET_ARN))
    snapshot = _secret_snapshot(_identity(), secret_fetch_role_arns=[fetcher.arn])
    snapshot.identities.append(fetcher)
    grant = build_secret_grants(snapshot)[0]
    assert grant.authorized is True
    assert grant.identity_arn == fetcher.arn
    assert any(f.rule_id == "AIP-303" for f in analyse(snapshot, NOW).findings)


def test_failed_inventory_means_not_assessed_instead_of_a_clean_pass():
    identity = _identity(allow("bedrock:InvokeModel"))
    clean = analyse(_snapshot(identity), NOW)
    data = next(d for d in clean.agents[0].domains if d.domain.value == "data")
    snapshot = _snapshot(identity)
    snapshot.stores = []
    snapshot.coverage = [Coverage(source="S3", status=CoverageStatus.ACCESS_DENIED)]
    result = analyse(snapshot, NOW)
    denied = next(d for d in result.agents[0].domains if d.domain.value == "data")
    assert denied.score is None
    assert denied.assessed < data.assessed
    assert result.agents[0].trifecta.sensitive_data.state is None


def test_findings_still_count_when_inventory_is_partial():
    identity = _identity(allow("s3:PutObject", f"{BUCKET}/*"))
    snapshot = _snapshot(identity)
    snapshot.coverage = [Coverage(source="DynamoDB", status=CoverageStatus.THROTTLED)]
    result = analyse(snapshot, NOW)
    assert any(f.rule_id == "AIP-202" for f in result.findings)
    assert next(d for d in result.agents[0].domains if d.domain.value == "data").score is not None


def test_a_service_that_is_switched_off_does_not_block_the_assessment():
    snapshot = _snapshot(_identity(allow("bedrock:InvokeModel")))
    snapshot.coverage = [Coverage(source="Macie", status=CoverageStatus.NOT_ENABLED)]
    result = analyse(snapshot, NOW)
    assert next(d for d in result.agents[0].domains if d.domain.value == "data").score is not None


def test_model_only_workload_is_a_model_consumer_not_an_agent():
    identity = _identity(allow("bedrock:InvokeModel"), allow(["logs:PutLogEvents"]))
    snapshot = _snapshot(identity, signal="behaviour")
    analyse(snapshot, NOW)
    assert snapshot.agents[0].kind == AgentKind.MODEL_CONSUMER
    assert snapshot.agents[0].confidence == Confidence.CONFIRMED


def test_workload_that_can_write_is_an_agent():
    identity = _identity(allow("bedrock:InvokeModel"), allow("s3:PutObject", f"{BUCKET}/*"))
    snapshot = _snapshot(identity)
    analyse(snapshot, NOW)
    assert snapshot.agents[0].kind == AgentKind.AGENT
    assert snapshot.agents[0].confidence == Confidence.LIKELY


def test_permission_alone_is_only_possible():
    identity = _identity(allow("bedrock:*"))
    snapshot = _snapshot(identity, signal="iam")
    analyse(snapshot, NOW)
    assert snapshot.agents[0].kind == AgentKind.UNKNOWN
    assert snapshot.agents[0].confidence == Confidence.POSSIBLE


def test_unknown_inputs_produce_possible_trifecta_not_a_pass():
    identity = _identity(allow("s3:GetObject", f"{BUCKET}/*"))
    result = analyse(_snapshot(identity), NOW)
    trifecta = result.agents[0].trifecta
    assert trifecta.sensitive_data.state is True
    assert trifecta.untrusted_input.state is None
    assert not trifecta.complete and trifecta.possible


def test_complete_trifecta_is_critical_and_caps_score():
    identity = _identity(allow("s3:GetObject", f"{BUCKET}/*"))
    snapshot = _snapshot(
        identity,
        untrusted_inputs=["emails"],
        network=NetworkProfile(inbound=[], internet_egress=True, in_vpc=False),
    )
    result = analyse(snapshot, NOW)
    assert result.agents[0].trifecta.complete
    assert any(f.rule_id == "AIP-201" and f.severity.value == "critical" for f in result.findings)
    assert result.agents[0].score <= 40


def test_unknown_data_is_not_scored_as_a_pass():
    identity = _identity(allow("bedrock:InvokeModel"))
    result = analyse(_snapshot(identity), NOW)
    runtime = next(d for d in result.agents[0].domains if d.domain.value == "runtime")
    assert runtime.assessed < runtime.total
    assert result.coverage_pct < 100


def test_estate_score_is_pulled_down_by_the_worst_agents():
    assert estate_score([100, 100, 100, 0]) < 75
    assert estate_score([]) is None


class TestDemoEstate:
    def setup_method(self):
        self.snapshot = build_snapshot(now=NOW)
        self.result = analyse(self.snapshot, NOW)
        self.by_id = {r.agent_id: r for r in self.result.agents}

    def _findings(self, agent_id):
        return {f.rule_id for f in self.result.findings if f.agent_id == agent_id}

    def test_each_failure_pattern_is_found_by_the_real_rules(self):
        assert "AIP-101" in self._findings("ops-autopilot")
        assert "AIP-201" in self._findings("support-copilot")
        assert {"AIP-301", "AIP-401", "AIP-501"} <= self._findings("invoice-triage-worker")
        assert "AIP-604" in self._findings("ops-autopilot")
        assert "AIP-107" in self._findings("dev-assistant-prod")
        assert "AIP-207" in self._findings("content-sync-agent")
        assert "AIP-211" in self._findings("hr-policy-bot")
        assert "AIP-110" in self._findings("finance-reconciler")
        assert {"AIP-104", "AIP-108", "AIP-508"} <= self._findings("code-review-agent")

    def test_the_well_configured_agent_scores_well(self):
        assert self.by_id["claims-assistant"].score >= 90
        severities = {
            f.severity.value for f in self.result.findings if f.agent_id == "claims-assistant"
        }
        assert not severities & {"critical", "high"}

    def test_a_knowledge_base_exposes_its_source_bucket_indirectly(self):
        grant = next(
            g
            for g in self.result.grants
            if g.agent_id == "hr-policy-bot" and g.store_arn.endswith("acme-hr-documents")
        )
        assert grant.indirect
        assert AccessLevel.READ in grant.levels

    def test_assumed_admin_role_reaches_data_indirectly(self):
        grant = next(
            g
            for g in self.result.grants
            if g.agent_id == "finance-reconciler" and g.store_arn.endswith("customer-profiles")
        )
        assert grant.indirect
        assert "assumes ops-autopilot-role" in grant.path

    def test_snapshot_round_trips_through_json(self):
        assert Snapshot.model_validate_json(self.snapshot.model_dump_json()) == self.snapshot
