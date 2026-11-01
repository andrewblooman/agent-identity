"""Permissions, discovery and scoring, driven by real policy documents."""

from datetime import UTC, datetime

from agent_identity.analysis.engine import analyse, estate_score
from agent_identity.analysis.permissions import (
    assumable_roles,
    evaluate,
    is_admin_equivalent,
    parse_policy,
    privilege_escalation_paths,
)
from agent_identity.demo.estate import build_snapshot
from agent_identity.models import (
    AccessLevel,
    Agent,
    AgentKind,
    Confidence,
    DataStore,
    Evidence,
    Identity,
    NetworkProfile,
    Platform,
    Sensitivity,
    Snapshot,
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
