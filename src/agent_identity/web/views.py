"""Turn a snapshot and its results into what each page shows."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

from agent_identity.analysis import permissions
from agent_identity.models import (
    AccessLevel,
    Agent,
    AgentKind,
    AgentResult,
    Confidence,
    DataGrant,
    Domain,
    Finding,
    Platform,
    Result,
    Sensitivity,
    Severity,
    Snapshot,
)
from agent_identity.rules.catalog import ASI_NAMES, AWS_DIMENSIONS, NHI_NAMES, RULES, SENSITIVE
from agent_identity.web import charts

MANAGED = {Platform.BEDROCK_AGENT, Platform.AGENTCORE}
SEVERITIES = list(Severity)
SENSITIVITY_ORDER = [
    Sensitivity.RESTRICTED,
    Sensitivity.CONFIDENTIAL,
    Sensitivity.UNKNOWN,
    Sensitivity.INTERNAL,
    Sensitivity.PUBLIC,
]
LEVEL_ORDER = [AccessLevel.ADMIN, AccessLevel.DELETE, AccessLevel.WRITE, AccessLevel.READ]
PROVISIONAL_BELOW = 75


@dataclass
class Row:
    agent: Agent
    result: AgentResult
    findings: list[Finding]
    grants: list[DataGrant]

    @property
    def critical(self) -> int:
        return sum(f.severity == Severity.CRITICAL for f in self.findings)

    @property
    def high(self) -> int:
        return sum(f.severity == Severity.HIGH for f in self.findings)

    @property
    def provisional(self) -> bool:
        return self.result.coverage_pct < PROVISIONAL_BELOW

    @property
    def internet(self) -> bool:
        return any(e.internet for e in self.agent.network.inbound or [])


@dataclass
class Estate:
    snapshot: Snapshot
    result: Result
    agents: dict[str, Agent] = field(init=False)
    stores: dict[str, Any] = field(init=False)
    secrets: dict[str, Any] = field(init=False)
    identities: dict[str, Any] = field(init=False)
    rows: list[Row] = field(init=False)

    def __post_init__(self) -> None:
        self.agents = {a.id: a for a in self.snapshot.agents}
        self.stores = {s.arn: s for s in self.snapshot.stores}
        self.secrets = {s.arn: s for s in self.snapshot.secrets}
        self.identities = {i.arn: i for i in self.snapshot.identities}
        findings = defaultdict(list)
        for f in self.result.findings:
            findings[f.agent_id].append(f)
        grants = defaultdict(list)
        for g in self.result.grants:
            grants[g.agent_id].append(g)
        self.rows = sorted(
            (
                Row(self.agents[r.agent_id], r, findings[r.agent_id], grants[r.agent_id])
                for r in self.result.agents
            ),
            key=lambda row: (
                -row.result.trifecta.complete,
                row.result.score if row.result.score is not None else 101,
                -row.critical,
                row.agent.name,
            ),
        )

    def row(self, agent_id: str) -> Row:
        return next(r for r in self.rows if r.agent.id == agent_id)


def _sensitive_reach(row: Row, estate: Estate) -> list[DataGrant]:
    return [g for g in row.grants if estate.stores[g.store_arn].sensitivity in SENSITIVE]


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(f.severity.value for f in findings)
    return {s.value: counts.get(s.value, 0) for s in SEVERITIES}


def _flags(row: Row, estate: Estate) -> set[str]:
    flags: set[str] = set()
    t = row.result.trifecta
    if t.complete:
        flags.add("trifecta")
    if t.possible:
        flags.add("possible-trifecta")
    if row.result.admin_equivalent:
        flags.add("admin")
    if row.internet:
        flags.add("internet")
    if not row.agent.owner:
        flags.add("no-owner")
    if row.agent.platform not in MANAGED:
        flags.add("unmanaged")
    if _sensitive_reach(row, estate):
        flags.add("sensitive")
    if row.agent.plaintext_secrets:
        flags.add("plaintext")
    if row.agent.guardrail is False:
        flags.add("no-guardrail")
    if any(f.rule_id == "AIP-501" for f in row.findings):
        flags.add("exploitable")
    return flags


FLAG_LABELS = {
    "trifecta": "Lethal trifecta",
    "possible-trifecta": "Possible trifecta",
    "admin": "Administrator access",
    "internet": "Internet-facing",
    "no-owner": "No owner",
    "unmanaged": "Not on a managed service",
    "sensitive": "Reaches sensitive data",
    "plaintext": "Credential in plain text",
    "no-guardrail": "No guardrail",
    "exploitable": "Exploitable vulnerability",
}


def _severity_ring(findings: list[Finding]) -> dict:
    counts = _severity_counts(findings)
    return charts.doughnut(
        [
            {
                "label": s.value.capitalize(),
                "count": counts[s.value],
                "tone": s.value,
                "href": f"/findings?severity={s.value}",
            }
            for s in SEVERITIES
        ]
    )


def _band_ring(rows: list[Row]) -> dict:
    scores = [r.result.score for r in rows]
    bands = [
        (
            "High risk",
            "critical",
            "score 0 to 40",
            [s for s in scores if s is not None and s <= 40],
        ),
        ("Medium risk", "high", "score 41 to 70", [s for s in scores if s and 40 < s <= 70]),
        ("Lower risk", "good", "score above 70", [s for s in scores if s and s > 70]),
        ("Not scored", "medium", "not enough data", [s for s in scores if s is None]),
    ]
    return charts.doughnut(
        [
            {"label": label, "count": len(members), "tone": tone, "note": note, "href": "/agents"}
            for label, tone, note, members in bands
            if members or label != "Not scored"
        ]
    )


def _area_gauges(rows: list[Row]) -> list[dict]:
    areas = []
    for domain in sorted(Domain, key=lambda d: d != Domain.DATA):
        values = [
            d.score
            for r in rows
            for d in r.result.domains
            if d.domain == domain and d.score is not None
        ]
        score = round(sum(values) / len(values)) if values else None
        href = {
            Domain.DATA: "/data",
            Domain.IDENTITY: "/identity",
            Domain.SECRETS: "/secrets",
            Domain.NETWORK: "/network",
            Domain.RUNTIME: "/runtime",
        }.get(domain, f"/findings?domain={domain.value}")
        areas.append({"label": domain.value.capitalize(), "href": href, **charts.gauge(score)})
    return areas


def overview(estate: Estate, prior: Result | None) -> dict:
    rows = estate.rows
    flags = {r.agent.id: _flags(r, estate) for r in rows}

    def count(flag: str) -> int:
        return sum(flag in f for f in flags.values())

    tiles = [
        {"label": "Lethal trifecta", "flag": "trifecta", "tone": "critical"},
        {"label": "Administrator access", "flag": "admin", "tone": "critical"},
        {"label": "Plain text credentials", "flag": "plaintext", "tone": "critical"},
        {"label": "Reach sensitive data", "flag": "sensitive", "tone": "high"},
        {"label": "Internet-facing", "flag": "internet", "tone": "high"},
        {"label": "No owner", "flag": "no-owner", "tone": "high"},
    ]
    for tile in tiles:
        tile["count"] = count(tile["flag"])
        tile["href"] = f"/agents?flag={tile['flag']}"
    change = None
    if prior is not None and prior.score is not None and estate.result.score is not None:
        change = estate.result.score - prior.score
    gaps = [c for c in estate.snapshot.coverage if c.status.value != "ok"]
    trifecta = [r for r in rows if r.result.trifecta.complete]
    worst = sorted(
        (r for r in rows if r.result.score is not None),
        key=lambda r: (r.result.score, -r.critical, r.agent.name),
    )[:5]
    return {
        "rows": rows,
        "trifecta": trifecta,
        "posture": charts.gauge(estate.result.score),
        "change": change,
        "severity_ring": _severity_ring(estate.result.findings),
        "band_ring": _band_ring(rows),
        "tiles": tiles,
        "areas": _area_gauges(rows),
        "worst": [{"row": r, "tone": charts.score_tone(r.result.score)} for r in worst],
        "gap_count": len(gaps),
    }


def agents(estate: Estate, params: dict[str, str]) -> dict:
    rows = estate.rows
    query = params.get("q", "").strip().lower()
    if query:
        rows = [r for r in rows if query in r.agent.name.lower()]
    if kind := params.get("kind"):
        rows = [r for r in rows if r.agent.kind.value == kind]
    if confidence := params.get("confidence"):
        rows = [r for r in rows if r.agent.confidence.value == confidence]
    if platform := params.get("platform"):
        rows = [r for r in rows if r.agent.platform.value == platform]
    if flag := params.get("flag"):
        rows = [r for r in rows if flag in _flags(r, estate)]
    return {
        "rows": rows,
        "params": params,
        "partial": "_agents_table.html",
        "kinds": [k.value for k in AgentKind],
        "confidences": [c.value for c in Confidence],
        "platforms": sorted({r.agent.platform.value for r in estate.rows}),
        "flag_labels": FLAG_LABELS,
        "sensitive_counts": {r.agent.id: len(_sensitive_reach(r, estate)) for r in estate.rows},
    }


def _tone_for_store(store) -> str:
    if store.sensitivity == Sensitivity.RESTRICTED:
        return "critical"
    if store.sensitivity == Sensitivity.CONFIDENTIAL:
        return "warn"
    return "neutral"


def _graph(estate: Estate, row: Row) -> charts.Graph:
    agent = row.agent
    entries = [
        {
            "id": f"in-{i}",
            "label": e.kind,
            "detail": e.auth_detail or e.detail,
            "tone": "critical"
            if e.internet and e.authenticated is False
            else "warn"
            if e.internet
            else "neutral",
        }
        for i, e in enumerate(agent.network.inbound or [])
    ]
    entries += [
        {"id": f"un-{i}", "label": text, "detail": "untrusted content", "tone": "warn"}
        for i, text in enumerate(agent.untrusted_inputs or [])
    ]
    if not entries:
        known = agent.network.inbound is not None and agent.untrusted_inputs is not None
        entries = [
            {
                "id": "in-none",
                "label": "None found" if known else "Not assessed",
                "detail": "no outside entry point" if known else "inputs unknown",
                "tone": "neutral",
            }
        ]

    centre = [{"id": "agent", "label": agent.name, "detail": agent.platform.value, "tone": "agent"}]

    identities = []
    seen = set()
    for grant in [*row.grants, *estate.result.secret_grants]:
        arn = grant.identity_arn
        if (
            arn
            and arn in estate.identities
            and arn not in seen
            and getattr(grant, "agent_id", None) == agent.id
        ):
            seen.add(arn)
            identities.append(arn)
    if agent.identity_arn and agent.identity_arn not in seen:
        identities.insert(0, agent.identity_arn)
    id_nodes = []
    for arn in identities[:4]:
        identity = estate.identities.get(arn)
        if identity is None:
            continue
        admin = permissions.is_admin_equivalent(identity)
        id_nodes.append(
            {
                "id": f"id-{arn}",
                "label": identity.name,
                "detail": "administrator access" if admin else f"IAM {identity.kind}",
                "tone": "critical" if admin else "neutral",
                "href": f"/identity/detail?arn={quote(arn, safe='')}",
            }
        )
    if not id_nodes:
        id_nodes = [{"id": "id-none", "label": "Not determined", "detail": "", "tone": "neutral"}]

    targets, edges = [], []
    rank = {s: i for i, s in enumerate(SENSITIVITY_ORDER)}
    ordered = sorted(row.grants, key=lambda g: rank[estate.stores[g.store_arn].sensitivity])
    shown = ordered[:5]
    for grant in shown:
        store = estate.stores[grant.store_arn]
        node_id = f"st-{store.arn}"
        targets.append(
            {
                "id": node_id,
                "label": store.name,
                "detail": f"{store.sensitivity.value}, {_strongest(grant).value}",
                "tone": _tone_for_store(store),
                "href": f"/data/store?arn={quote(store.arn, safe='')}",
            }
        )
        source = f"id-{grant.identity_arn}"
        edges.append((source if grant.identity_arn in identities[:4] else "agent", node_id))
    extra = len(ordered) - len(shown)
    if extra > 0:
        targets.append(
            {
                "id": "st-more",
                "label": f"{extra} more data stores",
                "detail": "see below",
                "tone": "neutral",
            }
        )
        edges.append(("agent", "st-more"))
    if (
        agent.network.internet_egress
        or any(t.external for t in agent.tools)
        or any(s.can_write for s in agent.saas)
    ):
        destinations = sorted({s.vendor for s in agent.saas if s.can_write})
        detail = ", ".join(destinations) if destinations else "outbound internet"
        targets.append(
            {"id": "out", "label": "Out of the account", "detail": detail, "tone": "warn"}
        )
        edges.append(("agent", "out"))
    if not targets:
        targets = [{"id": "st-none", "label": "No data found", "detail": "", "tone": "neutral"}]
        edges.append(("agent", "st-none"))

    edges += [(e["id"], "agent") for e in entries]
    edges += [("agent", n["id"]) for n in id_nodes]
    return charts.attack_graph([entries, centre, id_nodes, targets], edges)


def agent_detail(estate: Estate, agent_id: str) -> dict:
    row = estate.row(agent_id)
    identity = estate.identities.get(row.agent.identity_arn or "")
    rank = {s: i for i, s in enumerate(SENSITIVITY_ORDER)}
    grants = sorted(row.grants, key=lambda g: rank[estate.stores[g.store_arn].sensitivity])
    return {
        "row": row,
        "identity": identity,
        "graph": _graph(estate, row),
        "grants": grants,
        "secret_grants": [g for g in estate.result.secret_grants if g.agent_id == agent_id],
        "by_domain": {d: [f for f in row.findings if f.domain == d] for d in Domain},
        "severity_ring": _severity_ring(row.findings),
        "domains_scored": row.result.domains,
    }


def _strongest(grant: DataGrant) -> AccessLevel:
    return next(level for level in LEVEL_ORDER if level in grant.levels)


def data_access(estate: Estate, params: dict[str, str]) -> dict:
    rank = {s: i for i, s in enumerate(SENSITIVITY_ORDER)}
    stores = sorted(estate.snapshot.stores, key=lambda s: (rank[s.sensitivity], s.type, s.name))
    show = params.get("show", "sensitive")
    shown_stores = (
        stores
        if show == "all"
        else [
            s for s in stores if s.sensitivity in SENSITIVE or s.sensitivity == Sensitivity.UNKNOWN
        ]
    )
    cell = {(g.agent_id, g.store_arn): g for g in estate.result.grants}
    shown_arns = {s.arn for s in shown_stores}
    rows = sorted(
        (r for r in estate.rows if any(g.store_arn in shown_arns for g in r.grants)),
        key=lambda r: (-len(_sensitive_reach(r, estate)), -len(r.grants), r.agent.name),
    )
    grouped = []
    for sensitivity in SENSITIVITY_ORDER:
        members = [s for s in shown_stores if s.sensitivity == sensitivity]
        if members:
            grouped.append({"sensitivity": sensitivity.value, "count": len(members)})
    sensitive_grants = [
        g for g in estate.result.grants if estate.stores[g.store_arn].sensitivity in SENSITIVE
    ]
    writers = [
        g
        for g in sensitive_grants
        if {AccessLevel.WRITE, AccessLevel.DELETE, AccessLevel.ADMIN} & set(g.levels)
    ]
    use = Counter(g.use for g in sensitive_grants)
    poison = [f for f in estate.result.findings if f.rule_id == "AIP-207"]
    victims = [f for f in estate.result.findings if f.rule_id == "AIP-211"]
    return {
        "stores": shown_stores,
        "all_store_count": len(stores),
        "grouped": grouped,
        "rows": rows,
        "cell": cell,
        "show": show,
        "strongest": _strongest,
        "sensitive_grants": sensitive_grants,
        "writers": writers,
        "use": use,
        "poison": poison,
        "victims": victims,
        "indirect": [g for g in sensitive_grants if g.indirect or g.indirect_levels],
        "unused": [g for g in sensitive_grants if g.use == "unused"],
        "conditional": [g for g in estate.result.grants if g.conditional],
    }


def store_detail(estate: Estate, arn: str) -> dict:
    grants = sorted(
        (g for g in estate.result.grants if g.store_arn == arn),
        key=lambda g: LEVEL_ORDER.index(_strongest(g)),
    )
    consumers = [
        a
        for a in estate.snapshot.agents
        if arn in a.knowledge_base_arns
        or arn in a.memory_arns
        or any(
            arn in estate.stores[k].source_store_arns
            for k in a.knowledge_base_arns
            if k in estate.stores
        )
    ]
    return {
        "store": estate.stores[arn],
        "grants": grants,
        "strongest": _strongest,
        "consumers": consumers,
        "sources": [
            estate.stores[s] for s in estate.stores[arn].source_store_arns if s in estate.stores
        ],
        "fed": [s for s in estate.snapshot.stores if arn in s.source_store_arns],
        "findings": [f for f in estate.result.findings if f.subject == arn],
    }


def _goes_through(grant: DataGrant, arn: str) -> bool:
    return grant.identity_arn == arn or any(r.identity_arn == arn for r in grant.routes)


def _identity_summary(estate: Estate, identity) -> dict:
    agents_using = [
        a
        for a in estate.snapshot.agents
        if a.identity_arn == identity.arn or identity.arn in a.extra_identity_arns
    ]
    used = identity.service_last_used
    unused = sorted(k for k, v in used.items() if v is None) if used is not None else None
    return {
        "identity": identity,
        "agents": agents_using,
        "admin": permissions.is_admin_equivalent(identity),
        "privesc": permissions.privilege_escalation_paths(identity),
        "assumes": permissions.assumable_roles(identity, estate.snapshot.identities),
        "unused": unused,
        "used_count": sum(v is not None for v in used.values()) if used is not None else None,
        "store_count": len(
            {g.store_arn for g in estate.result.grants if _goes_through(g, identity.arn)}
        ),
        "secret_count": len(
            {
                g.secret_arn
                for g in estate.result.secret_grants
                if g.identity_arn == identity.arn and g.authorized is not False
            }
        ),
    }


def identity(estate: Estate) -> dict:
    summaries = [_identity_summary(estate, i) for i in estate.snapshot.identities]
    summaries.sort(key=lambda s: (not s["admin"], not s["privesc"], -s["store_count"]))
    keys = [
        {"key": key, "identity": s["identity"], "agents": s["agents"]}
        for s in summaries
        for key in s["identity"].access_keys
    ]
    providers = [
        s for s in estate.snapshot.secrets if s.kind in ("OAuth provider", "API key provider")
    ]
    return {
        "roles": [s for s in summaries if s["identity"].kind == "role"],
        "users": [s for s in summaries if s["identity"].kind == "user"],
        "keys": keys,
        "providers": providers,
        "shared": [s for s in summaries if len(s["agents"]) > 1],
    }


def identity_detail(estate: Estate, arn: str) -> dict:
    grants = [g for g in estate.result.grants if _goes_through(g, arn)]
    return {
        "summary": _identity_summary(estate, estate.identities[arn]),
        "grants": grants,
        "strongest": _strongest,
        "secret_grants": [
            g
            for g in estate.result.secret_grants
            if g.identity_arn == arn and g.authorized is not False
        ],
        "findings": [
            f for f in estate.result.findings if f.domain == Domain.IDENTITY and f.subject == arn
        ],
    }


def secrets(estate: Estate) -> dict:
    by_secret = defaultdict(list)
    for grant in estate.result.secret_grants:
        by_secret[grant.secret_arn].append(grant)
    rows = sorted(
        ({"secret": s, "grants": by_secret[s.arn]} for s in estate.snapshot.secrets),
        key=lambda r: (-len(r["grants"]), r["secret"].name),
    )
    plaintext = [(a, p) for a in estate.snapshot.agents for p in a.plaintext_secrets]
    now = datetime.now(UTC)
    return {
        "rows": rows,
        "plaintext": plaintext,
        "unreferenced": [g for g in estate.result.secret_grants if not g.referenced],
        "unrotated": [s for s in estate.snapshot.secrets if s.rotation_enabled is False],
        "stale": [
            s
            for s in estate.snapshot.secrets
            if s.rotation_enabled and s.last_rotated and (now - s.last_rotated).days > 90
        ],
    }


def network(estate: Estate) -> dict:
    inbound = [
        {"agent": r.agent, "exposure": e, "row": r}
        for r in estate.rows
        for e in r.agent.network.inbound or []
    ]
    inbound.sort(
        key=lambda i: (not i["exposure"].internet, i["exposure"].authenticated is not False)
    )
    domains = estate.result.domains
    return {
        "inbound": inbound,
        "rows": estate.rows,
        "domains": domains,
        "unknown_domains": [d for d in domains if d.category == "Unknown"],
        "domain_categories": Counter(d.category for d in domains),
        "any_observed": any(d.observed for d in domains),
        "open_egress": [r for r in estate.rows if r.agent.network.internet_egress],
        "egress_unknown": [r for r in estate.rows if r.agent.network.internet_egress is None],
    }


def runtime(estate: Estate) -> dict:
    vulns = [
        {"agent": r.agent, "vuln": v, "internet": r.internet}
        for r in estate.rows
        for v in r.agent.runtime.vulnerabilities
    ]
    vulns.sort(
        key=lambda i: (
            SEVERITIES.index(i["vuln"].severity),
            not i["vuln"].exploit_available,
            not i["internet"],
        )
    )
    counts = _severity_counts([])
    for item in vulns:
        counts[item["vuln"].severity.value] += 1
    frameworks = Counter(f for r in estate.rows for f in r.agent.runtime.frameworks)
    return {
        "rows": estate.rows,
        "vulns": vulns,
        "counts": counts,
        "severity_ring": charts.doughnut(
            [
                {"label": s.capitalize(), "count": c, "tone": s, "href": None}
                for s, c in counts.items()
            ]
        ),
        "not_assessed": [r for r in estate.rows if not r.agent.runtime.vulns_assessed],
        "frameworks": frameworks.most_common(),
        "containers": [r for r in estate.rows if r.agent.runtime.image],
    }


def saas(estate: Estate) -> dict:
    vendors: dict[str, dict] = {}
    for row in estate.rows:
        for connection in row.agent.saas:
            entry = vendors.setdefault(
                connection.vendor, {"vendor": connection.vendor, "connections": [], "writes": False}
            )
            entry["connections"].append({"agent": row.agent, "connection": connection})
            entry["writes"] = entry["writes"] or bool(connection.can_write)
    ordered = sorted(vendors.values(), key=lambda v: (not v["writes"], -len(v["connections"])))
    tools = [
        {"agent": r.agent, "tool": t} for r in estate.rows for t in r.agent.tools if t.external
    ]
    return {
        "vendors": ordered,
        "tools": tools,
        "reused": [
            v
            for v in ordered
            if len({c["connection"].credential_ref for c in v["connections"]})
            < len(v["connections"])
        ],
    }


def findings(estate: Estate, params: dict[str, str]) -> dict:
    items = estate.result.findings
    if severity := params.get("severity"):
        items = [f for f in items if f.severity.value == severity]
    if domain := params.get("domain"):
        items = [f for f in items if f.domain.value == domain]
    if agent := params.get("agent"):
        items = [f for f in items if f.agent_id == agent]
    if rule_id := params.get("rule"):
        items = [f for f in items if f.rule_id == rule_id]
    groups: dict[str, dict] = {}
    for finding in items:
        group = groups.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "title": finding.title,
                "domain": finding.domain.value,
                "worst": finding.severity,
                "remediation": finding.remediation,
                "items": [],
            },
        )
        group["items"].append(finding)
        if SEVERITIES.index(finding.severity) < SEVERITIES.index(group["worst"]):
            group["worst"] = finding.severity
    ordered = sorted(
        groups.values(), key=lambda g: (SEVERITIES.index(g["worst"]), -len(g["items"]))
    )
    return {
        "groups": ordered,
        "total": len(items),
        "params": params,
        "partial": "_findings_list.html",
        "severities": [s.value for s in SEVERITIES],
        "domains": [d.value for d in Domain],
        "agent_names": sorted((a.name, a.id) for a in estate.snapshot.agents),
    }


def frameworks(estate: Estate) -> dict:
    def build(names: dict[str, str] | None, attribute: str, values=None) -> list[dict]:
        entries = list(names.items()) if names else [(v, v) for v in values]
        rows = []
        for key, name in entries:
            rules = [
                r
                for r in RULES
                if key
                in getattr(r, {"nhi": "nhi", "asi": "asi", "aws_dimension": "aws"}[attribute])
            ]
            hits = [f for f in estate.result.findings if key in getattr(f, attribute)]
            rows.append(
                {
                    "id": key,
                    "name": name,
                    "rules": len(rules),
                    "findings": len(hits),
                    "counts": _severity_counts(hits),
                    "agents": len({f.agent_id for f in hits}),
                    "rule_ids": [r.id for r in rules],
                }
            )
        return rows

    scope_counts = Counter(r.autonomy_scope for r in estate.result.agents)
    scopes = [
        {"scope": 1, "name": "No agency", "text": "Read-only. Informs and recommends."},
        {
            "scope": 2,
            "name": "Prescribed agency",
            "text": "Proposes changes that a person approves.",
        },
        {
            "scope": 3,
            "name": "Supervised agency",
            "text": "Started by a person, then acts within limits.",
        },
        {
            "scope": 4,
            "name": "Full agency",
            "text": "Starts itself and acts with little oversight.",
        },
    ]
    for scope in scopes:
        scope["count"] = scope_counts.get(scope["scope"], 0)
        scope["agents"] = [
            r.agent for r in estate.rows if r.result.autonomy_scope == scope["scope"]
        ]
    return {
        "nhi": build(NHI_NAMES, "nhi"),
        "asi": build(ASI_NAMES, "asi"),
        "aws": build(None, "aws_dimension", AWS_DIMENSIONS),
        "scopes": scopes,
        "unscoped": scope_counts.get(None, 0),
        "logging": estate.snapshot.signals.model_invocation_logging,
    }
