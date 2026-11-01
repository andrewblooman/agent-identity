# Agent Identity

Finds AI agents running in an AWS account and shows what they can reach: data, secrets, networks
and outside services. This is a proof of concept that runs locally in Docker.

## Run it

```bash
cp .env.example .env
docker compose up --build
```

Open http://localhost:8080. It starts on made-up demo data, so nothing touches AWS until you ask.

## Scan your account

1. Set `AWS_PROFILE` and `SCAN_REGIONS` in `.env`. Your `~/.aws` folder is mounted read-only.
2. Open **Scans** and choose **Scan my account**.

Use a dedicated profile limited to [`iam/scanner-readonly-policy.json`](iam/scanner-readonly-policy.json).
A scan deploys nothing, enables nothing and creates no resources.

The policy limits log reading to log groups named `/aws/route53resolver/*`. If your Resolver query logs
go somewhere else, add that log group, or domains will show as "in config" rather than "contacted". It
also lets Trivy pull any image in the scanning account, because agent repositories have no fixed naming.
Remove the two `Trivy` statements and set `TRIVY_ENABLED=false` if you don't want that.

## What protects your account

- **Read-only in code.** Every AWS call has to be on an allowlist in
  [`aws/session.py`](src/agent_identity/aws/session.py), or it's blocked before it's signed. The one
  call that isn't a plain read is `GenerateServiceLastAccessedDetails`, which starts an IAM report job
  and changes no resources.
- **Secret values aren't read or kept.** The APIs for Lambda, ECS and AgentCore return environment
  variable values. These are checked in memory and dropped, keeping only the variable name, the type
  of credential and any hostname. Bedrock agent instructions are kept as a hash and a length.
- **Nothing gets turned on.** Access Analyzer, Macie and Inspector cost money, so they're used only if
  they're already on.
- **Unknown isn't safe.** A denied call or a disabled service shows as "not assessed". It never counts
  as a pass.
- **Local only.** There's no login, so the port is published on 127.0.0.1 and requests with any other
  Host header are refused. Don't expose it to a network.

## How agents are found

| Evidence | Where it comes from | Shown as |
|---|---|---|
| Managed service | Bedrock Agents, AgentCore runtimes | Confirmed |
| Recorded model calls | CloudTrail `InvokeModel` and `Converse` events | Confirmed |
| Config | Env var names, image names, layers and tags on Lambda, ECS and EC2 | Likely |
| Permission only | A role or key-holding user whose policy names model invocation | Possible |

A workload that only calls a model is a **model consumer**. It becomes an **agent** once it can also
act on something, through write permissions or tools. EKS is seen through Pod Identity associations.

## What it can't see

- **Pods inside EKS**, because that needs Kubernetes API access.
- **Calls to models outside AWS**, except through config or existing DNS logs.
- **Calls to the `bedrock-mantle` endpoint**, and `InvokeAgent` or `Retrieve` calls, which CloudTrail
  logs differently or only as data events.
- **OAuth grants inside SaaS products.** Agents with grants in Google Workspace, Salesforce and the
  like need SaaS connectors, which this version doesn't have. The SaaS page shows the AWS side only.
- **SCPs and session policies.** Permissions are worked out from identity policies, boundaries and
  resource policies, then confirmed with the IAM policy simulator, which doesn't test resource
  policies for roles. Reach may be overstated in an account with restrictive SCPs.

Permissions show what an agent could do, not what it did. The lethal trifecta check means the three
conditions exist. It doesn't mean an attack is possible through any particular prompt.

## Scoring

Each finding has an ID and maps to the OWASP NHI Top 10, the OWASP Top 10 for Agentic Applications and
the AWS Agentic AI Security Scoping Matrix. **Frameworks** in the app explains the formula. Use the
score to decide what to look at first. It doesn't measure breach likelihood.

## Develop

```bash
python3.14 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
.venv/bin/ruff check src tests
PYTHONPATH=src .venv/bin/uvicorn agent_identity.main:create_app --factory --port 8080
```

Rules are in [`rules/checks.py`](src/agent_identity/rules/checks.py). A rule returns a list of hits, an
empty list if it passes, or `None` if the data it needs isn't available. After changing dependencies in
`pyproject.toml`, rebuild `requirements.lock` with `pip-compile --generate-hashes --strip-extras
--output-file=requirements.lock pyproject.toml`.

Background and sources are in [`docs/research.md`](docs/research.md).
