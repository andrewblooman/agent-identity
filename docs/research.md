# Research: what matters for AI agent security

Researched November 2026 to decide what the dashboard measures.

## Summary

An AI agent is a non-human identity that decides for itself what to do with its access. Traditional
controls assume the holder of a credential behaves predictably, and an agent can be steered by the
content it reads. So the most useful question is how much damage an agent's access allows, and that
can be answered without predicting how the model behaves.

## Frameworks used

### OWASP Non-Human Identities Top 10 (2025)

Improper offboarding (NHI1), secret leakage (NHI2), vulnerable third-party NHI (NHI3), insecure
authentication (NHI4), overprivileged NHI (NHI5), insecure cloud deployment configurations (NHI6),
long-lived secrets (NHI7), environment isolation (NHI8), NHI reuse (NHI9), human use of NHI (NHI10).

### OWASP Top 10 for Agentic Applications (December 2025)

Agent goal hijack (ASI01), tool misuse and exploitation (ASI02), identity and privilege abuse (ASI03),
agentic supply chain vulnerabilities (ASI04), unexpected code execution (ASI05), context management and
retrieval manipulation (ASI06), insecure inter-agent communication (ASI07), cascading failures (ASI08),
human-agent trust exploitation (ASI09), rogue agents (ASI10).

These names come from a secondary summary (F5), because OWASP's own page puts the list in a download
that couldn't be retrieved. Check them against the OWASP document before quoting them formally. The
tool has no check for ASI07, and the Frameworks page says so.

### AWS Agentic AI Security Scoping Matrix

Four scopes by human oversight: no agency, prescribed agency, supervised agency and full agency. Six
dimensions: identity context; data, memory and state protection; audit and logging; agent and LLM
controls; agency perimeters and policies; orchestration. The dashboard estimates scope from
configuration, because real oversight can't be fully read from AWS APIs.

## Core concerns

**Excessive privilege.** Agents inherit standing access, because they're set up for automation. This
is both OWASP NHI5 and ASI03.

**Credentials that outlive their purpose.** Long-lived keys and secrets give an attacker unlimited time
to use them, as NHI2 and NHI7 describe.

**Third-party trust.** The Vercel and Context.ai incident (2026) ran in three hops: an infostealer at
an AI tool vendor, stolen OAuth tokens from the vendor's AWS environment, then a broad grant one
employee had approved, which led into Vercel's internal systems. The Cloud Security Alliance's lessons
were to audit OAuth grants continuously, treat AI tools as high-privilege third parties, and prefer
short-lived credentials. A valid token also gets around MFA. AWS APIs can't see these grants, which
is this tool's largest blind spot.

**Shadow agents.** A Lambda function can call a model without ever being registered as an agent. No
AWS API lists agents with their security settings, so discovery has to combine several signals. The
tool shows its evidence for each one.

**Prompt injection acting through valid access.** An instruction planted in data the agent reads gets
carried out with the agent's own credentials. AWS argues that boundaries have to be enforced outside
the model, since a model can be told to respect a limit but can't reliably enforce one. This is why the
dashboard's main indicator is the "lethal trifecta" (Simon Willison's term): sensitive data, untrusted
input and a way out. Removing any one of the three breaks the attack.

**Poisoned context.** Whoever can write to a knowledge base, its source bucket or shared memory can
influence every agent that reads from it (ASI06).

## What this means for AWS discovery

| Finding | Effect on the design |
|---|---|
| `InvokeModel` and `Converse` are CloudTrail management events | Observed model use works with no extra setup |
| `InvokeAgent`, `Retrieve` and `RetrieveAndGenerate` are data events | Not visible to `LookupEvents`, so not used |
| Streaming calls add a second `AwsServiceEvent` record | Filtered out, or call counts come out too high |
| `bedrock-mantle` has separate logging | Listed as a blind spot |
| Access Analyzer's internal access covers S3, DynamoDB and RDS snapshots, not all stores | Can't be the only source of data access answers, and it may not be on |
| Macie reports AccessDenied when off | Reported as "not enabled", not a permissions problem |

## Sources

- [OWASP Non-Human Identities Top 10 (2025)](https://owasp.github.io/www-project-non-human-identities-top-10/2025/top-10-2025)
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [F5 summary of the OWASP agentic list](https://www.f5.com/glossary/owasp-top-10-for-agentic-ai-applications)
- [AWS Agentic AI Security Scoping Matrix](https://aws.amazon.com/ai/security/agentic-ai-scoping-matrix/)
- [Cloud Security Alliance note on Vercel and Context.ai](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-saas-supply-chain-vercel-contextai-2026/)
- [Monitor Amazon Bedrock API calls using CloudTrail](https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html)
- [AgentCore control plane API](https://docs.aws.amazon.com/botocore/latest/reference/services/bedrock-agentcore-control.html)
- [IAM Access Analyzer internal access](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-manage-internal.md)
- [Datadog Bedrock detection rule](https://docs.datadoghq.com/security/default_rules/def-000-uto/)
- [Trivy compromise advisory, CVE-2026-33634](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)
