# SentinelFlow

Explainable AI that turns web and firewall logs into safe, validated response actions.

SentinelFlow is an AI-assisted security operations platform for correlating web access logs, application authentication events, and Linux firewall syslog messages into explainable security incidents.

> Status: Early development prototype.  
> Some commands, screenshots, and deployment details in this README are placeholders until the implementation is complete.

---

## Overview

Security teams often have access to large volumes of logs but still need to manually connect related events across multiple systems.

A single source IP may:

- scan administrative paths,
- attempt authentication against multiple accounts,
- trigger firewall events,
- generate an abnormal request burst.

Each event may appear insignificant when reviewed separately. SentinelFlow groups related activity into one incident, explains the evidence, proposes a proportionate response, validates the expected impact, and keeps the final enforcement decision under administrator control.

The intended workflow is:

```text
Log ingestion
    ↓
Normalization
    ↓
Deterministic detection
    ↓
Cross-source incident correlation
    ↓
GPT-5.6 analysis and explanation
    ↓
Structured response policy
    ↓
Syntax and impact validation
    ↓
Administrator approval
    ↓
Temporary nftables enforcement
```

---

## Core Features

The MVP is designed around the following capabilities:

- Receive syslog over TCP and UDP
- Parse Nginx access logs
- Parse application authentication events
- Parse Linux firewall and nftables syslog events
- Normalize different log formats into a shared event schema
- Detect suspicious activity using deterministic rules
- Correlate related events by source IP, time window, account, path, and service
- Use GPT-5.6 to explain likely attack behavior
- Show supporting evidence and possible false-positive explanations
- Generate a limited, structured firewall response policy
- Validate policy syntax before enforcement
- Estimate impact using historical traffic
- Require administrator approval before applying a rule
- Automatically expire temporary blocking rules
- Run repeatable normal-traffic and attack simulations

---

## Supported Detection Scenarios

The initial MVP focuses on a small number of clear and demonstrable scenarios.

### Credential stuffing

Detects patterns such as:

- many failed login attempts,
- multiple targeted usernames,
- repeated authentication failures from one source,
- related reconnaissance activity.

### Brute-force login attempts

Detects repeated authentication attempts against one or more accounts within a short time window.

### Automated path scanning

Detects requests to common administrative, backup, configuration, and vulnerable application paths.

### Abnormal request bursts

Detects sudden request-volume changes that may indicate automated abuse or application-layer denial-of-service activity.

---

## Design Principles

### Deterministic signals first

SentinelFlow does not send every raw log line directly to an AI model.

The detection engine first calculates measurable signals such as:

- request count,
- failed-login count,
- number of unique usernames,
- number of unique paths,
- observed ports,
- event frequency,
- time-window concentration.

### AI for context and explanation

GPT-5.6 is intended to handle tasks where contextual reasoning is useful:

- correlating related events,
- explaining why activity appears suspicious,
- classifying likely attack behavior,
- describing uncertainty,
- identifying possible false positives,
- recommending a proportionate response,
- converting security intent into a structured policy.

### Human approval before enforcement

The model does not receive unrestricted shell access and does not directly modify a production firewall.

A proposed response must pass:

1. schema validation,
2. protected-network checks,
3. nftables syntax validation,
4. historical-impact analysis,
5. administrator approval.

### Temporary and reversible actions

Blocking rules should have an expiration time and an auditable lifecycle.

---

## Planned Architecture

```text
┌───────────────────────────────────────────────────────────┐
│ Log Sources                                               │
│                                                           │
│ Nginx access logs                                         │
│ Application authentication events                         │
│ Linux / nftables syslog                                    │
└───────────────────────┬───────────────────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────────────────┐
│ Ingestion Service                                         │
│                                                           │
│ Syslog TCP/UDP receiver                                    │
│ Source-specific parsers                                    │
└───────────────────────┬───────────────────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────────────────┐
│ Normalization and Storage                                 │
│                                                           │
│ Shared event schema                                       │
│ PostgreSQL event and incident storage                      │
└───────────────────────┬───────────────────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────────────────┐
│ Detection and Correlation                                 │
│                                                           │
│ Deterministic rules                                       │
│ Time-window aggregation                                   │
│ Cross-source incident correlation                         │
└───────────────────────┬───────────────────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────────────────┐
│ GPT-5.6 Analyst                                           │
│                                                           │
│ Incident explanation                                      │
│ Confidence and false-positive analysis                    │
│ Recommended response                                      │
└───────────────────────┬───────────────────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────────────────┐
│ Policy Safety Pipeline                                    │
│                                                           │
│ Structured policy generation                              │
│ Protected-range checks                                    │
│ nftables syntax validation                                │
│ Historical-impact replay                                  │
└───────────────────────┬───────────────────────────────────┘
                        │
                        ▼
┌───────────────────────────────────────────────────────────┐
│ Approval and Enforcement                                  │
│                                                           │
│ Administrator review                                      │
│ Temporary nftables rule                                   │
│ Automatic expiration                                      │
│ Audit trail                                               │
└───────────────────────────────────────────────────────────┘
```

---

## Planned Technology Stack

### Backend

- Go
- chi
- pgx
- sqlc
- PostgreSQL
- OpenAI API
- Server-Sent Events

### Frontend

- React
- TypeScript
- Vite
- MUI

### Infrastructure

- Docker
- Docker Compose
- Nginx
- Linux
- nftables
- Syslog

---

## Event Model

Normalized events are expected to contain fields similar to:

```json
{
  "timestamp": "2026-07-15T06:30:00Z",
  "source_type": "nginx",
  "event_type": "http_request",
  "source_ip": "203.0.113.20",
  "destination_service": "web",
  "request_method": "POST",
  "request_path": "/login",
  "username": "example-user",
  "authentication_result": "failed",
  "severity_indicators": [
    "high_request_rate",
    "multiple_usernames"
  ],
  "raw_evidence": "203.0.113.20 - - [15/Jul/2026:06:30:00 +0000] ..."
}
```

The normalized fields are used for counting and correlation. Original evidence is retained for investigation and audit purposes.

---

## Structured Response Policy

AI-generated recommendations should be converted into a constrained policy format rather than arbitrary shell commands.

Example:

```yaml
name: credential-stuffing-temporary-block
description: Temporarily block a source that exceeded the credential-stuffing threshold.

match:
  source_ip: 203.0.113.20

exclusions:
  cidrs:
    - 10.0.0.0/8
    - 172.16.0.0/12
    - 192.168.0.0/16

action:
  type: block_ip
  duration: 30m

approval:
  required: true
```

This policy is validated before it can be translated into an nftables rule.

---

## How Codex Was Used

Codex is being used as a development partner throughout the project.

Planned and current uses include:

- designing the initial repository structure,
- implementing Go parsers and APIs,
- reviewing event schemas,
- generating unit and integration tests,
- identifying parser edge cases,
- reviewing firewall-policy safety checks,
- improving Docker Compose configuration,
- documenting installation and demo procedures,
- assisting with refactoring and debugging.

Human decisions remain responsible for:

- product scope,
- security boundaries,
- threat model,
- approval workflow,
- supported log sources,
- supported enforcement actions,
- final code review.

---

## How GPT-5.6 Is Used

GPT-5.6 is intended to receive a compact, structured incident summary rather than an unrestricted stream of raw logs.

Its responsibilities include:

- relating signals from multiple log sources,
- summarizing the incident,
- classifying likely attack behavior,
- explaining supporting evidence,
- identifying uncertainty,
- describing potential false positives,
- recommending a response,
- producing a constrained structured-policy proposal.

GPT-5.6 is not trusted to directly execute firewall commands.

---

## Repository Structure

The target repository layout is:

```text
sentinelflow/
├── cmd/
│   ├── api/
│   ├── ingestor/
│   ├── worker/
│   └── simulator/
├── internal/
│   ├── ai/
│   ├── api/
│   ├── correlation/
│   ├── detection/
│   ├── enforcement/
│   ├── events/
│   ├── ingestion/
│   ├── policy/
│   ├── repository/
│   └── validation/
├── db/
│   ├── migrations/
│   ├── queries/
│   └── schema/
├── web/
├── deployments/
├── samples/
├── scripts/
├── docs/
├── docker-compose.yml
├── .env.example
├── go.mod
└── README.md
```

This structure may change during implementation.

---

## Requirements

Planned minimum environment:

- Linux
- Docker Engine 24 or later
- Docker Compose v2
- 4 GB RAM
- Modern web browser
- OpenAI API key for GPT-5.6 analysis
- nftables support for enforcement testing

The default demo should run enforcement inside an isolated container or network namespace so that it does not modify the host firewall.

---

## Installation

> The following commands describe the intended final workflow. They may change while the prototype is under development.

Clone the repository:

```bash
git clone https://github.com/devwooops/sentinelflow.git
cd sentinelflow
```

Create the environment file:

```bash
cp .env.example .env
```

Set the required environment variables:

```dotenv
OPENAI_API_KEY=your_openai_api_key
POSTGRES_DB=sentinelflow
POSTGRES_USER=sentinelflow
POSTGRES_PASSWORD=change_me
```

Start the environment:

```bash
docker compose up --build
```

Open the dashboard:

```text
http://localhost:3000
```

---

## Demo Scenarios

The final repository is expected to include repeatable demo scenarios.

### Credential stuffing

```bash
docker compose run --rm simulator credential-stuffing
```

### Automated path scanning

```bash
docker compose run --rm simulator path-scanning
```

### Abnormal request burst

```bash
docker compose run --rm simulator request-burst
```

After running a scenario:

1. Open the SentinelFlow dashboard.
2. Select the generated incident.
3. Review the normalized events.
4. Review deterministic signals.
5. Review the GPT-5.6 explanation.
6. Inspect the recommended policy.
7. Run policy validation.
8. Review historical-impact results.
9. Approve or reject the action.
10. Confirm that temporary rules expire automatically.

---

## Testing

Planned backend tests:

```bash
go test ./...
```

Planned frontend tests:

```bash
cd web
npm install
npm test
```

Planned integration test:

```bash
docker compose --profile test up --build --abort-on-container-exit
```

Commands will be updated to match the final implementation.

---

## Safety Model

SentinelFlow is a defensive security prototype.

The project is designed around the following controls:

- no unrestricted model-generated shell commands,
- no automatic production enforcement by default,
- protected CIDR ranges,
- structured policy schema,
- syntax validation,
- impact simulation,
- explicit administrator approval,
- temporary rules,
- automatic expiration,
- audit logging,
- isolated demo enforcement.

Do not enable host-level enforcement on a production machine without reviewing the implementation, permissions, protected networks, rollback behavior, and audit configuration.

---

## Threat Model

The MVP considers risks including:

- malicious or malformed log input,
- prompt injection embedded in logs,
- incorrect event correlation,
- AI hallucination,
- false-positive blocking,
- administrator lockout,
- overly broad firewall rules,
- leaked API keys,
- privileged-container abuse.

Mitigations include:

- treating log contents as untrusted data,
- never treating embedded log text as model instructions,
- using deterministic aggregation before model analysis,
- limiting model outputs to a schema,
- protecting internal and management networks,
- requiring validation and approval,
- running the demo in isolation,
- keeping secrets outside the repository.

---

## Known Limitations

Expected MVP limitations include:

- limited log-source support,
- limited attack scenarios,
- rule-based thresholds rather than learned baselines,
- single-node deployment,
- nftables-only enforcement,
- no guarantee of detecting all attacks,
- possible false positives,
- dependence on log quality,
- GPT-5.6 analysis requiring network access and API credentials.

SentinelFlow is not intended to replace a production WAF, SIEM, IDS, IPS, or professional security review.

---

## Roadmap

Potential future work:

- Traefik support
- Apache support
- SSH authentication logs
- OpenSearch integration
- SIEM integrations
- organization-specific behavioral baselines
- Nginx rate-limit policies
- cloud WAF integrations
- multi-host enforcement agents
- role-based approval workflows
- policy rollback
- incident reports
- threat-intelligence enrichment
- MCP integrations
- multi-tenant deployments
- signed policy bundles
- production-grade audit and compliance controls

---

## License

A license will be selected before the final submission.

The expected choice is one of:

- Apache License 2.0
- MIT License

Until a license file is added, all rights are reserved.

---

## Disclaimer

SentinelFlow is an experimental project.

It must not be relied on as the sole security control for a production system. Review all generated recommendations and firewall policies before use.

