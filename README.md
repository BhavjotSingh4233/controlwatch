# ControlWatch

Automated security control monitoring built on Cloudflare.

ControlWatch continuously evaluates identity-security controls using deterministic logic, stores assessment results and findings in D1, preserves raw evidence in R2, and uses Workers AI to generate concise risk explanations for security leaders.

> **Control determination is deterministic; AI is used only for interpretation.**
>
> ControlWatch never relies on an LLM to determine whether a security control passes or fails.

## Live Demo

**ControlWatch:**  
https://controlwatch.bhavjotsingh4233.workers.dev

## Overview

Traditional GRC control testing often involves manually collecting evidence, evaluating controls, documenting findings, and communicating risk.

ControlWatch demonstrates how that workflow can be automated.

For every assessment, the application:

1. Collects synthetic identity-security data.
2. Runs deterministic control logic.
3. Produces a `PASS`, `FAIL`, or `ERROR` result.
4. Stores the assessment in Cloudflare D1.
5. Stores raw supporting evidence in Cloudflare R2.
6. Creates and risk-scores findings for detected exceptions.
7. Uses Workers AI to translate structured findings into executive-friendly risk explanations.
8. Displays the results through a lightweight monitoring dashboard.

## Architecture

```text
              ┌──────────────────────┐
              │ Synthetic Identity   │
              │ Security Data        │
              └─────────┬────────────┘
                        │
                        ▼
              ┌──────────────────────┐
              │ Cloudflare Worker    │
              │                      │
              │ API + Orchestration  │
              └─────────┬────────────┘
                        │
                        ▼
              ┌──────────────────────┐
              │ Deterministic        │
              │ Control Engine       │
              │                      │
              │ AC-001               │
              │ AC-002               │
              │ AC-003               │
              └─────┬─────────┬──────┘
                    │         │
              PASS  │         │ FAIL
                    │         │
                    ▼         ▼
              ┌──────────────────────┐
              │ Cloudflare D1        │
              │                      │
              │ Assessments          │
              │ Findings             │
              │ Risk Scores          │
              │ Remediation          │
              └──────────────────────┘
                    │
          ┌─────────┴──────────┐
          ▼                    ▼
┌─────────────────┐   ┌──────────────────┐
│ Cloudflare R2   │   │ Workers AI       │
│                 │   │                  │
│ Raw Evidence    │   │ Risk Summaries   │
└─────────────────┘   └──────────────────┘
          │                    │
          └─────────┬──────────┘
                    ▼
           ┌───────────────────┐
           │ GRC Dashboard     │
           │                   │
           │ Control Health    │
           │ Risk              │
           │ Evidence          │
           │ Findings          │
           │ Remediation       │
           └───────────────────┘
```

## Cloudflare Stack

### Cloudflare Workers

The Worker acts as the application's API and orchestration layer.

It:

- Executes security controls
- Coordinates assessment workflows
- Writes assessment data to D1
- Stores evidence in R2
- Invokes Workers AI
- Exposes API endpoints to the dashboard

### Cloudflare D1

D1 provides the relational persistence layer for:

- Assessment history
- Control results
- Findings
- Risk scores
- Finding owners
- Due dates
- Remediation plans
- Resolution status

This allows ControlWatch to maintain historical assessment and finding data rather than simply returning one-time control results.

### Cloudflare R2

R2 stores the raw evidence associated with each assessment.

Evidence objects use assessment-specific keys such as:

```text
AC-001/assessment-25.json
AC-002/assessment-26.json
AC-003/assessment-27.json
```

This separates structured assessment metadata in D1 from the raw evidence supporting the assessment.

### Cloudflare Workers AI

Workers AI generates concise explanations of deterministic security findings.

For a failed control, the model receives structured information including:

- Control ID
- Control requirement
- Deterministic result
- Detected exceptions
- Risk score
- Severity
- Assigned remediation

It returns:

- Risk Summary
- Potential Impact
- Recommended Remediation

Workers AI **does not determine whether a control passes or fails**.

This separation is intentional: conditions such as whether an administrator has MFA enabled are objectively measurable and should be evaluated with deterministic code.

AI is used downstream where natural-language interpretation is useful.

## Security Controls

ControlWatch currently implements three internal demo controls.

### AC-001 — Privileged Accounts Require MFA

**Objective**

All active privileged accounts must have multi-factor authentication enabled.

Example failure:

```text
User: Bob
Role: Admin
Active: Yes
MFA: Disabled

Result: FAIL
```

### AC-002 — Terminated Employees Must Not Retain Active Accounts

**Objective**

Accounts belonging to terminated employees must be deactivated.

Example failure:

```text
User: Dave
Employment Status: Terminated
Account Active: Yes

Result: FAIL
```

### AC-003 — Privileged Access Reviews

**Objective**

Active privileged accounts must have an access review completed within the previous 90 days.

Example failure:

```text
User: Bob
Role: Admin
Last Access Review: More than 90 days ago

Result: FAIL
```

The `AC-001`, `AC-002`, and `AC-003` identifiers are internal ControlWatch identifiers for the demo rather than identifiers from a specific compliance framework.

## Deterministic Assessment Engine

A major design principle of ControlWatch is separating **determination** from **interpretation**.

The control engine handles determination:

```text
Identity Data
     ↓
Deterministic Rule
     ↓
PASS / FAIL / ERROR
```

Workers AI handles interpretation:

```text
Structured Finding
     ↓
Workers AI
     ↓
Risk Summary
Potential Impact
Recommended Remediation
```

This prevents an LLM from changing an objectively measurable compliance result.

For example:

```text
active administrator
+
MFA disabled
=
FAIL
```

That decision does not require AI.

## PASS, FAIL, and ERROR

ControlWatch distinguishes between three assessment states:

```text
PASS
FAIL
ERROR
```

`PASS` means the available evidence satisfies the control.

`FAIL` means the evidence contains a deterministic control exception.

`ERROR` represents an inability to complete the assessment, such as an evidence collection failure.

This distinction is important because a monitoring failure should not automatically imply that the underlying security control passed or failed.

## Risk Scoring

Findings use a simple demonstration risk methodology:

```text
Risk Score = Likelihood × Impact
```

Both likelihood and impact are scored from 1–5.

For example:

```text
Likelihood: 4 / 5
Impact:     5 / 5

Risk Score: 20 / 25
Severity:   Critical
```

The scoring model is a ControlWatch demo methodology and is not presented as Cloudflare's risk-scoring methodology.

## Finding and Remediation Tracking

Failed controls can produce findings containing:

```text
Control
Subject
Description
Severity
Likelihood
Impact
Risk Score
Owner
Due Date
Remediation Plan
Status
```

For example:

```text
Control: AC-001
Subject: Bob
Severity: Critical
Risk: 20 / 25

Owner: Identity Security

Remediation:
Enable MFA for the affected privileged account and
verify MFA enforcement for privileged users.

Status: OPEN
```

This demonstrates a broader GRC lifecycle:

```text
Control
   ↓
Assessment
   ↓
Evidence
   ↓
Finding
   ↓
Risk
   ↓
Owner
   ↓
Remediation
   ↓
Resolution
```

## Dashboard

The dashboard provides visibility into:

- Overall control health
- Passing and failing controls
- Open findings
- Critical and high-risk findings
- Risk scores
- Control exceptions
- AI-generated risk analysis
- Finding ownership
- Remediation plans
- Due dates
- Assessment history
- Raw R2 evidence

The frontend intentionally uses lightweight HTML, CSS, and JavaScript rather than a large frontend framework.

## Example Assessment Flow

```text
Run AC-001
     ↓
Worker loads identity data
     ↓
Control engine checks active privileged users
     ↓
Bob has MFA disabled
     ↓
AC-001 = FAIL
     ↓
Assessment saved to D1
     ↓
Raw evidence saved to R2
     ↓
Finding created / updated in D1
     ↓
Risk score calculated
     ↓
Workers AI generates risk explanation
     ↓
Dashboard displays assessment
```

## Project Structure

```text
controlwatch/
├── public/
│   ├── index.html
│   ├── app.js
│   └── style.css
│
├── src/
│   ├── index.ts
│   ├── control.ts
│   └── data.ts
│
├── schema.sql
├── wrangler.jsonc
├── package.json
└── README.md
```

## Running Locally

Install dependencies:

```bash
npm install
```

Generate Cloudflare binding types when needed:

```bash
npx wrangler types
```

Initialize the local D1 database:

```bash
npx wrangler d1 execute controlwatch-db --local --file=./schema.sql
```

Start the development server:

```bash
npm run dev
```

Then open:

```text
http://localhost:8787
```

## Deployment

Initialize the production D1 schema when setting up a new environment:

```bash
npx wrangler d1 execute controlwatch-db --remote --file=./schema.sql
```

Deploy the Worker:

```bash
npx wrangler deploy
```

Wrangler deploys the Worker and static dashboard assets while connecting the application to its configured Cloudflare bindings.

## Tech Stack

- TypeScript
- Cloudflare Workers
- Cloudflare Workers AI
- Cloudflare D1
- Cloudflare R2
- Wrangler
- HTML
- CSS
- JavaScript

## Key Design Decisions

**Deterministic compliance decisions**

AI never decides whether a control passes or fails.

**Evidence separated from assessment metadata**

D1 stores structured assessment and finding data while R2 stores raw supporting evidence.

**AI as an interpretation layer**

Workers AI converts structured technical findings into language useful to security and risk stakeholders.

**Assessment failures are explicit**

The architecture supports `ERROR` separately from `PASS` and `FAIL`, avoiding false conclusions when monitoring itself fails.

**Serverless architecture**

The application uses Cloudflare's serverless platform for compute, relational storage, object storage, AI inference, and static asset delivery.

---

Built as a demonstration of automated security control monitoring and GRC workflows using the Cloudflare developer platform.