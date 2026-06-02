# Implementation Plan — AI PR Security Review Agent

**14-week, single-squad delivery · Azure DevOps first · pragmatic hybrid**

Approach: Build the thinnest end-to-end slice first (MVP walking skeleton), run advisory-only, then add depth, policy and rollout. Ship value every 2 weeks. Keep analysis logic in portable OCI containers; use Azure PaaS for plumbing.

---

## Phased overview

| Phase | Timeline | Key work | Exit criteria |
|-------|----------|----------|---------------|
| **P0 Foundation** | Wk 1–2 | Azure subscription, resource groups, IaC (Bicep), ACR, Key Vault, Entra managed identity, Azure OpenAI access approved, repo + CI skeleton | Environments reproducible; OpenAI reachable via managed identity |
| **P1 MVP** | Wk 3–6 | Functions webhook receiver → Service Bus → Container Apps orchestrator. Semgrep + secret scan. LLM triage (Azure OpenAI). Post summary + inline comments (advisory, non-blocking) | PR opened → comments appear automatically on a pilot repo |
| **P2 Depth** | Wk 7–10 | Add CodeQL + Trivy (SCA) + basic IaC scan. RAG over OWASP/Bosch baseline (PostgreSQL + pgvector). Findings store (Cosmos DB), Redis cache, dedupe + severity scoring | Lower false positives; richer, grounded findings; results persisted |
| **P3 Policy & rollout** | Wk 11–14 | Per-service gating policy (App Configuration), waiver/override workflow, KQL dashboard, CD-09000 evidence feed, onboard 3–5 teams, enforce gate for sensitive services | Configurable gate live; pilot teams onboarded; audit evidence flowing |
| **P4 Scale (next)** | Wk 15+ | GitHub adapter, auto fix-suggestions, custom Bosch rule packs, false-positive feedback loop, broader rollout | Multi-platform; continuous tuning; org-wide adoption |

---

## Team & milestones

| Role | Count |
|------|-------|
| Backend/Azure dev (AI-200 skills) | 1 |
| DevSecOps / pipelines | 1 |
| AppSec (rules, triage, validation) | 1 |
| Product/PM (scope, rollout, CD-09000) | 0.5 |

| Milestone | Week | Demo |
|-----------|------|------|
| M1 | Wk 2 | Infra up; Azure OpenAI hello-world works. Deploy from scratch + successful model call |
| M2 | Wk 6 | MVP advisory review live on pilot repo. Open a PR → comments appear automatically |
| M3 | Wk 10 | RAG + multi-scanner + dashboard |
| M4 | Wk 14 | Gating + 3–5 teams onboarded |

---

## Top risks

| Risk | Mitigation |
|------|-----------|
| False positives | Keep advisory-only until tuned; AppSec validates rules before gating |
| LLM cost | Cache + scope to diff only; set token budget per run |
| IP/data residency | In-tenant Azure OpenAI only; no data leaves the subscription |
| ADO API rate limits | Exponential backoff; queue-based architecture absorbs bursts |

---

## Detailed plan — P0 + P1 (Weeks 1–6)

Three 2-week sprints. 1 SP ≈ half a day.

### Sprint 0 — Foundation (Weeks 1–2) — **[IN PROGRESS]**

| US | User story | Acceptance criteria | SP | Status |
|----|------------|--------------------|----|--------|
| US-01 | As a platform engineer, I want the Azure environment provisioned via IaC so it is reproducible | One Bicep deploy creates RG, ACR, Container Apps env, Service Bus, Key Vault, Entra managed identity; re-run is idempotent | 5 | ✅ Scaffolded |
| US-02 | As a platform engineer, I want Azure OpenAI reachable via managed identity so there are no static keys | Model deployment in an approved region; test call succeeds via managed identity; secrets only in Key Vault | 3 | ✅ Scaffolded |
| US-03 | As a developer, I want a CI skeleton that builds and pushes the container image to ACR | Push to main builds the image, tags it, pushes to ACR; pipeline green | 3 | ✅ Scaffolded |

**M1 — Wk 2:** Infra up; Azure OpenAI hello-world works. Demo: deploy from scratch + a successful model call. **11 SP**

---

### Sprint 1 — Ingest & analyze (Weeks 3–4)

| US | User story | Acceptance criteria | SP | Status |
|----|------------|--------------------|----|--------|
| US-04 | As the agent, I receive Azure DevOps PR events via webhook so review starts automatically | Service hook → Functions receiver validates signature, enqueues a job on Service Bus; invalid signatures rejected | 5 | ⬜ Backlog |
| US-05 | As the agent, I fetch the PR diff and changed files so I know what to scan | Orchestrator (Container Apps) pulls the job, calls the Azure DevOps API, retrieves diff + file list; handles large diffs | 5 | ⬜ Backlog |
| US-06 | As a developer, I want Semgrep and secret scanning run on the diff so known issues are flagged | Scanner container runs on changed files; emits normalized findings (rule, file, line, severity) mapped to OWASP | 5 | ⬜ Backlog |

---

### Sprint 2 — Reason & report (Weeks 5–6)

| US | User story | Acceptance criteria | SP | Status |
|----|------------|--------------------|----|--------|
| US-07 | As a security engineer, I want LLM triage of findings so noise is reduced | LLM (Azure OpenAI) takes diff + findings and returns structured output: explanation, priority, likely-false-positive flag; it never overrides deterministic findings | 5 | ⬜ Backlog |
| US-08 | As a developer, I want a summary plus inline comments on my PR so I can fix issues early | Summary comment + inline comments (file/line, severity, fix hint) posted; an advisory (non-blocking) status check is set | 5 | ⬜ Backlog |
| US-09 | As DevOps, I want basic run logs and metrics so I can see it working | App Insights trace per run; success/failure and duration visible; failures raise an alert | 3 | ⬜ Backlog |

**M2 — Wk 6:** MVP advisory review live on pilot repo. Demo: open a PR, comments appear automatically. **13 SP**

---

## Sequence & dependencies

```
US-01 → US-02 / US-03        (infra first)
US-04 → US-05 → US-06        (event before diff before scan)
US-06 → US-07 → US-08        (findings before reasoning before posting)
```

From Sprint 1 on, keep one pilot repo and one test PR as the constant feedback loop.

**Total to MVP: 37 SP across 3 sprints**

---

## Definition of Done (every US)

- [ ] Code reviewed and merged; runs in the deployed environment, not just locally
- [ ] Secrets via Key Vault / managed identity — no hard-coded credentials
- [ ] A basic test or a demonstrable end-to-end run; trace visible in App Insights
- [ ] A short note in the README / runbook on how to operate or re-run it
