# Implementation Plan — AI PR Security Review Agent

**14-week, single-squad delivery · Azure DevOps first · pragmatic hybrid**

Approach: Build the thinnest end-to-end slice first (MVP walking skeleton), run advisory-only, then add depth, policy and rollout. Ship value every 2 weeks. Keep analysis logic in portable OCI containers; use Azure PaaS for plumbing.

---

## Phased overview

| Phase | Timeline | Key work | Exit criteria |
|-------|----------|----------|---------------|
| **P0 Foundation** | Wk 1–2 | Existing development resource group, IaC (Bicep), ACR, Key Vault, Entra managed identity, Azure OpenAI access approved, repo + CI skeleton | Environment reproducible in the approved resource group; OpenAI reachable via managed identity |
| **P1 MVP** | Wk 3–6 | Scale-to-zero webhook gateway → Service Bus → Container Apps orchestrator. Semgrep + secret scan. LLM triage (Azure OpenAI). Post summary + inline comments (advisory, non-blocking) | PR opened → comments appear automatically on a pilot repo |
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
| LLM cost | GPT-5.4 mini Global Standard; one triage call per PR iteration; 100k input and 8k completion caps; budget/telemetry safeguards |
| IP/data residency | Runtime remains in Southeast Asia; GPT-5.4 mini Global Standard triage runs in an approved supported region, so send only PR context and normalized findings |
| ADO API rate limits | Exponential backoff; queue-based architecture absorbs bursts |

---

## Detailed plan — P0 + P1 (Weeks 1–6)

Three 2-week sprints. 1 SP ≈ half a day.

### Sprint 0 — Foundation (Weeks 1–2) — **[HACKATHON FOUNDATION DEPLOYED; PILOT PENDING]**

| US | User story | Acceptance criteria | SP | Status |
|----|------------|--------------------|----|--------|
| US-01 | As a platform engineer, I want the Azure environment provisioned via IaC so it is reproducible | One Bicep group deployment targets the approved existing resource group and creates ACR, Container Apps env/job, Function App, Service Bus, Key Vault, App Insights, Entra managed identity; re-run is idempotent | 5 | ⚠️ Hackathon profile deployed; low-cost gateway added; production profile pending |
| US-02 | As a platform engineer, I want Azure OpenAI reachable via managed identity so there are no static keys | Model deployment in an approved region; a test call succeeds via managed identity; secrets only in Key Vault | 3 | ⚠️ GPT-5.4 mini is deployed; hackathon profile uses an account key; live model smoke test pending |
| US-03 | As a developer, I want a CI skeleton that builds and pushes the container image to ACR | Push to main builds the orchestrator image, tags it, pushes to ACR; pipeline green | 3 | ✅ Workflow validates/builds worker and gateway images; first hosted pipeline run pending |

**M1 — Wk 2:** Infra and runtime code implemented; Azure deployment + OpenAI smoke call pending. **11 SP**

### Phase-one deployment constraints

- Target resource group: `rg-hackathon-groupc-hvn` in the `BD-XDV-Learning-Sandbox` subscription.
- Runtime resources use Southeast Asia; Azure OpenAI uses GPT-5.4 mini Global Standard in East US 2.
- Prefer cold starts: a zero-idle Container Apps gateway plus a zero-idle Container Apps Job.
- Development budget target: US$20–50, with a US$25 Cost Management budget recommendation.

---

### Sprint 1 — Ingest & analyze (Weeks 3–4)

| US | User story | Acceptance criteria | SP | Status |
|----|------------|--------------------|----|--------|
| US-04 | As the agent, I receive Azure DevOps PR events via webhook so review starts automatically | Service hook → private-key-protected scale-to-zero gateway validates payload fields and enqueues a job on Service Bus; requests without a valid key are rejected | 5 | ⚠️ Gateway deployed and verified; Azure DevOps service hook still needs configuration |
| US-05 | As the agent, I fetch the PR diff and changed files so I know what to scan | Orchestrator (Container Apps Job) pulls the job, calls the Azure DevOps API, retrieves diff + file list; handles large diffs | 5 | ✅ Implemented locally; Azure validation pending |
| US-06 | As a developer, I want Semgrep and secret scanning run on the diff so known issues are flagged | Scanner container runs on changed files; emits normalized findings (rule, file, line, severity) mapped to OWASP | 5 | ✅ Implemented locally; Azure validation pending |

---

### Sprint 2 — Reason & report (Weeks 5–6)

| US | User story | Acceptance criteria | SP | Status |
|----|------------|--------------------|----|--------|
| US-07 | As a security engineer, I want LLM triage of findings so noise is reduced | LLM (Azure OpenAI) takes diff + findings and returns structured output: explanation, priority, likely-false-positive flag; it never overrides deterministic findings | 5 | ✅ Implemented locally; Azure validation pending |
| US-08 | As a developer, I want a summary plus inline comments on my PR so I can fix issues early | Summary comment + inline comments (file/line, severity, fix hint) posted; an advisory (non-blocking) status check is set | 5 | ✅ Implemented locally; Azure validation pending |
| US-09 | As DevOps, I want basic run logs and metrics so I can see it working | App Insights trace per run; success/failure and duration visible; failures raise an alert | 3 | ✅ Implemented locally; Azure validation pending |

**M2 — Wk 6:** Local advisory review is testable; real pilot PR and Azure comments remain pending. **13 SP**

---

## Current control-plane checkpoint — **[DEPLOYED; PILOT DATA PENDING]**

The temporary hackathon deployment now has a scale-to-zero admin gateway at
`/api/admin`, backed by the existing Storage account. It provides:

- review history and manual re-runs (without persisting raw PR content);
- global/repository review controls and cost/token caps;
- versioned `draft` / `active` / `retired` rule packs, applied deterministically by the worker;
- versioned regulation documents with `draft` / `approved` / `retired` states, source blobs, chunks,
  approval-only keyword retrieval, citations, and audit events.

The gateway, admin API, and updated worker image are deployed. Basic route authentication and Azure Storage
persistence are verified. The next acceptance gate is a real Azure DevOps service hook plus one pilot PR;
this must prove Service Bus enqueue, live PR diff retrieval, Semgrep, GPT-5.4 mini triage, and ADO reporting.

### Local verification status — **[COMPLETE]**

The natural-language policy-to-control engine is proven end to end without Azure. 193 tests pass across
`src/orchestrator` (124), `src/webhook-receiver` (28), and `src/prsa_control` (41), covering:

- both example policies (sanctions and cryptocurrency) from pasted text to cited PR findings, each
  compiling to the control types the obligation needs rather than to one shared regex;
- ambiguous obligations held in `needs_clarification` and refused for approval or activation;
- every illegal control-lifecycle transition, approval gates, version retirement, and optimistic concurrency;
- exception scoping, revocation, and automatic expiry restoring the finding;
- semantic-scanner guardrails (confidence floor, ungrounded output dropped, bounded content);
- dependency manifest parsing for all supported ecosystems, plus declared gaps for unsupported ones;
- the developer PR comment format, including policy name, version, source clause, and excerpt.

Remaining before this feature can be called done: the live Azure gate above, and the two open product
decisions on the legacy rule-pack UI and exception value matching (see `docs/policy-engine.md`).

### Azure verification status — 2026-08-08

Verified against `rg-hackathon-groupc-hvn` (subscription `BD-XDV-Learning-Sandbox`):

| Check | Result |
|-------|--------|
| US-02 Azure OpenAI reachable | ✅ `gpt-5.4-mini-2026-03-17` returned structured JSON (33 in / 34 out tokens) |
| Gateway + admin API live | ✅ `ca-prsa-admin-lt56u`, scale-to-zero, cold start under 3 min |
| Policy ingestion (paste) | ✅ `Sanctions and Integration Restrictions` @ `2026-01`, status `ready` |
| LLM control generation | ✅ 2 controls proposed: `literal_value` and `manual_review` |
| Clarification → approval → activation | ✅ audited at 13:17–13:18 with actor and timestamps |
| Active control runs on a PR | ✅ first proven on run `run-552cf6daf3cfb3a0b600a22b` (PR #5) |
| Deterministic control matches | ✅ run `run-2b6b4fa698b5d742e2a83084`: `control-0001` matched `Russia` at `/security-review-fixtures/deployment-region.yaml:4`, ERROR, confidence 0.97 |
| Finding cites policy + excerpt | ✅ policy name, version `2026-01`, paragraph, full excerpt |
| Control versions recorded per review | ✅ `control_snapshot` = 2, `policy_versions` = `control-0002@1.0, control-0001@1.0` |
| Deterministic findings preserved under triage | ✅ 7 Semgrep + 11 secret-scan findings kept; LLM only re-prioritised |
| Exception suppresses a finding | ✅ run `run-0a284e02bcabaa6f50a0efe6`: 19 → 18 findings, 1 suppressed, `exception_id` stamped |
| Exception revocation | ✅ revoked and audited; the finding is reported again on the next run |
| LLM failure degrades safely | ✅ malformed triage payload → `completed_with_triage_error`, all 18 deterministic findings still reported |
| Worker cold-start cost profile | ✅ execution completed in 64 s, then scaled back to zero |

Known gaps after this run:

- Every review before 13:18 ran with no active controls, so `policy_versions` is empty on runs 1–7.
- One dead-lettered message and one failed worker execution (12:55) remain from before the fix.
- GPT-5.4 mini returned a triage payload with no `summary` string on 1 of 2 runs. The parser now keeps
  the model's per-finding priorities instead of discarding them, and still fails closed when nothing
  usable is returned. Deployed as `orchestrator:policy-engine-v5-triage`.
- `review_on_updated` is `false`, so pushing a commit to an open pull request does not re-trigger a
  review. Reviews start on pull-request creation or a manual re-run. This is a deliberate cost control.
- The admin gateway is still protected only by a shared URL key. Microsoft Entra sign-in is wired for
  the production Function App profile but not for the hackathon Container App gateway.

For the later RAG migration, preserve the current citation shape and move only retrieval from keyword matching
to an approved Azure AI Search hybrid/vector index. See `docs/policy-and-rag.md`.

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
