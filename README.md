# AI PR Security Review Agent

An automated security review agent for Azure DevOps pull requests. When a PR is opened, the agent runs static analysis (Semgrep, CodeQL, Trivy), performs LLM-based triage via Azure OpenAI, and posts inline advisory comments — all without blocking the developer workflow.

## Architecture

```
Azure DevOps PR → Service Hook → Container Apps gateway (scale-to-zero)
                                        ↓
                                  Service Bus
                                        ↓
                                  Container Apps Job (orchestrator)
                             ├── Semgrep (diff scan)
                             ├── Secret scan
                             └── Azure OpenAI (triage)
                                        ↓
                             PR summary + inline comments (advisory)
```

**Azure PaaS plumbing:** Container Apps gateway + Jobs · Service Bus · Key Vault · Entra ID · App Insights · ACR · Azure OpenAI

**Portable containers:** Semgrep · CodeQL · Trivy · orchestration & LLM-reasoning logic (OCI images, runnable on self-hosted runners)

## Phases

| Phase | Weeks | Goal |
|-------|-------|------|
| P0 Foundation | 1–2 | IaC, ACR, Key Vault, OpenAI access |
| P1 MVP | 3–6 | Webhook → scan → LLM triage → advisory PR comments |
| P2 Depth | 7–10 | CodeQL + Trivy + RAG over OWASP baseline + findings store |
| P3 Policy & rollout | 11–14 | Per-service gating, dashboard, CD-09000 evidence, 3–5 teams |
| P4 Scale | 15+ | GitHub adapter, auto fix-suggestions, org-wide |

## Quick Start (local development)

### Prerequisites

- Azure CLI ≥ 2.55, Bicep CLI
- Docker Desktop
- Python 3.11+
- Azure subscription with Owner/Contributor access

Run the deterministic local fixture first:

```bash
docker compose up --build --abort-on-container-exit orchestrator
```

This exercises the job contract and secret scanner without Azure credentials. The real Azure pilot is
the acceptance gate for Service Bus, Azure DevOps, Azure OpenAI, and PR comment delivery.

For the local admin UI, start the gateway and open
`http://localhost:8000/api/admin?code=local-admin`. The `local-admin` key exists only in
`docker-compose.yml`; never use it outside local development.

### Admin control portal

The scale-to-zero Container Apps gateway exposes a clean, low-cost control portal at `/api/admin`.
The deployed portal uses single-tenant Microsoft Entra login and app-role assignment; the Azure DevOps
webhook continues to use its separate private URL key. Use the clean portal URL printed by
`configure-hackathon-secrets.ps1` or `show-hackathon-urls.ps1`. The portal persists
its data in the existing Storage account and lets an admin view review history, queue a re-run, enable or disable a
repository, adjust scan/token limits, create versioned simple rules, and store approved regulation text.

Approved regulations are chunked and searchable today using keyword retrieval. The stored document,
version, effective date, owner, tags, and chunk identifiers are deliberately shaped for a later Azure AI
Search hybrid/vector RAG index. The key-only portal mode remains available only for local development.

See [the policy and RAG design](docs/policy-and-rag.md) for the live data model,
approval rules, and the planned Azure AI Search migration path.

### Natural-language policies

The portal now provides a governed **Policies → Controls → Exceptions** workflow. Security administrators can paste business-language requirements, upload PDF/DOCX/TXT documents, or ingest a public HTTPS document. The worker preserves source clauses, uses Azure OpenAI to propose typed controls, verifies citations, maps every obligation to declared PR scan surfaces, runs generated positive and negative tests, and requires separate approval and activation before a control can scan a PR. Missing adapters, uncovered obligations, and detector vocabulary absent from the policy fail into visible clarification or partial coverage instead of being treated as compliance. Developers see the policy title, version, clause, exact statement, reason, and suggested action rather than regex or Semgrep implementation details.

Policy administration supports Microsoft Entra app roles; the existing key-only mode remains for local development. See [the policy-engine guide](docs/policy-engine.md) for lifecycle, API, scanner coverage, identity, URL safety, and operational details.

### 1. Deploy infrastructure

```bash
az login
az deployment group create \
  --resource-group rg-hackathon-groupc-hvn \
  --template-file infra/main.bicep \
  --parameters infra/main.bicepparam
```

### 2. Build and publish the orchestrator

```bash
cd src/orchestrator
docker build -t orchestrator .
# CI pushes the orchestrator image to ACR on merge to main.
# CI also publishes the scale-to-zero webhook/admin gateway image.
```

The phase-one defaults keep the gateway and Container Apps Job in **Southeast Asia**, with no
always-on instances. GPT-5.4 mini is deployed as Azure OpenAI Global Standard in **East US 2**;
it remains part of the same resource group but processes triage through that supported model region.

The default review budget is up to 100,000 input tokens and 8,000 completion tokens. It is invoked
only when deterministic scanners find something. Configure a Cost Management budget before the pilot.

### Hackathon deployment profile

`infra/hackathon.bicep` is the temporary low-cost profile for subscriptions where the team cannot grant
role-assignment permission or modify a central deployment pipeline. It uses a Container Apps gateway
and event-driven job with zero idle replicas, Basic ACR, and Basic queue-only Service Bus. The job is
disabled until an image has been pushed, and updated-PR events are ignored to avoid repeat model cost.
Worker telemetry uses structured logs in this profile; Application Insights remains enabled for the
Function App without adding the incompatible worker telemetry dependency.

It uses limited keys instead of managed identity: an ADO PAT, a Function-host-key-derived gateway key,
a Service Bus send/listen key, an Azure OpenAI key, and the temporary ACR admin credential. Only the ADO PAT must
be supplied locally; the helper reuses the Function host key as the gateway access key and the deployment creates the
other scoped credentials. Do not commit the PAT or the private webhook URL. See the hackathon
procedure in the runbook.

### 3. Configure the Azure DevOps service hook

In your Azure DevOps project → **Project Settings → Service hooks → Create subscription**:
- Service: **Web Hooks**
- Trigger: **Pull request created** (the hackathon profile intentionally ignores updates to limit cost)
- URL: the complete gateway URL printed by `configure-hackathon-secrets.ps1`, such as
  `https://<gateway>.southeastasia.azurecontainerapps.io/api/webhook?code=<private-key>`
- Authentication: private URL key; do not configure Basic Authentication

## Repository structure

```
infra/
  main.bicep              # Entry point — deploys all modules
  main.bicepparam         # Environment parameters
  modules/
    container-registry.bicep
    container-apps.bicep
    service-bus.bicep
    key-vault.bicep
    openai.bicep
src/
  webhook-receiver/       # Webhook/admin gateway (Functions-compatible handlers + Container App)
    host.json
    app.py
    function_app.py
  orchestrator/            # Container Apps event-driven job
    ado_client.py
    scanner.py
    triage.py
    reporter.py
.github/
  workflows/
    build-push.yml        # CI: build/push orchestrator image to ACR
    deploy-infra.yml      # CD: deploy Bicep + Function App source
```

## Secrets management

The production PAT is stored in **Azure Key Vault**. The temporary hackathon gateway uses one
private URL key for both the webhook and portal. No credentials are hard-coded.

| Secret name | Description |
|-------------|-------------|
| `ado-pat` | Azure DevOps PAT for reading diffs and posting comments |

Azure OpenAI uses the Container Apps/Function managed identity; no production API key is required.

The production profile above is deliberately different from the temporary hackathon profile. The
hackathon profile must be deleted or migrated to managed identity once the event is complete.

The Container Apps managed identity is granted:
- `Key Vault Secrets User` on Key Vault
- `AcrPull` on ACR
- `Cognitive Services OpenAI User` on the OpenAI account
- `Azure Service Bus Data Receiver/Sender` on the Service Bus namespace

## Definition of Done (every user story)

- Code reviewed and merged; runs in the deployed environment, not just locally
- Secrets via Key Vault / managed identity — no hard-coded credentials
- A basic test or a demonstrable end-to-end run; trace visible in App Insights
- A short note in this README / runbook on how to operate or re-run it

## Runbook

See [docs/runbook.md](docs/runbook.md) for operational procedures, re-deployment steps, and alert triage.
