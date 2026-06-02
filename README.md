# AI PR Security Review Agent

An automated security review agent for Azure DevOps pull requests. When a PR is opened, the agent runs static analysis (Semgrep, CodeQL, Trivy), performs LLM-based triage via Azure OpenAI, and posts inline advisory comments — all without blocking the developer workflow.

## Architecture

```
Azure DevOps PR → Service Hook → Azure Functions (webhook receiver)
                                        ↓
                                  Service Bus
                                        ↓
                             Container Apps (orchestrator)
                             ├── Semgrep (diff scan)
                             ├── Secret scan
                             └── Azure OpenAI (triage)
                                        ↓
                             PR summary + inline comments (advisory)
```

**Azure PaaS plumbing:** Functions · Service Bus · Container Apps + KEDA · Cosmos DB · PostgreSQL/pgvector · Redis · Key Vault · App Configuration · Entra ID · App Insights · ACR · Azure OpenAI

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

### 1. Deploy infrastructure

```bash
az login
az deployment sub create \
  --location eastus \
  --template-file infra/main.bicep \
  --parameters infra/main.bicepparam
```

### 2. Build and push the webhook receiver

```bash
cd src/webhook-receiver
docker build -t webhook-receiver .
# Or let CI push to ACR on merge to main
```

### 3. Configure the Azure DevOps service hook

In your Azure DevOps project → **Project Settings → Service hooks → Create subscription**:
- Service: **Web Hooks**
- Trigger: **Pull request created** (+ updated)
- URL: `https://<functions-app>.azurewebsites.net/api/webhook`
- Basic auth / HMAC secret: stored in Key Vault as `ado-webhook-secret`

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
  webhook-receiver/       # Azure Functions app (webhook + Service Bus enqueue)
    Dockerfile
    app.py
.github/
  workflows/
    build-push.yml        # CI: build image, push to ACR (OIDC, no secrets)
    deploy-infra.yml      # CD: deploy Bicep on infra/ changes
```

## Secrets management

All secrets are stored in **Azure Key Vault**. No credentials are hard-coded.

| Secret name | Description |
|-------------|-------------|
| `ado-webhook-secret` | HMAC shared secret for ADO service hook validation |
| `ado-pat` | Azure DevOps PAT for reading diffs and posting comments |
| `openai-key` | Fallback key (managed identity is preferred) |

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
