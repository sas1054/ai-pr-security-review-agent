# Runbook — AI PR Security Review Agent

## Natural-language policy operations

Use the admin portal's **Policies** page to queue extraction and control generation. A queued policy uses the same Service Bus queue as PR reviews with `job_kind=policy_ingestion`; the worker dispatches it independently and records progress in `PolicyIngestionJobs`. Do not retry by overwriting a document version. Correct metadata or content by creating a new policy version.

Before production rollout, deploy `infra/main.bicep` with `enableAdminEntraAuth=true` and the pre-created admin application's client and tenant IDs. Assign the `Policy.Author`, `Policy.Approver`, `Policy.Activator`, and `Exception.Approver` app roles documented in [policy-engine.md](policy-engine.md). Confirm `ADMIN_REQUIRE_ENTRA=true` in the Function App configuration.

When ingestion fails, check the job's `errors`, then verify document type/size, PDF text extraction, public-HTTPS URL restrictions, Azure OpenAI configuration, and generated citation/test validation. A failure or coverage gap must not be interpreted as compliance. Suspended and retired controls do not scan new PRs; historical review snapshots and detector hashes remain available.

## Re-deploying from scratch

```bash
az login
az deployment group create \
  --resource-group rg-hackathon-groupc-hvn \
  --template-file infra/main.bicep \
  --parameters infra/main.bicepparam
```

A successful deploy prints all output values (ACR login server, Key Vault URI, etc.).

## Hackathon deployment without role-assignment permission

Use this only for the short-lived pilot when the subscription cannot grant
`Microsoft.Authorization/roleAssignments/write`. It does not change a central pipeline and does not
require Key Vault or managed-identity roles.

1. Create an Azure DevOps PAT with the minimum **Code (Read & write)** scope for the pilot repository.
2. In the PowerShell session used for deployment only, set the value. Do not put it in a file or
   commit it:

```powershell
$env:PRSA_ADO_PAT = '<Azure-DevOps-PAT>'
```

3. Deploy the low-cost foundation first; the worker is disabled until its container image exists:

```powershell
az deployment group create `
  --resource-group rg-hackathon-groupc-hvn `
  --template-file infra/hackathon.bicep `
  --parameters infra/hackathon.bicepparam `
  --parameters deployWorkerJob=false
```

This profile uses Basic ACR and Basic queue-only Service Bus, a scale-to-zero gateway and worker,
disabled Container Apps log ingestion, a one-day queue TTL, and one model call only for a
newly-created PR that has deterministic findings. Its ADO PAT, temporary gateway URL key, Azure OpenAI key,
Service Bus key, and ACR admin credential are temporary deployment secrets. Delete the resource group after the
hackathon or migrate to the managed-identity profile before any production use.

The worker uses structured logs only in this profile to keep its Semgrep dependency compatible and avoid
additional telemetry ingestion. Application Insights remains enabled for the Function App.

After the foundation and image are deployed, run the following command in an interactive PowerShell.
It prompts for the PAT without writing it to disk, updates the worker, and prints the exact private
gateway service-hook URL:

```powershell
.\scripts\configure-hackathon-secrets.ps1
```

To show those private URLs later without re-entering the PAT, run:

```powershell
.\scripts\show-hackathon-urls.ps1
```

Create the Azure DevOps subscription only after the script prints its URL:

1. In the pilot project, open **Project settings** → **Service hooks** → **Create subscription**.
2. Select **Web Hooks** and the **Pull request created** event.
3. Paste the complete private URL printed by the script, including `?code=...`.
4. Leave Basic Authentication empty, select the pilot repository when a filter is offered, then test and save.

The private URL key is the webhook credential. Do not paste the URL into tickets, chat, source control, or
public documentation. Rotate it by regenerating the linked Function host key, updating the gateway secret,
and updating the service-hook URL.

## Admin control portal

The same helper prints a second private URL for `/api/admin`. It gives the hackathon administrator a
simple portal for review history, manual re-runs, repository controls, rule packs, regulation documents,
and scan/token settings. It uses the existing Container Apps environment and Storage account with zero
minimum replicas, so it has no always-on compute cost.

The Function key is appropriate only for the short-lived, single-admin pilot. Before onboarding other
users, move the portal to Microsoft Entra authentication and give admin identities a dedicated role.

## Storing secrets in Key Vault

```bash
RG=rg-hackathon-groupc-hvn
# Read this value from the successful deployment output: keyVaultUri.
KV=<deployed-key-vault-name>

az keyvault secret set --vault-name $KV --name ado-pat           --value "<your-ado-pat>"
```

## Configuring the GitHub Actions OIDC trust

1. Create an App Registration in Entra ID.
2. Add a federated credential: `repo:sas1054/ai-pr-security-review-agent:ref:refs/heads/main`
3. Assign `Contributor` on the subscription (or scoped to the resource group).
4. Add these GitHub secrets/variables to the repo:
   - `AZURE_CLIENT_ID` — app registration client ID
   - `AZURE_TENANT_ID` — your tenant ID
   - `AZURE_SUBSCRIPTION_ID` — your subscription ID
   - `ACR_LOGIN_SERVER` (variable) — e.g. `acrprsadev.azurecr.io`
   - `ALERT_EMAIL` (variable, optional) — notification recipient for Azure Monitor alerts

## Running tests locally

```bash
cd src/webhook-receiver
pip install -r requirements-dev.txt
pytest -v

cd ../orchestrator
pip install -r requirements-dev.txt
pytest -v

cd ../prsa_control
PYTHONPATH=../ pytest -v
```

`conftest.py` puts `src/` on the path, so `pytest` works from `src/orchestrator` and
`src/webhook-receiver` without extra setup. The fixture runner is a plain script, so it still needs
the path exported:

```bash
cd src/orchestrator
PYTHONPATH=.. python orchestrator.py --fixture fixtures/local_job.json
```

The fixture runner uses fake ADO and Semgrep adapters, so it does not need Azure credentials.
`test_policy_demo_scenarios.py` runs the two example policies (sanctions and cryptocurrency) from
natural-language text through control generation to cited PR findings, also without Azure.

## Deploying the application

1. Configure the GitHub OIDC secrets, the `ACR_LOGIN_SERVER` repository variable, and optionally
   `AZURE_RESOURCE_GROUP` (defaults to `rg-hackathon-groupc-hvn`).
2. Leave runtime resources in Southeast Asia. The phase-one GPT-5.4 mini Global Standard deployment
   uses East US 2 by default; override only with another supported Global Standard region.
3. Optionally set the `alertEmail` deployment parameter for worker and dead-letter notifications.
4. Merge to `main` to build and push the orchestrator image to ACR.
5. Run **Deploy Infrastructure** manually for the target environment.
6. The workflow deploys the worker and scale-to-zero gateway images after Bicep completes.
7. Set the `ado-pat` Key Vault secret before creating the ADO service hook. Use the private gateway endpoint
   URL printed by the helper script.

## Phase-one cost controls

- The gateway and Container Apps Job scale to zero when idle; no always-ready instances are configured.
- GPT-5.4 mini uses Azure OpenAI Global Standard in East US 2, with a 100,000-token input cap and
  8,000-token completion cap per review. Only reviews with deterministic findings call the model.
- The Container Apps Job allows one concurrent execution and polls the queue every 60 seconds.
- Log Analytics is capped at 1 GiB/day as an emergency guard; normal development ingestion should be
  far below the 5 GiB/month free allowance.
- Set `ENABLE_COST_BUDGET=true` and `AZURE_MONTHLY_BUDGET=25` GitHub variables to deploy the
  resource-group-filtered Cost Management budget. The numeric amount uses the subscription billing
  currency; it notifies at 50%, 80%, and forecasted 100%, but does not automatically stop resources.

Webhook authentication is fail-closed at the gateway. It rejects a request without the configured
private URL key. Azure DevOps Web Hooks do not provide native HMAC signatures, so the private URL key
is the temporary hackathon credential for this endpoint.

## Azure pilot acceptance checklist

- [ ] `az deployment group what-if --resource-group rg-hackathon-groupc-hvn` reports no unexpected deletes.
- [ ] Gateway responds to `POST /api/webhook` with `401` when the private URL key is missing or invalid.
- [ ] A valid Azure DevOps PR event creates one Service Bus message.
- [ ] The Container Apps job completes the message only after ADO reporting succeeds.
- [ ] The PR receives one summary thread, inline comments for positioned findings, and an advisory status.
- [ ] Re-delivering the same PR iteration does not duplicate review threads.
- [ ] Application Insights contains the same `run_id` across the run.
- [ ] A failed run is abandoned and appears in the Service Bus dead-letter path after repeated delivery.

## Checking App Insights traces

In the Azure portal → your Log Analytics workspace → Logs:

```kusto
traces
| where timestamp > ago(1h)
| order by timestamp desc
```

## Alert triage

| Alert | Likely cause | Fix |
|-------|-------------|-----|
| Webhook 401 | Missing, invalid, or rotated private URL key in the service-hook URL | Re-run the helper script and update the full gateway URL in the ADO service hook |
| Service Bus dead-letter growing | Orchestrator container not running | Check Container Apps revision status |
| OpenAI 429 | Token quota exceeded | Reduce `capacityK` or add retry with backoff |
| No inline comments | ADO PAT or repository path is invalid | Check `ado-pat`, project/repository IDs, and worker logs |
