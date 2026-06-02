# Runbook — AI PR Security Review Agent

## Re-deploying from scratch

```bash
az login
az deployment sub create \
  --location eastus \
  --template-file infra/main.bicep \
  --parameters infra/main.bicepparam
```

A successful deploy prints all output values (ACR login server, Key Vault URI, etc.).

## Storing secrets in Key Vault

```bash
RG=rg-prsa-dev
KV=kv-prsa-dev

az keyvault secret set --vault-name $KV --name ado-webhook-secret --value "<your-hmac-secret>"
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

## Running tests locally

```bash
cd src/webhook-receiver
pip install -r requirements.txt pytest
pytest test_app.py -v
```

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
| Webhook 401 | Wrong HMAC secret in ADO service hook | Re-generate secret, update KV + ADO |
| Service Bus dead-letter growing | Orchestrator container not running | Check Container Apps revision status |
| OpenAI 429 | Token quota exceeded | Reduce `capacityK` or add retry with backoff |
