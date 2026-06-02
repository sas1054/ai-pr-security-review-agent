using './main.bicep'

// ── Dev environment defaults ──────────────────────────────────────────────────
// Override for staging/prod:
//   az deployment sub create ... --parameters env=prod prefix=prsa location=eastus

param env      = 'dev'
param location = 'eastus'   // Must be an Azure OpenAI-approved region
param prefix   = 'prsa'     // Change to your org prefix (3–8 chars, lowercase alphanumeric)
