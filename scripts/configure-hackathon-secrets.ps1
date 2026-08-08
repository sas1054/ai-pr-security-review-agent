[CmdletBinding()]
param(
    [string]$ResourceGroup = 'rg-hackathon-groupc-hvn',
    [string]$FunctionApp = 'func-prsa-dev-lt56u',
    [string]$ContainerJob = 'job-prsa-dev-lt56u',
    [string]$GatewayApp = 'ca-prsa-admin-lt56u',
    [string]$ExpectedSubscriptionId = '867cdad6-e31e-43db-94a0-ea0457112ddc'
)

$ErrorActionPreference = 'Stop'

function ConvertFrom-SecureStringInMemory {
    param([Parameter(Mandatory)][securestring]$Value)

    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Value)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

$subscriptionId = (& az account show --query id --output tsv).Trim()
if ($subscriptionId -ne $ExpectedSubscriptionId) {
    throw "Azure CLI is set to subscription '$subscriptionId', expected '$ExpectedSubscriptionId'."
}

Write-Host 'Enter the short-lived Azure DevOps PAT. It is used only in this process and is not written to disk.'
$adoPat = ConvertFrom-SecureStringInMemory (Read-Host 'Azure DevOps PAT (Code Read & write)' -AsSecureString)

if ([string]::IsNullOrWhiteSpace($adoPat)) {
    throw 'An Azure DevOps PAT is required.'
}

& az containerapp job secret set `
    --resource-group $ResourceGroup `
    --name $ContainerJob `
    --secrets ('ado-pat=' + $adoPat) `
    --output none
if ($LASTEXITCODE -ne 0) { throw 'Could not update the Container Apps Job ADO PAT.' }

$webhookKey = (& az functionapp keys list `
    --resource-group $ResourceGroup `
    --name $FunctionApp `
    --query 'functionKeys.default' `
    --output tsv).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($webhookKey)) {
    throw 'Could not read the Function App host key needed for the Azure DevOps webhook URL.'
}
$encodedWebhookKey = [Uri]::EscapeDataString($webhookKey)
$gatewayHost = (& az containerapp show `
    --resource-group $ResourceGroup `
    --name $GatewayApp `
    --query 'properties.configuration.ingress.fqdn' `
    --output tsv).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($gatewayHost)) {
    throw 'Could not read the public gateway hostname.'
}

& az containerapp secret set `
    --resource-group $ResourceGroup `
    --name $GatewayApp `
    --secrets ('admin-access-key=' + $webhookKey) `
    --output none
if ($LASTEXITCODE -ne 0) { throw 'Could not update the gateway access key.' }
& az containerapp update `
    --resource-group $ResourceGroup `
    --name $GatewayApp `
    --set-env-vars 'ADMIN_ACCESS_KEY=secretref:admin-access-key' `
    --output none
if ($LASTEXITCODE -ne 0) { throw 'Could not roll the gateway onto the updated access key.' }

Remove-Variable adoPat -ErrorAction SilentlyContinue

Write-Host ''
Write-Host 'PAT updated. Create an Azure DevOps Web Hook subscription:'
Write-Host "  URL: https://$gatewayHost/api/webhook?code=$encodedWebhookKey"
Write-Host '  Trigger: Pull request created'
Write-Host '  Authentication: the private URL key; do not add Basic Authentication.'
Write-Host ''
Write-Host 'Admin control portal (keep this URL private):'
Write-Host "  https://$gatewayHost/api/admin?code=$encodedWebhookKey"
Write-Host 'The worker remains scale-to-zero until that hook sends a valid PR event.'
