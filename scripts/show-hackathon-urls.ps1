[CmdletBinding()]
param(
    [string]$ResourceGroup = 'rg-hackathon-groupc-hvn',
    [string]$FunctionApp = 'func-prsa-dev-lt56u',
    [string]$GatewayApp = 'ca-prsa-admin-lt56u',
    [string]$ExpectedSubscriptionId = '867cdad6-e31e-43db-94a0-ea0457112ddc'
)

$ErrorActionPreference = 'Stop'

$subscriptionId = (& az account show --query id --output tsv).Trim()
if ($subscriptionId -ne $ExpectedSubscriptionId) {
    throw "Azure CLI is set to subscription '$subscriptionId', expected '$ExpectedSubscriptionId'."
}

$accessKey = (& az functionapp keys list `
    --resource-group $ResourceGroup `
    --name $FunctionApp `
    --query 'functionKeys.default' `
    --output tsv).Trim()
$gatewayHost = (& az containerapp show `
    --resource-group $ResourceGroup `
    --name $GatewayApp `
    --query 'properties.configuration.ingress.fqdn' `
    --output tsv).Trim()
$entraRequired = (& az containerapp show `
    --resource-group $ResourceGroup `
    --name $GatewayApp `
    --query "properties.template.containers[0].env[?name=='ADMIN_REQUIRE_ENTRA'].value | [0]" `
    --output tsv).Trim() -eq 'true'

if ([string]::IsNullOrWhiteSpace($accessKey) -or [string]::IsNullOrWhiteSpace($gatewayHost)) {
    throw 'Could not read the private gateway access details.'
}

$code = [Uri]::EscapeDataString($accessKey)
Write-Host 'Keep these URLs private:'
if ($entraRequired) {
    Write-Host "  Admin portal: https://$gatewayHost/api/admin (Microsoft Entra login)"
} else {
    Write-Host "  Admin portal: https://$gatewayHost/api/admin?code=$code"
}
Write-Host "  ADO webhook:  https://$gatewayHost/api/webhook?code=$code"
