/*
  AI PR Security Review Agent — main infrastructure entry point
  Scope: subscription (creates resource group + all resources)
  Usage:
    az deployment sub create \
      --location eastus \
      --template-file infra/main.bicep \
      --parameters infra/main.bicepparam
*/

targetScope = 'subscription'

// ── Parameters ──────────────────────────────────────────────────────────────

@description('Short environment tag: dev | staging | prod')
@allowed(['dev', 'staging', 'prod'])
param env string = 'dev'

@description('Azure region for all resources')
param location string = 'eastus'

@description('Short prefix for resource names (3–8 chars, lowercase alphanumeric)')
@minLength(3)
@maxLength(8)
param prefix string = 'prsa'

// ── Resource naming ──────────────────────────────────────────────────────────

var suffix    = '${prefix}-${env}'
var rgName    = 'rg-${suffix}'
var acrName   = replace('acr${prefix}${env}', '-', '')  // ACR names: alphanumeric only
var kvName    = 'kv-${suffix}'
var sbnName   = 'sb-${suffix}'
var caEnvName = 'cae-${suffix}'
var lawName   = 'law-${suffix}'
var openaiName = 'oai-${suffix}'
var miName    = 'mi-${suffix}'

var tags = {
  project: 'ai-pr-security-review-agent'
  env: env
  managedBy: 'bicep'
}

// ── Resource Group ───────────────────────────────────────────────────────────

resource rg 'Microsoft.Resources/resourceGroups@2023-07-01' = {
  name: rgName
  location: location
  tags: tags
}

// ── User-assigned Managed Identity ──────────────────────────────────────────

module managedIdentity 'br/public:avm/res/managed-identity/user-assigned-identity:0.2.2' = {
  name: 'deploy-managed-identity'
  scope: rg
  params: {
    name: miName
    location: location
    tags: tags
  }
}

// ── Log Analytics (for Container Apps + App Insights) ────────────────────────

module logAnalytics 'br/public:avm/res/operational-insights/workspace:0.3.4' = {
  name: 'deploy-log-analytics'
  scope: rg
  params: {
    name: lawName
    location: location
    tags: tags
    skuName: 'PerGB2018'
    retentionInDays: 30
  }
}

// ── Azure Container Registry ─────────────────────────────────────────────────

module acr './modules/container-registry.bicep' = {
  name: 'deploy-acr'
  scope: rg
  params: {
    name: acrName
    location: location
    tags: tags
    acrPullPrincipalIds: [managedIdentity.outputs.principalId]
  }
}

// ── Key Vault ────────────────────────────────────────────────────────────────

module kv './modules/key-vault.bicep' = {
  name: 'deploy-kv'
  scope: rg
  params: {
    name: kvName
    location: location
    tags: tags
    secretsUserPrincipalIds: [managedIdentity.outputs.principalId]
  }
}

// ── Service Bus ───────────────────────────────────────────────────────────────

module sb './modules/service-bus.bicep' = {
  name: 'deploy-service-bus'
  scope: rg
  params: {
    name: sbnName
    location: location
    tags: tags
    senderPrincipalIds: [managedIdentity.outputs.principalId]
    receiverPrincipalIds: [managedIdentity.outputs.principalId]
  }
}

// ── Container Apps Environment ────────────────────────────────────────────────

module caEnv './modules/container-apps.bicep' = {
  name: 'deploy-container-apps-env'
  scope: rg
  params: {
    envName: caEnvName
    location: location
    tags: tags
    logAnalyticsWorkspaceId: logAnalytics.outputs.resourceId
    logAnalyticsCustomerId: logAnalytics.outputs.logAnalyticsWorkspaceId
    logAnalyticsSharedKey: logAnalytics.outputs.primarySharedKey
  }
}

// ── Azure OpenAI ──────────────────────────────────────────────────────────────

module openai './modules/openai.bicep' = {
  name: 'deploy-openai'
  scope: rg
  params: {
    name: openaiName
    location: location  // ensure the region supports Azure OpenAI
    tags: tags
    openaiUserPrincipalIds: [managedIdentity.outputs.principalId]
  }
}

// ── Outputs ───────────────────────────────────────────────────────────────────

output resourceGroupName string = rg.name
output acrLoginServer string = acr.outputs.loginServer
output keyVaultUri string = kv.outputs.uri
output serviceBusEndpoint string = sb.outputs.endpoint
output serviceBusQueueName string = sb.outputs.queueName
output containerAppsEnvId string = caEnv.outputs.environmentId
output openaiEndpoint string = openai.outputs.endpoint
output openaiDeploymentName string = openai.outputs.deploymentName
output managedIdentityClientId string = managedIdentity.outputs.clientId
output managedIdentityPrincipalId string = managedIdentity.outputs.principalId
