/*
  AI PR Security Review Agent — phase-one infrastructure entry point.
  Scope: the existing resource group selected at deployment time.

  Phase-one defaults are deliberately cost-constrained:
  - Southeast Asia for the Azure runtime resources.
  - East US 2 only for the GPT-5.4 mini Global Standard deployment.
  - Scale-to-zero Functions and Container Apps Job.
*/

targetScope = 'resourceGroup'

@description('Short environment tag: dev | staging | prod')
@allowed(['dev', 'staging', 'prod'])
param env string = 'dev'

@description('Azure region for the runtime resources in the existing resource group')
@allowed(['southeastasia'])
param location string = 'southeastasia'

@description('Supported Global Standard region for the GPT-5.4 mini Azure OpenAI deployment')
@allowed([
  'eastus2'
  'swedencentral'
  'southcentralus'
  'polandcentral'
])
param openaiLocation string = 'eastus2'

@description('Short prefix for resource names (3–8 chars, lowercase alphanumeric)')
@minLength(3)
@maxLength(8)
param prefix string = 'prsa'

@description('Container image tag for the orchestrator job. Use a commit SHA for a reproducible release.')
param imageTag string = 'latest'

@description('Optional email receiver for operational alerts')
param alertEmail string = ''

@description('Deploy Log Analytics alert rules. Disabled for the low-cost development profile.')
param enableOperationalAlerts bool = false

@description('Require Microsoft Entra authentication on admin portal routes. Enable for production.')
param enableAdminEntraAuth bool = false

@description('Client ID of the pre-created Microsoft Entra admin application.')
param adminEntraClientId string = ''

@description('Tenant ID of the Microsoft Entra admin application.')
param adminEntraTenantId string = tenant().tenantId

@description('Maximum Log Analytics ingestion per day in GiB. This is a safety cap, not a normal operating target.')
@minValue(1)
param logAnalyticsDailyCapGb int = 1

@description('Azure OpenAI model for PR triage')
@allowed(['gpt-5.4-mini'])
param openaiModelName string = 'gpt-5.4-mini'

@description('Azure OpenAI model version for PR triage')
param openaiModelVersion string = '2026-03-17'

@description('Azure OpenAI deployment SKU')
@allowed(['GlobalStandard'])
param openaiDeploymentSkuName string = 'GlobalStandard'

@description('Tokens-per-minute capacity requested for the pay-as-you-go Global Standard deployment')
@minValue(1)
param openaiCapacityK int = 120

@description('Largest model input allowed for one PR triage request')
@minValue(1000)
param llmMaxInputTokens int = 100000

@description('Largest model completion, including reasoning, allowed for one PR triage request')
@minValue(1000)
param llmMaxOutputTokens int = 16000

@description('Reasoning effort used by GPT-5.4 mini for security triage')
@allowed(['low', 'medium', 'high'])
param llmReasoningEffort string = 'medium'

@description('Maximum concurrent event-driven job executions')
@minValue(1)
param jobMaxExecutions int = 1

@description('Seconds between queue-scale checks for the event-driven job')
@minValue(30)
param jobPollingIntervalSeconds int = 30

@description('Maximum time allowed for one review job execution')
@minValue(60)
param jobReplicaTimeoutSeconds int = 900

var suffix = '${prefix}-${env}'
var uniqueSuffix = toLower(take(uniqueString(resourceGroup().id), 5))
var acrName = 'acr${prefix}${env}${uniqueSuffix}'
var kvName = 'kv-${suffix}-${uniqueSuffix}'
var sbnName = 'sb-${suffix}-${uniqueSuffix}'
var caEnvName = 'cae-${suffix}-${uniqueSuffix}'
var lawName = 'law-${suffix}-${uniqueSuffix}'
var openaiName = 'oai-${suffix}-${uniqueSuffix}'
var miName = 'mi-${suffix}-${uniqueSuffix}'
var storageName = 'st${prefix}${env}${uniqueSuffix}'
var appInsightsName = 'appi-${suffix}-${uniqueSuffix}'
var functionAppName = 'func-${suffix}-${uniqueSuffix}'
var functionPlanName = 'asp-${suffix}-${uniqueSuffix}'
var containerJobName = 'job-${suffix}-${uniqueSuffix}'

var tags = {
  project: 'ai-pr-security-review-agent'
  env: env
  managedBy: 'bicep'
  costProfile: 'phase1-low-idle-cost'
  costBudget: 'usd-20-50'
}

module managedIdentity 'br/public:avm/res/managed-identity/user-assigned-identity:0.2.2' = {
  name: 'deploy-managed-identity'
  params: {
    name: miName
    location: location
    tags: tags
  }
}

module logAnalytics './modules/log-analytics.bicep' = {
  name: 'deploy-log-analytics'
  params: {
    name: lawName
    location: location
    tags: tags
    dailyQuotaGb: logAnalyticsDailyCapGb
  }
}

module storage './modules/storage.bicep' = {
  name: 'deploy-function-storage'
  params: {
    name: storageName
    location: location
    tags: tags
    blobContributorPrincipalIds: [managedIdentity.outputs.principalId]
    tableContributorPrincipalIds: [managedIdentity.outputs.principalId]
  }
}

module appInsights './modules/app-insights.bicep' = {
  name: 'deploy-app-insights'
  params: {
    name: appInsightsName
    location: location
    tags: tags
    workspaceResourceId: logAnalytics.outputs.resourceId
  }
}

module acr './modules/container-registry.bicep' = {
  name: 'deploy-acr'
  params: {
    name: acrName
    location: location
    tags: tags
    acrPullPrincipalIds: [managedIdentity.outputs.principalId]
  }
}

module kv './modules/key-vault.bicep' = {
  name: 'deploy-kv'
  params: {
    name: kvName
    location: location
    tags: tags
    secretsUserPrincipalIds: [managedIdentity.outputs.principalId]
  }
}

module sb './modules/service-bus.bicep' = {
  name: 'deploy-service-bus'
  params: {
    name: sbnName
    location: location
    tags: tags
    senderPrincipalIds: [managedIdentity.outputs.principalId]
    receiverPrincipalIds: [managedIdentity.outputs.principalId]
  }
}

module caEnv './modules/container-apps.bicep' = {
  name: 'deploy-container-apps-env'
  params: {
    envName: caEnvName
    location: location
    tags: tags
    logAnalyticsCustomerId: logAnalytics.outputs.customerId
    logAnalyticsSharedKey: logAnalytics.outputs.primarySharedKey
  }
}

module functionApp './modules/function-app.bicep' = {
  name: 'deploy-function-app'
  params: {
    name: functionAppName
    planName: functionPlanName
    location: location
    tags: tags
    storageConnectionString: storage.outputs.connectionString
    identityResourceId: managedIdentity.outputs.resourceId
    identityClientId: managedIdentity.outputs.clientId
    serviceBusNamespace: sb.outputs.namespaceName
    serviceBusQueue: sb.outputs.queueName
    appInsightsConnectionString: appInsights.outputs.connectionString
    enableAdminEntraAuth: enableAdminEntraAuth
    adminEntraClientId: adminEntraClientId
    adminEntraTenantId: adminEntraTenantId
  }
}

module openai './modules/openai.bicep' = {
  name: 'deploy-openai'
  params: {
    name: openaiName
    location: openaiLocation
    tags: tags
    modelName: openaiModelName
    modelVersion: openaiModelVersion
    deploymentSkuName: openaiDeploymentSkuName
    capacityK: openaiCapacityK
    openaiUserPrincipalIds: [managedIdentity.outputs.principalId]
  }
}

module orchestratorJob './modules/container-app-job.bicep' = {
  name: 'deploy-orchestrator-job'
  params: {
    name: containerJobName
    location: location
    tags: tags
    environmentId: caEnv.outputs.environmentId
    image: '${acr.outputs.loginServer}/orchestrator:${imageTag}'
    acrLoginServer: acr.outputs.loginServer
    identityResourceId: managedIdentity.outputs.resourceId
    identityClientId: managedIdentity.outputs.clientId
    serviceBusNamespace: sb.outputs.namespaceName
    serviceBusQueue: sb.outputs.queueName
    storageAccountName: storage.outputs.name
    keyVaultUri: kv.outputs.uri
    appInsightsConnectionString: appInsights.outputs.connectionString
    openaiEndpoint: openai.outputs.endpoint
    openaiDeploymentName: openai.outputs.deploymentName
    llmMaxInputTokens: llmMaxInputTokens
    llmMaxOutputTokens: llmMaxOutputTokens
    llmReasoningEffort: llmReasoningEffort
    maxExecutions: jobMaxExecutions
    pollingIntervalSeconds: jobPollingIntervalSeconds
    replicaTimeoutSeconds: jobReplicaTimeoutSeconds
  }
}

module monitoring './modules/monitoring.bicep' = if (enableOperationalAlerts) {
  name: 'deploy-monitoring'
  params: {
    namePrefix: 'mon-${suffix}-${uniqueSuffix}'
    location: location
    tags: tags
    workspaceResourceId: logAnalytics.outputs.resourceId
    serviceBusResourceId: sb.outputs.resourceId
    alertEmail: alertEmail
  }
}

output resourceGroupName string = resourceGroup().name
output runtimeLocation string = location
output azureOpenaiLocation string = openaiLocation
output acrLoginServer string = acr.outputs.loginServer
output keyVaultUri string = kv.outputs.uri
output serviceBusEndpoint string = sb.outputs.endpoint
output serviceBusQueueName string = sb.outputs.queueName
output containerAppsEnvId string = caEnv.outputs.environmentId
output openaiEndpoint string = openai.outputs.endpoint
output openaiDeploymentName string = openai.outputs.deploymentName
output managedIdentityClientId string = managedIdentity.outputs.clientId
output managedIdentityPrincipalId string = managedIdentity.outputs.principalId
output functionAppName string = functionApp.outputs.name
output functionAppHostName string = functionApp.outputs.defaultHostName
output orchestratorJobName string = orchestratorJob.outputs.name
output appInsightsResourceId string = appInsights.outputs.resourceId
