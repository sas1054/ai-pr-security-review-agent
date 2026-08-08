/*
  Temporary hackathon profile.
  It intentionally uses limited service keys because the current subscription does not permit
  Microsoft.Authorization/roleAssignments/write. Do not use this profile for production.
*/

targetScope = 'resourceGroup'

@description('Azure region for runtime resources in the existing resource group')
@allowed(['southeastasia'])
param location string = 'southeastasia'

@description('Supported Global Standard region for GPT-5.4 mini')
@allowed(['eastus2'])
param openaiLocation string = 'eastus2'

@description('Short environment tag')
@allowed(['dev'])
param env string = 'dev'

@description('Short lowercase resource-name prefix')
@minLength(3)
@maxLength(8)
param prefix string = 'prsa'

@description('Container image tag. Deploy the worker only after this image has been pushed to ACR.')
param imageTag string = 'latest'

@description('Deploy the queue-triggered worker. Keep false until the image is in ACR.')
param deployWorkerJob bool = false

@description('Deploy the external webhook and admin gateway after its image and temporary access key are available.')
param deployGateway bool = false

@description('Container image tag for the webhook and admin gateway.')
param gatewayImageTag string = 'latest'

@secure()
@description('Temporary shared access key for Azure DevOps Web Hooks and the admin portal.')
param gatewayAccessKey string = ''

@secure()
@description('Azure DevOps PAT used only by the worker to read and report on pull requests')
param adoPat string

@description('Tokens-per-minute capacity requested for pay-as-you-go GPT-5.4 mini')
@minValue(1)
param openaiCapacityK int = 120

@description('Maximum model input tokens for one PR')
@minValue(1000)
param llmMaxInputTokens int = 100000

@description('Maximum model completion tokens for one PR')
@minValue(1000)
param llmMaxOutputTokens int = 8000

@description('GPT-5.4 mini reasoning effort')
@allowed(['low', 'medium', 'high'])
param llmReasoningEffort string = 'medium'

@description('Maximum simultaneous worker executions')
@minValue(1)
param jobMaxExecutions int = 1

@description('Seconds between Service Bus scale checks')
@minValue(30)
param jobPollingIntervalSeconds int = 30

@description('Maximum seconds for one PR review worker execution')
@minValue(60)
param jobReplicaTimeoutSeconds int = 900

@description('Daily Log Analytics cap in GiB. It is retained only for Function telemetry.')
@minValue(1)
param logAnalyticsDailyCapGb int = 1

var suffix = '${prefix}-${env}'
var uniqueSuffix = toLower(take(uniqueString(resourceGroup().id), 5))
var acrName = 'acr${prefix}${env}${uniqueSuffix}'
var sbnName = 'sb-${suffix}-${uniqueSuffix}'
var caEnvName = 'cae-${suffix}-${uniqueSuffix}'
var lawName = 'law-${suffix}-${uniqueSuffix}'
var openaiName = 'oai-${suffix}-${uniqueSuffix}'
var storageName = 'st${prefix}${env}${uniqueSuffix}'
var appInsightsName = 'appi-${suffix}-${uniqueSuffix}'
var functionAppName = 'func-${suffix}-${uniqueSuffix}'
var functionPlanName = 'asp-${suffix}-${uniqueSuffix}'
var containerJobName = 'job-${suffix}-${uniqueSuffix}'
var gatewayName = 'ca-${prefix}-admin-${uniqueSuffix}'

var tags = {
  project: 'ai-pr-security-review-agent'
  env: env
  managedBy: 'bicep'
  deploymentProfile: 'hackathon-short-lived'
  costProfile: 'lowest-idle-cost'
  cleanupRequired: 'true'
}

module logAnalytics './modules/log-analytics.bicep' = {
  name: 'hackathon-log-analytics'
  params: {
    name: lawName
    location: location
    tags: tags
    dailyQuotaGb: logAnalyticsDailyCapGb
  }
}

module storage './modules/storage.bicep' = {
  name: 'hackathon-function-storage'
  params: {
    name: storageName
    location: location
    tags: tags
  }
}

module appInsights './modules/app-insights.bicep' = {
  name: 'hackathon-app-insights'
  params: {
    name: appInsightsName
    location: location
    tags: tags
    workspaceResourceId: logAnalytics.outputs.resourceId
  }
}

module acr './modules/container-registry-hackathon.bicep' = {
  name: 'hackathon-acr'
  params: {
    name: acrName
    location: location
    tags: tags
  }
}

module serviceBus './modules/service-bus-hackathon.bicep' = {
  name: 'hackathon-service-bus'
  params: {
    name: sbnName
    location: location
    tags: tags
  }
}

module caEnv './modules/container-apps.bicep' = {
  name: 'hackathon-container-apps-env'
  params: {
    envName: caEnvName
    location: location
    tags: tags
    logAnalyticsCustomerId: logAnalytics.outputs.customerId
    logAnalyticsSharedKey: logAnalytics.outputs.primarySharedKey
    enableLogAnalytics: false
  }
}

module functionApp './modules/function-app-hackathon.bicep' = {
  name: 'hackathon-function-app'
  params: {
    name: functionAppName
    planName: functionPlanName
    location: location
    tags: tags
    storageConnectionString: storage.outputs.connectionString
    serviceBusConnectionString: serviceBus.outputs.connectionString
    appInsightsConnectionString: appInsights.outputs.connectionString
  }
}

module openai './modules/openai-hackathon.bicep' = {
  name: 'hackathon-openai'
  params: {
    name: openaiName
    location: openaiLocation
    tags: tags
    capacityK: openaiCapacityK
  }
}

module orchestratorJob './modules/container-app-job-hackathon.bicep' = if (deployWorkerJob) {
  name: 'hackathon-orchestrator-job'
  params: {
    name: containerJobName
    location: location
    tags: tags
    environmentId: caEnv.outputs.environmentId
    image: '${acr.outputs.loginServer}/orchestrator:${imageTag}'
    acrLoginServer: acr.outputs.loginServer
    acrUsername: acr.outputs.username
    acrPassword: acr.outputs.password
    serviceBusNamespace: serviceBus.outputs.namespaceName
    serviceBusQueue: serviceBus.outputs.queueName
    serviceBusConnectionString: serviceBus.outputs.connectionString
    storageConnectionString: storage.outputs.connectionString
    adoPat: adoPat
    appInsightsConnectionString: appInsights.outputs.connectionString
    openaiEndpoint: openai.outputs.endpoint
    openaiDeploymentName: openai.outputs.deploymentName
    openaiApiKey: openai.outputs.apiKey
    llmMaxInputTokens: llmMaxInputTokens
    llmMaxOutputTokens: llmMaxOutputTokens
    llmReasoningEffort: llmReasoningEffort
    maxExecutions: jobMaxExecutions
    pollingIntervalSeconds: jobPollingIntervalSeconds
    replicaTimeoutSeconds: jobReplicaTimeoutSeconds
  }
}

module gateway './modules/container-app-gateway-hackathon.bicep' = if (deployGateway) {
  name: 'hackathon-webhook-admin-gateway'
  params: {
    name: gatewayName
    location: location
    tags: tags
    environmentId: caEnv.outputs.environmentId
    image: '${acr.outputs.loginServer}/webhook-admin:${gatewayImageTag}'
    acrLoginServer: acr.outputs.loginServer
    acrUsername: acr.outputs.username
    acrPassword: acr.outputs.password
    accessKey: gatewayAccessKey
    storageConnectionString: storage.outputs.connectionString
    serviceBusConnectionString: serviceBus.outputs.connectionString
    serviceBusQueue: serviceBus.outputs.queueName
  }
}

output resourceGroupName string = resourceGroup().name
output functionAppName string = functionApp.outputs.name
output functionAppHostName string = functionApp.outputs.defaultHostName
output acrName string = acrName
output acrLoginServer string = acr.outputs.loginServer
output serviceBusNamespace string = serviceBus.outputs.namespaceName
output serviceBusQueueName string = serviceBus.outputs.queueName
output openaiEndpoint string = openai.outputs.endpoint
output openaiDeploymentName string = openai.outputs.deploymentName
output orchestratorJobName string = containerJobName
output gatewayName string = gatewayName
