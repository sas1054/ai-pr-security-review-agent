@description('Name of the Azure OpenAI account')
param name string

@description('Supported Azure OpenAI Global Standard region for GPT-5.4 mini')
param location string

@description('Resource tags')
param tags object

@description('GPT model to deploy')
param modelName string = 'gpt-5.4-mini'

@description('Model version')
param modelVersion string = '2026-03-17'

@description('Tokens-per-minute capacity requested for the pay-as-you-go deployment')
param capacityK int = 120

@description('Azure OpenAI deployment SKU')
@allowed([
  'GlobalStandard'
  'DataZoneStandard'
  'Standard'
])
param deploymentSkuName string = 'GlobalStandard'

@description('Principal IDs granted Cognitive Services OpenAI User role')
param openaiUserPrincipalIds array = []

resource openai 'Microsoft.CognitiveServices/accounts@2025-06-01' = {
  name: name
  location: location
  tags: tags
  kind: 'OpenAI'
  sku: {
    name: 'S0'
  }
  properties: {
    customSubDomainName: name
    publicNetworkAccess: 'Enabled'
    disableLocalAuth: true // managed identity only
    networkAcls: {
      defaultAction: 'Allow'
    }
  }
}

resource modelDeployment 'Microsoft.CognitiveServices/accounts/deployments@2025-06-01' = {
  parent: openai
  name: modelName
  sku: {
    name: deploymentSkuName
    capacity: capacityK
  }
  properties: {
    model: {
      format: 'OpenAI'
      name: modelName
      version: modelVersion
    }
  }
}

// Built-in role: Cognitive Services OpenAI User
var openaiUserRoleId = '5e0bd9bd-7b93-4f28-af87-19fc36ad61bd'

resource openaiUserAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for principalId in openaiUserPrincipalIds: {
    name: guid(openai.id, principalId, openaiUserRoleId)
    scope: openai
    properties: {
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', openaiUserRoleId)
      principalId: principalId
      principalType: 'ServicePrincipal'
    }
  }
]

output endpoint string = openai.properties.endpoint
output resourceId string = openai.id
output deploymentName string = modelDeployment.name
