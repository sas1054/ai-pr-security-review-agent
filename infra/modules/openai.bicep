@description('Name of the Azure OpenAI account')
param name string

@description('Azure region — must be approved for Azure OpenAI (e.g. eastus, swedencentral)')
param location string

@description('Resource tags')
param tags object

@description('GPT model to deploy')
param modelName string = 'gpt-4o'

@description('Model version')
param modelVersion string = '2024-11-20'

@description('Tokens-per-minute capacity (in thousands)')
param capacityK int = 30

@description('Principal IDs granted Cognitive Services OpenAI User role')
param openaiUserPrincipalIds array = []

resource openai 'Microsoft.CognitiveServices/accounts@2023-10-01-preview' = {
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
    disableLocalAuth: false // keep key auth as fallback; managed identity is preferred
    networkAcls: {
      defaultAction: 'Allow'
    }
  }
}

resource modelDeployment 'Microsoft.CognitiveServices/accounts/deployments@2023-10-01-preview' = {
  parent: openai
  name: modelName
  sku: {
    name: 'Standard'
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
