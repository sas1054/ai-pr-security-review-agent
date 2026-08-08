@description('Name of the Azure OpenAI account')
param name string

@description('Supported Global Standard region for GPT-5.4 mini')
param location string

@description('Resource tags')
param tags object

@description('GPT model to deploy')
param modelName string = 'gpt-5.4-mini'

@description('Model version')
param modelVersion string = '2026-03-17'

@description('Tokens-per-minute capacity requested for the pay-as-you-go deployment')
param capacityK int = 120

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
    disableLocalAuth: false
    networkAcls: {
      defaultAction: 'Allow'
    }
  }
}

resource modelDeployment 'Microsoft.CognitiveServices/accounts/deployments@2025-06-01' = {
  parent: openai
  name: modelName
  sku: {
    name: 'GlobalStandard'
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

var keys = listKeys(openai.id, openai.apiVersion)

output endpoint string = openai.properties.endpoint
output deploymentName string = modelDeployment.name
@secure()
output apiKey string = keys.key1
output resourceId string = openai.id
