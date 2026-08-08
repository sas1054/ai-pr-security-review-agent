@description('Name of the Function App')
param name string

@description('Name of the Consumption plan')
param planName string

@description('Azure region')
param location string

@description('Resource tags')
param tags object

@secure()
@description('Storage account connection string for the Functions host')
param storageConnectionString string

@secure()
@description('Limited Service Bus Send/Listen connection string')
param serviceBusConnectionString string

@description('Application Insights connection string')
param appInsightsConnectionString string

resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: planName
  location: location
  tags: tags
  kind: 'linux'
  sku: {
    name: 'Y1'
    tier: 'Dynamic'
  }
  properties: {
    reserved: true
  }
}

resource functionApp 'Microsoft.Web/sites@2023-12-01' = {
  name: name
  location: location
  tags: tags
  kind: 'functionapp,linux'
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'Python|3.11'
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      appSettings: [
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'python'
        }
        {
          name: 'AzureWebJobsStorage'
          value: storageConnectionString
        }
        {
          name: 'SERVICE_BUS_CONNECTION_STRING'
          value: serviceBusConnectionString
        }
        {
          name: 'ENVIRONMENT'
          value: 'hackathon'
        }
        {
          name: 'HACKATHON_MODE'
          value: 'true'
        }
        {
          name: 'REVIEW_ON_UPDATED_EVENTS'
          value: 'false'
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: appInsightsConnectionString
        }
      ]
    }
  }
}

output name string = functionApp.name
output resourceId string = functionApp.id
output defaultHostName string = functionApp.properties.defaultHostName
