@description('Name of the Function App')
param name string

@description('Name of the App Service plan')
param planName string

@description('Azure region')
param location string

@description('Resource tags')
param tags object

@description('Storage account connection string for the Functions host')
@secure()
param storageConnectionString string

@description('User-assigned managed identity resource ID')
param identityResourceId string

@description('User-assigned managed identity client ID')
param identityClientId string

@description('Service Bus namespace')
param serviceBusNamespace string

@description('Service Bus queue')
param serviceBusQueue string

@description('Application Insights connection string')
param appInsightsConnectionString string

@description('Require Microsoft Entra authentication for admin APIs (webhook and health remain excluded by Easy Auth).')
param enableAdminEntraAuth bool = false

@description('Client ID of the Microsoft Entra application used by the admin portal.')
param adminEntraClientId string = ''

@description('Microsoft Entra tenant ID for the admin portal application.')
param adminEntraTenantId string = ''

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
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identityResourceId}': {}
    }
  }
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
          name: 'SERVICE_BUS_NAMESPACE'
          value: serviceBusNamespace
        }
        {
          name: 'SERVICE_BUS_QUEUE'
          value: serviceBusQueue
        }
        {
          name: 'ENVIRONMENT'
          value: 'azure'
        }
        {
          name: 'AZURE_CLIENT_ID'
          value: identityClientId
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: appInsightsConnectionString
        }
        {
          name: 'ADMIN_REQUIRE_ENTRA'
          value: string(enableAdminEntraAuth)
        }
      ]
    }
  }
}

resource adminAuth 'Microsoft.Web/sites/config@2023-12-01' = if (enableAdminEntraAuth) {
  parent: functionApp
  name: 'authsettingsV2'
  properties: {
    platform: {
      enabled: true
      runtimeVersion: '~1'
    }
    globalValidation: {
      requireAuthentication: true
      unauthenticatedClientAction: 'Return401'
      excludedPaths: [
        '/api/webhook'
        '/api/health'
      ]
    }
    identityProviders: {
      azureActiveDirectory: {
        enabled: true
        registration: {
          clientId: adminEntraClientId
          openIdIssuer: 'https://sts.windows.net/${adminEntraTenantId}/v2.0'
        }
        validation: {
          allowedAudiences: [
            'api://${adminEntraClientId}'
            'https://${functionApp.properties.defaultHostName}'
          ]
        }
      }
    }
    login: {
      tokenStore: {
        enabled: false
      }
    }
  }
}

output name string = functionApp.name
output resourceId string = functionApp.id
output defaultHostName string = functionApp.properties.defaultHostName
