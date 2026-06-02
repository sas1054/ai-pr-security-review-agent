@description('Name of the Azure Container Registry')
param name string

@description('Azure region')
param location string

@description('Resource tags')
param tags object

@description('Principal IDs granted AcrPull role')
param acrPullPrincipalIds array = []

resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: name
  location: location
  tags: tags
  sku: {
    name: 'Basic'
  }
  properties: {
    adminUserEnabled: false // managed identity only
    publicNetworkAccess: 'Enabled'
    zoneRedundancy: 'Disabled'
  }
}

// Built-in role: AcrPull
var acrPullRoleId = '7f951dda-4ed3-4680-a7ca-43fe172d538d'

resource acrPullAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for principalId in acrPullPrincipalIds: {
    name: guid(acr.id, principalId, acrPullRoleId)
    scope: acr
    properties: {
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', acrPullRoleId)
      principalId: principalId
      principalType: 'ServicePrincipal'
    }
  }
]

output loginServer string = acr.properties.loginServer
output resourceId string = acr.id
output name string = acr.name
