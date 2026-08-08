@description('Name of the Azure Container Registry')
param name string

@description('Azure region')
param location string

@description('Resource tags')
param tags object

// This is intentionally a short-lived hackathon credential. Production uses AcrPull + managed identity.
resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: name
  location: location
  tags: tags
  sku: {
    name: 'Basic'
  }
  properties: {
    adminUserEnabled: true
    publicNetworkAccess: 'Enabled'
    zoneRedundancy: 'Disabled'
  }
}

var credentials = listCredentials(acr.id, acr.apiVersion)

output loginServer string = acr.properties.loginServer
output username string = credentials.username
@secure()
output password string = credentials.passwords[0].value
output resourceId string = acr.id
