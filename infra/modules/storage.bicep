@description('Name of the storage account used by Azure Functions')
param name string

@description('Azure region')
param location string

@description('Resource tags')
param tags object

@description('Principal IDs granted Storage Blob Data Contributor')
param blobContributorPrincipalIds array = []

@description('Principal IDs granted Storage Table Data Contributor')
param tableContributorPrincipalIds array = []

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: name
  location: location
  tags: tags
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    publicNetworkAccess: 'Enabled'
  }
}

var blobContributorRoleId = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
var tableContributorRoleId = '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'

resource blobContributorAssignments 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for principalId in blobContributorPrincipalIds: {
    name: guid(storage.id, principalId, blobContributorRoleId)
    scope: storage
    properties: {
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', blobContributorRoleId)
      principalId: principalId
      principalType: 'ServicePrincipal'
    }
  }
]

resource tableContributorAssignments 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for principalId in tableContributorPrincipalIds: {
    name: guid(storage.id, principalId, tableContributorRoleId)
    scope: storage
    properties: {
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', tableContributorRoleId)
      principalId: principalId
      principalType: 'ServicePrincipal'
    }
  }
]

output name string = storage.name
output resourceId string = storage.id
output connectionString string = 'DefaultEndpointsProtocol=https;AccountName=${storage.name};AccountKey=${listKeys(storage.id, storage.apiVersion).keys[0].value};EndpointSuffix=${environment().suffixes.storage}'
