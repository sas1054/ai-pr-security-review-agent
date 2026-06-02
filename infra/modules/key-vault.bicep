@description('Name of the Key Vault')
param name string

@description('Azure region')
param location string

@description('Resource tags')
param tags object

@description('Principal IDs granted Key Vault Secrets User role')
param secretsUserPrincipalIds array = []

resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true   // RBAC only; no access policies
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    enablePurgeProtection: false    // allow purge in dev; set true for prod
    publicNetworkAccess: 'Enabled'
  }
}

// Built-in role: Key Vault Secrets User (read-only)
var kvSecretsUserRoleId = '4633458b-17de-408a-b874-0445c86b69e6'

resource kvSecretsUserAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for principalId in secretsUserPrincipalIds: {
    name: guid(kv.id, principalId, kvSecretsUserRoleId)
    scope: kv
    properties: {
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', kvSecretsUserRoleId)
      principalId: principalId
      principalType: 'ServicePrincipal'
    }
  }
]

output uri string = kv.properties.vaultUri
output resourceId string = kv.id
output name string = kv.name
