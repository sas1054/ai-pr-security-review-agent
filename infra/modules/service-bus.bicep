@description('Name of the Service Bus namespace')
param name string

@description('Azure region')
param location string

@description('Resource tags')
param tags object

@description('Name of the queue for PR review jobs')
param queueName string = 'pr-review-jobs'

@description('Principal IDs granted Service Bus Data Sender role')
param senderPrincipalIds array = []

@description('Principal IDs granted Service Bus Data Receiver role')
param receiverPrincipalIds array = []

resource sbn 'Microsoft.ServiceBus/namespaces@2022-10-01-preview' = {
  name: name
  location: location
  tags: tags
  sku: {
    name: 'Standard' // Standard tier required for queues with dead-letter
    tier: 'Standard'
  }
  properties: {
    minimumTlsVersion: '1.2'
    publicNetworkAccess: 'Enabled'
    disableLocalAuth: true // managed identity only
  }
}

resource queue 'Microsoft.ServiceBus/namespaces/queues@2022-10-01-preview' = {
  parent: sbn
  name: queueName
  properties: {
    maxDeliveryCount: 5
    lockDuration: 'PT5M'             // 5-minute visibility lock
    defaultMessageTimeToLive: 'P1D'  // 1-day TTL
    deadLetteringOnMessageExpiration: true
    requiresDuplicateDetection: false
    requiresSession: false
  }
}

// Built-in roles
var sbSenderRoleId   = '69a216fc-b8fb-44d8-bc22-1f3c2cd27a39'
var sbReceiverRoleId = '4f6d3b9b-027b-4f4c-9142-0e5a2a2247e0'

resource senderAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for principalId in senderPrincipalIds: {
    name: guid(sbn.id, principalId, sbSenderRoleId)
    scope: sbn
    properties: {
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', sbSenderRoleId)
      principalId: principalId
      principalType: 'ServicePrincipal'
    }
  }
]

resource receiverAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for principalId in receiverPrincipalIds: {
    name: guid(sbn.id, principalId, sbReceiverRoleId)
    scope: sbn
    properties: {
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', sbReceiverRoleId)
      principalId: principalId
      principalType: 'ServicePrincipal'
    }
  }
]

output namespaceName string = sbn.name
output queueName string = queue.name
output resourceId string = sbn.id
output endpoint string = '${sbn.name}.servicebus.windows.net'
