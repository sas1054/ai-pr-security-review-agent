@description('Name of the Service Bus namespace')
param name string

@description('Azure region')
param location string

@description('Resource tags')
param tags object

@description('Name of the queue for PR review jobs')
param queueName string = 'pr-review-jobs'

// Basic is queue-only and avoids the Standard namespace base charge. The project does not use topics,
// sessions, transactions, or duplicate detection in hackathon mode.
resource sbn 'Microsoft.ServiceBus/namespaces@2022-10-01-preview' = {
  name: name
  location: location
  tags: tags
  sku: {
    name: 'Basic'
    tier: 'Basic'
  }
  properties: {
    minimumTlsVersion: '1.2'
    publicNetworkAccess: 'Enabled'
    disableLocalAuth: false
  }
}

resource queue 'Microsoft.ServiceBus/namespaces/queues@2022-10-01-preview' = {
  parent: sbn
  name: queueName
  properties: {
    maxDeliveryCount: 3
    lockDuration: 'PT5M'
    defaultMessageTimeToLive: 'P1D'
    deadLetteringOnMessageExpiration: true
    requiresDuplicateDetection: false
    requiresSession: false
  }
}

resource appRule 'Microsoft.ServiceBus/namespaces/AuthorizationRules@2022-10-01-preview' = {
  parent: sbn
  name: 'hackathon-agent'
  properties: {
    rights: [
      'Listen'
      'Send'
      // KEDA needs Manage to query queue runtime metrics for scale-to-zero activation.
      'Manage'
    ]
  }
}

var appRuleKeys = listKeys(appRule.id, appRule.apiVersion)

output namespaceName string = sbn.name
output queueName string = queue.name
output resourceId string = sbn.id
output endpoint string = '${sbn.name}.servicebus.windows.net'
@secure()
output connectionString string = appRuleKeys.primaryConnectionString
