@description('Name prefix for monitor resources')
param namePrefix string

@description('Azure region')
param location string

@description('Resource tags')
param tags object

@description('Log Analytics workspace resource ID')
param workspaceResourceId string

@description('Service Bus namespace resource ID')
param serviceBusResourceId string

@description('Optional alert recipient')
param alertEmail string = ''

resource actionGroup 'Microsoft.Insights/actionGroups@2023-01-01' = if (!empty(alertEmail)) {
  name: '${namePrefix}-alerts'
  location: 'global'
  tags: tags
  properties: {
    groupShortName: 'PRSA'
    enabled: true
    emailReceivers: [
      {
        name: 'primary'
        emailAddress: alertEmail
        useCommonAlertSchema: true
      }
    ]
  }
}

var actionGroupIds = empty(alertEmail) ? [] : [actionGroup.id]

resource workerFailureAlert 'Microsoft.Insights/scheduledQueryRules@2023-12-01' = {
  name: '${namePrefix}-worker-failures'
  location: location
  tags: tags
  kind: 'LogAlert'
  properties: {
    displayName: 'PRSA worker failures'
    description: 'Alerts when the review worker fails to process a queued job.'
    enabled: true
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    severity: 2
    autoMitigate: true
    skipQueryValidation: true
    scopes: [workspaceResourceId]
    criteria: {
      allOf: [
        {
          query: 'AppTraces | where Message has "Failed to process job" | summarize Count=count()'
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
        }
      ]
    }
    actions: {
      actionGroups: actionGroupIds
    }
  }
}

resource deadLetterAlert 'Microsoft.Insights/scheduledQueryRules@2023-12-01' = {
  name: '${namePrefix}-deadletters'
  location: location
  tags: tags
  kind: 'LogAlert'
  properties: {
    displayName: 'PRSA Service Bus dead letters'
    description: 'Alerts when Service Bus dead-letter messages are observed.'
    enabled: true
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    severity: 2
    autoMitigate: true
    skipQueryValidation: true
    scopes: [workspaceResourceId]
    criteria: {
      allOf: [
        {
          query: 'AzureMetrics | where ResourceId =~ "${serviceBusResourceId}" | where MetricName =~ "DeadletteredMessages" | summarize DeadLetters=sum(Total)'
          timeAggregation: 'Total'
          operator: 'GreaterThan'
          threshold: 0
        }
      ]
    }
    actions: {
      actionGroups: actionGroupIds
    }
  }
}

output workerFailureAlertId string = workerFailureAlert.id
output deadLetterAlertId string = deadLetterAlert.id
