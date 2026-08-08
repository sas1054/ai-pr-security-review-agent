@description('Name of the Log Analytics workspace')
param name string

@description('Azure region')
param location string

@description('Resource tags')
param tags object

@description('Maximum billable analytics log ingestion per day in GiB')
@minValue(1)
param dailyQuotaGb int = 1

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: name
  location: location
  tags: tags
  sku: {
    name: 'PerGB2018'
  }
  properties: {
    retentionInDays: 30
    workspaceCapping: {
      dailyQuotaGb: dailyQuotaGb
    }
  }
}

output resourceId string = workspace.id
output customerId string = workspace.properties.customerId
output primarySharedKey string = listKeys(workspace.id, workspace.apiVersion).primarySharedKey
