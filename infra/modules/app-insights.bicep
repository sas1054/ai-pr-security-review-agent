@description('Name of the Application Insights component')
param name string

@description('Azure region')
param location string

@description('Resource tags')
param tags object

@description('Workspace resource ID')
param workspaceResourceId string

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: name
  location: location
  tags: tags
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: workspaceResourceId
  }
}

output resourceId string = appInsights.id
output connectionString string = appInsights.properties.ConnectionString
