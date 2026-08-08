@description('Name of the scale-to-zero webhook and admin gateway')
param name string

@description('Azure region')
param location string

@description('Container Apps environment resource ID')
param environmentId string

@description('Gateway image')
param image string

@description('ACR login server')
param acrLoginServer string

@description('ACR admin username')
param acrUsername string

@secure()
@description('ACR admin password')
param acrPassword string

@secure()
@description('Shared Function-key-derived access key for the service hook and temporary portal')
param accessKey string

@secure()
@description('Storage connection string for the control-plane data')
param storageConnectionString string

@secure()
@description('Service Bus send connection string')
param serviceBusConnectionString string

@description('Service Bus queue name')
param serviceBusQueue string

@description('Resource tags')
param tags object

resource gateway 'Microsoft.App/containerApps@2025-07-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    environmentId: environmentId
    configuration: {
      activeRevisionsMode: 'Single'
      secrets: [
        {
          name: 'gateway-access-key'
          value: accessKey
        }
        {
          name: 'storage-connection'
          value: storageConnectionString
        }
        {
          name: 'service-bus-connection'
          value: serviceBusConnectionString
        }
        {
          name: 'acr-password'
          value: acrPassword
        }
      ]
      ingress: {
        external: true
        targetPort: 8000
        transport: 'auto'
        allowInsecure: false
        traffic: [
          {
            latestRevision: true
            weight: 100
          }
        ]
      }
      registries: [
        {
          server: acrLoginServer
          username: acrUsername
          passwordSecretRef: 'acr-password'
        }
      ]
    }
    template: {
      containers: [
        {
          name: 'gateway'
          image: image
          resources: {
            cpu: json('0.25')
            memory: '0.5Gi'
          }
          env: [
            {
              name: 'ADMIN_ACCESS_KEY'
              secretRef: 'gateway-access-key'
            }
            {
              name: 'AZURE_STORAGE_CONNECTION_STRING'
              secretRef: 'storage-connection'
            }
            {
              name: 'SERVICE_BUS_CONNECTION_STRING'
              secretRef: 'service-bus-connection'
            }
            {
              name: 'SERVICE_BUS_QUEUE'
              value: serviceBusQueue
            }
            {
              name: 'HACKATHON_MODE'
              value: 'true'
            }
            {
              name: 'ENVIRONMENT'
              value: 'hackathon'
            }
            {
              name: 'REVIEW_ON_UPDATED_EVENTS'
              value: 'false'
            }
          ]
        }
      ]
      scale: {
        minReplicas: 0
        maxReplicas: 1
      }
    }
  }
}

output name string = gateway.name
output fqdn string = gateway.properties.configuration.ingress.fqdn
