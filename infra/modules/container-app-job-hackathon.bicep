@description('Name of the event-driven Container Apps job')
param name string

@description('Azure region')
param location string

@description('Container Apps environment resource ID')
param environmentId string

@description('Container image to execute')
param image string

@description('ACR login server')
param acrLoginServer string

@description('ACR admin username')
param acrUsername string

@secure()
@description('ACR admin password')
param acrPassword string

@description('Service Bus namespace')
param serviceBusNamespace string

@description('Service Bus queue')
param serviceBusQueue string

@secure()
@description('Limited Service Bus Send/Listen connection string')
param serviceBusConnectionString string

@secure()
@description('Storage connection string used for low-cost control-plane Tables and Blobs')
param storageConnectionString string

@secure()
@description('Azure DevOps PAT')
param adoPat string

@description('Application Insights connection string')
param appInsightsConnectionString string

@description('Azure OpenAI endpoint')
param openaiEndpoint string

@description('Azure OpenAI deployment name')
param openaiDeploymentName string

@secure()
@description('Azure OpenAI account key')
param openaiApiKey string

@description('Largest model input allowed for one PR triage request')
param llmMaxInputTokens int

@description('Largest model completion allowed for one PR triage request')
param llmMaxOutputTokens int

@description('Reasoning effort used for Azure OpenAI triage')
param llmReasoningEffort string

@description('Maximum concurrent event-driven job executions')
param maxExecutions int = 1

@description('Seconds between queue-scale checks')
param pollingIntervalSeconds int = 30

@description('Maximum time allowed for one review job execution')
param replicaTimeoutSeconds int = 900

@description('Resource tags')
param tags object

resource job 'Microsoft.App/jobs@2025-07-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    environmentId: environmentId
    configuration: {
      triggerType: 'Event'
      replicaTimeout: replicaTimeoutSeconds
      replicaRetryLimit: 0
      secrets: [
        {
          name: 'acr-password'
          value: acrPassword
        }
        {
          name: 'service-bus-connection'
          value: serviceBusConnectionString
        }
        {
          name: 'ado-pat'
          value: adoPat
        }
        {
          name: 'storage-connection'
          value: storageConnectionString
        }
        {
          name: 'openai-api-key'
          value: openaiApiKey
        }
      ]
      eventTriggerConfig: {
        parallelism: 1
        replicaCompletionCount: 1
        scale: {
          minExecutions: 0
          maxExecutions: maxExecutions
          pollingInterval: pollingIntervalSeconds
          rules: [
            {
              name: 'service-bus-queue'
              type: 'azure-servicebus'
              auth: [
                {
                  secretRef: 'service-bus-connection'
                  triggerParameter: 'connection'
                }
              ]
              metadata: {
                namespace: serviceBusNamespace
                queueName: serviceBusQueue
                messageCount: '1'
              }
            }
          ]
        }
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
          name: 'orchestrator'
          image: image
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          env: [
            {
              name: 'SERVICE_BUS_CONNECTION_STRING'
              secretRef: 'service-bus-connection'
            }
            {
              name: 'SERVICE_BUS_NAMESPACE'
              value: serviceBusNamespace
            }
            {
              name: 'SERVICE_BUS_QUEUE'
              value: serviceBusQueue
            }
            {
              name: 'ADO_PAT'
              secretRef: 'ado-pat'
            }
            {
              name: 'AZURE_STORAGE_CONNECTION_STRING'
              secretRef: 'storage-connection'
            }
            {
              name: 'AZURE_OPENAI_ENDPOINT'
              value: openaiEndpoint
            }
            {
              name: 'AZURE_OPENAI_DEPLOYMENT'
              value: openaiDeploymentName
            }
            {
              name: 'AZURE_OPENAI_API_KEY'
              secretRef: 'openai-api-key'
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
              name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
              value: appInsightsConnectionString
            }
            {
              name: 'LLM_MAX_INPUT_TOKENS'
              value: string(llmMaxInputTokens)
            }
            {
              name: 'LLM_MAX_OUTPUT_TOKENS'
              value: string(llmMaxOutputTokens)
            }
            {
              name: 'LLM_REASONING_EFFORT'
              value: llmReasoningEffort
            }
            {
              name: 'LLM_TIMEOUT_SECONDS'
              value: '90'
            }
          ]
        }
      ]
    }
  }
}

output name string = job.name
output resourceId string = job.id
