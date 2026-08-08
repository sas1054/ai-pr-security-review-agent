using './hackathon.bicep'

// Set these only in the local deployment shell. Do not put secrets in this file or commit them.
param adoPat = readEnvironmentVariable('PRSA_ADO_PAT')

param location = 'southeastasia'
param openaiLocation = 'eastus2'
param env = 'dev'
param prefix = 'prsa'
param deployWorkerJob = false
param deployGateway = false
param gatewayImageTag = 'latest'
param openaiCapacityK = 120
param llmMaxInputTokens = 100000
param llmMaxOutputTokens = 8000
param llmReasoningEffort = 'medium'
param jobMaxExecutions = 1
param jobPollingIntervalSeconds = 60
param jobReplicaTimeoutSeconds = 900
param logAnalyticsDailyCapGb = 1
