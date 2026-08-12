using './main.bicep'

// Phase-one development defaults. Deploy into the existing
// rg-hackathon-groupc-hvn resource group with `az deployment group create`.
param env = 'dev'
param location = 'southeastasia'
param openaiLocation = 'eastus2'
param prefix = 'prsa'
param openaiModelName = 'gpt-5.4-mini'
param openaiModelVersion = '2026-03-17'
param openaiDeploymentSkuName = 'GlobalStandard'
param openaiCapacityK = 120
param llmMaxInputTokens = 100000
param llmMaxOutputTokens = 16000
param llmReasoningEffort = 'medium'
param jobMaxExecutions = 1
param jobPollingIntervalSeconds = 60
param jobReplicaTimeoutSeconds = 900
param logAnalyticsDailyCapGb = 1
param enableOperationalAlerts = false
