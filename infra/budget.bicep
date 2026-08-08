/* Phase-one Cost Management budget. This deployment is subscription-scoped,
   but it filters all tracked spend to the named project resource group. */

targetScope = 'subscription'

@description('Name of the Cost Management budget')
param name string = 'prsa-phase1-dev'

@description('Monthly cost amount in the subscription billing currency')
@minValue(1)
param amount int = 25

@description('First day of the current month, in YYYY-MM-DD format')
param startDate string

@description('Budget end date, in YYYY-MM-DD format')
param endDate string

@description('Only this resource group is included in the budget')
param targetResourceGroup string = 'rg-hackathon-groupc-hvn'

@description('Optional additional budget-notification email addresses')
param contactEmails array = []

resource budget 'Microsoft.Consumption/budgets@2023-11-01' = {
  name: name
  properties: {
    amount: amount
    category: 'Cost'
    timeGrain: 'Monthly'
    timePeriod: {
      startDate: startDate
      endDate: endDate
    }
    filter: {
      dimensions: {
        name: 'ResourceGroupName'
        operator: 'In'
        values: [targetResourceGroup]
      }
    }
    notifications: {
      actual50: {
        enabled: true
        operator: 'GreaterThan'
        threshold: 50
        contactEmails: contactEmails
        contactRoles: [
          'Owner'
        ]
      }
      actual80: {
        enabled: true
        operator: 'GreaterThan'
        threshold: 80
        contactEmails: contactEmails
        contactRoles: [
          'Owner'
        ]
      }
      forecast100: {
        enabled: true
        operator: 'GreaterThan'
        threshold: 100
        thresholdType: 'Forecasted'
        contactEmails: contactEmails
        contactRoles: [
          'Owner'
        ]
      }
    }
  }
}

output resourceId string = budget.id
