export function validateKQL(query) {
  const errors = []
  const warnings = []
  const suggestions = []

  const validTables = [
    'SecurityEvent',
    'CommonSecurityLog',
    'DeviceProcessEvents',
    'DeviceNetworkEvents',
    'DeviceFileEvents',
    'DeviceLogonEvents',
    'DeviceRegistryEvents',
    'DeviceEvents',
    'ASimDnsActivityLogs',
    'OfficeActivity',
    'SigninLogs',
    'AuditLogs',
    'AzureActivity',
    'Syslog',
    'Event',
    'Heartbeat',
    'WindowsFirewall',
  ]

  const lines = query.trim().split('\n')
  const firstLine = lines[0].trim()
  const tableUsed = validTables.find((t) => firstLine.startsWith(t))

  if (!tableUsed) {
    warnings.push(`Table "${firstLine}" not in known Sentinel tables — verify it exists`)
  }
  if (!query.includes('ago(') && !query.includes('TimeGenerated') && !query.includes('Timestamp')) {
    errors.push('Missing time filter — add TimeGenerated > ago(1d)')
  }
  if (query.includes('contains') && !query.includes('has')) {
    suggestions.push('Use "has" instead of "contains" for better performance')
  }
  if (!query.includes('project') && !query.includes('summarize')) {
    warnings.push('No project/summarize — will return all columns')
  }
  if (query.includes('*')) {
    warnings.push('Wildcard * detected — impacts performance on large tables')
  }

  const score =
    errors.length === 0 && warnings.length === 0
      ? 100
      : errors.length === 0
        ? Math.max(60, 100 - warnings.length * 10)
        : Math.max(20, 100 - errors.length * 25 - warnings.length * 10)

  return {
    valid: errors.length === 0,
    score,
    grade: score >= 90 ? 'A' : score >= 70 ? 'B' : score >= 50 ? 'C' : 'D',
    gradeColor:
      score >= 90
        ? '#3fb950'
        : score >= 70
          ? '#58a6ff'
          : score >= 50
            ? '#d29922'
            : '#f85149',
    errors,
    warnings,
    suggestions,
  }
}
