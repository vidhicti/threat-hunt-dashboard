const LOG_SOURCE_MAP = {
  All: 'Fortigate Firewall, Palo Alto Firewall, Sophos XG, Active Directory, MDE, DNS, Office 365, Trend Micro',
  Fortigate: 'Fortigate Firewall: CommonSecurityLog where DeviceVendor == "Fortinet"',
  PaloAlto: 'Palo Alto Firewall: CommonSecurityLog where DeviceVendor == "Palo Alto Networks"',
  Sophos: 'Sophos XG: CommonSecurityLog where DeviceVendor == "Sophos"',
  AD: 'Active Directory: SecurityEvent',
  MDE: 'MDE: DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceLogonEvents, DeviceRegistryEvents',
  DNS: 'DNS: ASimDnsActivityLogs',
  O365: 'Office 365: OfficeActivity',
  TrendMicro: 'Trend Micro: CommonSecurityLog where DeviceVendor == "Trend Micro"',
}

export async function generateKQLFromTTP(ttp, logSources, groqApiKey) {
  if (!groqApiKey?.trim()) {
    throw new Error('Groq API key is required')
  }

  const sourceHint = LOG_SOURCE_MAP[logSources] || LOG_SOURCE_MAP.All

  const prompt = `You are a Microsoft Sentinel KQL expert. Generate a production-ready KQL hunting query for MITRE ATT&CK technique ${ttp}.

Available log sources and their Sentinel table names:
- Fortigate Firewall: CommonSecurityLog where DeviceVendor == "Fortinet"
- Palo Alto Firewall: CommonSecurityLog where DeviceVendor == "Palo Alto Networks"  
- Sophos XG: CommonSecurityLog where DeviceVendor == "Sophos"
- Active Directory: SecurityEvent
- MDE: DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceLogonEvents, DeviceRegistryEvents
- DNS: ASimDnsActivityLogs
- Office 365: OfficeActivity
- Trend Micro: CommonSecurityLog where DeviceVendor == "Trend Micro"

Focus on these log sources for this request: ${sourceHint}

Return ONLY a valid KQL query, no explanation, no markdown backticks. Use TimeGenerated > ago(1d) for time filter.`

  const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${groqApiKey}`,
    },
    body: JSON.stringify({
      model: 'llama-3.3-70b-versatile',
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.1,
      max_tokens: 1000,
    }),
  })

  if (!response.ok) {
    const errText = await response.text()
    throw new Error(errText || `Groq API error ${response.status}`)
  }

  const data = await response.json()
  let content = data.choices?.[0]?.message?.content || ''
  content = content.replace(/^```kql?\n?/i, '').replace(/```\s*$/i, '').trim()
  return content
}

export async function generateBulkKQL(ttpList, logSources, groqApiKey) {
  const results = []
  for (const ttp of ttpList) {
    const trimmed = ttp.trim()
    if (!trimmed) continue
    try {
      const kql = await generateKQLFromTTP(trimmed, logSources, groqApiKey)
      results.push({ ttp: trimmed, kql, error: null })
    } catch (err) {
      results.push({ ttp: trimmed, kql: '', error: err.message })
    }
  }
  return results
}
