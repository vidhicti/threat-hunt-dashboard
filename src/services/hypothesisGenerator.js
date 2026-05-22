export async function fetchLiveThreatActors(groqApiKey) {
  const prompt = `You are a threat intelligence analyst. List the 5 most active threat actors or ransomware groups in the last 30 days. For each provide:
- name
- type (APT/Ransomware/Cybercrime)  
- targetedSectors (array)
- recentActivity (one sentence)
- mitreTechniques (array of top 5 TTP IDs like T1566, T1059 etc)
- severity (critical/high/medium)

Respond ONLY with a valid JSON array, no explanation, no markdown. Example:
[{"name":"LockBit","type":"Ransomware","targetedSectors":["Healthcare","Finance"],"recentActivity":"Active campaigns targeting VMware ESXi","mitreTechniques":["T1486","T1490","T1059","T1078","T1021"],"severity":"critical"}]`

  const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${groqApiKey}`
    },
    body: JSON.stringify({
      model: 'llama-3.3-70b-versatile',
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.3,
      max_tokens: 2000
    })
  })
  const data = await response.json()
  const text = data.choices?.[0]?.message?.content || '[]'
  const clean = text.replace(/```json|```/g, '').trim()
  return JSON.parse(clean)
}

export async function generateHypothesisFromActor(actor, logSources, groqApiKey) {
  const prompt = `You are a threat hunting expert. Generate a threat hunting hypothesis for the threat actor: ${actor.name} (${actor.type}).

Recent activity: ${actor.recentActivity}
Known TTPs: ${actor.mitreTechniques.join(', ')}
Targeted sectors: ${actor.targetedSectors.join(', ')}

Available log sources in our Microsoft Sentinel environment:
- Fortigate Firewall: CommonSecurityLog where DeviceVendor == "Fortinet"
- Palo Alto Firewall: CommonSecurityLog where DeviceVendor == "Palo Alto Networks"
- Sophos XG: CommonSecurityLog where DeviceVendor == "Sophos"
- Active Directory: SecurityEvent (4624,4625,4648,4688,4698,4720,4732,4769)
- MDE: DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceLogonEvents, DeviceRegistryEvents
- DNS: ASimDnsActivityLogs
- Office 365: OfficeActivity
- Trend Micro: CommonSecurityLog where DeviceVendor == "Trend Micro"

Generate ONE hunting hypothesis as JSON with these exact fields:
{
  "id": "LIVE-001",
  "priority": "critical",
  "title": "hypothesis title",
  "tacticChain": "Initial Access → Execution → Impact",
  "logSources": ["MDE", "SecurityEvents"],
  "description": "2-3 sentence description of what to hunt for",
  "tags": ["tag1","tag2"],
  "threatActor": "${actor.name}",
  "generatedAt": "${new Date().toISOString()}",
  "kqlQueries": [
    {
      "title": "query title",
      "logSource": "table name",
      "severity": "high",
      "mitreTechnique": "T1XXX",
      "kql": "full KQL query using correct Sentinel table names"
    }
  ]
}

Return ONLY valid JSON, no explanation, no markdown backticks.`

  const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${groqApiKey}`
    },
    body: JSON.stringify({
      model: 'llama-3.3-70b-versatile',
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.2,
      max_tokens: 3000
    })
  })
  const data = await response.json()
  const text = data.choices?.[0]?.message?.content || '{}'
  const clean = text.replace(/```json|```/g, '').trim()
  return JSON.parse(clean)
}

export async function generateCustomHypothesis(userRequirements, groqApiKey) {
  const prompt = `You are a threat hunting expert for Microsoft Sentinel. Generate a threat hunting hypothesis based on these requirements:

${userRequirements}

Available log sources:
- Fortigate Firewall: CommonSecurityLog where DeviceVendor == "Fortinet"
- Palo Alto Firewall: CommonSecurityLog where DeviceVendor == "Palo Alto Networks"
- Sophos XG: CommonSecurityLog where DeviceVendor == "Sophos"
- Active Directory: SecurityEvent (4624,4625,4648,4688,4698,4720,4732,4769)
- MDE: DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceLogonEvents, DeviceRegistryEvents
- DNS: ASimDnsActivityLogs
- Office 365: OfficeActivity
- Trend Micro: CommonSecurityLog where DeviceVendor == "Trend Micro"

Return ONE hypothesis as JSON:
{
  "id": "CUSTOM-001",
  "priority": "high",
  "title": "title",
  "tacticChain": "tactic chain",
  "logSources": ["array"],
  "description": "description",
  "tags": ["tags"],
  "threatActor": "Custom",
  "generatedAt": "ISO date",
  "kqlQueries": [
    {
      "title": "query title",
      "logSource": "table",
      "severity": "high",
      "mitreTechnique": "TXXXX",
      "kql": "full KQL"
    }
  ]
}

Return ONLY valid JSON, no markdown.`

  const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${groqApiKey}`
    },
    body: JSON.stringify({
      model: 'llama-3.3-70b-versatile',
      messages: [{ role: 'user', content: prompt }],
      temperature: 0.2,
      max_tokens: 3000
    })
  })
  const data = await response.json()
  const text = data.choices?.[0]?.message?.content || '{}'
  const clean = text.replace(/```json|```/g, '').trim()
  return JSON.parse(clean)
}
