export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization')
  if (req.method === 'OPTIONS') {
    res.status(200).end()
    return
  }

  try {
    const body = req.method === 'POST' ? req.body : req.query
    const { groqApiKey, mode, actorName, requirements } = body

    if (!groqApiKey) {
      return res.status(200).json({ success: false, error: 'Groq API key required' })
    }

    let prompt = ''

    if (mode === 'trends') {
      prompt = `List the 6 most active threat actors, ransomware groups, or 
malware campaigns reported in the last 60 days based on your training data 
and general knowledge. For each provide:
- name
- type (APT/Ransomware/Cybercrime/Initial Access Broker)
- targetedSectors (array of 2-3 sectors)
- recentActivity (1-2 sentence summary)
- mitreTechniques (array of 4-6 TTP IDs like T1566, T1059)
- severity (critical/high/medium)
- firstSeen (approximate year/period this group became active)

Respond ONLY with a valid JSON array, no markdown, no explanation.
Example: [{"name":"LockBit","type":"Ransomware","targetedSectors":["Healthcare","Manufacturing"],"recentActivity":"...","mitreTechniques":["T1486","T1490"],"severity":"critical","firstSeen":"2019"}]`
    } else if (mode === 'historical') {
      prompt = `List 10 historically significant threat actor groups or APTs 
(state-sponsored or major cybercrime groups) that security teams should know 
about for context, even if not currently most active. For each provide:
- name
- type (APT/Ransomware/Cybercrime/Nation-State)
- origin (suspected country/region if known, else "Unknown")
- activeYears (e.g. "2014-Present")
- notableCampaigns (array of 2-3 well-known campaign/incident names)
- mitreTechniques (array of 4-6 TTP IDs)
- targetedSectors (array)
- description (1-2 sentences)

Respond ONLY with a valid JSON array, no markdown.
Example: [{"name":"APT28","type":"Nation-State","origin":"Russia","activeYears":"2004-Present","notableCampaigns":["DNC Hack 2016","Olympic Destroyer"],"mitreTechniques":["T1566","T1078"],"targetedSectors":["Government","Defense"],"description":"..."}]`
    } else if (mode === 'hypothesis' && actorName) {
      prompt = `Generate a threat hunting hypothesis for the threat actor: ${actorName}.

Available Microsoft Sentinel log sources:
- Fortigate Firewall: CommonSecurityLog where DeviceVendor == "Fortinet"
- Palo Alto Firewall: CommonSecurityLog where DeviceVendor == "Palo Alto Networks"
- Sophos XG: CommonSecurityLog where DeviceVendor == "Sophos"
- Active Directory: SecurityEvent (4624,4625,4688,4698,4720,4732,4769)
- MDE: DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceLogonEvents
- DNS: ASimDnsActivityLogs
- Office 365: OfficeActivity
- Trend Micro: CommonSecurityLog where DeviceVendor == "Trend Micro"

Return ONE hypothesis as JSON:
{
  "id": "LIVE-${Date.now()}",
  "priority": "critical",
  "title": "hypothesis title",
  "tacticChain": "Initial Access -> Execution -> Impact",
  "logSources": ["MDE","SecurityEvents"],
  "description": "2-3 sentences",
  "tags": ["tag1","tag2"],
  "threatActor": "${actorName}",
  "generatedAt": "${new Date().toISOString()}",
  "kqlQueries": [
    {"title":"query title","logSource":"table","severity":"high","mitreTechnique":"T1XXX","kql":"full KQL"}
  ]
}
Return ONLY valid JSON, no markdown.`
    } else if (mode === 'custom' && requirements) {
      prompt = `Generate a threat hunting hypothesis for Microsoft Sentinel based on:
${requirements}

Available log sources:
- Fortigate: CommonSecurityLog (DeviceVendor=="Fortinet")
- Palo Alto: CommonSecurityLog (DeviceVendor=="Palo Alto Networks")
- Sophos: CommonSecurityLog (DeviceVendor=="Sophos")
- AD: SecurityEvent
- MDE: DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents
- DNS: ASimDnsActivityLogs
- O365: OfficeActivity
- Trend Micro: CommonSecurityLog (DeviceVendor=="Trend Micro")

Return ONE hypothesis as JSON:
{
  "id": "CUSTOM-${Date.now()}",
  "priority": "high",
  "title": "title",
  "tacticChain": "chain",
  "logSources": ["array"],
  "description": "description",
  "tags": ["tags"],
  "threatActor": "Custom",
  "generatedAt": "${new Date().toISOString()}",
  "kqlQueries": [{"title":"","logSource":"","severity":"high","mitreTechnique":"","kql":""}]
}
Return ONLY valid JSON, no markdown.`
    } else {
      return res.status(200).json({ success: false, error: 'Invalid mode or missing parameters' })
    }

    const groqRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${groqApiKey}`,
      },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages: [{ role: 'user', content: prompt }],
        temperature: 0.3,
        max_tokens: 3000,
      }),
      signal: AbortSignal.timeout(25000),
    })

    if (!groqRes.ok) {
      const errText = await groqRes.text()
      return res.status(200).json({
        success: false,
        error: `Groq API error: ${groqRes.status} - ${errText.slice(0, 200)}`,
      })
    }

    const groqData = await groqRes.json()
    const text = groqData.choices?.[0]?.message?.content || ''
    const clean = text.replace(/```json|```/g, '').trim()

    let parsed
    try {
      parsed = JSON.parse(clean)
    } catch {
      return res.status(200).json({ success: false, error: 'AI returned invalid JSON - try again' })
    }

    return res.status(200).json({ success: true, data: parsed })
  } catch (e) {
    return res.status(200).json({ success: false, error: e.message })
  }
}
