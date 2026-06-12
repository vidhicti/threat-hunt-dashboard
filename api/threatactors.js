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
    const { groqApiKey, mode, actorName, requirements, logSourceHint } = body

    if (!groqApiKey) {
      return res.status(200).json({ success: false, error: 'Groq API key required' })
    }

    let prompt = ''

    if (mode === 'trends') {
      prompt = `List 10 of the most relevant current cyber threats for a SOC 
threat hunting team, covering ALL of these categories (at least 1 from each 
category where applicable):

1. Ransomware groups (e.g. LockBit, BlackCat, Akira)
2. Nation-state APT groups (e.g. APT28, APT29, Lazarus)
3. Initial Access Brokers (IABs)
4. Banking/financial malware and trojans (e.g. QakBot, IcedID)
5. Infostealers (e.g. RedLine, Lumma, Vidar)
6. Botnets (e.g. Emotet successors, Mirai variants)
7. Phishing-as-a-Service / BEC groups
8. Supply chain compromise campaigns
9. Living-off-the-land / fileless malware campaigns
10. Cloud/SaaS-targeting threats (O365, Azure AD attacks)

For each provide:
- name
- category (one of: "Ransomware","Nation-State APT","Initial Access Broker","Banking Trojan","Infostealer","Botnet","Phishing/BEC","Supply Chain","LOLBin Campaign","Cloud/SaaS Threat")
- type (APT/Ransomware/Cybercrime/Infostealer/Botnet/IAB)
- targetedSectors (array of 2-3)
- recentActivity (1-2 sentences)
- mitreTechniques (array of 4-6 TTP IDs)
- severity (critical/high/medium)
- firstSeen (year)
- relevantLogSources (array from: "MDE","SecurityEvents","CommonSecurityLog-Fortinet","CommonSecurityLog-PaloAlto","CommonSecurityLog-Sophos","CommonSecurityLog-TrendMicro","ASimDnsActivityLogs","OfficeActivity")

Respond ONLY with valid JSON array, no markdown.`
    } else if (mode === 'historical') {
      prompt = `List 12 historically significant and educational threat actor 
groups/campaigns across these categories for SOC reference:

1. Nation-state APTs (Russia, China, Iran, North Korea origin examples)
2. Major ransomware families (historical and evolved)
3. Notorious banking trojans
4. Significant supply chain attacks
5. Major botnets
6. Well-known infostealer operations
7. Historic worm/wiper malware

For each provide:
- name
- category (same categories as above)
- type
- origin (country/region or "Unknown")
- activeYears (e.g. "2014-Present" or "2017-2019")
- notableCampaigns (array of 2-3)
- mitreTechniques (array of 4-6 TTP IDs)
- targetedSectors (array)
- relevantLogSources (array same options as above)
- description (1-2 sentences)

Respond ONLY with valid JSON array, no markdown.`
    } else if (mode === 'hypothesis' && actorName) {
      const logSourceFocus = logSourceHint?.length
        ? `\nFocus the hypothesis specifically on these log sources if possible: ${logSourceHint.join(', ')}`
        : ''
      prompt = `Generate a threat hunting hypothesis for the threat actor: ${actorName}.${logSourceFocus}

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
    } else if (mode === 'vulnerabilities') {
      prompt = `List 10 significant recently disclosed or actively exploited 
vulnerabilities (CVEs) that SOC teams should be hunting for, covering:

1. Actively exploited zero-days
2. Critical CVEs in common enterprise software (Windows, VMware, Citrix, 
   Fortinet, Palo Alto, Microsoft Exchange, etc.)
3. Vulnerabilities with public PoC/exploit code
4. CVEs being used by ransomware groups for initial access

For each provide:
- cveId (e.g. "CVE-2024-XXXXX")
- name (short descriptive name)
- product (affected product/vendor)
- severity (critical/high/medium) 
- cvssScore (number 0-10)
- description (1-2 sentences)
- exploitStatus ("Actively Exploited"/"PoC Available"/"Patch Available")
- affectedVersions (string)
- mitreTechniques (array of 2-4 relevant TTPs like T1190, T1133)
- huntingGuidance (1-2 sentences on what to look for in logs)
- relevantLogSources (array from: "MDE","SecurityEvents","CommonSecurityLog-Fortinet","CommonSecurityLog-PaloAlto","CommonSecurityLog-Sophos","CommonSecurityLog-TrendMicro","ASimDnsActivityLogs","OfficeActivity")
- disclosedPeriod (approximate, e.g. "Late 2024" or "Early 2025")

Respond ONLY with valid JSON array, no markdown.`
    } else if (mode === 'attackcampaigns') {
      prompt = `List 8 significant recent attack campaigns or incidents 
(last 6-12 months) that SOC teams should know about, covering:

1. Major breaches with public attribution
2. Notable ransomware attacks on specific sectors
3. Supply chain compromises
4. Significant phishing/BEC campaigns
5. Critical infrastructure attacks

For each provide:
- name (campaign/incident name)
- category ("Data Breach"/"Ransomware Attack"/"Supply Chain"/"Phishing Campaign"/"Critical Infrastructure"/"Espionage")
- attributedTo (threat actor name if known, else "Unknown")
- targetSector (industry affected)
- summary (2-3 sentences on what happened)
- initialAccessVector (how they got in - e.g. "Phishing email with malicious attachment")
- mitreTechniques (array of 4-6 TTPs used in this campaign)
- relevantLogSources (array same options as above)
- timeframe (approximate, e.g. "Q3 2025")
- severity (critical/high/medium)

Respond ONLY with valid JSON array, no markdown.`
    } else if (mode === 'cvehypothesis' && actorName) {
      prompt = `Generate a threat hunting hypothesis for detecting exploitation 
attempts of ${actorName} in a Microsoft Sentinel environment.

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
  "id": "CVE-${Date.now()}",
  "priority": "critical",
  "title": "title mentioning the CVE",
  "tacticChain": "Initial Access -> ...",
  "logSources": ["array"],
  "description": "description including exploitation indicators",
  "tags": ["cve","exploit-detection"],
  "threatActor": "${actorName}",
  "generatedAt": "${new Date().toISOString()}",
  "kqlQueries": [{"title":"","logSource":"","severity":"critical","mitreTechnique":"","kql":""}]
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
        max_tokens: 4000,
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
