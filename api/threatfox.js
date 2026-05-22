export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
  if (req.method === 'OPTIONS') return res.status(200).end()
  try {
    const response = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: 'get_iocs', days: 7 })
    })
    const data = await response.json()
    const iocs = (data.data || []).slice(0, 300).map(ioc => ({
      indicator: ioc.ioc,
      type: ioc.ioc_type,
      ttp: ioc.malware || 'Unknown',
      ttpId: ioc.tags?.[0] || '',
      source: 'ThreatFox',
      logSource: mapLogSource(ioc.ioc_type),
      confidence: ioc.confidence_level > 70 ? 'High' : ioc.confidence_level > 40 ? 'Medium' : 'Low',
      status: 'active',
      dateAdded: ioc.first_seen?.split(' ')[0] || new Date().toISOString().split('T')[0],
      malwareFamily: ioc.malware,
      threatType: ioc.threat_type,
      reporter: ioc.reporter
    }))
    res.status(200).json({ success: true, count: iocs.length, iocs })
  } catch(e) {
    res.status(500).json({ success: false, error: e.message, iocs: [] })
  }
}
function mapLogSource(type) {
  if (!type) return 'CommonSecurityLog'
  if (type.includes('ip')) return 'CommonSecurityLog'
  if (type.includes('domain') || type.includes('url')) return 'ASimDnsActivityLogs'
  if (type.includes('sha') || type.includes('md5')) return 'MDE'
  return 'CommonSecurityLog'
}
