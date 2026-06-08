export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
  if (req.method === 'OPTIONS') return res.status(200).end()

  const feed = req.query.feed || req.body?.feed

  try {
    let iocs = []

    if (feed === 'threatfox') {
      const r = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: 'get_iocs', days: 3 }),
        signal: AbortSignal.timeout(8000),
      })
      const data = await r.json()
      iocs = (data.data || []).slice(0, 200).map((ioc) => ({
        indicator: ioc.ioc,
        type: ioc.ioc_type,
        ttp: ioc.malware || 'Unknown',
        ttpId: ioc.tags?.[0] || '',
        source: 'ThreatFox',
        logSource: mapLogSource(ioc.ioc_type),
        confidence: ioc.confidence_level > 70 ? 'High' : ioc.confidence_level > 40 ? 'Medium' : 'Low',
        status: 'active',
        dateAdded: ioc.first_seen?.split(' ')[0] || today(),
        malwareFamily: ioc.malware,
        threatType: ioc.threat_type,
      }))
    } else if (feed === 'urlhaus') {
      const r = await fetch('https://urlhaus-api.abuse.ch/v1/urls/recent/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: 'get_urls', limit: 100 }),
        signal: AbortSignal.timeout(8000),
      })
      const data = await r.json()
      iocs = (data.urls || []).map((u) => ({
        indicator: u.url,
        type: 'URL',
        ttp: 'T1566.002 Phishing Link',
        ttpId: 'T1566.002',
        source: 'URLhaus',
        logSource: 'ASimDnsActivityLogs',
        confidence: 'High',
        status: u.url_status === 'online' ? 'active' : 'watchlist',
        dateAdded: u.date_added?.split(' ')[0] || today(),
        malwareFamily: u.tags?.join(', ') || 'Unknown',
        threatType: 'Malware Distribution',
      }))
    } else if (feed === 'feodotracker') {
      const r = await fetch('https://feodotracker.abuse.ch/downloads/ipblocklist.json', {
        signal: AbortSignal.timeout(8000),
      })
      const data = await r.json()
      iocs = (data || []).slice(0, 200).map((item) => ({
        indicator: item.ip_address,
        type: 'IP',
        ttp: 'T1071 C2 Botnet',
        ttpId: 'T1071',
        source: 'FeodoTracker',
        logSource: 'CommonSecurityLog',
        confidence: 'High',
        status: item.status === 'online' ? 'active' : 'watchlist',
        dateAdded: item.first_seen?.split(' ')[0] || today(),
        malwareFamily: item.malware,
        threatType: 'Botnet C2',
        port: item.port,
      }))
    } else if (feed === 'malwarebazaar') {
      const r = await fetch('https://mb-api.abuse.ch/api/v1/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: 'get_recent', selector: '100' }),
        signal: AbortSignal.timeout(8000),
      })
      const data = await r.json()
      iocs = (data.data || []).map((item) => ({
        indicator: item.sha256_hash,
        type: 'SHA256',
        ttp: 'T1204 Malicious File',
        ttpId: 'T1204',
        source: 'MalwareBazaar',
        logSource: 'MDE',
        confidence: 'High',
        status: 'active',
        dateAdded: item.first_seen?.split(' ')[0] || today(),
        malwareFamily: item.tags?.join(', ') || item.signature || 'Unknown',
        threatType: 'Malware Sample',
        fileName: item.file_name,
        fileType: item.file_type,
      }))
    }

    res.status(200).json({ success: true, count: iocs.length, iocs })
  } catch (e) {
    res.status(200).json({ success: false, error: e.message, iocs: [] })
  }
}

function mapLogSource(type) {
  if (!type) return 'CommonSecurityLog'
  if (type.includes('ip')) return 'CommonSecurityLog'
  if (type.includes('domain') || type.includes('url')) return 'ASimDnsActivityLogs'
  if (type.includes('sha') || type.includes('md5')) return 'MDE'
  return 'CommonSecurityLog'
}

function today() {
  return new Date().toISOString().split('T')[0]
}
