export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-apikey')
  if (req.method === 'OPTIONS') {
    res.status(200).end()
    return
  }

  const feed = req.query.feed || req.body?.feed

  let iocs = []

  if (feed === 'threatfox') {
    try {
      const r = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
        method: 'POST',
        headers: getAbuseChHeaders(),
        body: JSON.stringify({ query: 'get_iocs', days: 1 }),
        signal: AbortSignal.timeout(6000),
      })
      if (r.status === 401) {
        return res.status(200).json({
          success: false,
          error: 'ThreatFox requires free Auth-Key registration at auth.abuse.ch - add ABUSECH_AUTH_KEY env var',
          iocs: [],
        })
      }
      if (!r.ok) return res.status(200).json({ success: false, error: `ThreatFox HTTP ${r.status}`, iocs: [] })
      const data = await r.json()
      iocs = (data.data || []).slice(0, 100).map((ioc) => ({
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
    } catch (e) {
      return res.status(200).json({ success: false, error: `ThreatFox: ${e.message}`, iocs: [] })
    }

  } else if (feed === 'urlhaus') {
    try {
      const r = await fetch('https://urlhaus-api.abuse.ch/v1/urls/recent/', {
        method: 'POST',
        headers: getAbuseChHeaders(),
        body: JSON.stringify({ query: 'get_urls', limit: 50 }),
        signal: AbortSignal.timeout(6000),
      })
      if (r.status === 401) {
        return res.status(200).json({
          success: false,
          error: 'URLhaus requires free Auth-Key registration at auth.abuse.ch - add ABUSECH_AUTH_KEY env var',
          iocs: [],
        })
      }
      if (!r.ok) return res.status(200).json({ success: false, error: `URLhaus HTTP ${r.status}`, iocs: [] })
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
    } catch (e) {
      return res.status(200).json({ success: false, error: `URLhaus: ${e.message}`, iocs: [] })
    }

  } else if (feed === 'feodotracker') {
    try {
      const r = await fetch('https://feodotracker.abuse.ch/downloads/ipblocklist.json', {
        signal: AbortSignal.timeout(6000),
      })
      if (!r.ok) return res.status(200).json({ success: false, error: `FeodoTracker HTTP ${r.status}`, iocs: [] })
      const data = await r.json()
      iocs = (data || []).slice(0, 100).map((item) => ({
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
    } catch (e) {
      return res.status(200).json({ success: false, error: `FeodoTracker: ${e.message}`, iocs: [] })
    }

  } else if (feed === 'malwarebazaar') {
    try {
      const r = await fetch('https://mb-api.abuse.ch/api/v1/', {
        method: 'POST',
        headers: getAbuseChHeaders(),
        body: JSON.stringify({ query: 'get_recent', selector: '50' }),
        signal: AbortSignal.timeout(6000),
      })
      if (r.status === 401) {
        return res.status(200).json({
          success: false,
          error: 'MalwareBazaar requires free Auth-Key registration at auth.abuse.ch - add ABUSECH_AUTH_KEY env var',
          iocs: [],
        })
      }
      if (!r.ok) return res.status(200).json({ success: false, error: `MalwareBazaar HTTP ${r.status}`, iocs: [] })
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
    } catch (e) {
      return res.status(200).json({ success: false, error: `MalwareBazaar: ${e.message}`, iocs: [] })
    }

  } else {
    return res.status(400).json({ success: false, error: `Unknown feed: ${feed}`, iocs: [] })
  }

  res.status(200).json({ success: true, count: iocs.length, iocs })
}

function getAbuseChHeaders() {
  const headers = { 'Content-Type': 'application/json', Accept: 'application/json' }
  if (process.env.ABUSECH_AUTH_KEY) {
    headers['Auth-Key'] = process.env.ABUSECH_AUTH_KEY
  }
  return headers
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
