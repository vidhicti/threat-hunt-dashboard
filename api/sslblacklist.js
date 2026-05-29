const FETCH_OPTS = {
  headers: { 'User-Agent': 'threat-hunt-dashboard/1.0' },
  signal: AbortSignal.timeout(8000),
}

function mapSslItem(item) {
  return {
    indicator: item.Destination || item.destination,
    type: 'IP',
    ttp: 'T1071.001 C2 over SSL',
    ttpId: 'T1071.001',
    source: 'SSL Blacklist',
    logSource: 'CommonSecurityLog',
    confidence: 'High',
    status: 'active',
    dateAdded: item.Listingdate?.split(' ')[0] || new Date().toISOString().split('T')[0],
    malwareFamily: item.Listingreason || item.listingreason,
    threatType: 'SSL C2',
    port: item.DstPort || item.dstport,
  }
}

function mapFeodoItem(item) {
  const ip = typeof item === 'string' ? item : (item.ip_address || item.IP || item.indicator)
  if (!ip) return null
  return {
    indicator: ip,
    type: 'IP',
    ttp: 'T1071.001 C2 over SSL',
    ttpId: 'T1071.001',
    source: 'SSL Blacklist',
    logSource: 'CommonSecurityLog',
    confidence: 'High',
    status: 'active',
    dateAdded: item.last_online?.split(' ')[0] || new Date().toISOString().split('T')[0],
    malwareFamily: item.malware || 'FeodoTracker fallback',
    threatType: 'SSL C2',
    port: item.port,
  }
}

async function tryFetchList(url, mapper) {
  const r = await fetch(url, FETCH_OPTS)
  if (!r.ok) return []
  const data = await r.json()
  const list = data.blacklist || data.results || (Array.isArray(data) ? data : [])
  if (list.length === 0) return []
  return list.map(mapper).filter((ioc) => ioc?.indicator)
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  if (req.method === 'OPTIONS') return res.status(200).end()

  const urls = [
    'https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.json',
    'https://sslbl.abuse.ch/blacklist/sslipblacklist.json',
  ]

  try {
    for (const url of urls) {
      try {
        const iocs = await tryFetchList(url, mapSslItem)
        if (iocs.length > 0) {
          return res.status(200).json({ success: true, count: iocs.length, iocs })
        }
      } catch {
        continue
      }
    }

    try {
      const iocs = await tryFetchList(
        'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
        mapFeodoItem
      )
      if (iocs.length > 0) {
        return res.status(200).json({ success: true, count: iocs.length, iocs })
      }
    } catch {
      // fall through to empty response
    }

    return res.status(200).json({ success: true, count: 0, iocs: [] })
  } catch {
    return res.status(200).json({ success: true, count: 0, iocs: [] })
  }
}
