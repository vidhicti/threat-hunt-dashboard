export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
  if (req.method === 'OPTIONS') return res.status(200).end()

  try {
    const { apiKey } = req.method === 'POST' ? req.body : req.query
    if (!apiKey) return res.status(400).json({ success: false, error: 'Missing apiKey' })

    const response = await fetch('https://otx.alienvault.com/api/v1/pulses/subscribed?limit=10&page=1', {
      headers: { 'X-OTX-API-KEY': apiKey },
    })
    if (response.status === 403) return res.status(200).json({ success: false, error: 'Invalid OTX API key' })
    if (!response.ok) return res.status(200).json({ success: false, error: `OTX error: ${response.status}` })

    const data = await response.json()
    const iocs = []

    for (const pulse of (data.results || []).slice(0, 5)) {
      for (const indicator of (pulse.indicators || []).slice(0, 50)) {
        iocs.push({
          indicator: indicator.indicator,
          type: mapOTXType(indicator.type),
          ttp: pulse.name || 'Unknown',
          ttpId: pulse.attack_ids?.[0]?.id || '',
          source: 'AlienVault OTX',
          logSource: mapOTXLogSource(indicator.type),
          confidence: 'Medium',
          status: 'active',
          dateAdded: indicator.created?.split('T')[0] || new Date().toISOString().split('T')[0],
          malwareFamily: pulse.malware_families?.[0]?.display_name || 'Unknown',
          threatType: pulse.name,
        })
      }
    }

    res.status(200).json({ success: true, count: iocs.length, iocs })
  } catch (e) {
    res.status(200).json({ success: false, error: e.message })
  }
}

function mapOTXType(type) {
  if (type === 'IPv4' || type === 'IPv6') return 'IP'
  if (type === 'domain' || type === 'hostname') return 'Domain'
  if (type === 'URL') return 'URL'
  if (type === 'FileHash-SHA256') return 'SHA256'
  if (type === 'FileHash-MD5') return 'MD5'
  return type
}

function mapOTXLogSource(type) {
  if (type === 'IPv4' || type === 'IPv6') return 'CommonSecurityLog'
  if (type === 'domain' || type === 'hostname' || type === 'URL') return 'ASimDnsActivityLogs'
  return 'MDE'
}
