export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  if (req.method === 'OPTIONS') return res.status(200).end()
  try {
    const response = await fetch('https://urlhaus-api.abuse.ch/v1/urls/recent/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: 'get_urls', limit: 200 })
    })
    const data = await response.json()
    const iocs = (data.urls || []).map(u => ({
      indicator: u.url,
      type: 'URL',
      ttp: 'T1566.002 Phishing Link',
      ttpId: 'T1566.002',
      source: 'URLhaus',
      logSource: 'ASimDnsActivityLogs',
      confidence: 'High',
      status: u.url_status === 'online' ? 'active' : 'watchlist',
      dateAdded: u.date_added?.split(' ')[0],
      malwareFamily: u.tags?.join(', ') || 'Unknown',
      threatType: 'Malware Distribution'
    }))
    res.status(200).json({ success: true, count: iocs.length, iocs })
  } catch(e) {
    res.status(500).json({ success: false, error: e.message, iocs: [] })
  }
}
