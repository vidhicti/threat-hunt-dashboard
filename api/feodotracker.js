export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  if (req.method === 'OPTIONS') return res.status(200).end()
  try {
    const response = await fetch('https://feodotracker.abuse.ch/downloads/ipblocklist.json')
    const data = await response.json()
    const iocs = (data || []).slice(0, 300).map(item => ({
      indicator: item.ip_address,
      type: 'IP',
      ttp: 'T1071 C2 Botnet',
      ttpId: 'T1071',
      source: 'FeodoTracker',
      logSource: 'CommonSecurityLog',
      confidence: 'High',
      status: item.status === 'online' ? 'active' : 'watchlist',
      dateAdded: item.first_seen?.split(' ')[0],
      malwareFamily: item.malware,
      threatType: 'Botnet C2',
      port: item.port
    }))
    res.status(200).json({ success: true, count: iocs.length, iocs })
  } catch(e) {
    res.status(500).json({ success: false, error: e.message, iocs: [] })
  }
}
