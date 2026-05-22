export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  if (req.method === 'OPTIONS') return res.status(200).end()
  try {
    const response = await fetch('https://reputation.alienvault.com/reputation.generic')
    const text = await response.text()
    const today = new Date().toISOString().split('T')[0]
    const iocs = text.split('\n')
      .filter(l => l && !l.startsWith('#'))
      .slice(0, 300)
      .map(line => {
        const parts = line.split('#')
        return {
          indicator: parts[0]?.trim(),
          type: 'IP',
          ttp: 'T1071 C2',
          ttpId: 'T1071',
          source: 'AlienVault OTX',
          logSource: 'CommonSecurityLog',
          confidence: 'Medium',
          status: 'active',
          dateAdded: today,
          malwareFamily: parts[2]?.trim() || 'Unknown',
          threatType: parts[3]?.trim() || 'Malicious IP'
        }
      })
      .filter(i => i.indicator?.match(/^\d+\.\d+\.\d+\.\d+$/))
    res.status(200).json({ success: true, count: iocs.length, iocs })
  } catch(e) {
    res.status(500).json({ success: false, error: e.message, iocs: [] })
  }
}
