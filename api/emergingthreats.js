export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  if (req.method === 'OPTIONS') return res.status(200).end()
  try {
    const response = await fetch('https://rules.emergingthreats.net/blockrules/compromised-ips.txt')
    const text = await response.text()
    const today = new Date().toISOString().split('T')[0]
    const iocs = text.split('\n')
      .filter(l => l && !l.startsWith('#') && l.match(/^\d+\.\d+\.\d+\.\d+/))
      .slice(0, 300)
      .map(line => ({
        indicator: line.trim(),
        type: 'IP',
        ttp: 'T1071 C2',
        ttpId: 'T1071',
        source: 'EmergingThreats',
        logSource: 'CommonSecurityLog',
        confidence: 'High',
        status: 'active',
        dateAdded: today,
        malwareFamily: 'Compromised Host',
        threatType: 'Compromised IP'
      }))
    res.status(200).json({ success: true, count: iocs.length, iocs })
  } catch(e) {
    res.status(500).json({ success: false, error: e.message, iocs: [] })
  }
}
