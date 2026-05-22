export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  if (req.method === 'OPTIONS') return res.status(200).end()
  try {
    const response = await fetch('https://cinsscore.com/list/ci-badguys.txt')
    const text = await response.text()
    const today = new Date().toISOString().split('T')[0]
    const iocs = text.split('\n')
      .filter(l => l && !l.startsWith('#') && l.match(/^\d+\.\d+\.\d+\.\d+/))
      .slice(0, 300)
      .map(ip => ({
        indicator: ip.trim(),
        type: 'IP',
        ttp: 'T1190 External Exploit',
        ttpId: 'T1190',
        source: 'CINS Army',
        logSource: 'CommonSecurityLog',
        confidence: 'Medium',
        status: 'active',
        dateAdded: today,
        malwareFamily: 'Bad Actor',
        threatType: 'Malicious IP'
      }))
    res.status(200).json({ success: true, count: iocs.length, iocs })
  } catch(e) {
    res.status(500).json({ success: false, error: e.message, iocs: [] })
  }
}
