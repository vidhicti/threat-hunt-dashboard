export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
  if (req.method === 'OPTIONS') return res.status(200).end()

  const feed = req.query.feed || req.body?.feed
  const t = new Date().toISOString().split('T')[0]

  let iocs = []

  if (feed === 'emergingthreats') {
    try {
      const r = await fetch('https://rules.emergingthreats.net/blockrules/compromised-ips.txt', {
        signal: AbortSignal.timeout(6000),
      })
      if (!r.ok) return res.status(200).json({ success: false, error: `EmergingThreats HTTP ${r.status}`, iocs: [] })
      const text = await r.text()
      iocs = text.split('\n')
        .filter((l) => l && !l.startsWith('#') && l.match(/^\d+\.\d+\.\d+\.\d+/))
        .slice(0, 100)
        .map((line) => ({
          indicator: line.trim(),
          type: 'IP',
          ttp: 'T1071 C2',
          ttpId: 'T1071',
          source: 'EmergingThreats',
          logSource: 'CommonSecurityLog',
          confidence: 'High',
          status: 'active',
          dateAdded: t,
          malwareFamily: 'Compromised Host',
          threatType: 'Compromised IP',
        }))
    } catch (e) {
      return res.status(200).json({ success: false, error: `EmergingThreats: ${e.message}`, iocs: [] })
    }
  } else if (feed === 'cinsarmy') {
    try {
      const r = await fetch('https://cinsscore.com/list/ci-badguys.txt', {
        signal: AbortSignal.timeout(6000),
      })
      if (!r.ok) return res.status(200).json({ success: false, error: `CINS Army HTTP ${r.status}`, iocs: [] })
      const text = await r.text()
      iocs = text.split('\n')
        .filter((l) => l && !l.startsWith('#') && l.match(/^\d+\.\d+\.\d+\.\d+/))
        .slice(0, 100)
        .map((ip) => ({
          indicator: ip.trim(),
          type: 'IP',
          ttp: 'T1190 External Exploit',
          ttpId: 'T1190',
          source: 'CINS Army',
          logSource: 'CommonSecurityLog',
          confidence: 'Medium',
          status: 'active',
          dateAdded: t,
          malwareFamily: 'Bad Actor',
          threatType: 'Malicious IP',
        }))
    } catch (e) {
      return res.status(200).json({ success: false, error: `CINS Army: ${e.message}`, iocs: [] })
    }
  } else if (feed === 'sslblacklist') {
    try {
      const r = await fetch('https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.json', {
        headers: { 'User-Agent': 'threat-hunt-dashboard/1.0' },
        signal: AbortSignal.timeout(6000),
      })
      if (!r.ok) return res.status(200).json({ success: false, error: `SSL Blacklist HTTP ${r.status}`, iocs: [] })
      const data = await r.json()
      iocs = (data.blacklist || [])
        .slice(0, 100)
        .map((item) => ({
          indicator: item.Destination,
          type: 'IP',
          ttp: 'T1071.001 C2 over SSL',
          ttpId: 'T1071.001',
          source: 'SSL Blacklist',
          logSource: 'CommonSecurityLog',
          confidence: 'High',
          status: 'active',
          dateAdded: item.Listingdate?.split(' ')[0] || t,
          malwareFamily: item.Listingreason || 'SSL C2',
          threatType: 'SSL C2',
          port: item.DstPort,
        }))
        .filter((i) => i.indicator?.match(/^\d+\.\d+\.\d+\.\d+$/))
    } catch (e) {
      return res.status(200).json({ success: false, error: `SSL Blacklist: ${e.message}`, iocs: [] })
    }
  } else {
    return res.status(400).json({ success: false, error: `Unknown feed: ${feed}`, iocs: [] })
  }

  res.status(200).json({ success: true, count: iocs.length, iocs })
}
