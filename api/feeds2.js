export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
  if (req.method === 'OPTIONS') return res.status(200).end()

  const feed = req.query.feed || req.body?.feed
  const t = new Date().toISOString().split('T')[0]

  try {
    let iocs = []

    if (feed === 'emergingthreats') {
      const r = await fetch('https://rules.emergingthreats.net/blockrules/compromised-ips.txt')
      const text = await r.text()
      iocs = text.split('\n')
        .filter((l) => l && !l.startsWith('#') && l.match(/^\d+\.\d+\.\d+\.\d+/))
        .slice(0, 300)
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
    } else if (feed === 'cinsarmy') {
      const r = await fetch('https://cinsscore.com/list/ci-badguys.txt')
      const text = await r.text()
      iocs = text.split('\n')
        .filter((l) => l && !l.startsWith('#') && l.match(/^\d+\.\d+\.\d+\.\d+/))
        .slice(0, 300)
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
    } else if (feed === 'sslblacklist') {
      const urls = [
        'https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.json',
        'https://sslbl.abuse.ch/blacklist/sslipblacklist.json',
      ]
      for (const url of urls) {
        try {
          const r = await fetch(url, {
            headers: { 'User-Agent': 'threat-hunt-dashboard/1.0' },
            signal: AbortSignal.timeout(8000),
          })
          if (!r.ok) continue
          const data = await r.json()
          const list = data.blacklist || []
          if (list.length > 0) {
            iocs = list.map((item) => ({
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
            })).filter((i) => i.indicator?.match(/^\d+\.\d+\.\d+\.\d+$/))
            break
          }
        } catch {
          continue
        }
      }
    }

    res.status(200).json({ success: true, count: iocs.length, iocs })
  } catch (e) {
    res.status(200).json({ success: false, error: e.message, iocs: [] })
  }
}
