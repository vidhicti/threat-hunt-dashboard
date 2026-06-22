export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-apikey')
  if (req.method === 'OPTIONS') {
    res.status(200).end()
    return
  }

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
      const r = await fetch('https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset', {
        signal: AbortSignal.timeout(6000),
      })
      if (!r.ok) return res.status(200).json({ success: false, error: `FireHOL HTTP ${r.status}`, iocs: [] })
      const text = await r.text()
      iocs = text.split('\n')
        .filter((l) => l && !l.startsWith('#') && l.match(/^\d+\.\d+\.\d+\.\d+/))
        .slice(0, 150)
        .map((line) => {
          const ip = line.split('/')[0].trim()
          return {
            indicator: ip,
            type: 'IP',
            ttp: 'T1071.001 C2 / High Confidence Malicious',
            ttpId: 'T1071.001',
            source: 'FireHOL Level1',
            logSource: 'CommonSecurityLog',
            confidence: 'High',
            status: 'active',
            dateAdded: today(),
            malwareFamily: 'High Confidence Malicious Network',
            threatType: 'FireHOL Blocklist',
          }
        })
        .filter((i) => i.indicator?.match(/^\d+\.\d+\.\d+\.\d+$/))
    } catch (e) {
      return res.status(200).json({ success: false, error: `FireHOL: ${e.message}`, iocs: [] })
    }
  } else if (feed === 'tornodes') {
    try {
      const r = await fetch('https://check.torproject.org/torbulkexitlist', {
        signal: AbortSignal.timeout(6000),
      })
      if (!r.ok) return res.status(200).json({ success: false, error: `TorNodes HTTP ${r.status}`, iocs: [] })
      const text = await r.text()
      iocs = text.split('\n')
        .filter((l) => l && l.match(/^\d+\.\d+\.\d+\.\d+$/))
        .slice(0, 150)
        .map((ip) => ({
          indicator: ip.trim(),
          type: 'IP',
          ttp: 'T1090.003 Multi-hop Proxy',
          ttpId: 'T1090.003',
          source: 'Tor Exit Nodes',
          logSource: 'CommonSecurityLog',
          confidence: 'Medium',
          status: 'active',
          dateAdded: today(),
          malwareFamily: 'Tor Exit Node',
          threatType: 'Anonymization Proxy',
        }))
    } catch (e) {
      return res.status(200).json({ success: false, error: `TorNodes: ${e.message}`, iocs: [] })
    }
  } else {
    return res.status(400).json({ success: false, error: `Unknown feed: ${feed}`, iocs: [] })
  }

  res.status(200).json({ success: true, count: iocs.length, iocs })
}

function today() {
  return new Date().toISOString().split('T')[0]
}
