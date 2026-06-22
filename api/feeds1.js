export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-apikey')
  if (req.method === 'OPTIONS') {
    res.status(200).end()
    return
  }

  const feed = req.query.feed || req.body?.feed

  let iocs = []

  if (feed === 'threatfox') {
    try {
      const r = await fetch('https://www.spamhaus.org/drop/drop.txt', {
        signal: AbortSignal.timeout(6000),
      })
      if (!r.ok) return res.status(200).json({ success: false, error: `Spamhaus HTTP ${r.status}`, iocs: [] })
      const text = await r.text()
      iocs = text.split('\n')
        .filter((l) => l && !l.startsWith(';') && l.includes('/'))
        .slice(0, 150)
        .map((line) => {
          const ip = line.split(';')[0].trim().split('/')[0]
          return {
            indicator: ip,
            type: 'IP',
            ttp: 'T1071 C2 / Spam Network',
            ttpId: 'T1071',
            source: 'Spamhaus DROP',
            logSource: 'CommonSecurityLog',
            confidence: 'High',
            status: 'active',
            dateAdded: today(),
            malwareFamily: 'Known Bad Network',
            threatType: 'Spamhaus DROP',
          }
        })
        .filter((i) => i.indicator?.match(/^\d+\.\d+\.\d+\.\d+$/))
    } catch (e) {
      return res.status(200).json({ success: false, error: `Spamhaus: ${e.message}`, iocs: [] })
    }

  } else if (feed === 'urlhaus') {
    try {
      const r = await fetch('https://lists.blocklist.de/lists/all.txt', {
        signal: AbortSignal.timeout(6000),
      })
      if (!r.ok) return res.status(200).json({ success: false, error: `Blocklist.de HTTP ${r.status}`, iocs: [] })
      const text = await r.text()
      iocs = text.split('\n')
        .filter((l) => l && l.match(/^\d+\.\d+\.\d+\.\d+$/))
        .slice(0, 150)
        .map((ip) => ({
          indicator: ip.trim(),
          type: 'IP',
          ttp: 'T1110 Brute Force / Attack Source',
          ttpId: 'T1110',
          source: 'Blocklist.de',
          logSource: 'CommonSecurityLog',
          confidence: 'Medium',
          status: 'active',
          dateAdded: today(),
          malwareFamily: 'Attack Source',
          threatType: 'Brute Force / Scanning',
        }))
    } catch (e) {
      return res.status(200).json({ success: false, error: `Blocklist.de: ${e.message}`, iocs: [] })
    }

  } else if (feed === 'feodotracker') {
    try {
      const r = await fetch('https://feodotracker.abuse.ch/downloads/ipblocklist.json', {
        signal: AbortSignal.timeout(6000),
      })
      if (!r.ok) return res.status(200).json({ success: false, error: `FeodoTracker HTTP ${r.status}`, iocs: [] })
      const data = await r.json()
      iocs = (data || []).slice(0, 100).map((item) => ({
        indicator: item.ip_address,
        type: 'IP',
        ttp: 'T1071 C2 Botnet',
        ttpId: 'T1071',
        source: 'FeodoTracker',
        logSource: 'CommonSecurityLog',
        confidence: 'High',
        status: item.status === 'online' ? 'active' : 'watchlist',
        dateAdded: item.first_seen?.split(' ')[0] || today(),
        malwareFamily: item.malware,
        threatType: 'Botnet C2',
        port: item.port,
      }))
    } catch (e) {
      return res.status(200).json({ success: false, error: `FeodoTracker: ${e.message}`, iocs: [] })
    }

  } else if (feed === 'malwarebazaar') {
    try {
      // Try VirusShare hash feed (no auth, public)
      const r = await fetch('https://virusshare.com/hashfiles/VirusShare_00498.md5', {
        signal: AbortSignal.timeout(6000),
      })
      if (r.ok) {
        const text = await r.text()
        iocs = text.split('\n')
          .filter((l) => l && !l.startsWith('#') && l.match(/^[a-f0-9]{32}$/i))
          .slice(0, 100)
          .map((hash) => ({
            indicator: hash.trim(),
            type: 'MD5',
            ttp: 'T1204.002 Malicious File',
            ttpId: 'T1204.002',
            source: 'VirusShare',
            logSource: 'MDE',
            confidence: 'Medium',
            status: 'active',
            dateAdded: today(),
            malwareFamily: 'VirusShare Sample',
            threatType: 'Malware Hash',
          }))
      }
      // If VirusShare fails, try OpenPhish for URLs instead
      if (iocs.length === 0) {
        const r2 = await fetch('https://openphish.com/feed.txt', {
          signal: AbortSignal.timeout(6000),
        })
        if (r2.ok) {
          const text = await r2.text()
          iocs = text.split('\n')
            .filter((l) => l && l.startsWith('http'))
            .slice(0, 100)
            .map((url) => ({
              indicator: url.trim(),
              type: 'URL',
              ttp: 'T1566.002 Phishing Link',
              ttpId: 'T1566.002',
              source: 'OpenPhish',
              logSource: 'ASimDnsActivityLogs',
              confidence: 'High',
              status: 'active',
              dateAdded: today(),
              malwareFamily: 'Phishing URL',
              threatType: 'Phishing',
            }))
        }
      }
    } catch (e) {
      return res.status(200).json({ success: false, error: `Hash feed: ${e.message}`, iocs: [] })
    }

  } else {
    return res.status(400).json({ success: false, error: `Unknown feed: ${feed}`, iocs: [] })
  }

  res.status(200).json({ success: true, count: iocs.length, iocs })
}

function today() {
  return new Date().toISOString().split('T')[0]
}
