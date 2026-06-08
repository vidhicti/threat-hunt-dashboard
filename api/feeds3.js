export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
  if (req.method === 'OPTIONS') return res.status(200).end()

  const body = req.method === 'POST' ? req.body : {}
  const feed = req.query.feed || body.feed
  const apiKey = body.apiKey || req.query.apiKey
  const t = new Date().toISOString().split('T')[0]

  try {
    let iocs = []

    if (feed === 'alienvault') {
      const r = await fetch('https://reputation.alienvault.com/reputation.generic')
      const text = await r.text()
      iocs = text.split('\n')
        .filter((l) => l && !l.startsWith('#'))
        .slice(0, 300)
        .map((line) => {
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
            dateAdded: t,
            malwareFamily: parts[2]?.trim() || 'Unknown',
            threatType: parts[3]?.trim() || 'Malicious IP',
          }
        })
        .filter((i) => i.indicator?.match(/^\d+\.\d+\.\d+\.\d+$/))
    } else if (feed === 'alienvaultkey' && apiKey) {
      const r = await fetch('https://otx.alienvault.com/api/v1/pulses/subscribed?limit=10&page=1', {
        headers: { 'X-OTX-API-KEY': apiKey },
      })
      if (r.status === 403) return res.status(200).json({ success: false, error: 'Invalid OTX API key', iocs: [] })
      const data = await r.json()
      for (const pulse of (data.results || []).slice(0, 5)) {
        for (const ind of (pulse.indicators || []).slice(0, 50)) {
          const type = ind.type === 'IPv4' ? 'IP' : ind.type === 'domain' ? 'Domain' : ind.type === 'URL' ? 'URL' : ind.type === 'FileHash-SHA256' ? 'SHA256' : 'IP'
          iocs.push({
            indicator: ind.indicator,
            type,
            ttp: pulse.name || 'Unknown',
            ttpId: pulse.attack_ids?.[0]?.id || '',
            source: 'AlienVault OTX (Auth)',
            logSource: type === 'IP' ? 'CommonSecurityLog' : type === 'SHA256' ? 'MDE' : 'ASimDnsActivityLogs',
            confidence: 'Medium',
            status: 'active',
            dateAdded: ind.created?.split('T')[0] || t,
            malwareFamily: pulse.malware_families?.[0]?.display_name || 'Unknown',
            threatType: pulse.name,
          })
        }
      }
    } else if (feed === 'certpoland') {
      const r = await fetch('https://hole.cert.pl/domains/domains.json')
      const data = await r.json()
      iocs = (data || []).slice(0, 300).map((item) => ({
        indicator: typeof item === 'string' ? item : item.DomainAddress,
        type: 'Domain',
        ttp: 'T1566 Phishing / T1071 C2',
        ttpId: 'T1566',
        source: 'CERT Poland',
        logSource: 'ASimDnsActivityLogs',
        confidence: 'High',
        status: 'active',
        dateAdded: item.InsertDate || t,
        malwareFamily: item.Type || 'Phishing',
        threatType: 'Malicious Domain',
      }))
    }

    res.status(200).json({ success: true, count: iocs.length, iocs })
  } catch (e) {
    res.status(200).json({ success: false, error: e.message, iocs: [] })
  }
}
