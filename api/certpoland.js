export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  if (req.method === 'OPTIONS') return res.status(200).end()
  try {
    const response = await fetch('https://hole.cert.pl/domains/domains.json')
    const data = await response.json()
    const today = new Date().toISOString().split('T')[0]
    const iocs = (data || []).slice(0, 300).map(item => ({
      indicator: typeof item === 'string' ? item : item.DomainAddress,
      type: 'Domain',
      ttp: 'T1566 Phishing / T1071 C2',
      ttpId: 'T1566',
      source: 'CERT Poland',
      logSource: 'ASimDnsActivityLogs',
      confidence: 'High',
      status: 'active',
      dateAdded: item.InsertDate || today,
      malwareFamily: item.Type || 'Phishing',
      threatType: 'Malicious Domain'
    }))
    res.status(200).json({ success: true, count: iocs.length, iocs })
  } catch(e) {
    res.status(500).json({ success: false, error: e.message, iocs: [] })
  }
}
