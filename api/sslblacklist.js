export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  if (req.method === 'OPTIONS') return res.status(200).end()
  try {
    const response = await fetch('https://sslbl.abuse.ch/blacklist/sslipblacklist.json')
    const data = await response.json()
    const iocs = (data.blacklist || []).map(item => ({
      indicator: item.Destination,
      type: 'IP',
      ttp: 'T1071.001 C2 over SSL',
      ttpId: 'T1071.001',
      source: 'SSL Blacklist',
      logSource: 'CommonSecurityLog',
      confidence: 'High',
      status: 'active',
      dateAdded: item.Listingdate?.split(' ')[0],
      malwareFamily: item.Listingreason,
      threatType: 'SSL C2',
      port: item.DstPort
    }))
    res.status(200).json({ success: true, count: iocs.length, iocs })
  } catch(e) {
    res.status(500).json({ success: false, error: e.message, iocs: [] })
  }
}
