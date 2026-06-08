export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
  if (req.method === 'OPTIONS') return res.status(200).end()

  try {
    const { ip, apiKey } = req.method === 'POST' ? req.body : req.query

    if (!ip || !apiKey) return res.status(400).json({ success: false, error: 'Missing ip or apiKey' })

    const response = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose`,
      { headers: { Key: apiKey, Accept: 'application/json' } }
    )

    if (response.status === 401) return res.status(200).json({ success: false, error: 'Invalid API key' })
    if (response.status === 429) return res.status(200).json({ success: false, error: 'Daily limit reached' })
    if (!response.ok) return res.status(200).json({ success: false, error: `API error: ${response.status}` })

    const data = await response.json()
    const d = data.data || {}

    res.status(200).json({
      success: true,
      result: {
        abuseScore: d.abuseConfidenceScore,
        totalReports: d.totalReports,
        lastReported: d.lastReportedAt,
        isTor: d.isTor,
        usageType: d.usageType,
        isp: d.isp,
        domain: d.domain,
        countryCode: d.countryCode,
        enrichedBy: 'AbuseIPDB',
      },
    })
  } catch (e) {
    res.status(200).json({ success: false, error: e.message })
  }
}
