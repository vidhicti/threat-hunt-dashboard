export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-apikey')
  if (req.method === 'OPTIONS') return res.status(200).end()

  try {
    const { indicator, type, apiKey } = req.method === 'POST'
      ? req.body
      : req.query

    if (!indicator || !apiKey) {
      return res.status(400).json({ success: false, error: 'Missing indicator or apiKey' })
    }

    let url
    if (type === 'IP') url = `https://www.virustotal.com/api/v3/ip_addresses/${indicator}`
    else if (type === 'Domain') url = `https://www.virustotal.com/api/v3/domains/${indicator}`
    else if (type === 'SHA256') url = `https://www.virustotal.com/api/v3/files/${indicator}`
    else if (type === 'URL') {
      const encoded = Buffer.from(indicator).toString('base64').replace(/=/g, '')
      url = `https://www.virustotal.com/api/v3/urls/${encoded}`
    } else {
      return res.status(400).json({ success: false, error: 'Unknown type' })
    }

    const response = await fetch(url, {
      headers: { 'x-apikey': apiKey },
    })

    if (response.status === 401) return res.status(200).json({ success: false, error: 'Invalid API key' })
    if (response.status === 429) return res.status(200).json({ success: false, error: 'Rate limit exceeded - 4 lookups/min on free tier' })
    if (!response.ok) return res.status(200).json({ success: false, error: `VT API error: ${response.status}` })

    const data = await response.json()
    const stats = data.data?.attributes?.last_analysis_stats || {}
    const total = (stats.malicious || 0) + (stats.suspicious || 0) + (stats.undetected || 0) + (stats.harmless || 0)

    res.status(200).json({
      success: true,
      result: {
        vtMalicious: stats.malicious || 0,
        vtSuspicious: stats.suspicious || 0,
        vtTotal: total,
        vtScore: `${stats.malicious || 0}/${total}`,
        reputation: data.data?.attributes?.reputation,
        categories: data.data?.attributes?.categories,
        enrichedBy: 'VirusTotal',
      },
    })
  } catch (e) {
    res.status(200).json({ success: false, error: e.message })
  }
}
