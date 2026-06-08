export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
  if (req.method === 'OPTIONS') return res.status(200).end()

  try {
    const { ip, apiKey } = req.method === 'POST' ? req.body : req.query
    if (!ip || !apiKey) return res.status(400).json({ success: false, error: 'Missing ip or apiKey' })

    const response = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${apiKey}`)
    if (response.status === 401) return res.status(200).json({ success: false, error: 'Invalid API key' })
    if (!response.ok) return res.status(200).json({ success: false, error: `Shodan error: ${response.status}` })

    const data = await response.json()
    res.status(200).json({
      success: true,
      result: {
        openPorts: data.ports || [],
        vulns: Object.keys(data.vulns || {}),
        hostnames: data.hostnames || [],
        tags: data.tags || [],
        os: data.os,
        enrichedBy: 'Shodan',
      },
    })
  } catch (e) {
    res.status(200).json({ success: false, error: e.message })
  }
}
