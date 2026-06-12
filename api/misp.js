export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-apikey')
  if (req.method === 'OPTIONS') {
    res.status(200).end()
    return
  }

  try {
    const { mispUrl, apiKey, action } = req.method === 'POST' ? req.body : req.query

    if (!mispUrl || !apiKey) {
      return res.status(400).json({ success: false, error: 'Missing mispUrl or apiKey' })
    }

    const baseUrl = mispUrl.replace(/\/$/, '')

    if (action === 'test') {
      // Lightweight test: fetch a single attribute to verify connectivity and auth
      const response = await fetch(`${baseUrl}/attributes/restSearch`, {
        method: 'POST',
        headers: {
          Authorization: apiKey,
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({ returnFormat: 'json', limit: 1, to_ids: 1 }),
      })

      if (response.status === 401 || response.status === 403) {
        return res.status(200).json({ success: false, error: 'Invalid MISP API key' })
      }
      if (!response.ok) {
        return res.status(200).json({ success: false, error: `MISP connection failed: ${response.status}` })
      }

      const data = await response.json()
      const count = data.response?.Attribute?.length ?? 0
      return res.status(200).json({ success: true, count })
    }

    return res.status(400).json({ success: false, error: 'Unknown action' })
  } catch (e) {
    res.status(200).json({ success: false, error: e.message })
  }
}
