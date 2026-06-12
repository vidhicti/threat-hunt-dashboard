export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-apikey')
  if (req.method === 'OPTIONS') {
    res.status(200).end()
    return
  }

  try {
    const { openctiUrl, apiKey, action } = req.method === 'POST' ? req.body : req.query

    if (!openctiUrl || !apiKey) {
      return res.status(400).json({ success: false, error: 'Missing openctiUrl or apiKey' })
    }

    const baseUrl = openctiUrl.replace(/\/$/, '')

    if (action === 'test') {
      const response = await fetch(`${baseUrl}/graphql`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ query: '{ about { version } }' }),
      })

      if (response.status === 401 || response.status === 403) {
        return res.status(200).json({ success: false, error: 'Invalid OpenCTI API token' })
      }
      if (!response.ok) {
        return res.status(200).json({ success: false, error: `OpenCTI connection failed: ${response.status}` })
      }

      return res.status(200).json({ success: true })
    }

    return res.status(400).json({ success: false, error: 'Unknown action' })
  } catch (e) {
    res.status(200).json({ success: false, error: e.message })
  }
}
