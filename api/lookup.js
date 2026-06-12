export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-apikey')
  if (req.method === 'OPTIONS') {
    res.status(200).end()
    return
  }

  try {
    const body = req.method === 'POST' ? req.body : req.query
    const { type, indicator } = body

    if (type === 'threatfox') {
      const r = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: 'search_ioc', search_term: indicator }),
        signal: AbortSignal.timeout(8000),
      })
      const data = await r.json()
      return res.status(200).json({ success: true, data })
    }

    if (type === 'urlhaus') {
      const endpoint = indicator.includes('/') || indicator.startsWith('http')
        ? 'https://urlhaus-api.abuse.ch/v1/url/'
        : 'https://urlhaus-api.abuse.ch/v1/host/'
      const key = indicator.startsWith('http') ? 'url' : 'host'
      const r = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `${key}=${encodeURIComponent(indicator)}`,
        signal: AbortSignal.timeout(8000),
      })
      const data = await r.json()
      return res.status(200).json({ success: true, data })
    }

    if (type === 'malwarebazaar') {
      const r = await fetch('https://mb-api.abuse.ch/api/v1/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `query=get_info&hash=${indicator}`,
        signal: AbortSignal.timeout(8000),
      })
      const data = await r.json()
      return res.status(200).json({ success: true, data })
    }

    if (type === 'whois') {
      const r = await fetch(`https://api.domainsdb.info/v1/domains/search?domain=${indicator}&limit=1`, {
        signal: AbortSignal.timeout(8000),
      })
      if (!r.ok) return res.status(200).json({ success: false, error: `WHOIS HTTP ${r.status}` })
      const data = await r.json()
      return res.status(200).json({ success: true, data })
    }

    if (type === 'dns') {
      const r = await fetch(`https://dns.google/resolve?name=${indicator}&type=A`, {
        signal: AbortSignal.timeout(8000),
      })
      const data = await r.json()
      return res.status(200).json({ success: true, data })
    }

    return res.status(400).json({ success: false, error: 'Unknown lookup type' })
  } catch (e) {
    return res.status(200).json({ success: false, error: e.message })
  }
}
