const CACHE_KEY = 'iocEnrichmentCache'
const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000

const API_BASE = window.location.hostname === 'localhost'
  ? 'http://localhost:3000'
  : 'https://threat-hunt-dashboard.vercel.app'

function loadCache() {
  try {
    return JSON.parse(localStorage.getItem(CACHE_KEY) || '{}')
  } catch {
    return {}
  }
}

function saveCache(cache) {
  localStorage.setItem(CACHE_KEY, JSON.stringify(cache))
}

export function getCachedEnrichment(indicator) {
  const cache = loadCache()
  const entry = cache[indicator]
  if (!entry) return null
  if (Date.now() - entry.ts > CACHE_TTL_MS) {
    delete cache[indicator]
    saveCache(cache)
    return null
  }
  return entry.data
}

export function setCachedEnrichment(indicator, data) {
  const cache = loadCache()
  cache[indicator] = { data, ts: Date.now() }
  saveCache(cache)
}

export async function enrichIP(ip) {
  try {
    const res = await fetch(
      `https://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,country,countryCode,regionName,city,isp,org,as,proxy,hosting,query`
    )
    const json = await res.json()
    if (json.status !== 'success') {
      return { enriched: false }
    }
    return {
      enriched: true,
      country: json.country,
      countryCode: json.countryCode,
      city: json.city,
      region: json.regionName,
      isp: json.isp,
      asn: json.as || json.org,
      isProxy: !!json.proxy,
      isHosting: !!json.hosting,
    }
  } catch {
    return { enriched: false }
  }
}

export async function enrichIPWithAbuseIPDB(ip, apiKey) {
  try {
    const r = await fetch(`${API_BASE}/api/abuseipdb`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, apiKey }),
    })
    const data = await r.json()
    return data.success ? data.result : null
  } catch {
    return null
  }
}

export async function enrichIPWithShodan(ip, apiKey) {
  try {
    const r = await fetch(`${API_BASE}/api/shodan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, apiKey }),
    })
    const data = await r.json()
    return data.success ? data.result : null
  } catch {
    return null
  }
}

export async function enrichWithVirusTotal(indicator, type, apiKey) {
  try {
    const r = await fetch(`${API_BASE}/api/virustotal`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ indicator, type, apiKey }),
    })
    const data = await r.json()
    return data.success ? data.result : null
  } catch {
    return null
  }
}

export async function enrichIOC(ioc) {
  const config = JSON.parse(localStorage.getItem('connectorConfig') || '{}')

  let result = {}

  if (ioc.type === 'IP') {
    result = { ...result, ...(await enrichIP(ioc.indicator)) }

    if (config.abuseipdb?.apiKey && config.abuseipdb?.enabled !== false) {
      const abuse = await enrichIPWithAbuseIPDB(ioc.indicator, config.abuseipdb.apiKey)
      if (abuse) result = { ...result, ...abuse }
    }

    if (config.shodan?.apiKey && config.shodan?.enabled !== false) {
      const shodan = await enrichIPWithShodan(ioc.indicator, config.shodan.apiKey)
      if (shodan) result = { ...result, ...shodan }
    }
  }

  if (config.virustotal?.apiKey && config.virustotal?.enabled !== false) {
    const vt = await enrichWithVirusTotal(ioc.indicator, ioc.type, config.virustotal.apiKey)
    if (vt) result = { ...result, ...vt }
  }

  return { ...result, enriched: true }
}
