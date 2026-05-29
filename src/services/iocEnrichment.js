const CACHE_KEY = 'iocEnrichmentCache'
const CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000

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
