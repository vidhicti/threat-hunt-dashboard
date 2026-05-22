const CACHE_KEY = 'iocEnrichmentCache'
const CACHE_TTL = 24 * 60 * 60 * 1000 // 24 hours

export async function enrichIP(ip) {
  try {
    const r = await fetch(
      `http://ip-api.com/json/${ip}?fields=status,country,countryCode,city,isp,org,as,proxy,hosting,query`
    )
    const d = await r.json()
    if (d.status === 'success')
      return {
        country: d.country,
        countryCode: d.countryCode.toLowerCase(),
        city: d.city,
        isp: d.isp,
        org: d.org,
        asn: d.as,
        isProxy: d.proxy,
        isHosting: d.hosting,
        enriched: true,
      }
  } catch {
    /* ignore */
  }
  return { enriched: false }
}

export async function enrichDomain(domain) {
  try {
    const r = await fetch(
      `https://api.domainsdb.info/v1/domains/search?domain=${encodeURIComponent(domain)}&limit=1`
    )
    const d = await r.json()
    return {
      registered: d.domains?.[0]?.create_date,
      updated: d.domains?.[0]?.update_date,
      enriched: true,
    }
  } catch {
    /* ignore */
  }
  return { enriched: false }
}

export async function enrichHash(hash) {
  try {
    const r = await fetch('https://mb-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: 'get_info', hash }),
    })
    const d = await r.json()
    if (d.query_status === 'hash_found') {
      const item = d.data[0]
      return {
        fileName: item.file_name,
        fileType: item.file_type,
        fileSize: item.file_size,
        malwareFamily: item.signature,
        tags: item.tags,
        firstSeen: item.first_seen,
        enriched: true,
      }
    }
  } catch {
    /* ignore */
  }
  return { enriched: false }
}

export async function enrichIOC(ioc) {
  const type = String(ioc.type || '').toUpperCase()
  if (type === 'IP' || type.includes('IP')) return enrichIP(ioc.indicator)
  if (type === 'DOMAIN') return enrichDomain(ioc.indicator)
  if (type === 'SHA256' || type.includes('SHA256')) return enrichHash(ioc.indicator)
  return { enriched: false }
}

export function getCachedEnrichment(indicator) {
  try {
    const cache = JSON.parse(localStorage.getItem(CACHE_KEY)) || {}
    const entry = cache[indicator]
    if (entry && Date.now() - entry.timestamp < CACHE_TTL) return entry.data
  } catch {
    /* ignore */
  }
  return null
}

export function setCachedEnrichment(indicator, data) {
  try {
    const cache = JSON.parse(localStorage.getItem(CACHE_KEY)) || {}
    cache[indicator] = { data, timestamp: Date.now() }
    const keys = Object.keys(cache)
    if (keys.length > 500) delete cache[keys[0]]
    localStorage.setItem(CACHE_KEY, JSON.stringify(cache))
  } catch {
    /* ignore */
  }
}

export function countryFlag(code) {
  if (!code || code.length !== 2) return ''
  return String.fromCodePoint(
    ...[...code.toUpperCase()].map((c) => 0x1f1e0 + c.charCodeAt(0) - 65)
  )
}

export function truncate(str, len = 20) {
  const s = String(str || '')
  return s.length > len ? `${s.slice(0, len)}…` : s
}

export function domainAgeDays(registered) {
  if (!registered) return null
  const d = new Date(registered)
  if (Number.isNaN(d.getTime())) return null
  return Math.floor((Date.now() - d.getTime()) / (24 * 60 * 60 * 1000))
}
