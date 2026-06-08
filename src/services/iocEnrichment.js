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

export async function enrichIPWithAbuseIPDB(ip, apiKey) {
  try {
    const response = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
      { headers: { Key: apiKey, Accept: 'application/json' } }
    )
    const data = await response.json()
    return {
      abuseScore: data.data?.abuseConfidenceScore,
      totalReports: data.data?.totalReports,
      lastReported: data.data?.lastReportedAt,
      isTor: data.data?.isTor,
      usageType: data.data?.usageType,
      enrichedBy: 'AbuseIPDB',
    }
  } catch {
    return null
  }
}

export async function enrichIPWithShodan(ip, apiKey) {
  try {
    const response = await fetch(`https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(apiKey)}`)
    const data = await response.json()
    return {
      openPorts: data.ports,
      vulns: Object.keys(data.vulns || {}),
      hostnames: data.hostnames,
      tags: data.tags,
      enrichedBy: 'Shodan',
    }
  } catch {
    return null
  }
}

export async function enrichWithVirusTotal(indicator, type, apiKey) {
  try {
    let url
    if (type === 'IP') url = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(indicator)}`
    else if (type === 'Domain') url = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(indicator)}`
    else if (type === 'SHA256') url = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(indicator)}`
    else return null

    const response = await fetch(url, {
      headers: { 'x-apikey': apiKey },
    })
    const data = await response.json()
    const stats = data.data?.attributes?.last_analysis_stats
    const total = (stats?.malicious || 0) + (stats?.suspicious || 0) + (stats?.undetected || 0) + (stats?.harmless || 0)
    return {
      vtMalicious: stats?.malicious || 0,
      vtSuspicious: stats?.suspicious || 0,
      vtTotal: total,
      vtScore: stats ? `${stats.malicious}/${total}` : null,
      enrichedBy: 'VirusTotal',
    }
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
