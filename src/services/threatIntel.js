const API_BASE = window.location.hostname === 'localhost'
  ? 'http://localhost:3000'
  : 'https://threat-hunt-dashboard.vercel.app'

export const FEED_LABELS = {
  threatfox: 'ThreatFox',
  urlhaus: 'URLhaus',
  feodotracker: 'FeodoTracker',
  malwarebazaar: 'MalwareBazaar',
  emergingThreats: 'EmergingThreats',
  cinsArmy: 'CINS Army',
  sslBlacklist: 'SSL Blacklist',
  alienVault: 'AlienVault OTX',
  certPoland: 'CERT Poland',
}

export const FEED_COUNT = Object.keys(FEED_LABELS).length

async function fetchFromAPI(endpoint) {
  try {
    const response = await fetch(`${API_BASE}/api/${endpoint}`)
    const data = await response.json()
    return {
      items: data.iocs || [],
      success: response.ok && data.success !== false,
    }
  } catch {
    return { items: [], success: false }
  }
}

export async function fetchThreatFoxIOCs() {
  return fetchFromAPI('threatfox')
}

export async function fetchURLhausIOCs() {
  return fetchFromAPI('urlhaus')
}

export async function fetchFeodoTrackerIOCs() {
  return fetchFromAPI('feodotracker')
}

export async function fetchMalwareBazaarIOCs() {
  return fetchFromAPI('malwarebazaar')
}

export async function fetchEmergingThreatsIOCs() {
  return fetchFromAPI('emergingthreats')
}

export async function fetchCINSArmyIOCs() {
  return fetchFromAPI('cinsarmy')
}

export async function fetchSSLBlacklistIOCs() {
  return fetchFromAPI('sslblacklist')
}

export async function fetchAlienVaultIOCs() {
  return fetchFromAPI('alienvault')
}

export async function fetchCERTPolandIOCs() {
  return fetchFromAPI('certpoland')
}

const FEED_FETCHERS = [
  { key: 'threatfox', fetch: fetchThreatFoxIOCs },
  { key: 'urlhaus', fetch: fetchURLhausIOCs },
  { key: 'feodotracker', fetch: fetchFeodoTrackerIOCs },
  { key: 'malwarebazaar', fetch: fetchMalwareBazaarIOCs },
  { key: 'emergingThreats', fetch: fetchEmergingThreatsIOCs },
  { key: 'cinsArmy', fetch: fetchCINSArmyIOCs },
  { key: 'sslBlacklist', fetch: fetchSSLBlacklistIOCs },
  { key: 'alienVault', fetch: fetchAlienVaultIOCs },
  { key: 'certPoland', fetch: fetchCERTPolandIOCs },
]

export function mergeIocLists(live, local) {
  const seen = new Set()
  const merged = []

  ;[...live, ...local].forEach((ioc) => {
    const key = String(ioc.indicator).toLowerCase()
    if (!key || seen.has(key)) return
    seen.add(key)
    merged.push(ioc)
  })

  merged.sort((a, b) => {
    const da = new Date(a.dateAdded).getTime() || 0
    const db = new Date(b.dateAdded).getTime() || 0
    return db - da
  })

  return merged
}

export async function fetchAllIOCs() {
  const feedStatus = {}
  const merged = []

  const results = await Promise.allSettled(
    FEED_FETCHERS.map(({ fetch }) => fetch())
  )

  results.forEach((result, index) => {
    const { key } = FEED_FETCHERS[index]
    if (result.status === 'fulfilled') {
      feedStatus[key] = result.value.success
      merged.push(...result.value.items)
    } else {
      feedStatus[key] = false
    }
  })

  const seen = new Set()
  const deduped = merged.filter((ioc) => {
    const key = String(ioc.indicator).toLowerCase()
    if (!key || seen.has(key)) return false
    seen.add(key)
    return true
  })

  deduped.sort((a, b) => {
    const da = new Date(a.dateAdded).getTime() || 0
    const db = new Date(b.dateAdded).getTime() || 0
    return db - da
  })

  return {
    iocs: deduped,
    feedStatus,
    totalCount: deduped.length,
  }
}

function escapeKqlString(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"')
}

export function generateWatchlistKQL(selectedIOCs) {
  const ips = []
  const domains = []
  const hashes = []
  const urls = []

  selectedIOCs.forEach((ioc) => {
    const type = String(ioc.type || '').toLowerCase()
    const val = escapeKqlString(ioc.indicator)
    if (type === 'ip' || type.includes('ip')) ips.push(`"${val}"`)
    else if (type === 'domain') domains.push(`"${val}"`)
    else if (type === 'url') urls.push(`"${val}"`)
    else if (type === 'sha256' || type === 'md5' || type.includes('sha256')) hashes.push(`"${val}"`)
    else domains.push(`"${val}"`)
  })

  const lines = []
  lines.push(`let IPWatchlist = dynamic([${ips.join(',') || ''}]);`)
  lines.push(`let DomainWatchlist = dynamic([${domains.join(',') || ''}]);`)
  lines.push(`let HashWatchlist = dynamic([${hashes.join(',') || ''}]);`)
  lines.push(`let URLWatchlist = dynamic([${urls.join(',') || ''}]);`)
  lines.push('// Fortigate + Palo Alto + Sophos - IP matches')
  lines.push('let FirewallHits = CommonSecurityLog')
  lines.push('| where TimeGenerated > ago(7d)')
  lines.push('| where DeviceVendor in ("Fortinet","Palo Alto Networks","Sophos","Trend Micro")')
  lines.push('| where SourceIP in (IPWatchlist) or DestinationIP in (IPWatchlist)')
  lines.push('| project TimeGenerated, DeviceVendor, SourceIP, DestinationIP, Activity, DeviceAction;')
  lines.push('let DnsHits = ASimDnsActivityLogs')
  lines.push('| where TimeGenerated > ago(7d)')
  lines.push('| where array_length(DomainWatchlist) == 0 or DnsQuery has_any (DomainWatchlist)')
  lines.push('| project TimeGenerated, DnsQuery, SrcIpAddr, DnsResponseCode;')
  lines.push('let HashHits = DeviceFileEvents')
  lines.push('| where Timestamp > ago(7d)')
  lines.push('| where array_length(HashWatchlist) == 0 or SHA256 in (HashWatchlist)')
  lines.push('| project TimeGenerated = Timestamp, DeviceName, FileName, SHA256, InitiatingProcessAccountName;')
  lines.push('let UrlHits = DeviceNetworkEvents')
  lines.push('| where Timestamp > ago(7d)')
  lines.push('| where array_length(URLWatchlist) == 0 or RemoteUrl has_any (URLWatchlist)')
  lines.push('| project TimeGenerated = Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName;')
  lines.push('union FirewallHits, DnsHits, HashHits, UrlHits')
  lines.push('| order by TimeGenerated desc')

  return lines.join('\n')
}
