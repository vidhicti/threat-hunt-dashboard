import { FEED_DEFINITIONS } from '../data/feedConfig'

const API_BASE = window.location.hostname === 'localhost'
  ? 'http://localhost:3000'
  : 'https://threat-hunt-dashboard.vercel.app'

export const FEED_LABELS = Object.fromEntries(
  FEED_DEFINITIONS
    .filter((f) => f.usedFor !== 'enrichment')
    .map((f) => [f.id, f.name])
)

export const FEED_COUNT = FEED_DEFINITIONS.filter((f) => f.usedFor !== 'enrichment').length

export function getConnectorConfig() {
  try {
    return JSON.parse(localStorage.getItem('connectorConfig') || '{}')
  } catch {
    return {}
  }
}

export function isFeedEnabled(feedId) {
  const config = getConnectorConfig()
  const feedCfg = config[feedId]
  const feedDef = FEED_DEFINITIONS.find((f) => f.id === feedId)
  if (!feedCfg) {
    if (feedDef?.requiresKey) return false
    return true
  }
  return feedCfg.enabled !== false
}

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

function mapOTXType(otxType) {
  const t = String(otxType || '').toLowerCase()
  if (t.includes('ipv4') || t.includes('ip')) return 'IP'
  if (t.includes('domain') || t.includes('hostname')) return 'Domain'
  if (t.includes('url')) return 'URL'
  if (t.includes('sha256') || t.includes('sha-256')) return 'SHA256'
  if (t.includes('md5')) return 'MD5'
  return 'Domain'
}

function mapMISPType(mispType) {
  const t = String(mispType || '').toLowerCase()
  if (t.includes('ip')) return 'IP'
  if (t === 'domain') return 'Domain'
  if (t === 'url') return 'URL'
  if (t.includes('sha256')) return 'SHA256'
  if (t.includes('md5')) return 'MD5'
  return 'Domain'
}

function mapLogSource(type) {
  const t = String(type || '').toLowerCase()
  if (t.includes('ip')) return 'CommonSecurityLog'
  if (t === 'domain') return 'ASimDnsActivityLogs'
  if (t === 'url') return 'DeviceNetworkEvents'
  return 'DeviceFileEvents'
}

export async function fetchThreatFoxIOCs() {
  if (!isFeedEnabled('threatfox')) return { items: [], success: true }
  return fetchFromAPI('threatfox')
}

export async function fetchURLhausIOCs() {
  if (!isFeedEnabled('urlhaus')) return { items: [], success: true }
  return fetchFromAPI('urlhaus')
}

export async function fetchFeodoTrackerIOCs() {
  if (!isFeedEnabled('feodotracker')) return { items: [], success: true }
  return fetchFromAPI('feodotracker')
}

export async function fetchMalwareBazaarIOCs() {
  if (!isFeedEnabled('malwarebazaar')) return { items: [], success: true }
  return fetchFromAPI('malwarebazaar')
}

export async function fetchEmergingThreatsIOCs() {
  if (!isFeedEnabled('emergingthreats')) return { items: [], success: true }
  return fetchFromAPI('emergingthreats')
}

export async function fetchCINSArmyIOCs() {
  if (!isFeedEnabled('cinsarmy')) return { items: [], success: true }
  return fetchFromAPI('cinsarmy')
}

export async function fetchSSLBlacklistIOCs() {
  if (!isFeedEnabled('sslblacklist')) return { items: [], success: true }
  return fetchFromAPI('sslblacklist')
}

export async function fetchAlienVaultIOCs() {
  if (!isFeedEnabled('alienvault')) return { items: [], success: true }

  const config = getConnectorConfig()
  const otxKey = config?.alienvault?.apiKey

  if (otxKey) {
    try {
      const response = await fetch('https://otx.alienvault.com/api/v1/pulses/subscribed?limit=10', {
        headers: { 'X-OTX-API-KEY': otxKey },
      })
      if (!response.ok) return fetchFromAPI('alienvault')

      const data = await response.json()
      const items = []
      const today = new Date().toISOString().split('T')[0]

      for (const pulse of data.results || []) {
        for (const ind of pulse.indicators || []) {
          if (!ind.indicator) continue
          items.push({
            indicator: ind.indicator,
            type: mapOTXType(ind.type),
            ttp: pulse.name || 'Threat Intelligence',
            ttpId: 'T1071',
            source: 'AlienVault OTX',
            logSource: mapLogSource(mapOTXType(ind.type)),
            confidence: 'High',
            status: 'active',
            dateAdded: pulse.modified ? pulse.modified.split('T')[0] : today,
            malwareFamily: pulse.malware_families?.[0] || pulse.name || 'Unknown',
          })
        }
      }

      return { items, success: items.length > 0 }
    } catch {
      return fetchFromAPI('alienvault')
    }
  }

  return fetchFromAPI('alienvault')
}

export async function fetchCERTPolandIOCs() {
  if (!isFeedEnabled('certpoland')) return { items: [], success: true }
  return fetchFromAPI('certpoland')
}

export async function fetchMISPIOCs() {
  const mispConfig = getConnectorConfig()?.misp
  if (!mispConfig?.enabled || !mispConfig?.apiKey || !mispConfig?.mispUrl) {
    return { items: [], success: true }
  }

  try {
    const baseUrl = mispConfig.mispUrl.replace(/\/$/, '')
    const response = await fetch(`${baseUrl}/attributes/restSearch`, {
      method: 'POST',
      headers: {
        Authorization: mispConfig.apiKey,
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({
        returnFormat: 'json',
        type: ['ip-dst', 'domain', 'url', 'sha256', 'md5'],
        limit: 500,
        to_ids: 1,
      }),
    })

    if (!response.ok) return { items: [], success: false }

    const data = await response.json()
    const items = (data.response?.Attribute || []).map((attr) => ({
      indicator: attr.value,
      type: mapMISPType(attr.type),
      ttp: attr.comment || 'Unknown',
      ttpId: 'T1071',
      source: 'MISP',
      logSource: mapLogSource(attr.type),
      confidence: 'High',
      status: 'active',
      dateAdded: new Date((attr.timestamp || 0) * 1000).toISOString().split('T')[0],
      malwareFamily: attr.comment || 'Unknown',
    }))

    return { items, success: true }
  } catch {
    return { items: [], success: false }
  }
}

const FEED_FETCHERS = [
  { key: 'threatfox', fetch: fetchThreatFoxIOCs },
  { key: 'urlhaus', fetch: fetchURLhausIOCs },
  { key: 'feodotracker', fetch: fetchFeodoTrackerIOCs },
  { key: 'malwarebazaar', fetch: fetchMalwareBazaarIOCs },
  { key: 'emergingthreats', fetch: fetchEmergingThreatsIOCs },
  { key: 'cinsarmy', fetch: fetchCINSArmyIOCs },
  { key: 'sslblacklist', fetch: fetchSSLBlacklistIOCs },
  { key: 'alienvault', fetch: fetchAlienVaultIOCs },
  { key: 'certpoland', fetch: fetchCERTPolandIOCs },
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

  const fetchers = [...FEED_FETCHERS]
  const mispConfig = getConnectorConfig()?.misp
  if (mispConfig?.enabled && mispConfig?.apiKey && mispConfig?.mispUrl) {
    fetchers.push({ key: 'misp', fetch: fetchMISPIOCs })
  }

  const results = await Promise.allSettled(
    fetchers.map(({ fetch }) => fetch())
  )

  results.forEach((result, index) => {
    const { key } = fetchers[index]
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
