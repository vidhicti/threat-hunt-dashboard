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

async function fetchFeed(endpoint) {
  try {
    const r = await fetch(`${API_BASE}${endpoint}`)
    const data = await r.json()
    return { iocs: data.iocs || [], success: data.success, feedName: endpoint }
  } catch (e) {
    return { iocs: [], success: false, error: e.message }
  }
}

async function fetchFeedPost(endpoint, body) {
  try {
    const r = await fetch(`${API_BASE}${endpoint}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    const data = await r.json()
    return { iocs: data.iocs || [], success: data.success }
  } catch (e) {
    return { iocs: [], success: false, error: e.message }
  }
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

async function fetchMISPIOCs() {
  const mispConfig = getConnectorConfig()?.misp
  if (!mispConfig?.enabled || !mispConfig?.apiKey || !mispConfig?.mispUrl) {
    return { iocs: [], success: true }
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

    if (!response.ok) return { iocs: [], success: false }

    const data = await response.json()
    const iocs = (data.response?.Attribute || []).map((attr) => ({
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

    return { iocs, success: true }
  } catch {
    return { iocs: [], success: false }
  }
}

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
  const config = getConnectorConfig()

  const feedCalls = [
    { name: 'Spamhaus DROP', call: () => fetchFeed('/api/feeds1?feed=threatfox'), enabled: config.threatfox?.enabled !== false },
    { name: 'Blocklist.de', call: () => fetchFeed('/api/feeds1?feed=urlhaus'), enabled: config.urlhaus?.enabled !== false },
    { name: 'FeodoTracker', call: () => fetchFeed('/api/feeds1?feed=feodotracker'), enabled: config.feodotracker?.enabled !== false },
    { name: 'MalwareBazaar', call: () => fetchFeed('/api/feeds1?feed=malwarebazaar'), enabled: config.malwarebazaar?.enabled !== false },
    { name: 'EmergingThreats', call: () => fetchFeed('/api/feeds2?feed=emergingthreats'), enabled: config.emergingthreats?.enabled !== false },
    { name: 'CINS Army', call: () => fetchFeed('/api/feeds2?feed=cinsarmy'), enabled: config.cinsarmy?.enabled !== false },
    { name: 'FireHOL Level1', call: () => fetchFeed('/api/feeds2?feed=sslblacklist'), enabled: config.sslblacklist?.enabled !== false },
    { name: 'Tor Exit Nodes', call: () => fetchFeed('/api/feeds2?feed=tornodes'), enabled: config.tornodes?.enabled !== false },
    {
      name: 'AlienVault OTX',
      call: () => {
        const otxKey = config.alienvault?.apiKey
        if (otxKey && config.alienvault?.enabled !== false) {
          return fetchFeedPost('/api/feeds3', { feed: 'alienvaultkey', apiKey: otxKey })
        }
        return fetchFeed('/api/feeds3?feed=alienvault')
      },
      enabled: config.alienvault?.enabled !== false,
    },
    { name: 'CERT Poland', call: () => fetchFeed('/api/feeds3?feed=certpoland'), enabled: config.certpoland?.enabled !== false },
  ]

  if (config.misp?.enabled && config.misp?.apiKey && config.misp?.mispUrl) {
    feedCalls.push({ name: 'MISP', call: fetchMISPIOCs, enabled: true })
  }

  const enabledFeeds = feedCalls.filter((f) => f.enabled)
  const results = await Promise.allSettled(enabledFeeds.map((f) => f.call()))

  const feedStatus = {}
  const allIOCs = []

  results.forEach((result, i) => {
    const feedName = enabledFeeds[i].name
    if (result.status === 'fulfilled' && result.value.success && result.value.iocs.length > 0) {
      feedStatus[feedName] = true
      allIOCs.push(...result.value.iocs)
    } else {
      feedStatus[feedName] = false
    }
  })

  const seen = new Set()
  const deduped = allIOCs.filter((ioc) => {
    if (seen.has(ioc.indicator)) return false
    seen.add(ioc.indicator)
    return true
  })

  deduped.sort((a, b) => new Date(b.dateAdded) - new Date(a.dateAdded))

  return { iocs: deduped, feedStatus, totalCount: deduped.length }
}

export function generateWatchlistKQL(selectedIOCs) {
  const ips = selectedIOCs.filter((i) => i.type === 'IP').map((i) => i.indicator)
  const domains = selectedIOCs.filter((i) => i.type === 'Domain').map((i) => i.indicator)
  const hashes = selectedIOCs.filter((i) => i.type === 'SHA256').map((i) => i.indicator)
  const urls = selectedIOCs.filter((i) => i.type === 'URL').map((i) => i.indicator)

  let kql = ''
  if (ips.length) kql += `let IPWatchlist = dynamic(${JSON.stringify(ips)});\n`
  if (domains.length) kql += `let DomainWatchlist = dynamic(${JSON.stringify(domains)});\n`
  if (hashes.length) kql += `let HashWatchlist = dynamic(${JSON.stringify(hashes)});\n`
  if (urls.length) kql += `let URLWatchlist = dynamic(${JSON.stringify(urls)});\n`

  kql += `\n// Firewall - IP matches\nCommonSecurityLog\n| where DeviceVendor in ("Fortinet","Palo Alto Networks","Sophos","Trend Micro")\n`
  if (ips.length) kql += `| where SourceIP in (IPWatchlist) or DestinationIP in (IPWatchlist)\n`
  kql += `| project TimeGenerated, DeviceVendor, SourceIP, DestinationIP, Activity, DeviceAction\n`

  if (domains.length) {
    kql += `| union (\nASimDnsActivityLogs\n| where DnsQuery has_any (DomainWatchlist)\n| project TimeGenerated, DnsQuery, SrcIpAddr, DnsResponseCode\n)\n`
  }
  if (hashes.length) {
    kql += `| union (\nDeviceFileEvents\n| where SHA256 in (HashWatchlist)\n| project TimeGenerated, DeviceName, FileName, SHA256, InitiatingProcessFileName\n)\n`
  }

  kql += `| order by TimeGenerated desc`
  return kql
}
