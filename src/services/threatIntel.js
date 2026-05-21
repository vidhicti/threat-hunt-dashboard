export const FEEDS = {
  threatfox: 'https://threatfox-api.abuse.ch/api/v1/',
  urlhaus: 'https://urlhaus-api.abuse.ch/v1/',
  feodotracker: 'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
  malwarebazaar: 'https://mb-api.abuse.ch/api/v1/',
  openphish: 'https://openphish.com/feed.txt',
  botvrij: 'https://www.botvrij.eu/data/ioclist.ip-dst.txt',
}

function getFeedUrl(key) {
  if (import.meta.env.DEV) {
    const proxies = {
      threatfox: '/proxy/threatfox/',
      urlhaus: '/proxy/urlhaus/',
      feodotracker: '/proxy/feodotracker/downloads/ipblocklist.json',
      malwarebazaar: '/proxy/malwarebazaar/',
    }
    return proxies[key] || FEEDS[key]
  }
  return FEEDS[key]
}

const ABUSE_HEADERS = {
  'Content-Type': 'application/json',
  'User-Agent': 'ThreatHuntDashboard/1.0 (Sentinel SOC)',
}

function normalizeType(iocType) {
  if (!iocType) return 'Unknown'
  const t = String(iocType).toLowerCase()
  if (t.includes('ip')) return 'IP'
  if (t === 'domain') return 'Domain'
  if (t === 'url') return 'URL'
  if (t.includes('sha256') || t === 'sha256_hash') return 'SHA256'
  if (t.includes('md5')) return 'MD5'
  return iocType
}

function formatDate(value) {
  if (!value) return new Date().toISOString().slice(0, 10)
  const d = new Date(value)
  if (Number.isNaN(d.getTime())) return String(value).slice(0, 10)
  return d.toISOString().slice(0, 10)
}

export function mapTypeToLogSource(type) {
  const t = String(type || '').toLowerCase()
  if (t === 'ip' || t.includes('ip')) return 'CommonSecurityLog'
  if (t === 'domain' || t === 'url') return 'ASimDnsActivityLogs'
  if (t === 'sha256' || t === 'md5' || t.includes('sha256')) return 'MDE'
  return 'CommonSecurityLog'
}

export async function fetchThreatFoxIOCs() {
  const response = await fetch(getFeedUrl('threatfox'), {
    method: 'POST',
    headers: ABUSE_HEADERS,
    body: JSON.stringify({ query: 'get_iocs', days: 3 }),
  })
  if (!response.ok) throw new Error(`ThreatFox HTTP ${response.status}`)
  const json = await response.json()
  if (json.query_status !== 'ok' || !Array.isArray(json.data)) return []

  return json.data.map((row) => {
    const type = normalizeType(row.ioc_type)
    return {
      indicator: row.ioc || row.ioc_value || '',
      type,
      ttp: row.malware || row.threat_type || 'Unknown',
      ttpId: '',
      source: 'ThreatFox',
      logSource: mapTypeToLogSource(type),
      confidence: 'High',
      status: 'active',
      dateAdded: formatDate(row.first_seen_utc || row.last_seen_utc),
      malwareFamily: row.malware || '',
      threatType: row.threat_type || '',
    }
  }).filter((ioc) => ioc.indicator)
}

export async function fetchURLhausIOCs() {
  const response = await fetch(getFeedUrl('urlhaus'), {
    method: 'POST',
    headers: ABUSE_HEADERS,
    body: JSON.stringify({ query: 'get_urls', limit: 50 }),
  })
  if (!response.ok) throw new Error(`URLhaus HTTP ${response.status}`)
  const json = await response.json()
  if (json.query_status !== 'ok' || !Array.isArray(json.urls)) return []

  return json.urls.map((row) => ({
    indicator: row.url || '',
    type: 'URL',
    ttp: 'T1566.002',
    ttpId: 'T1566.002',
    source: 'URLhaus',
    logSource: 'CommonSecurityLog',
    confidence: 'High',
    status: row.url_status === 'online' ? 'active' : 'watchlist',
    dateAdded: formatDate(row.date_added),
    malwareFamily: Array.isArray(row.tags) ? row.tags.join(', ') : '',
    threatType: row.threat || '',
  })).filter((ioc) => ioc.indicator)
}

export async function fetchFeodoTrackerIOCs() {
  const response = await fetch(getFeedUrl('feodotracker'), {
    headers: { 'User-Agent': ABUSE_HEADERS['User-Agent'] },
  })
  if (!response.ok) throw new Error(`FeodoTracker HTTP ${response.status}`)
  const json = await response.json()
  const rows = Array.isArray(json) ? json : json.data || []

  return rows.map((row) => ({
    indicator: row.ip_address || row.ip || '',
    type: 'IP',
    ttp: 'T1071 C2',
    ttpId: 'T1071',
    source: 'FeodoTracker',
    logSource: 'CommonSecurityLog',
    confidence: 'High',
    status: row.status === 'offline' ? 'watchlist' : 'active',
    dateAdded: formatDate(row.last_online),
    malwareFamily: row.malware || row.botname || '',
    threatType: 'botnet_cc',
  })).filter((ioc) => ioc.indicator)
}

export async function fetchMalwareBazaarIOCs() {
  const response = await fetch(getFeedUrl('malwarebazaar'), {
    method: 'POST',
    headers: ABUSE_HEADERS,
    body: JSON.stringify({ query: 'get_recent', selector: '100' }),
  })
  if (!response.ok) throw new Error(`MalwareBazaar HTTP ${response.status}`)
  const json = await response.json()
  if (json.query_status !== 'ok' || !Array.isArray(json.data)) return []

  return json.data.map((row) => ({
    indicator: row.sha256_hash || row.sha256 || '',
    type: 'SHA256',
    ttp: 'T1204',
    ttpId: 'T1204.002',
    source: 'MalwareBazaar',
    logSource: 'MDE',
    confidence: 'High',
    status: 'active',
    dateAdded: formatDate(row.first_seen || row.first_seen_utc),
    malwareFamily: Array.isArray(row.tags) ? row.tags.join(', ') : row.signature || '',
    threatType: row.file_type || '',
  })).filter((ioc) => ioc.indicator)
}

export async function fetchAllIOCs() {
  const results = await Promise.allSettled([
    fetchThreatFoxIOCs(),
    fetchURLhausIOCs(),
    fetchFeodoTrackerIOCs(),
    fetchMalwareBazaarIOCs(),
  ])

  const feedNames = ['threatfox', 'urlhaus', 'feodotracker', 'malwarebazaar']
  const activeFeeds = {}
  const merged = []

  results.forEach((result, index) => {
    const name = feedNames[index]
    if (result.status === 'fulfilled') {
      activeFeeds[name] = true
      merged.push(...result.value)
    } else {
      activeFeeds[name] = false
    }
  })

  const seen = new Set()
  const deduped = merged.filter((ioc) => {
    const key = String(ioc.indicator).toLowerCase()
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })

  deduped.sort((a, b) => {
    const da = new Date(a.dateAdded).getTime() || 0
    const db = new Date(b.dateAdded).getTime() || 0
    return db - da
  })

  return { iocs: deduped, activeFeeds }
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
