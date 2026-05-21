const PROXY = 'https://corsproxy.io/?'
const today = new Date().toISOString().split('T')[0]

export const FEEDS = {
  threatfox: 'https://threatfox-api.abuse.ch/api/v1/',
  urlhaus: 'https://urlhaus-api.abuse.ch/v1/urls/recent/',
  feodotracker: 'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
  malwarebazaar: 'https://mb-api.abuse.ch/api/v1/',
  emergingThreats: 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
  cinsArmy: 'https://cinsscore.com/list/ci-badguys.txt',
  sslBlacklist: 'https://sslbl.abuse.ch/blacklist/sslipblacklist.json',
  phishTank: 'https://data.phishtank.com/data/online-valid.json',
}

const ABUSE_HEADERS = {
  'Content-Type': 'application/json',
  'User-Agent': 'ThreatHuntDashboard/1.0 (Sentinel SOC)',
}

const IPV4_REGEX =
  /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/

function isValidIPv4(value) {
  return IPV4_REGEX.test(String(value).trim())
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
  if (!value) return today
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

function feedResult(items, success) {
  return { items, success }
}

export async function fetchThreatFoxIOCs() {
  try {
    const response = await fetch(FEEDS.threatfox, {
      method: 'POST',
      headers: ABUSE_HEADERS,
      body: JSON.stringify({ query: 'get_iocs', days: 7 }),
    })
    if (!response.ok) return feedResult([], false)
    const json = await response.json()
    const rows = (json.data || []).slice(0, 200)
    if (json.query_status && json.query_status !== 'ok') return feedResult([], false)

    const items = rows
      .map((row) => {
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
      })
      .filter((ioc) => ioc.indicator)
    return feedResult(items, true)
  } catch {
    return feedResult([], false)
  }
}

export async function fetchURLhausIOCs() {
  try {
    const response = await fetch(FEEDS.urlhaus, {
      method: 'POST',
      headers: ABUSE_HEADERS,
      body: JSON.stringify({ query: 'get_urls', limit: 100 }),
    })
    if (!response.ok) return feedResult([], false)
    const json = await response.json()
    const rows = (json.urls || []).slice(0, 100)
    if (json.query_status && json.query_status !== 'ok') return feedResult([], false)

    const items = rows
      .map((row) => ({
        indicator: row.url || '',
        type: 'URL',
        ttp: 'T1566.002',
        ttpId: 'T1566.002',
        source: 'URLhaus',
        logSource: 'ASimDnsActivityLogs',
        confidence: 'High',
        status: row.url_status === 'online' ? 'active' : 'watchlist',
        dateAdded: formatDate(row.date_added),
        malwareFamily: Array.isArray(row.tags) ? row.tags.join(', ') : '',
        threatType: row.threat || '',
      }))
      .filter((ioc) => ioc.indicator)
    return feedResult(items, true)
  } catch {
    return feedResult([], false)
  }
}

export async function fetchFeodoTrackerIOCs() {
  try {
    const response = await fetch(FEEDS.feodotracker, {
      headers: { 'User-Agent': ABUSE_HEADERS['User-Agent'] },
    })
    if (!response.ok) return feedResult([], false)
    const json = await response.json()
    const rows = (Array.isArray(json) ? json : json.data || []).slice(0, 100)

    const items = rows
      .map((row) => ({
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
      }))
      .filter((ioc) => ioc.indicator)
    return feedResult(items, true)
  } catch {
    return feedResult([], false)
  }
}

export async function fetchMalwareBazaarIOCs() {
  try {
    const response = await fetch(FEEDS.malwarebazaar, {
      method: 'POST',
      headers: ABUSE_HEADERS,
      body: JSON.stringify({ query: 'get_recent', selector: '100' }),
    })
    if (!response.ok) return feedResult([], false)
    const json = await response.json()
    const rows = (json.data || []).slice(0, 100)
    if (json.query_status && json.query_status !== 'ok') return feedResult([], false)

    const items = rows
      .map((row) => ({
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
      }))
      .filter((ioc) => ioc.indicator)
    return feedResult(items, true)
  } catch {
    return feedResult([], false)
  }
}

export async function fetchEmergingThreatsIOCs() {
  try {
    const response = await fetch(`${PROXY}${FEEDS.emergingThreats}`)
    if (!response.ok) return feedResult([], false)
    const text = await response.text()
    const lines = text
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('#') && isValidIPv4(line))
      .slice(0, 100)

    const items = lines.map((ip) => ({
      indicator: ip,
      type: 'IP',
      ttp: 'T1071 C2',
      ttpId: 'T1071',
      source: 'EmergingThreats',
      logSource: 'CommonSecurityLog',
      confidence: 'High',
      status: 'active',
      dateAdded: today,
      malwareFamily: '',
      threatType: '',
    }))
    return feedResult(items, true)
  } catch {
    return feedResult([], false)
  }
}

export async function fetchCINSArmyIOCs() {
  try {
    const response = await fetch(`${PROXY}${FEEDS.cinsArmy}`)
    if (!response.ok) return feedResult([], false)
    const text = await response.text()
    const lines = text
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line && isValidIPv4(line))
      .slice(0, 100)

    const items = lines.map((ip) => ({
      indicator: ip,
      type: 'IP',
      ttp: 'T1190',
      ttpId: 'T1190',
      source: 'CINS Army',
      logSource: 'CommonSecurityLog',
      confidence: 'Medium',
      status: 'active',
      dateAdded: today,
      malwareFamily: '',
      threatType: '',
    }))
    return feedResult(items, true)
  } catch {
    return feedResult([], false)
  }
}

export async function fetchSSLBlacklistIOCs() {
  try {
    const response = await fetch(FEEDS.sslBlacklist, {
      headers: { 'User-Agent': ABUSE_HEADERS['User-Agent'] },
    })
    if (!response.ok) return feedResult([], false)
    const json = await response.json()
    const rows = (json.blacklist || []).slice(0, 100)

    const items = rows
      .map((item) => ({
        indicator: item.Destination || '',
        type: 'IP',
        ttp: item.Listingreason || 'SSL Blacklist',
        ttpId: '',
        source: 'SSL Blacklist',
        logSource: 'CommonSecurityLog',
        confidence: 'High',
        status: 'active',
        dateAdded: formatDate(item.Listingdate),
        malwareFamily: item.Port ? `Port ${item.Port}` : '',
        threatType: item.Listingreason || '',
      }))
      .filter((ioc) => ioc.indicator)
    return feedResult(items, true)
  } catch {
    return feedResult([], false)
  }
}

export async function fetchPhishTankIOCs() {
  try {
    const response = await fetch(`${PROXY}${FEEDS.phishTank}`)
    if (!response.ok) return feedResult([], false)
    const json = await response.json()
    const rows = Array.isArray(json) ? json.slice(0, 100) : []

    const items = rows
      .map((item) => ({
        indicator: item.url || '',
        type: 'URL',
        ttp: 'T1566.002 Phishing',
        ttpId: 'T1566.002',
        source: 'PhishTank',
        logSource: 'ASimDnsActivityLogs',
        confidence: 'High',
        status: 'active',
        dateAdded: formatDate(item.submission_time),
        malwareFamily: '',
        threatType: 'phishing',
      }))
      .filter((ioc) => ioc.indicator)
    return feedResult(items, true)
  } catch {
    return feedResult([], false)
  }
}

const FEED_FETCHERS = [
  { key: 'threatfox', fetch: fetchThreatFoxIOCs },
  { key: 'urlhaus', fetch: fetchURLhausIOCs },
  { key: 'feodotracker', fetch: fetchFeodoTrackerIOCs },
  { key: 'malwarebazaar', fetch: fetchMalwareBazaarIOCs },
  { key: 'emergingThreats', fetch: fetchEmergingThreatsIOCs },
  { key: 'cinsArmy', fetch: fetchCINSArmyIOCs },
  { key: 'sslBlacklist', fetch: fetchSSLBlacklistIOCs },
  { key: 'phishTank', fetch: fetchPhishTankIOCs },
]

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
