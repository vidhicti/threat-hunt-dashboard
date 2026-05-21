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
  alienVaultOtx: 'https://otx.alienvault.com/api/v1/pulses/subscribed?limit=5',
  alienVaultReputation: 'https://reputation.alienvault.com/reputation.generic',
  certPoland: 'https://hole.cert.pl/domains/domains.json',
}

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

const JSON_HEADERS = { 'Content-Type': 'application/json' }

const IPV4_REGEX =
  /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/

function proxied(url) {
  return PROXY + encodeURIComponent(url)
}

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

export async function fetchThreatFoxIOCs() {
  try {
    const response = await fetch(proxied(FEEDS.threatfox), {
      method: 'POST',
      headers: JSON_HEADERS,
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
    const response = await fetch(proxied(FEEDS.urlhaus), {
      method: 'POST',
      headers: JSON_HEADERS,
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
    const response = await fetch(proxied(FEEDS.feodotracker))
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
    const response = await fetch(proxied(FEEDS.malwarebazaar), {
      method: 'POST',
      headers: JSON_HEADERS,
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
    const response = await fetch(proxied(FEEDS.emergingThreats))
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
    const response = await fetch(proxied(FEEDS.cinsArmy))
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
    const response = await fetch(proxied(FEEDS.sslBlacklist))
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

function parseAlienVaultReputation(text) {
  const lines = text.split('\n').filter((l) => l && !l.startsWith('#')).slice(0, 100)
  return lines
    .map((line) => {
      const parts = line.split('#')
      const indicator = parts[0].trim()
      return {
        indicator,
        type: 'IP',
        ttp: 'T1071 C2',
        ttpId: 'T1071',
        source: 'AlienVault OTX',
        logSource: 'CommonSecurityLog',
        confidence: 'Medium',
        status: 'active',
        dateAdded: today,
        malwareFamily: parts[2]?.trim() || 'Unknown',
        threatType: '',
      }
    })
    .filter((i) => i.indicator.match(/^\d+\.\d+\.\d+\.\d+$/))
}

function parseAlienVaultPulses(json) {
  const items = []
  const pulses = json.results || []
  for (const pulse of pulses.slice(0, 5)) {
    const indicators = pulse.indicators || []
    for (const ind of indicators.slice(0, 50)) {
      const type = normalizeType(ind.type)
      items.push({
        indicator: ind.indicator || '',
        type,
        ttp: pulse.name || 'T1071 C2',
        ttpId: 'T1071',
        source: 'AlienVault OTX',
        logSource: mapTypeToLogSource(type),
        confidence: 'Medium',
        status: 'active',
        dateAdded: formatDate(pulse.created),
        malwareFamily: pulse.malware_families?.[0] || pulse.name || '',
        threatType: ind.type || '',
      })
    }
  }
  return items.filter((i) => i.indicator).slice(0, 100)
}

export async function fetchAlienVaultIOCs() {
  try {
    const response = await fetch(proxied(FEEDS.alienVaultOtx), {
      headers: { 'X-OTX-API-KEY': '' },
    })
    if (response.ok) {
      const json = await response.json()
      const items = parseAlienVaultPulses(json)
      if (items.length > 0) return feedResult(items, true)
    }
  } catch {
    /* fall through to reputation feed */
  }

  try {
    const fallback = await fetch(proxied(FEEDS.alienVaultReputation))
    if (!fallback.ok) return feedResult([], false)
    const text = await fallback.text()
    const items = parseAlienVaultReputation(text)
    return feedResult(items, items.length > 0)
  } catch {
    return feedResult([], false)
  }
}

export async function fetchAbuseCHDNS() {
  try {
    const response = await fetch(FEEDS.certPoland)
    if (!response.ok) return feedResult([], false)
    const data = await response.json()
    const rows = Array.isArray(data) ? data.slice(0, 200) : []

    const items = rows
      .map((item) => {
        const domain =
          typeof item === 'string'
            ? item
            : item.DomainAddress || item.domain || item.name || ''
        return {
          indicator: domain,
          type: 'Domain',
          ttp: 'T1566 Phishing / T1071 C2',
          ttpId: 'T1566',
          source: 'CERT Poland',
          logSource: 'ASimDnsActivityLogs',
          confidence: 'High',
          status: 'active',
          dateAdded: formatDate(
            typeof item === 'object' ? item.InsertDate || item.insert_date : null
          ),
          malwareFamily:
            typeof item === 'object'
              ? item.Category || item.Reason || 'Unknown'
              : 'Unknown',
          threatType: 'phishing',
        }
      })
      .filter((ioc) => ioc.indicator && !ioc.indicator.includes(' '))
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
  { key: 'alienVault', fetch: fetchAlienVaultIOCs },
  { key: 'certPoland', fetch: fetchAbuseCHDNS },
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
