import { useState, useEffect } from 'react'

const API_BASE = ''

async function postLookup(type, indicator) {
  const r = await fetch(`${API_BASE}/api/lookup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type, indicator }),
  })
  return r.json()
}

const countryFlag = (code) =>
  code
    ? String.fromCodePoint(...[...code.toUpperCase()].map((c) => 0x1f1e0 + c.charCodeAt(0) - 65))
    : '🌍'

function abuseColor(score) {
  if (score > 50) return '#f85149'
  if (score > 20) return '#d29922'
  return '#3fb950'
}

function generateIOCKQL(ioc) {
  if (ioc.type === 'IP') {
    return `CommonSecurityLog\n| where SourceIP == "${ioc.indicator}" or DestinationIP == "${ioc.indicator}"\n| where DeviceVendor in ("Fortinet","Palo Alto Networks","Sophos","Trend Micro")\n| where TimeGenerated > ago(1d)\n| project TimeGenerated, DeviceVendor, SourceIP, DestinationIP, Activity, DeviceAction\n| order by TimeGenerated desc`
  }
  if (ioc.type === 'Domain') {
    return `ASimDnsActivityLogs\n| where DnsQuery has "${ioc.indicator}"\n| where TimeGenerated > ago(1d)\n| project TimeGenerated, DnsQuery, SrcIpAddr, DnsResponseCode\n| order by TimeGenerated desc`
  }
  if (ioc.type === 'SHA256') {
    return `DeviceFileEvents\n| where SHA256 == "${ioc.indicator}"\n| where TimeGenerated > ago(1d)\n| project TimeGenerated, DeviceName, FileName, SHA256, InitiatingProcessFileName\n| order by TimeGenerated desc`
  }
  if (ioc.type === 'URL') {
    return `DeviceNetworkEvents\n| where RemoteUrl has "${ioc.indicator}"\n| where TimeGenerated > ago(1d)\n| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName\n| order by TimeGenerated desc`
  }
  return `CommonSecurityLog\n| where Message has "${ioc.indicator}"\n| where TimeGenerated > ago(1d)\n| order by TimeGenerated desc`
}

function vtLink(ioc) {
  const ind = encodeURIComponent(ioc.indicator)
  if (ioc.type === 'IP') return `https://www.virustotal.com/gui/ip-address/${ind}`
  if (ioc.type === 'Domain') return `https://www.virustotal.com/gui/domain/${ind}`
  if (ioc.type === 'SHA256') return `https://www.virustotal.com/gui/file/${ind}`
  return `https://www.virustotal.com/gui/search/${ind}`
}

function buildMarkdownReport(ioc, results) {
  const lines = [
    `# IOC Investigation Report`,
    ``,
    `**Indicator:** \`${ioc.indicator}\``,
    `**Type:** ${ioc.type}`,
    `**Source:** ${ioc.source || 'Unknown'}`,
    `**Generated:** ${new Date().toISOString()}`,
    ``,
  ]

  Object.entries(results).forEach(([source, data]) => {
    if (data?.skipped || data?.error) return
    lines.push(`## ${source}`)
    lines.push('```json')
    lines.push(JSON.stringify(data, null, 2))
    lines.push('```')
    lines.push('')
  })

  lines.push('## Sentinel KQL')
  lines.push('```kql')
  lines.push(generateIOCKQL(ioc))
  lines.push('```')
  return lines.join('\n')
}

function InvestCard({ title, icon, sourceKey, loading, error, skipped, skipMessage, wide, children }) {
  return (
    <div className={`ioc-inv-card ${wide ? 'ioc-inv-card-wide' : ''}`}>
      <div className="ioc-inv-card-header">
        <span className="ioc-inv-card-icon">{icon}</span>
        <span className="ioc-inv-card-title">{title}</span>
        {loading && <span className="ioc-inv-spinner">⟳</span>}
      </div>
      <div className="ioc-inv-card-body">
        {loading && <div className="ioc-inv-loading">Fetching intelligence...</div>}
        {!loading && skipped && (
          <div className="ioc-inv-skipped">{skipMessage || 'Not configured — Add API key in Settings'}</div>
        )}
        {!loading && error && <div className="ioc-inv-error">{error}</div>}
        {!loading && !skipped && !error && children}
      </div>
    </div>
  )
}

export default function IocInvestigator({ ioc, onClose, onAddToWatchlist, onWhitelist }) {
  const [results, setResults] = useState({})
  const [loading, setLoading] = useState({})
  const [showKql, setShowKql] = useState(false)
  const [whitelistConfirm, setWhitelistConfirm] = useState(false)
  const [toast, setToast] = useState('')

  const config = (() => {
    try {
      return JSON.parse(localStorage.getItem('connectorConfig') || '{}')
    } catch {
      return {}
    }
  })()

  const kql = generateIOCKQL(ioc)

  useEffect(() => {
    if (!ioc) return

    const checks = []

    const setLoad = (key, val) => setLoading((prev) => ({ ...prev, [key]: val }))
    const setResult = (key, val) => setResults((prev) => ({ ...prev, [key]: val }))

    if (ioc.type === 'IP') {
      checks.push(async () => {
        setLoad('geolocation', true)
        try {
          const r = await fetch(
            `http://ip-api.com/json/${encodeURIComponent(ioc.indicator)}?fields=status,country,countryCode,city,isp,org,as,proxy,hosting,mobile,query`
          )
          const data = await r.json()
          if (data.status !== 'success') throw new Error('Geolocation lookup failed')
          setResult('geolocation', data)
        } catch (e) {
          setResult('geolocation', { error: e.message })
        } finally {
          setLoad('geolocation', false)
        }
      })
    }

    if (config.virustotal?.apiKey && config.virustotal?.enabled !== false) {
      checks.push(async () => {
        setLoad('virustotal', true)
        try {
          const r = await fetch(`${API_BASE}/api/virustotal`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              indicator: ioc.indicator,
              type: ioc.type,
              apiKey: config.virustotal.apiKey,
            }),
          })
          const data = await r.json()
          if (!data.success) throw new Error(data.error || 'VirusTotal lookup failed')
          setResult('virustotal', data.result)
        } catch (e) {
          setResult('virustotal', { error: e.message })
        } finally {
          setLoad('virustotal', false)
        }
      })
    } else {
      setResults((prev) => ({ ...prev, virustotal: { skipped: true } }))
    }

    if (ioc.type === 'IP' && config.abuseipdb?.apiKey && config.abuseipdb?.enabled !== false) {
      checks.push(async () => {
        setLoad('abuseipdb', true)
        try {
          const r = await fetch(`${API_BASE}/api/abuseipdb`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ioc.indicator, apiKey: config.abuseipdb.apiKey }),
          })
          const data = await r.json()
          if (!data.success) throw new Error(data.error || 'AbuseIPDB lookup failed')
          setResult('abuseipdb', data.result)
        } catch (e) {
          setResult('abuseipdb', { error: e.message })
        } finally {
          setLoad('abuseipdb', false)
        }
      })
    } else if (ioc.type === 'IP') {
      setResults((prev) => ({ ...prev, abuseipdb: { skipped: true } }))
    }

    if (ioc.type === 'IP' && config.shodan?.apiKey && config.shodan?.enabled !== false) {
      checks.push(async () => {
        setLoad('shodan', true)
        try {
          const r = await fetch(`${API_BASE}/api/shodan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ioc.indicator, apiKey: config.shodan.apiKey }),
          })
          const data = await r.json()
          if (!data.success) throw new Error(data.error || 'Shodan lookup failed')
          setResult('shodan', data.result)
        } catch (e) {
          setResult('shodan', { error: e.message })
        } finally {
          setLoad('shodan', false)
        }
      })
    } else if (ioc.type === 'IP') {
      setResults((prev) => ({ ...prev, shodan: { skipped: true } }))
    }

    if (ioc.type === 'SHA256') {
      checks.push(async () => {
        setLoad('malwarebazaar', true)
        try {
          const result = await postLookup('malwarebazaar', ioc.indicator)
          const data = result.data
          if (!result.success || data?.query_status === 'hash_not_found') {
            setResult('malwarebazaar', { notFound: true })
          } else if (data?.query_status !== 'ok') {
            throw new Error(data.query_status || 'MalwareBazaar lookup failed')
          } else {
            setResult('malwarebazaar', data.data)
          }
        } catch (e) {
          setResult('malwarebazaar', { error: e.message })
        } finally {
          setLoad('malwarebazaar', false)
        }
      })
    }

    checks.push(async () => {
      setLoad('threatfox', true)
      try {
        const result = await postLookup('threatfox', ioc.indicator)
        const data = result.data
        if (data?.query_status === 'ok' && data.data?.length > 0) {
          setResult('threatfox', data.data[0])
        } else {
          setResult('threatfox', { notFound: true })
        }
      } catch {
        setResult('threatfox', { notFound: true })
      } finally {
        setLoad('threatfox', false)
      }
    })

    if (ioc.type === 'URL' || ioc.type === 'Domain') {
      checks.push(async () => {
        setLoad('urlhaus', true)
        try {
          const result = await postLookup('urlhaus', ioc.indicator)
          const data = result.data
          if (result.success && data?.query_status === 'ok') {
            setResult('urlhaus', data)
          } else {
            setResult('urlhaus', { notFound: true })
          }
        } catch {
          setResult('urlhaus', { notFound: true })
        } finally {
          setLoad('urlhaus', false)
        }
      })
    }

    if (ioc.type === 'Domain') {
      checks.push(async () => {
        setLoad('whois', true)
        try {
          const [whoisResult, dnsResult] = await Promise.all([
            postLookup('whois', ioc.indicator),
            postLookup('dns', ioc.indicator),
          ])
          const domain = whoisResult.success ? whoisResult.data?.domains?.[0] : null
          const ips = dnsResult.success
            ? (dnsResult.data?.Answer || []).filter((a) => a.type === 1).map((a) => a.data)
            : []
          let ageDays = null
          if (domain?.create_date) {
            ageDays = Math.floor((Date.now() - new Date(domain.create_date).getTime()) / 86400000)
          }
          setResult('whois', {
            domain,
            ips,
            ageDays,
            whoisUnavailable: !whoisResult.success,
          })
        } catch {
          setResult('whois', { whoisUnavailable: true, ips: [] })
        } finally {
          setLoad('whois', false)
        }
      })
    }

    Promise.allSettled(checks.map((fn) => fn()))
  }, [ioc])

  function copyText(text) {
    navigator.clipboard.writeText(text).catch(() => {})
    setToast('Copied!')
    setTimeout(() => setToast(''), 2000)
  }

  function exportReport() {
    const md = buildMarkdownReport(ioc, results)
    const blob = new Blob([md], { type: 'text/markdown' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `ioc-investigation-${ioc.indicator.slice(0, 20).replace(/[^a-zA-Z0-9]/g, '_')}.md`
    a.click()
  }

  function handleWhitelist() {
    if (onWhitelist) {
      onWhitelist(ioc.indicator)
    } else {
      const list = JSON.parse(localStorage.getItem('iocWhitelist') || '[]')
      if (!list.includes(ioc.indicator)) {
        localStorage.setItem('iocWhitelist', JSON.stringify([...list, ioc.indicator]))
      }
    }
    setWhitelistConfirm(false)
    onClose()
  }

  const confColor = (c) => (c === 'High' ? '#f85149' : c === 'Medium' ? '#d29922' : '#8b949e')
  const statusColor = (s) => (s === 'active' ? '#f85149' : s === 'investigating' ? '#d29922' : '#3fb950')

  const geo = results.geolocation
  const vt = results.virustotal
  const abuse = results.abuseipdb
  const shodan = results.shodan
  const mb = results.malwarebazaar
  const tf = results.threatfox
  const uh = results.urlhaus
  const whois = results.whois

  if (!ioc) return null

  return (
    <div className="ioc-inv-overlay" onClick={onClose}>
      <div className="ioc-inv-modal" onClick={(e) => e.stopPropagation()}>
        <div className="ioc-inv-header">
          <div className="ioc-inv-header-main">
            <div className="ioc-inv-indicator">{ioc.indicator}</div>
            <div className="ioc-inv-badges">
              <span className="ioc-inv-badge">{ioc.type}</span>
              {ioc.source && <span className="ioc-inv-badge ioc-inv-badge-source">{ioc.source}</span>}
              {ioc.confidence && (
                <span className="ioc-inv-badge" style={{ color: confColor(ioc.confidence) }}>{ioc.confidence}</span>
              )}
              {ioc.status && (
                <span className="ioc-inv-badge">
                  <span className="ioc-inv-status-dot" style={{ background: statusColor(ioc.status) }} />
                  {ioc.status}
                </span>
              )}
            </div>
          </div>
          <div className="ioc-inv-header-actions">
            <button type="button" className="ioc-inv-btn-secondary" onClick={() => copyText(ioc.indicator)}>
              Copy IOC
            </button>
            <button type="button" className="ioc-inv-btn-secondary" onClick={() => setShowKql(!showKql)}>
              {showKql ? 'Hide KQL' : 'Show KQL'}
            </button>
            <button type="button" className="ioc-inv-close" onClick={onClose}>✕</button>
          </div>
        </div>

        {showKql && (
          <div className="ioc-inv-kql-panel">
            <pre>{kql}</pre>
            <button type="button" className="ioc-inv-btn-secondary" onClick={() => copyText(kql)}>Copy KQL</button>
          </div>
        )}

        <div className="ioc-inv-body">
          {ioc.type === 'IP' && (
            <InvestCard
              title="IP Geolocation"
              icon="🌍"
              sourceKey="geolocation"
              loading={loading.geolocation}
              error={geo?.error}
              wide
            >
              {geo && !geo.error && (
                <>
                  <div className="ioc-inv-geo-row">
                    <span className="ioc-inv-geo-flag">{countryFlag(geo.countryCode)}</span>
                    <div>
                      <div className="ioc-inv-geo-country">{geo.country} — {geo.city}</div>
                      <div className="ioc-inv-geo-detail">ISP: {geo.isp || '—'}</div>
                      <div className="ioc-inv-geo-detail">ASN: {geo.as || geo.org || '—'}</div>
                    </div>
                  </div>
                  <div className="ioc-inv-badge-row">
                    {geo.proxy && <span className="ioc-inv-pill ioc-inv-pill-red">PROXY</span>}
                    {geo.hosting && <span className="ioc-inv-pill ioc-inv-pill-amber">VPN/HOSTING</span>}
                    {geo.mobile && <span className="ioc-inv-pill ioc-inv-pill-blue">MOBILE</span>}
                  </div>
                  <div className="ioc-inv-map-placeholder">
                    {countryFlag(geo.countryCode)} {geo.country}
                  </div>
                </>
              )}
            </InvestCard>
          )}

          <div className="ioc-inv-grid">
            <InvestCard
              title="VirusTotal"
              icon="🦠"
              loading={loading.virustotal}
              skipped={vt?.skipped}
              error={vt?.error}
            >
              {vt && !vt.skipped && !vt.error && (
                <>
                  {vt.vtMalicious > 0 ? (
                    <div className="ioc-inv-vt-malicious">MALICIOUS — {vt.vtMalicious} engines</div>
                  ) : (
                    <div className="ioc-inv-vt-clean">Clean</div>
                  )}
                  <div className="ioc-inv-progress-wrap">
                    <div
                      className="ioc-inv-progress-bar"
                      style={{
                        width: `${vt.vtTotal ? (vt.vtMalicious / vt.vtTotal) * 100 : 0}%`,
                        background: vt.vtMalicious > 0 ? '#f85149' : '#3fb950',
                      }}
                    />
                  </div>
                  <div className="ioc-inv-detail">
                    {vt.vtMalicious}/{vt.vtTotal} engines detected
                  </div>
                  {vt.categories && Object.keys(vt.categories).length > 0 && (
                    <div className="ioc-inv-detail">
                      Categories: {Object.values(vt.categories).join(', ')}
                    </div>
                  )}
                  <a href={vtLink(ioc)} target="_blank" rel="noreferrer" className="ioc-inv-link">
                    View on VirusTotal →
                  </a>
                </>
              )}
            </InvestCard>

            {ioc.type === 'IP' && (
              <InvestCard
                title="AbuseIPDB"
                icon="🚨"
                loading={loading.abuseipdb}
                skipped={abuse?.skipped}
                error={abuse?.error}
              >
                {abuse && !abuse.skipped && !abuse.error && (
                  <>
                    <div className="ioc-inv-abuse-score" style={{ color: abuseColor(abuse.abuseScore) }}>
                      {abuse.abuseScore ?? 0}
                      <span className="ioc-inv-abuse-max">/100</span>
                    </div>
                    <div className="ioc-inv-progress-wrap">
                      <div
                        className="ioc-inv-progress-bar"
                        style={{ width: `${abuse.abuseScore || 0}%`, background: abuseColor(abuse.abuseScore) }}
                      />
                    </div>
                    <div className="ioc-inv-detail">{abuse.totalReports || 0} reports</div>
                    {abuse.lastReported && (
                      <div className="ioc-inv-detail">Last reported: {abuse.lastReported}</div>
                    )}
                    <div className="ioc-inv-badge-row">
                      {abuse.isTor && <span className="ioc-inv-pill ioc-inv-pill-red">TOR</span>}
                      {abuse.usageType && <span className="ioc-inv-pill ioc-inv-pill-amber">{abuse.usageType}</span>}
                    </div>
                    <a
                      href={`https://www.abuseipdb.com/check/${encodeURIComponent(ioc.indicator)}`}
                      target="_blank"
                      rel="noreferrer"
                      className="ioc-inv-link"
                    >
                      View on AbuseIPDB →
                    </a>
                  </>
                )}
              </InvestCard>
            )}

            {ioc.type === 'IP' && (
              <InvestCard
                title="Shodan"
                icon="🔭"
                loading={loading.shodan}
                skipped={shodan?.skipped}
                error={shodan?.error}
              >
                {shodan && !shodan.skipped && !shodan.error && (
                  <>
                    {shodan.os && <div className="ioc-inv-detail">OS: {shodan.os}</div>}
                    <div className="ioc-inv-port-row">
                      {(shodan.openPorts || []).slice(0, 12).map((p) => (
                        <span key={p} className="ioc-inv-port-badge">{p}</span>
                      ))}
                    </div>
                    {shodan.hostnames?.length > 0 && (
                      <div className="ioc-inv-detail">Hostnames: {shodan.hostnames.join(', ')}</div>
                    )}
                    {shodan.vulns?.length > 0 ? (
                      <div className="ioc-inv-cve-alert">{shodan.vulns.length} CVEs found</div>
                    ) : null}
                    {shodan.vulns?.length > 0 && (
                      <div className="ioc-inv-vuln-list">{shodan.vulns.slice(0, 8).join(', ')}</div>
                    )}
                    <a
                      href={`https://www.shodan.io/host/${encodeURIComponent(ioc.indicator)}`}
                      target="_blank"
                      rel="noreferrer"
                      className="ioc-inv-link"
                    >
                      View on Shodan →
                    </a>
                  </>
                )}
              </InvestCard>
            )}

            <InvestCard title="ThreatFox" icon="🦊" loading={loading.threatfox}>
              {tf && (
                tf.notFound ? (
                  <div className="ioc-inv-not-found">Not listed in ThreatFox</div>
                ) : (
                  <>
                    <div className="ioc-inv-listed">Listed in ThreatFox</div>
                    <div className="ioc-inv-detail">Malware: {tf.malware || tf.malware_printable || '—'}</div>
                    <div className="ioc-inv-detail">Threat type: {tf.threat_type || '—'}</div>
                    <div className="ioc-inv-detail">First seen: {tf.first_seen || '—'}</div>
                    <div className="ioc-inv-detail">
                      Confidence: {tf.confidence_level ?? '—'}
                    </div>
                    {tf.tags?.length > 0 && (
                      <div className="ioc-inv-badge-row">
                        {tf.tags.map((t) => (
                          <span key={t} className="ioc-inv-pill">{t}</span>
                        ))}
                      </div>
                    )}
                  </>
                )
              )}
            </InvestCard>

            {(ioc.type === 'URL' || ioc.type === 'Domain') && (
              <InvestCard title="URLhaus" icon="🔗" loading={loading.urlhaus}>
                {uh && (
                  uh.notFound ? (
                    <div className="ioc-inv-not-found">Not listed in URLhaus</div>
                  ) : (
                    <>
                      <span className={`ioc-inv-pill ${uh.url_status === 'online' || uh.host_status === 'online' ? 'ioc-inv-pill-red' : 'ioc-inv-pill-amber'}`}>
                        {uh.url_status || uh.host_status || 'unknown'}
                      </span>
                      {uh.tags && <div className="ioc-inv-detail">Tags: {Array.isArray(uh.tags) ? uh.tags.join(', ') : uh.tags}</div>}
                      {uh.blacklists && <div className="ioc-inv-detail">Blacklists: {JSON.stringify(uh.blacklists)}</div>}
                      {(uh.url_count != null || uh.urls_count != null) && (
                        <div className="ioc-inv-detail">URLs: {uh.url_count ?? uh.urls_count}</div>
                      )}
                      {uh.urlhaus_reference && (
                        <a href={uh.urlhaus_reference} target="_blank" rel="noreferrer" className="ioc-inv-link">
                          View on URLhaus →
                        </a>
                      )}
                    </>
                  )
                )}
              </InvestCard>
            )}

            {ioc.type === 'Domain' && (
              <InvestCard title="WHOIS / DNS" icon="📋" loading={loading.whois}>
                {whois && (
                  <>
                    {whois.whoisUnavailable && (
                      <div className="ioc-inv-not-found">WHOIS data unavailable</div>
                    )}
                    {whois.domain?.create_date && (
                      <div className="ioc-inv-detail">Registered: {whois.domain.create_date}</div>
                    )}
                    {whois.ageDays != null && (
                      <div className="ioc-inv-detail">Domain age: {whois.ageDays} days</div>
                    )}
                    {whois.domain?.registrar && (
                      <div className="ioc-inv-detail">Registrar: {whois.domain.registrar}</div>
                    )}
                    {whois.ips?.length > 0 ? (
                      <div className="ioc-inv-detail">Resolved IPs: {whois.ips.join(', ')}</div>
                    ) : (
                      <div className="ioc-inv-not-found">No A records found</div>
                    )}
                  </>
                )}
              </InvestCard>
            )}

            {ioc.type === 'SHA256' && (
              <InvestCard title="MalwareBazaar" icon="🧬" loading={loading.malwarebazaar} error={mb?.error} wide>
                {mb && !mb.error && (
                  mb.notFound ? (
                    <div className="ioc-inv-not-found">Hash not found in MalwareBazaar</div>
                  ) : (
                    <>
                      <div className="ioc-inv-detail">File: {mb.file_name || '—'} ({mb.file_type_mime || mb.file_type || '—'})</div>
                      <div className="ioc-inv-detail">Size: {mb.file_size ? `${mb.file_size} bytes` : '—'}</div>
                      <div className="ioc-inv-detail">Malware: {mb.signature || '—'}</div>
                      <div className="ioc-inv-detail">First seen: {mb.first_seen || '—'}</div>
                      <div className="ioc-inv-detail">Last seen: {mb.last_seen || '—'}</div>
                      {mb.tags?.length > 0 && (
                        <div className="ioc-inv-badge-row">
                          {mb.tags.map((t) => (
                            <span key={t} className="ioc-inv-pill">{t}</span>
                          ))}
                        </div>
                      )}
                      {mb.delivery_url && (
                        <a href={mb.delivery_url} target="_blank" rel="noreferrer" className="ioc-inv-link">
                          Download sample →
                        </a>
                      )}
                    </>
                  )
                )}
              </InvestCard>
            )}
          </div>
        </div>

        <div className="ioc-inv-footer">
          <button type="button" className="ioc-inv-btn-primary" onClick={() => copyText(kql)}>
            Generate Sentinel Hunt Query
          </button>
          <button
            type="button"
            className="ioc-inv-btn-secondary"
            onClick={() => {
              onAddToWatchlist?.(ioc)
              setToast('Added to watchlist selection')
              setTimeout(() => setToast(''), 2000)
            }}
          >
            Add to Watchlist
          </button>
          <button type="button" className="ioc-inv-btn-secondary" onClick={() => setWhitelistConfirm(true)}>
            Whitelist this IOC
          </button>
          <button type="button" className="ioc-inv-btn-secondary" onClick={exportReport}>
            Export Investigation Report
          </button>
        </div>

        {whitelistConfirm && (
          <div className="ioc-inv-confirm-overlay" onClick={() => setWhitelistConfirm(false)}>
            <div className="ioc-inv-confirm" onClick={(e) => e.stopPropagation()}>
              <p>Whitelist <code>{ioc.indicator}</code>? It will be hidden from the IOC tracker.</p>
              <div className="ioc-inv-confirm-actions">
                <button type="button" className="ioc-inv-btn-secondary" onClick={() => setWhitelistConfirm(false)}>Cancel</button>
                <button type="button" className="ioc-inv-btn-danger" onClick={handleWhitelist}>Confirm</button>
              </div>
            </div>
          </div>
        )}

        {toast && <div className="ioc-inv-toast">{toast}</div>}
      </div>
    </div>
  )
}
