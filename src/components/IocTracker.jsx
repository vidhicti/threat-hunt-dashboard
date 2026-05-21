import { useState, useEffect, useMemo, useCallback } from 'react'
import localIocs from '../data/iocs.json'
import { fetchAllIOCs, generateWatchlistKQL } from '../services/threatIntel'

const STATUS_DOT = {
  active: 'var(--red)',
  investigating: 'var(--amber)',
  watchlist: 'var(--green)',
}

const FEED_LABELS = {
  threatfox: 'ThreatFox',
  urlhaus: 'URLhaus',
  feodotracker: 'FeodoTracker',
  malwarebazaar: 'MalwareBazaar',
}

const CSV_HEADERS = [
  'Indicator',
  'Type',
  'TTP',
  'TTP ID',
  'Malware Family',
  'Log Source',
  'Confidence',
  'Status',
  'Source',
  'Date Added',
]

function escapeCsv(value) {
  const str = String(value ?? '')
  if (str.includes('"') || str.includes(',') || str.includes('\n')) {
    return `"${str.replace(/"/g, '""')}"`
  }
  return str
}

function normalizeLocalIoc(ioc) {
  return {
    ...ioc,
    malwareFamily: ioc.malwareFamily || '',
    threatType: ioc.threatType || '',
    ttpId: ioc.ttpId || '',
  }
}

function mergeIocs(live, local) {
  const seen = new Set()
  const merged = []

  ;[...live, ...local.map(normalizeLocalIoc)].forEach((ioc) => {
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

function IocTracker() {
  const [iocs, setIocs] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [lastUpdated, setLastUpdated] = useState(null)
  const [selectedIOCs, setSelectedIOCs] = useState(new Set())
  const [searchTerm, setSearchTerm] = useState('')
  const [filterType, setFilterType] = useState('All')
  const [filterSource, setFilterSource] = useState('All')
  const [filterConfidence, setFilterConfidence] = useState('All')
  const [filterStatus, setFilterStatus] = useState('All')
  const [generatedKQL, setGeneratedKQL] = useState('')
  const [showKQLModal, setShowKQLModal] = useState(false)
  const [activeFeeds, setActiveFeeds] = useState({})
  const [copyMsg, setCopyMsg] = useState('')

  const loadIOCs = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const { iocs: live, activeFeeds: feeds } = await fetchAllIOCs()
      setActiveFeeds(feeds)
      setIocs(mergeIocs(live, localIocs))
      setLastUpdated(new Date())
    } catch (err) {
      setError(err.message || 'Failed to load live IOCs')
      setIocs(mergeIocs([], localIocs))
      setActiveFeeds({
        threatfox: false,
        urlhaus: false,
        feodotracker: false,
        malwarebazaar: false,
      })
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadIOCs()
  }, [loadIOCs])

  const types = useMemo(() => {
    const set = new Set(iocs.map((i) => i.type).filter(Boolean))
    return ['All', ...Array.from(set).sort()]
  }, [iocs])

  const sources = useMemo(() => {
    const set = new Set(iocs.map((i) => i.source).filter(Boolean))
    return ['All', ...Array.from(set).sort()]
  }, [iocs])

  const filtered = useMemo(() => {
    const term = searchTerm.trim().toLowerCase()
    return iocs.filter((ioc) => {
      if (filterType !== 'All' && ioc.type !== filterType) return false
      if (filterSource !== 'All' && ioc.source !== filterSource) return false
      if (filterConfidence !== 'All' && ioc.confidence !== filterConfidence) return false
      if (filterStatus !== 'All' && ioc.status !== filterStatus) return false
      if (!term) return true
      return [
        ioc.indicator,
        ioc.type,
        ioc.ttp,
        ioc.ttpId,
        ioc.source,
        ioc.logSource,
        ioc.confidence,
        ioc.status,
        ioc.malwareFamily,
        ioc.dateAdded,
      ]
        .join(' ')
        .toLowerCase()
        .includes(term)
    })
  }, [iocs, searchTerm, filterType, filterSource, filterConfidence, filterStatus])

  const stats = useMemo(() => {
    const norm = (t) => String(t || '').toLowerCase()
    return {
      total: iocs.length,
      active: iocs.filter((i) => i.status === 'active').length,
      ips: iocs.filter((i) => norm(i.type) === 'ip' || norm(i.type).includes('ip')).length,
      domains: iocs.filter((i) => norm(i.type) === 'domain').length,
      hashes: iocs.filter((i) =>
        ['hash', 'sha256', 'md5'].some((h) => norm(i.type).includes(h))
      ).length,
      urls: iocs.filter((i) => norm(i.type) === 'url').length,
    }
  }, [iocs])

  const minutesAgo = lastUpdated
    ? Math.max(0, Math.floor((Date.now() - lastUpdated.getTime()) / 60000))
    : null

  const toggleSelect = (indicator) => {
    setSelectedIOCs((prev) => {
      const next = new Set(prev)
      if (next.has(indicator)) next.delete(indicator)
      else next.add(indicator)
      return next
    })
  }

  const toggleSelectAll = () => {
    if (selectedIOCs.size === filtered.length) {
      setSelectedIOCs(new Set())
    } else {
      setSelectedIOCs(new Set(filtered.map((i) => i.indicator)))
    }
  }

  const clearFilters = () => {
    setSearchTerm('')
    setFilterType('All')
    setFilterSource('All')
    setFilterConfidence('All')
    setFilterStatus('All')
  }

  const selectedObjects = iocs.filter((i) => selectedIOCs.has(i.indicator))

  const handleGenerateKQL = () => {
    const kql = generateWatchlistKQL(selectedObjects)
    setGeneratedKQL(kql)
    setShowKQLModal(true)
  }

  const exportCsv = () => {
    const rows = filtered.length ? filtered : iocs
    const lines = [
      CSV_HEADERS.join(','),
      ...rows.map((ioc) =>
        [
          ioc.indicator,
          ioc.type,
          ioc.ttp,
          ioc.ttpId,
          ioc.malwareFamily,
          ioc.logSource,
          ioc.confidence,
          ioc.status,
          ioc.source,
          ioc.dateAdded,
        ]
          .map(escapeCsv)
          .join(',')
      ),
    ]
    const blob = new Blob([lines.join('\n')], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'ioc-tracker.csv'
    link.click()
    URL.revokeObjectURL(url)
  }

  const copyAllIOCs = async () => {
    const text = (filtered.length ? filtered : iocs)
      .map((i) => `${i.type}\t${i.indicator}\t${i.source}`)
      .join('\n')
    try {
      await navigator.clipboard.writeText(text)
      setCopyMsg('Copied!')
      setTimeout(() => setCopyMsg(''), 2000)
    } catch {
      setCopyMsg('Copy failed')
    }
  }

  const copyKql = async () => {
    try {
      await navigator.clipboard.writeText(generatedKQL)
      setCopyMsg('KQL copied!')
      setTimeout(() => setCopyMsg(''), 2000)
    } catch {
      setCopyMsg('Copy failed')
    }
  }

  return (
    <div className="ioc-tracker ioc-tracker-live">
      <div className="ioc-top-bar">
        <div className="ioc-title-group">
          <h2>IOC Tracker</h2>
          <span className="live-badge">
            <span className="live-dot" aria-hidden="true" />
            LIVE
          </span>
          <span className="ioc-count-badge">{iocs.length} IOCs</span>
        </div>
        <div className="ioc-top-actions">
          {minutesAgo !== null && (
            <span className="last-updated">
              Last updated: {minutesAgo === 0 ? 'just now' : `${minutesAgo} mins ago`}
            </span>
          )}
          <button
            type="button"
            className="refresh-btn"
            onClick={loadIOCs}
            disabled={loading}
          >
            {loading ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
      </div>

      <div className="feed-status-row">
        {Object.entries(FEED_LABELS).map(([key, label]) => (
          <span
            key={key}
            className={`feed-badge ${activeFeeds[key] ? 'feed-ok' : 'feed-fail'}`}
          >
            {label} {activeFeeds[key] ? '✓' : '✗'}
          </span>
        ))}
      </div>

      {error && <p className="ioc-error-banner">{error} — showing local IOCs only.</p>}

      <div className="ioc-filter-row">
        <input
          type="search"
          placeholder="Search indicators, types, TTPs, sources…"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="ioc-search-input"
          aria-label="Search IOCs"
        />
        <select value={filterType} onChange={(e) => setFilterType(e.target.value)} aria-label="Filter by type">
          {types.map((t) => (
            <option key={t} value={t}>
              {t === 'All' ? 'Type: All' : t}
            </option>
          ))}
        </select>
        <select value={filterSource} onChange={(e) => setFilterSource(e.target.value)} aria-label="Filter by source">
          {sources.map((s) => (
            <option key={s} value={s}>
              {s === 'All' ? 'Source: All' : s}
            </option>
          ))}
        </select>
        <select
          value={filterConfidence}
          onChange={(e) => setFilterConfidence(e.target.value)}
          aria-label="Filter by confidence"
        >
          {['All', 'High', 'Medium', 'Low'].map((c) => (
            <option key={c} value={c}>
              {c === 'All' ? 'Confidence: All' : c}
            </option>
          ))}
        </select>
        <select
          value={filterStatus}
          onChange={(e) => setFilterStatus(e.target.value)}
          aria-label="Filter by status"
        >
          {['All', 'active', 'investigating', 'watchlist'].map((s) => (
            <option key={s} value={s}>
              {s === 'All' ? 'Status: All' : s}
            </option>
          ))}
        </select>
        <button type="button" className="clear-filters-btn" onClick={clearFilters}>
          Clear filters
        </button>
      </div>

      <div className="ioc-stats-row">
        <div className="ioc-stat-card">
          <span className="ioc-stat-value">{stats.total}</span>
          <span className="ioc-stat-label">Total IOCs</span>
        </div>
        <div className="ioc-stat-card">
          <span className="ioc-stat-value">{stats.active}</span>
          <span className="ioc-stat-label">Active</span>
        </div>
        <div className="ioc-stat-card">
          <span className="ioc-stat-value">{stats.ips}</span>
          <span className="ioc-stat-label">IPs</span>
        </div>
        <div className="ioc-stat-card">
          <span className="ioc-stat-value">{stats.domains}</span>
          <span className="ioc-stat-label">Domains</span>
        </div>
        <div className="ioc-stat-card">
          <span className="ioc-stat-value">{stats.hashes}</span>
          <span className="ioc-stat-label">Hashes</span>
        </div>
        <div className="ioc-stat-card">
          <span className="ioc-stat-value">{stats.urls}</span>
          <span className="ioc-stat-label">URLs</span>
        </div>
      </div>

      {loading && iocs.length === 0 ? (
        <p className="ioc-loading">Loading live threat intelligence feeds…</p>
      ) : (
        <div className="ioc-table-wrapper">
          <table className="ioc-table">
            <thead>
              <tr>
                <th>
                  <input
                    type="checkbox"
                    checked={filtered.length > 0 && selectedIOCs.size === filtered.length}
                    onChange={toggleSelectAll}
                    aria-label="Select all visible IOCs"
                  />
                </th>
                <th>Indicator</th>
                <th>Type</th>
                <th>TTP</th>
                <th>Malware Family</th>
                <th>Log Source</th>
                <th>Confidence</th>
                <th>Status</th>
                <th>Source</th>
                <th>Date Added</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((ioc, index) => (
                <tr key={`${ioc.indicator}-${index}`}>
                  <td>
                    <input
                      type="checkbox"
                      checked={selectedIOCs.has(ioc.indicator)}
                      onChange={() => toggleSelect(ioc.indicator)}
                      aria-label={`Select ${ioc.indicator}`}
                    />
                  </td>
                  <td className="indicator-cell" title={ioc.indicator}>
                    {ioc.indicator}
                  </td>
                  <td>
                    <span className="type-badge">{ioc.type}</span>
                  </td>
                  <td>
                    <span className="ttp-cell">
                      {ioc.ttpId || ioc.ttp}
                      {ioc.ttpId && <small>{ioc.ttp}</small>}
                    </span>
                  </td>
                  <td className="malware-cell" title={ioc.malwareFamily}>
                    {ioc.malwareFamily || '—'}
                  </td>
                  <td>{ioc.logSource}</td>
                  <td>
                    <span className={`confidence-${(ioc.confidence || '').toLowerCase()}`}>
                      {ioc.confidence}
                    </span>
                  </td>
                  <td>
                    <span className="status-cell">
                      <span
                        className="status-dot"
                        style={{ backgroundColor: STATUS_DOT[ioc.status] || 'var(--text-muted)' }}
                        aria-hidden="true"
                      />
                      {ioc.status}
                    </span>
                  </td>
                  <td>{ioc.source}</td>
                  <td>{ioc.dateAdded}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {!loading && filtered.length === 0 && (
        <p className="empty-state">No IOCs match your filters.</p>
      )}

      <div className="ioc-bottom-bar">
        <span className="selected-count">{selectedIOCs.size} selected</span>
        {copyMsg && <span className="copy-feedback">{copyMsg}</span>}
        <div className="ioc-bottom-actions">
          <button
            type="button"
            className="export-btn"
            disabled={selectedIOCs.size === 0}
            onClick={handleGenerateKQL}
          >
            Generate Sentinel KQL Watchlist
          </button>
          <button type="button" className="export-btn secondary" onClick={exportCsv}>
            Export CSV
          </button>
          <button type="button" className="export-btn secondary" onClick={copyAllIOCs}>
            Copy All IOCs
          </button>
        </div>
      </div>

      {showKQLModal && (
        <div className="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="kql-modal-title">
          <div className="modal-content">
            <div className="modal-header">
              <h3 id="kql-modal-title">Sentinel Watchlist KQL</h3>
              <button
                type="button"
                className="panel-close-btn"
                onClick={() => setShowKQLModal(false)}
                aria-label="Close modal"
              >
                ×
              </button>
            </div>
            <pre className="kql-block modal-kql">
              <code>{generatedKQL}</code>
            </pre>
            <div className="modal-actions">
              <button type="button" className="copy-btn" onClick={copyKql}>
                Copy KQL
              </button>
              <a
                className="sentinel-link-btn"
                href="https://portal.azure.com/#blade/Microsoft_Azure_Monitoring_Logs/LogsBlade"
                target="_blank"
                rel="noopener noreferrer"
              >
                Open in Sentinel
              </a>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default IocTracker
