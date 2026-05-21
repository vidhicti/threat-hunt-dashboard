import { useState, useEffect, useMemo, useCallback } from 'react'
import localIocs from '../data/iocs.json'
import {
  fetchAllIOCs,
  generateWatchlistKQL,
  FEED_LABELS,
  FEED_COUNT,
  mergeIocLists,
} from '../services/threatIntel'

const PAGE_SIZE = 50

const STATUS_DOT = {
  active: 'var(--red)',
  investigating: 'var(--amber)',
  watchlist: 'var(--green)',
}

const TYPE_OPTIONS = ['All', 'IP', 'URL', 'Domain', 'SHA256']

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

const today = new Date().toISOString().split('T')[0]

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


function matchesType(ioc, filterType) {
  if (filterType === 'All') return true
  const t = String(ioc.type || '')
  if (filterType === 'IP') return t === 'IP' || t.toLowerCase().includes('ip')
  return t === filterType
}

function LoadingSkeleton() {
  return (
    <div className="ioc-skeleton-wrap" aria-hidden="true">
      {[1, 2, 3].map((n) => (
        <div key={n} className="ioc-skeleton-row">
          <span className="ioc-skeleton-cell short" />
          <span className="ioc-skeleton-cell long" />
          <span className="ioc-skeleton-cell medium" />
          <span className="ioc-skeleton-cell medium" />
          <span className="ioc-skeleton-cell long" />
        </div>
      ))}
    </div>
  )
}

function IocTracker({ onIocCountChange }) {
  const [iocs, setIocs] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [lastUpdated, setLastUpdated] = useState(null)
  const [totalCount, setTotalCount] = useState(0)
  const [feedStatus, setFeedStatus] = useState({})
  const [loadProgress, setLoadProgress] = useState(0)
  const [selectedIOCs, setSelectedIOCs] = useState(new Set())
  const [searchTerm, setSearchTerm] = useState('')
  const [filterType, setFilterType] = useState('All')
  const [filterSource, setFilterSource] = useState('All')
  const [filterConfidence, setFilterConfidence] = useState('All')
  const [filterStatus, setFilterStatus] = useState('All')
  const [page, setPage] = useState(1)
  const [generatedKQL, setGeneratedKQL] = useState('')
  const [showKQLModal, setShowKQLModal] = useState(false)
  const [copyMsg, setCopyMsg] = useState('')

  const loadIOCs = useCallback(async () => {
    setLoading(true)
    setError(null)
    setLoadProgress(0)

    const progressTimer = setInterval(() => {
      setLoadProgress((p) => Math.min(p + 8, 90))
    }, 400)

    try {
      const { iocs: live, feedStatus: status, totalCount: count } =
        await fetchAllIOCs()
      const merged = mergeIocLists(live, localIocs.map(normalizeLocalIoc))
      setFeedStatus(status)
      setTotalCount(merged.length)
      setIocs(merged)
      onIocCountChange?.(merged.length)
      setLastUpdated(new Date())
      setLoadProgress(100)
    } catch (err) {
      setError(err.message || 'Failed to load live IOCs')
      const merged = mergeIocLists([], localIocs.map(normalizeLocalIoc))
      setIocs(merged)
      setTotalCount(merged.length)
      onIocCountChange?.(merged.length)
      setFeedStatus(
        Object.fromEntries(Object.keys(FEED_LABELS).map((k) => [k, false]))
      )
    } finally {
      clearInterval(progressTimer)
      setLoading(false)
      setTimeout(() => setLoadProgress(0), 600)
    }
  }, [onIocCountChange])

  useEffect(() => {
    loadIOCs()
  }, [loadIOCs])

  useEffect(() => {
    setPage(1)
  }, [searchTerm, filterType, filterSource, filterConfidence, filterStatus])

  const sourceOptions = useMemo(
    () => ['All', ...Object.values(FEED_LABELS), 'Threat Intel Feed', 'Hunt Finding Q005'],
    []
  )

  const filtered = useMemo(() => {
    const term = searchTerm.trim().toLowerCase()
    return iocs.filter((ioc) => {
      if (!matchesType(ioc, filterType)) return false
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

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))

  const paginated = useMemo(() => {
    const start = (page - 1) * PAGE_SIZE
    return filtered.slice(start, start + PAGE_SIZE)
  }, [filtered, page])

  const stats = useMemo(() => {
    const norm = (t) => String(t || '').toLowerCase()
    return {
      total: iocs.length,
      ips: iocs.filter((i) => norm(i.type) === 'ip' || norm(i.type).includes('ip')).length,
      domainsUrls: iocs.filter((i) => norm(i.type) === 'domain' || norm(i.type) === 'url').length,
      hashes: iocs.filter((i) =>
        ['hash', 'sha256', 'md5'].some((h) => norm(i.type).includes(h))
      ).length,
      active: iocs.filter((i) => i.status === 'active').length,
      today: iocs.filter((i) => i.dateAdded === today).length,
    }
  }, [iocs])

  const feedsOnline = Object.values(feedStatus).filter(Boolean).length

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
    const visible = paginated.map((i) => i.indicator)
    const allSelected = visible.every((id) => selectedIOCs.has(id))
    setSelectedIOCs((prev) => {
      const next = new Set(prev)
      if (allSelected) {
        visible.forEach((id) => next.delete(id))
      } else {
        visible.forEach((id) => next.add(id))
      }
      return next
    })
  }

  const clearFilters = () => {
    setSearchTerm('')
    setFilterType('All')
    setFilterSource('All')
    setFilterConfidence('All')
    setFilterStatus('All')
    setPage(1)
  }

  const selectedObjects = iocs.filter((i) => selectedIOCs.has(i.indicator))

  const handleGenerateKQL = () => {
    setGeneratedKQL(generateWatchlistKQL(selectedObjects))
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
          <span className="ioc-count-badge">
            {totalCount} IOCs from {FEED_COUNT} feeds
            {feedsOnline > 0 && ` (${feedsOnline} online)`}
          </span>
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
            className={`feed-badge ${feedStatus[key] ? 'feed-ok' : 'feed-fail'}`}
          >
            {label} {feedStatus[key] ? '✓' : '✗'}
          </span>
        ))}
      </div>

      {loading && (
        <div className="ioc-load-progress-wrap">
          <p className="ioc-loading-msg">
            Fetching from {FEED_COUNT} threat intel feeds…
          </p>
          <div className="ioc-progress-track" role="progressbar" aria-valuenow={loadProgress} aria-valuemin={0} aria-valuemax={100}>
            <div
              className="ioc-progress-bar"
              style={{ width: `${loadProgress}%` }}
            />
          </div>
        </div>
      )}

      {error && <p className="ioc-error-banner">{error} — showing local IOCs only.</p>}

      <div className="ioc-filter-row">
        <input
          type="search"
          placeholder="Search indicators, types, TTPs, sources…"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="ioc-search-input"
          aria-label="Search IOCs"
          disabled={loading && iocs.length === 0}
        />
        <select
          value={filterType}
          onChange={(e) => setFilterType(e.target.value)}
          aria-label="Filter by type"
        >
          {TYPE_OPTIONS.map((t) => (
            <option key={t} value={t}>
              Type: {t}
            </option>
          ))}
        </select>
        <select
          value={filterSource}
          onChange={(e) => setFilterSource(e.target.value)}
          aria-label="Filter by source"
        >
          {sourceOptions.map((s) => (
            <option key={s} value={s}>
              Source: {s}
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
              Confidence: {c}
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
              Status: {s}
            </option>
          ))}
        </select>
        <button type="button" className="clear-filters-btn" onClick={clearFilters}>
          Clear filters
        </button>
      </div>

      <div className="ioc-stats-row ioc-stats-row-6">
        <div className="ioc-stat-card">
          <span className="ioc-stat-value">{stats.total}</span>
          <span className="ioc-stat-label">Total</span>
        </div>
        <div className="ioc-stat-card">
          <span className="ioc-stat-value">{stats.ips}</span>
          <span className="ioc-stat-label">IPs</span>
        </div>
        <div className="ioc-stat-card">
          <span className="ioc-stat-value">{stats.domainsUrls}</span>
          <span className="ioc-stat-label">Domains/URLs</span>
        </div>
        <div className="ioc-stat-card">
          <span className="ioc-stat-value">{stats.hashes}</span>
          <span className="ioc-stat-label">Hashes</span>
        </div>
        <div className="ioc-stat-card">
          <span className="ioc-stat-value">{stats.active}</span>
          <span className="ioc-stat-label">Active</span>
        </div>
        <div className="ioc-stat-card">
          <span className="ioc-stat-value">{stats.today}</span>
          <span className="ioc-stat-label">Today</span>
        </div>
      </div>

      {loading && iocs.length === 0 ? (
        <LoadingSkeleton />
      ) : (
        <>
          <div className="ioc-table-wrapper">
            <table className="ioc-table">
              <thead>
                <tr>
                  <th>
                    <input
                      type="checkbox"
                      checked={
                        paginated.length > 0 &&
                        paginated.every((i) => selectedIOCs.has(i.indicator))
                      }
                      onChange={toggleSelectAll}
                      aria-label="Select all on this page"
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
                {paginated.map((ioc, index) => (
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
                      <span
                        className={`confidence-${(ioc.confidence || '').toLowerCase()}`}
                      >
                        {ioc.confidence}
                      </span>
                    </td>
                    <td>
                      <span className="status-cell">
                        <span
                          className="status-dot"
                          style={{
                            backgroundColor:
                              STATUS_DOT[ioc.status] || 'var(--text-muted)',
                          }}
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

          {filtered.length > PAGE_SIZE && (
            <div className="ioc-pagination">
              <button
                type="button"
                className="pagination-btn"
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                Previous
              </button>
              <span className="page-indicator">
                Page {page} of {totalPages} ({filtered.length} matching)
              </span>
              <button
                type="button"
                className="pagination-btn"
                disabled={page >= totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              >
                Next
              </button>
            </div>
          )}
        </>
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
        <div
          className="modal-overlay"
          role="dialog"
          aria-modal="true"
          aria-labelledby="kql-modal-title"
        >
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
