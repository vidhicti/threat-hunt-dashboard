import { useState, useMemo } from 'react'
import iocs from '../data/iocs.json'

const STATUS_DOT = {
  active: 'var(--red)',
  investigating: 'var(--amber)',
  watchlist: 'var(--green)',
}

function IocTracker() {
  const [search, setSearch] = useState('')

  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase()
    if (!term) return iocs

    return iocs.filter((ioc) =>
      [
        ioc.indicator,
        ioc.type,
        ioc.ttp,
        ioc.ttpId,
        ioc.source,
        ioc.logSource,
        ioc.confidence,
        ioc.status,
        ioc.dateAdded,
      ]
        .join(' ')
        .toLowerCase()
        .includes(term)
    )
  }, [search])

  return (
    <div className="ioc-tracker">
      <div className="ioc-search-bar">
        <input
          type="search"
          placeholder="Search indicators, types, TTPs, sources, status..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="ioc-search-input"
          aria-label="Search IOCs"
        />
        <span className="ioc-count">
          {filtered.length} of {iocs.length} IOCs
        </span>
      </div>

      <div className="ioc-table-wrapper">
        <table className="ioc-table">
          <thead>
            <tr>
              <th>Indicator</th>
              <th>Type</th>
              <th>TTP</th>
              <th>Log Source</th>
              <th>Confidence</th>
              <th>Status</th>
              <th>Date Added</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((ioc, index) => (
              <tr key={`${ioc.indicator}-${index}`}>
                <td className="indicator-cell" title={ioc.indicator}>
                  {ioc.indicator}
                </td>
                <td>
                  <span className="type-badge">{ioc.type}</span>
                </td>
                <td>
                  <span className="ttp-cell">
                    {ioc.ttpId}
                    <small>{ioc.ttp}</small>
                  </span>
                </td>
                <td>{ioc.logSource}</td>
                <td>
                  <span className={`confidence-${ioc.confidence.toLowerCase()}`}>
                    {ioc.confidence}
                  </span>
                </td>
                <td>
                  <span className="status-cell">
                    <span
                      className="status-dot"
                      style={{ backgroundColor: STATUS_DOT[ioc.status] }}
                      aria-hidden="true"
                    />
                    {ioc.status}
                  </span>
                </td>
                <td>{ioc.dateAdded}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {filtered.length === 0 && (
        <p className="empty-state">No IOCs match your search.</p>
      )}
    </div>
  )
}

export default IocTracker
