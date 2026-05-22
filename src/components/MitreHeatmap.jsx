import { useState, useMemo, useEffect, useContext } from 'react'
import queries from '../data/queries.json'
import hypothesesData from '../data/hypotheses.json'
import { ThreatDataContext } from '../context/ThreatDataContext'
import {
  getTechniquesWithCoverage,
  countQueriesForTechnique,
} from '../utils/techniqueCoverage'

const COVERAGE_COLORS = {
  none: '#484f58',
  low: '#d29922',
  medium: '#db6d28',
  high: '#bd561d',
  critical: '#f85149',
  baselining: '#3fb950',
}

const STATUS_DOT = {
  active: 'var(--red)',
  investigating: 'var(--amber)',
  watchlist: 'var(--green)',
}

const TACTIC_ORDER = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Exfiltration',
  'Command and Control',
  'Impact',
]

function techniqueMatchesQuery(techId, mitreTechnique) {
  if (!mitreTechnique) return false
  return (
    mitreTechnique === techId ||
    mitreTechnique.startsWith(`${techId}.`) ||
    techId.startsWith(`${mitreTechnique}.`)
  )
}

function iocMatchesTechnique(techId, ioc) {
  const ttp = String(ioc.ttpId || '').toUpperCase()
  const tid = techId.toUpperCase()
  if (!ttp) return false
  return ttp === tid || ttp.startsWith(`${tid}.`) || tid.startsWith(`${ttp}.`)
}

function hypothesisMatchesTechnique(tech, hyp) {
  const chain = Array.isArray(hyp.tacticChain)
    ? hyp.tacticChain.join(' ')
    : hyp.tacticChain || ''
  if (chain.toLowerCase().includes(tech.tactic.toLowerCase())) return true
  if ((hyp.tags || []).some((t) => String(t).toUpperCase().includes(tech.id))) return true
  const related = hyp.relatedQueryIds || []
  return related.some((qid) => {
    const q = queries.find((x) => x.id === qid)
    return q && techniqueMatchesQuery(tech.id, q.mitreTechnique)
  })
}

function MitreHeatmap({ highlightId, onHighlightDone }) {
  const { liveIOCs } = useContext(ThreatDataContext)
  const [tooltip, setTooltip] = useState(null)
  const [selectedTech, setSelectedTech] = useState(null)
  const [copiedQueryId, setCopiedQueryId] = useState(null)

  const techniques = useMemo(() => getTechniquesWithCoverage(), [])

  const grouped = TACTIC_ORDER.map((tactic) => ({
    tactic,
    techniques: techniques.filter((t) => t.tactic === tactic),
  })).filter((g) => g.techniques.length > 0)

  const drawerQueries = useMemo(() => {
    if (!selectedTech) return []
    return queries.filter((q) => techniqueMatchesQuery(selectedTech.id, q.mitreTechnique))
  }, [selectedTech])

  const drawerIOCs = useMemo(() => {
    if (!selectedTech) return []
    return liveIOCs.filter((ioc) => iocMatchesTechnique(selectedTech.id, ioc))
  }, [selectedTech, liveIOCs])

  const drawerHypotheses = useMemo(() => {
    if (!selectedTech) return []
    return hypothesesData.filter((hyp) => hypothesisMatchesTechnique(selectedTech, hyp))
  }, [selectedTech])

  useEffect(() => {
    if (!highlightId) return
    const tech = techniques.find((t) => t.id === highlightId)
    if (tech) {
      setSelectedTech(tech)
      requestAnimationFrame(() => {
        document
          .getElementById(`technique-tile-${highlightId}`)
          ?.scrollIntoView({ behavior: 'smooth', block: 'center' })
        onHighlightDone?.()
      })
    }
  }, [highlightId, techniques, onHighlightDone])

  const handleTileEnter = (tech, event) => {
    const rect = event.currentTarget.getBoundingClientRect()
    const count = tech.queryCount ?? countQueriesForTechnique(tech.id)
    setTooltip({
      id: tech.id,
      name: tech.name,
      coverage: tech.coverage,
      queryCount: count,
      x: rect.left + rect.width / 2,
      y: rect.top,
    })
  }

  const handleTileClick = (tech) => {
    setSelectedTech(tech)
    setTooltip(null)
  }

  const copyKql = async (query) => {
    try {
      await navigator.clipboard.writeText(query.kql)
      setCopiedQueryId(query.id)
      setTimeout(() => setCopiedQueryId(null), 2000)
    } catch {
      setCopiedQueryId(null)
    }
  }

  return (
    <div className={`mitre-heatmap heatmap-wrap ${selectedTech ? 'drawer-open' : ''}`}>
      <div className="heatmap-main">
        <div className="heatmap-legend">
          {Object.entries(COVERAGE_COLORS).map(([level, color]) => (
            <span key={level} className="legend-item">
              <span className="legend-swatch" style={{ backgroundColor: color }} />
              {level}
            </span>
          ))}
        </div>
        <p className="heatmap-scroll-hint" aria-hidden="true">
          ← Scroll tactics horizontally on mobile →
        </p>

        <div className="heatmap-grid">
          {grouped.map(({ tactic, techniques: techs }) => (
            <div key={tactic} className="tactic-group">
              <h3 className="tactic-title">{tactic}</h3>
              <div className="tactic-tiles">
                {techs.map((tech) => (
                  <button
                    key={tech.id}
                    id={`technique-tile-${tech.id}`}
                    type="button"
                    className={`technique-tile ${selectedTech?.id === tech.id ? 'selected' : ''} ${highlightId === tech.id ? 'search-highlight-flash' : ''}`}
                    style={{ backgroundColor: COVERAGE_COLORS[tech.coverage] }}
                    title={`${tech.id} — ${tech.name}`}
                    onClick={() => handleTileClick(tech)}
                    onMouseEnter={(e) => handleTileEnter(tech, e)}
                    onMouseLeave={() => setTooltip(null)}
                    onFocus={(e) => handleTileEnter(tech, e)}
                    onBlur={() => setTooltip(null)}
                  >
                    <span className="tile-id">{tech.id}</span>
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>

        {tooltip && !selectedTech && (
          <div
            className="heatmap-tooltip"
            style={{ left: tooltip.x, top: tooltip.y - 8 }}
            role="tooltip"
          >
            <strong>Technique: {tooltip.id}</strong>
            <span>{tooltip.name}</span>
            <span className="tooltip-coverage">
              Coverage: {tooltip.queryCount} quer
              {tooltip.queryCount === 1 ? 'y' : 'ies'} · {tooltip.coverage}
            </span>
            <span className="tooltip-hint">Click to view queries</span>
          </div>
        )}
      </div>

      {selectedTech && (
        <>
          <button
            type="button"
            className="technique-drawer-backdrop"
            aria-label="Close drawer"
            onClick={() => setSelectedTech(null)}
          />
          <aside className="technique-drawer" aria-label="Technique details">
            <div className="technique-drawer-header">
              <h2>
                {selectedTech.id} — {selectedTech.name}
              </h2>
              <button
                type="button"
                className="panel-close-btn"
                onClick={() => setSelectedTech(null)}
                aria-label="Close panel"
              >
                ×
              </button>
            </div>

            <div className="technique-drawer-body">
              <section className="drawer-section">
                <h3>Detection Queries ({drawerQueries.length})</h3>
                {drawerQueries.length > 0 ? (
                  <ul className="drawer-query-list">
                    {drawerQueries.map((query) => (
                      <li key={query.id} className="drawer-query-item">
                        <div className="drawer-query-head">
                          <strong>{query.title}</strong>
                          <div className="query-badges">
                            <span className="badge badge-log">{query.logSource}</span>
                            <span className={`badge severity-${query.severity}`}>
                              {query.severity}
                            </span>
                          </div>
                        </div>
                        <button
                          type="button"
                          className="copy-btn small"
                          onClick={() => copyKql(query)}
                        >
                          {copiedQueryId === query.id ? 'Copied!' : 'Copy KQL'}
                        </button>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="drawer-empty">No queries mapped to this technique yet</p>
                )}
              </section>

              <section className="drawer-section">
                <h3>Active IOCs ({drawerIOCs.length})</h3>
                {drawerIOCs.length > 0 ? (
                  <ul className="drawer-ioc-list">
                    {drawerIOCs.slice(0, 50).map((ioc) => (
                      <li key={ioc.indicator} className="drawer-ioc-item">
                        <span className="drawer-ioc-indicator" title={ioc.indicator}>
                          {ioc.indicator.length > 36
                            ? `${ioc.indicator.slice(0, 36)}…`
                            : ioc.indicator}
                        </span>
                        <span className="type-badge">{ioc.type}</span>
                        <span className="drawer-ioc-meta">{ioc.source}</span>
                        <span className={`confidence-${(ioc.confidence || '').toLowerCase()}`}>
                          {ioc.confidence}
                        </span>
                        <span
                          className="drawer-status-dot"
                          style={{
                            backgroundColor: STATUS_DOT[ioc.status] || 'var(--text-muted)',
                          }}
                          title={ioc.status}
                        />
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="drawer-empty">No active IOCs for this technique</p>
                )}
              </section>

              <section className="drawer-section">
                <h3>Hypotheses ({drawerHypotheses.length})</h3>
                {drawerHypotheses.length > 0 ? (
                  <ul className="drawer-hyp-list">
                    {drawerHypotheses.map((hyp) => (
                      <li key={hyp.id} className="drawer-hyp-item">
                        <strong>{hyp.title}</strong>
                        <span className={`priority-pill priority-${hyp.priority}`}>
                          {hyp.priority}
                        </span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="drawer-empty">No related hypotheses</p>
                )}
              </section>
            </div>
          </aside>
        </>
      )}
    </div>
  )
}

export default MitreHeatmap
