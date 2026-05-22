import { useState, useMemo, useEffect } from 'react'
import queries from '../data/queries.json'
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

function MitreHeatmap({ highlightId, onHighlightDone }) {
  const [tooltip, setTooltip] = useState(null)
  const [selectedTech, setSelectedTech] = useState(null)

  const techniques = useMemo(() => getTechniquesWithCoverage(), [])

  const grouped = TACTIC_ORDER.map((tactic) => ({
    tactic,
    techniques: techniques.filter((t) => t.tactic === tactic),
  })).filter((g) => g.techniques.length > 0)

  const matchingQueries = useMemo(() => {
    if (!selectedTech) return []
    return queries.filter(
      (q) =>
        q.mitreTechnique === selectedTech.id ||
        q.mitreTechnique.startsWith(`${selectedTech.id}.`) ||
        selectedTech.id.startsWith(`${q.mitreTechnique}.`)
    )
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

  return (
    <div className={`mitre-heatmap ${selectedTech ? 'panel-open' : ''}`}>
      <div className="heatmap-main">
        <div className="heatmap-legend">
          {Object.entries(COVERAGE_COLORS).map(([level, color]) => (
            <span key={level} className="legend-item">
              <span className="legend-swatch" style={{ backgroundColor: color }} />
              {level}
            </span>
          ))}
        </div>

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
            style={{
              left: tooltip.x,
              top: tooltip.y - 8,
            }}
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
        <aside className="technique-panel" aria-label="Technique details">
          <div className="panel-header">
            <h2>Technique Details</h2>
            <button
              type="button"
              className="panel-close-btn"
              onClick={() => setSelectedTech(null)}
              aria-label="Close panel"
            >
              ×
            </button>
          </div>

          <div className="panel-body">
            <p className="panel-tech-id">{selectedTech.id}</p>
            <h3 className="panel-tech-name">{selectedTech.name}</h3>

            <dl className="panel-meta">
              <div className="panel-meta-row">
                <dt>Tactic</dt>
                <dd>{selectedTech.tactic}</dd>
              </div>
              <div className="panel-meta-row">
                <dt>Coverage</dt>
                <dd>
                  <span
                    className="panel-coverage-badge"
                    style={{
                      backgroundColor: COVERAGE_COLORS[selectedTech.coverage],
                    }}
                  >
                    {selectedTech.coverage} ({selectedTech.queryCount} queries)
                  </span>
                </dd>
              </div>
            </dl>

            <h4 className="panel-queries-title">
              Matching Hunt Queries ({matchingQueries.length})
            </h4>

            {matchingQueries.length > 0 ? (
              <ul className="panel-query-list">
                {matchingQueries.map((query) => (
                  <li key={query.id} className="panel-query-item">
                    <span className="panel-query-id">{query.id}</span>
                    <strong>{query.title}</strong>
                    <span className={`badge severity-${query.severity}`}>
                      {query.severity}
                    </span>
                    <p>{query.description}</p>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="panel-no-queries">
                No KQL queries mapped to this technique yet.
              </p>
            )}
          </div>
        </aside>
      )}
    </div>
  )
}

export default MitreHeatmap
