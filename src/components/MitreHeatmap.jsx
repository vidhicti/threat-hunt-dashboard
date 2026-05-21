import { useState } from 'react'
import techniques from '../data/techniques.json'

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

function MitreHeatmap() {
  const [tooltip, setTooltip] = useState(null)

  const grouped = TACTIC_ORDER.map((tactic) => ({
    tactic,
    techniques: techniques.filter((t) => t.tactic === tactic),
  })).filter((g) => g.techniques.length > 0)

  const handleTileEnter = (tech, event) => {
    const rect = event.currentTarget.getBoundingClientRect()
    setTooltip({
      id: tech.id,
      name: tech.name,
      coverage: tech.coverage,
      x: rect.left + rect.width / 2,
      y: rect.top,
    })
  }

  return (
    <div className="mitre-heatmap">
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
                  type="button"
                  className="technique-tile"
                  style={{ backgroundColor: COVERAGE_COLORS[tech.coverage] }}
                  title={`${tech.id} — ${tech.name}`}
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

      {tooltip && (
        <div
          className="heatmap-tooltip"
          style={{
            left: tooltip.x,
            top: tooltip.y - 8,
          }}
          role="tooltip"
        >
          <strong>{tooltip.id}</strong>
          <span>{tooltip.name}</span>
          <span className="tooltip-coverage">Coverage: {tooltip.coverage}</span>
        </div>
      )}
    </div>
  )
}

export default MitreHeatmap
