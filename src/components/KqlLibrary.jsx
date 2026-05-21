import { useState } from 'react'
import queries from '../data/queries.json'

const CATEGORIES = [
  { id: 'all', label: 'All' },
  { id: 'initial-access', label: 'Initial Access' },
  { id: 'execution', label: 'Execution' },
  { id: 'persistence', label: 'Persistence' },
  { id: 'lateral-movement', label: 'Lateral Movement' },
  { id: 'exfiltration', label: 'Exfiltration' },
  { id: 'c2', label: 'C2' },
  { id: 'defense-evasion', label: 'Defense Evasion' },
]

function KqlLibrary() {
  const [activeCategory, setActiveCategory] = useState('all')
  const [copiedId, setCopiedId] = useState(null)

  const filtered =
    activeCategory === 'all'
      ? queries
      : queries.filter((q) => q.category === activeCategory)

  const copyKql = async (query) => {
    try {
      await navigator.clipboard.writeText(query.kql)
      setCopiedId(query.id)
      setTimeout(() => setCopiedId(null), 2000)
    } catch {
      setCopiedId(null)
    }
  }

  return (
    <div className="kql-library">
      <div className="category-filters">
        {CATEGORIES.map((cat) => (
          <button
            key={cat.id}
            type="button"
            className={`filter-btn ${activeCategory === cat.id ? 'active' : ''}`}
            onClick={() => setActiveCategory(cat.id)}
          >
            {cat.label}
          </button>
        ))}
      </div>

      <div className="query-cards">
        {filtered.map((query) => (
          <article key={query.id} className="query-card">
            <div className="query-card-header">
              <h3>{query.title}</h3>
              <div className="query-badges">
                <span className={`badge severity-${query.severity}`}>
                  {query.severity}
                </span>
                <span className="badge badge-mitre">{query.mitreTechnique}</span>
                <span className="badge badge-log">{query.logSource}</span>
              </div>
            </div>

            <pre className="kql-block">
              <code>{query.kql}</code>
            </pre>

            <div className="query-card-footer">
              <p className="query-description">{query.description}</p>
              <button
                type="button"
                className="copy-btn"
                onClick={() => copyKql(query)}
              >
                {copiedId === query.id ? 'Copied!' : 'Copy KQL'}
              </button>
            </div>
          </article>
        ))}
      </div>

      {filtered.length === 0 && (
        <p className="empty-state">No queries in this category.</p>
      )}
    </div>
  )
}

export default KqlLibrary
