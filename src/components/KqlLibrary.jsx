import { useState, useEffect, useMemo } from 'react'
import queries from '../data/queries.json'

const CATEGORIES = [
  { id: 'all', label: 'All' },
  { id: 'initial-access', label: 'Initial Access' },
  { id: 'execution', label: 'Execution' },
  { id: 'persistence', label: 'Persistence' },
  { id: 'privilege-escalation', label: 'Privilege Escalation' },
  { id: 'defense-evasion', label: 'Defense Evasion' },
  { id: 'credential-access', label: 'Credential Access' },
  { id: 'discovery', label: 'Discovery' },
  { id: 'lateral-movement', label: 'Lateral Movement' },
  { id: 'collection', label: 'Collection' },
  { id: 'exfiltration', label: 'Exfiltration' },
  { id: 'c2', label: 'C2' },
  { id: 'impact', label: 'Impact' },
]

function exportAllKql() {
  const content = queries
    .map(
      (q) =>
        `${'='.repeat(60)}\n` +
        `${q.id}: ${q.title}\n` +
        `${'='.repeat(60)}\n` +
        `MITRE: ${q.mitreTechnique} | Tactic: ${q.tactic}\n` +
        `Log Source: ${q.logSource} | Severity: ${q.severity}\n` +
        `Category: ${q.category}\n\n` +
        `Description:\n${q.description}\n\n` +
        `KQL:\n${q.kql}\n`
    )
    .join('\n')

  const blob = new Blob([content], { type: 'text/plain' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = 'sentinel-hunt-queries.txt'
  link.click()
  URL.revokeObjectURL(url)
}

function KqlLibrary({ highlightId, highlightTerm, onHighlightDone }) {
  const [activeCategory, setActiveCategory] = useState('all')
  const [copiedId, setCopiedId] = useState(null)

  const filtered = useMemo(() => {
    if (activeCategory === 'all') return queries
    return queries.filter((q) => q.category === activeCategory)
  }, [activeCategory])

  useEffect(() => {
    if (!highlightId) return
    const el = document.getElementById(`query-card-${highlightId}`)
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'center' })
      onHighlightDone?.()
    }
  }, [highlightId, filtered, onHighlightDone])

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
      <div className="library-toolbar">
        <button type="button" className="export-btn" onClick={exportAllKql}>
          Export All KQL
        </button>
      </div>

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
          <article
            key={query.id}
            id={`query-card-${query.id}`}
            className={`query-card ${highlightId === query.id ? 'search-highlight-flash' : ''}`}
          >
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
