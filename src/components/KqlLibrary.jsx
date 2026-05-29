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

const TIME_RANGES = [
  { value: '1h', label: '1h' },
  { value: '6h', label: '6h' },
  { value: '1d', label: '1d' },
  { value: '3d', label: '3d' },
  { value: '7d', label: '7d' },
  { value: '14d', label: '14d' },
  { value: '30d', label: '30d' },
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

function KqlLibrary({ highlightId, highlightTerm, onHighlightDone, defaultLookback = '1d' }) {
  const [activeCategory, setActiveCategory] = useState('all')
  const [copiedId, setCopiedId] = useState(null)
  const [timeRange, setTimeRange] = useState(defaultLookback)

  useEffect(() => {
    setTimeRange(defaultLookback)
  }, [defaultLookback])

  const updateTimeFilter = (kql) => {
    return kql.replace(/ago\([^)]+\)/g, `ago(${timeRange})`)
  }

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
      await navigator.clipboard.writeText(updateTimeFilter(query.kql))
      setCopiedId(query.id)
      setTimeout(() => setCopiedId(null), 2000)
    } catch {
      setCopiedId(null)
    }
  }

  return (
    <div className="kql-library">
      <div className="library-toolbar">
        <div style={{display:'flex',gap:8,alignItems:'center',flexWrap:'wrap'}}>
          <span style={{fontSize:12,color:'#8b949e'}}>Time Range:</span>
          {TIME_RANGES.map((tr) => (
            <button
              key={tr.value}
              type="button"
              style={{
                padding:'4px 12px',
                background:timeRange === tr.value ? '#58a6ff' : '#21262d',
                border:timeRange === tr.value ? 'none' : '1px solid #30363d',
                borderRadius:20,
                color:timeRange === tr.value ? '#0d1117' : '#c9d1d9',
                fontSize:11,
                cursor:'pointer',
              }}
              onClick={() => setTimeRange(tr.value)}
            >
              {tr.label}
            </button>
          ))}
        </div>
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
              <code>{updateTimeFilter(query.kql)}</code>
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
