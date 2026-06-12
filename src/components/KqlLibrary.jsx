import { useState, useEffect, useMemo, useRef } from 'react'
import queries from '../data/queries.json'
import { validateKQL } from '../services/kqlValidator'

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

function ValidationPanel({ result }) {
  if (!result) return null
  const hasIssues =
    result.errors.length > 0 || result.warnings.length > 0 || result.suggestions.length > 0

  return (
    <div className="kql-validation-panel">
      <div className="kql-validation-score">
        <span>Score: {result.score}/100</span>
        <div className="kql-validation-bar">
          <div
            className="kql-validation-bar-fill"
            style={{ width: `${result.score}%`, background: result.gradeColor }}
          />
        </div>
      </div>
      {!hasIssues && <p className="kql-val-ok">All checks passed ✓</p>}
      {result.errors.length > 0 && (
        <ul className="kql-validation-list">
          {result.errors.map((msg, i) => (
            <li key={`e-${i}`} className="kql-val-error">
              ✗ {msg}
            </li>
          ))}
        </ul>
      )}
      {result.warnings.length > 0 && (
        <ul className="kql-validation-list">
          {result.warnings.map((msg, i) => (
            <li key={`w-${i}`} className="kql-val-warning">
              ⚠ {msg}
            </li>
          ))}
        </ul>
      )}
      {result.suggestions.length > 0 && (
        <ul className="kql-validation-list">
          {result.suggestions.map((msg, i) => (
            <li key={`s-${i}`} className="kql-val-suggestion">
              💡 {msg}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function KqlCodeBlock({ kql }) {
  const blockRef = useRef(null)
  const [showScrollHint, setShowScrollHint] = useState(false)
  const [isMobile, setIsMobile] = useState(() => window.innerWidth < 768)

  useEffect(() => {
    const check = () => {
      setIsMobile(window.innerWidth < 768)
      const el = blockRef.current
      if (el) setShowScrollHint(el.scrollWidth > el.clientWidth)
    }
    check()
    window.addEventListener('resize', check)
    return () => window.removeEventListener('resize', check)
  }, [kql])

  return (
    <>
      <pre className="kql-block" ref={blockRef}>
        <code className="kql-code">{kql}</code>
      </pre>
      {isMobile && showScrollHint && (
        <p className="kql-scroll-hint">← Scroll to see full query →</p>
      )}
    </>
  )
}

function KqlLibrary({ highlightId, highlightTerm, onHighlightDone, defaultLookback = '1d' }) {
  const [activeCategory, setActiveCategory] = useState('all')
  const [copiedId, setCopiedId] = useState(null)
  const [timeRange, setTimeRange] = useState(defaultLookback)
  const [validationResults, setValidationResults] = useState({})
  const [expandedValidation, setExpandedValidation] = useState({})

  useEffect(() => {
    setTimeRange(defaultLookback)
  }, [defaultLookback])

  useEffect(() => {
    const results = {}
    queries.forEach((q) => {
      results[q.id] = validateKQL(q.kql)
    })
    setValidationResults(results)
  }, [])

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

  useEffect(() => {
    try {
      const raw = sessionStorage.getItem('searchHighlight')
      if (!raw) return
      const { type, value, timestamp } = JSON.parse(raw)
      if (type !== 'query' || Date.now() - timestamp > 5000) return
      sessionStorage.removeItem('searchHighlight')
      const match = queries.find((q) => q.title === value || q.id === value)
      if (!match) return
      requestAnimationFrame(() => {
        const el = document.getElementById(`query-card-${match.id}`)
        if (el) {
          el.scrollIntoView({ behavior: 'smooth', block: 'center' })
          el.classList.add('search-highlight')
          setTimeout(() => el.classList.remove('search-highlight'), 2000)
        }
      })
    } catch {
      sessionStorage.removeItem('searchHighlight')
    }
  }, [])

  const copyKql = async (query) => {
    try {
      await navigator.clipboard.writeText(updateTimeFilter(query.kql))
      setCopiedId(query.id)
      setTimeout(() => setCopiedId(null), 2000)
    } catch {
      setCopiedId(null)
    }
  }

  const toggleValidation = (queryId) => {
    setExpandedValidation((prev) => ({ ...prev, [queryId]: !prev[queryId] }))
  }

  return (
    <div className="kql-library">
      <div className="library-toolbar">
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <span style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>Time Range:</span>
          {TIME_RANGES.map((tr) => (
            <button
              key={tr.value}
              type="button"
              style={{
                padding: '4px 12px',
                background: timeRange === tr.value ? 'var(--accent-blue)' : 'var(--bg-tertiary)',
                border: timeRange === tr.value ? 'none' : '1px solid var(--border-primary)',
                borderRadius: 20,
                color: timeRange === tr.value ? 'var(--bg-primary)' : 'var(--text-secondary)',
                fontSize: 11,
                cursor: 'pointer',
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
        {filtered.map((query) => {
          const validation = validationResults[query.id]
          return (
            <article
              key={query.id}
              id={`query-card-${query.id}`}
              className={`query-card ${highlightId === query.id ? 'search-highlight-flash' : ''}`}
            >
              <div className="query-card-header-with-grade">
                <div className="query-card-header">
                  <h3>{query.title}</h3>
                  <div className="query-badges">
                    <span className={`badge severity-${query.severity}`}>{query.severity}</span>
                    <span className="badge badge-mitre">{query.mitreTechnique}</span>
                    <span className="badge badge-log">{query.logSource}</span>
                  </div>
                </div>
                {validation && (
                  <button
                    type="button"
                    className="kql-grade-badge"
                    style={{ background: validation.gradeColor }}
                    title={`Grade ${validation.grade} — click for details`}
                    onClick={() => toggleValidation(query.id)}
                    aria-expanded={!!expandedValidation[query.id]}
                  >
                    {validation.grade}
                  </button>
                )}
              </div>

              {expandedValidation[query.id] && <ValidationPanel result={validation} />}

              <KqlCodeBlock kql={updateTimeFilter(query.kql)} />

              <div className="query-card-footer">
                <p className="query-description">{query.description}</p>
                <button type="button" className="copy-btn" onClick={() => copyKql(query)}>
                  {copiedId === query.id ? 'Copied!' : 'Copy KQL'}
                </button>
              </div>
            </article>
          )
        })}
      </div>

      {filtered.length === 0 && <p className="empty-state">No queries in this category.</p>}
    </div>
  )
}

export default KqlLibrary
