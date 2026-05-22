import { useState, useEffect, useRef, useMemo, useCallback } from 'react'
import queries from '../data/queries.json'
import hypothesesData from '../data/hypotheses.json'

const MAX_PER_SECTION = 5

function matchesQuery(text, q) {
  return String(text || '').toLowerCase().includes(q)
}

function searchIOCs(iocs, q) {
  return iocs.filter((ioc) =>
    [
      ioc.indicator,
      ioc.type,
      ioc.ttp,
      ioc.malwareFamily,
      ioc.source,
      ioc.ttpId,
      ioc.confidence,
    ].some((field) => matchesQuery(field, q))
  )
}

function searchQueries(q) {
  return queries.filter((query) =>
    [
      query.title,
      query.tactic,
      query.mitreTechnique,
      query.logSource,
      query.description,
      query.kql,
    ].some((field) => matchesQuery(field, q))
  )
}

function searchHypotheses(q) {
  return hypothesesData.filter((hyp) => {
    const tacticText = Array.isArray(hyp.tacticChain)
      ? hyp.tacticChain.join(' ')
      : hyp.tacticChain || ''
    return [
      hyp.title,
      tacticText,
      hyp.description,
      ...(hyp.tags || []),
    ].some((field) => matchesQuery(field, q))
  })
}

function GlobalSearch({ iocs = [], onResultSelect }) {
  const [query, setQuery] = useState('')
  const [results, setResults] = useState({ iocs: [], queries: [], hypotheses: [] })
  const [isOpen, setIsOpen] = useState(false)
  const [mobileExpanded, setMobileExpanded] = useState(false)
  const [loading, setLoading] = useState(false)
  const wrapperRef = useRef(null)
  const inputRef = useRef(null)

  const runSearch = useCallback(
    (text) => {
      const q = text.trim().toLowerCase()
      if (q.length <= 2) {
        setResults({ iocs: [], queries: [], hypotheses: [] })
        setLoading(false)
        return
      }
      setLoading(true)
      const iocHits = searchIOCs(iocs, q)
      const queryHits = searchQueries(q)
      const hypHits = searchHypotheses(q)
      setResults({
        iocs: iocHits.slice(0, MAX_PER_SECTION),
        queries: queryHits.slice(0, MAX_PER_SECTION),
        hypotheses: hypHits.slice(0, MAX_PER_SECTION),
      })
      setLoading(false)
    },
    [iocs]
  )

  useEffect(() => {
    if (query.trim().length <= 2) {
      setResults({ iocs: [], queries: [], hypotheses: [] })
      setIsOpen(false)
      return
    }
    setIsOpen(true)
    const timer = setTimeout(() => runSearch(query), 150)
    return () => clearTimeout(timer)
  }, [query, runSearch])

  useEffect(() => {
    const handleKey = (e) => {
      if (e.key === 'Escape') {
        setIsOpen(false)
        inputRef.current?.blur()
      }
    }
    const handleClickOutside = (e) => {
      if (wrapperRef.current && !wrapperRef.current.contains(e.target)) {
        setIsOpen(false)
      }
    }
    document.addEventListener('keydown', handleKey)
    document.addEventListener('mousedown', handleClickOutside)
    return () => {
      document.removeEventListener('keydown', handleKey)
      document.removeEventListener('mousedown', handleClickOutside)
    }
  }, [])

  const totals = useMemo(() => {
    if (query.trim().length <= 2) return { shown: 0, all: 0 }
    const q = query.trim().toLowerCase()
    const allIocs = searchIOCs(iocs, q).length
    const allQueries = searchQueries(q).length
    const allHyps = searchHypotheses(q).length
    const shown =
      results.iocs.length + results.queries.length + results.hypotheses.length
    return { shown, all: allIocs + allQueries + allHyps }
  }, [query, results, iocs])

  const handleSelect = (category, item) => {
    const id =
      category === 'iocs'
        ? item.indicator
        : category === 'queries'
          ? item.id
          : item.id
    onResultSelect?.({
      tab: category === 'iocs' ? 'iocs' : category === 'queries' ? 'kql' : 'hypotheses',
      id,
      term: query.trim(),
    })
    setIsOpen(false)
    setQuery('')
  }

  const hasResults =
    results.iocs.length > 0 ||
    results.queries.length > 0 ||
    results.hypotheses.length > 0

  const showPanel = isOpen && query.trim().length > 2

  return (
    <div
      className={`global-search ${mobileExpanded ? 'mobile-expanded' : ''}`}
      ref={wrapperRef}
    >
      <button
        type="button"
        className="global-search-mobile-toggle"
        aria-label="Open search"
        aria-expanded={mobileExpanded}
        onClick={() => {
          setMobileExpanded((v) => !v)
          if (!mobileExpanded) setTimeout(() => inputRef.current?.focus(), 50)
        }}
      >
        ⌕
      </button>
      <div className="global-search-input-wrap">
        <span className="global-search-icon" aria-hidden="true">
          ⌕
        </span>
        <input
          ref={inputRef}
          type="search"
          className="global-search-input"
          placeholder="Search IOCs, KQL queries, hypotheses…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onFocus={() => {
            if (query.trim().length > 2) setIsOpen(true)
            setMobileExpanded(true)
          }}
          aria-label="Global search"
          aria-expanded={showPanel}
          aria-controls="global-search-results"
        />
        {loading && <span className="global-search-spinner spinner" aria-hidden="true" />}
      </div>

      {showPanel && (
        <div
          id="global-search-results"
          className="global-search-dropdown"
          role="listbox"
        >
          {totals.all > 0 && (
            <p className="global-search-summary">
              {totals.all} result{totals.all !== 1 ? 's' : ''} across all categories
            </p>
          )}

          {loading && <p className="global-search-loading">Searching…</p>}

          {!loading && !hasResults && (
            <p className="global-search-empty">No results found</p>
          )}

          {results.iocs.length > 0 && (
            <section className="global-search-section">
              <h4>IOCs ({searchIOCs(iocs, query.trim().toLowerCase()).length})</h4>
              <ul>
                {results.iocs.map((ioc) => (
                  <li key={ioc.indicator}>
                    <button
                      type="button"
                      className="global-search-result"
                      onClick={() => handleSelect('iocs', ioc)}
                    >
                      <span className="gsr-primary">{ioc.indicator}</span>
                      <span className="type-badge">{ioc.type}</span>
                      <span className="gsr-meta">{ioc.source}</span>
                      <span className={`confidence-${(ioc.confidence || '').toLowerCase()}`}>
                        {ioc.confidence}
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {results.queries.length > 0 && (
            <section className="global-search-section">
              <h4>
                KQL Queries ({searchQueries(query.trim().toLowerCase()).length})
              </h4>
              <ul>
                {results.queries.map((q) => (
                  <li key={q.id}>
                    <button
                      type="button"
                      className="global-search-result"
                      onClick={() => handleSelect('queries', q)}
                    >
                      <span className="gsr-primary">{q.title}</span>
                      <span className={`badge severity-${q.severity}`}>{q.severity}</span>
                      <span className="gsr-meta">{q.tactic}</span>
                    </button>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {results.hypotheses.length > 0 && (
            <section className="global-search-section">
              <h4>
                Hypotheses ({searchHypotheses(query.trim().toLowerCase()).length})
              </h4>
              <ul>
                {results.hypotheses.map((hyp) => (
                  <li key={hyp.id}>
                    <button
                      type="button"
                      className="global-search-result"
                      onClick={() => handleSelect('hypotheses', hyp)}
                    >
                      <span className="gsr-primary">{hyp.title}</span>
                      <span className={`priority-pill priority-${hyp.priority}`}>
                        {hyp.priority}
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            </section>
          )}
        </div>
      )}
    </div>
  )
}

export default GlobalSearch
