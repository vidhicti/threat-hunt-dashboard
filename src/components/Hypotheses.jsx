import { useState, useMemo, useCallback, useEffect } from 'react'
import staticHypothesesData from '../data/hypotheses.json'
import queries from '../data/queries.json'
import {
  fetchLiveThreatActors,
  generateHypothesisFromActor,
} from '../services/hypothesisGenerator'
import {
  getHypothesisWorkflow,
  updateHypothesisStatus,
  updateHypothesisFields,
  computeStatsForHypotheses,
  getWorkflowStats,
} from '../services/huntWorkflow'
import { incrementQueriesRun } from '../services/huntSession'
import HuntSession from './HuntSession'

const PRIORITY_BORDER = {
  critical: 'var(--red)',
  high: 'var(--red)',
  medium: 'var(--amber)',
  low: 'var(--green)',
}

const STATIC_COUNT = staticHypothesesData.length

const WORKFLOW_STATUSES = [
  { id: 'open', label: 'Open' },
  { id: 'in-progress', label: 'In Progress' },
  { id: 'true-positive', label: 'True Positive' },
  { id: 'false-positive', label: 'False Positive' },
  { id: 'closed', label: 'Closed' },
]

const STATUS_LABELS = {
  open: 'Open',
  'in-progress': 'In Progress',
  'true-positive': 'True Positive ✓',
  'false-positive': 'False Positive ✗',
  closed: 'Closed',
}

function formatTacticChain(tacticChain) {
  if (Array.isArray(tacticChain)) return tacticChain.join(' → ')
  return tacticChain || ''
}

function formatLogSources(logSources) {
  if (Array.isArray(logSources)) return logSources.join(', ')
  return logSources || ''
}

function getQueriesForHypothesis(hyp, queriesById) {
  if (hyp.kqlQueries?.length) return hyp.kqlQueries
  return (hyp.relatedQueryIds || [])
    .map((id) => queriesById[id])
    .filter(Boolean)
}

function exportHypothesisKql(hyp, queriesById) {
  const qs = getQueriesForHypothesis(hyp, queriesById)
  const content = qs
    .map(
      (q, i) =>
        `${'='.repeat(60)}\n` +
        `${q.id || `Query ${i + 1}`}: ${q.title}\n` +
        `${'='.repeat(60)}\n` +
        `MITRE: ${q.mitreTechnique || 'N/A'} | Severity: ${q.severity || 'N/A'}\n` +
        `Log Source: ${q.logSource || 'N/A'}\n\n` +
        `KQL:\n${q.kql}\n`
    )
    .join('\n')

  const blob = new Blob([content], { type: 'text/plain' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `${hyp.id || 'hypothesis'}-kql-queries.txt`
  link.click()
  URL.revokeObjectURL(url)
}

function exportHuntReport(allHypotheses) {
  const stats = computeStatsForHypotheses(allHypotheses)
  const generated = new Date().toLocaleString()
  let md = `# Threat Hunt Report\nGenerated: ${generated}\n\n`
  md += `## Summary\n| Status | Count |\n|--------|-------|\n`
  md += `| Open | ${stats.open} |\n`
  md += `| In Progress | ${stats.inProgress} |\n`
  md += `| True Positive | ${stats.truePositive} |\n`
  md += `| False Positive | ${stats.falsePositive} |\n`
  md += `| Closed | ${stats.closed} |\n\n`
  md += `## Hypotheses Detail\n`
  allHypotheses.forEach((hyp) => {
    const w = getHypothesisWorkflow(hyp.id)
    const priority = (hyp.priority || 'medium').replace(/^./, (c) => c.toUpperCase())
    md += `### ${hyp.id} - ${hyp.title}\n`
    md += `**Priority:** ${priority}  \n`
    md += `**Status:** ${STATUS_LABELS[w.status] || w.status}  \n`
    md += `**Analyst:** ${w.analyst || '—'}  \n`
    md += `**Tactic Chain:** ${formatTacticChain(hyp.tacticChain)}  \n`
    md += `**Description:** ${hyp.description || '—'}  \n`
    md += `**Notes:** ${w.notes || '—'}  \n`
    md += `**Last Updated:** ${w.updatedAt ? new Date(w.updatedAt).toLocaleString() : '—'}  \n\n---\n\n`
  })
  const blob = new Blob([md], { type: 'text/markdown' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `threat-hunt-report-${new Date().toISOString().slice(0, 10)}.md`
  link.click()
  URL.revokeObjectURL(url)
}

function exportHuntReportPDF() {
  const reportWindow = window.open('', '_blank')
  if (!reportWindow) return

  const stats = getWorkflowStats()
  const sessions = JSON.parse(localStorage.getItem('huntSessions') || '[]')

  let html = `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Threat Hunt Report - ${new Date().toLocaleDateString()}</title>
      <style>
        body { font-family: -apple-system, sans-serif; padding: 40px; color: #1c2128; max-width: 900px; margin: 0 auto; }
        h1 { border-bottom: 3px solid #0969da; padding-bottom: 10px; }
        h2 { color: #0969da; margin-top: 30px; }
        .meta { color: #6e7781; font-size: 14px; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { border: 1px solid #d0d7de; padding: 8px 12px; text-align: left; font-size: 13px; }
        th { background: #f6f8fa; }
        .hyp-card { border: 1px solid #d0d7de; border-radius: 8px; padding: 15px; margin: 15px 0; page-break-inside: avoid; }
        .badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: 600; margin-right: 6px; }
        .critical { background: #ffebe9; color: #cf222e; }
        .high { background: #fff8c5; color: #9a6700; }
        .medium { background: #ddf4ff; color: #0969da; }
        .low { background: #dafbe1; color: #1a7f37; }
        .status-open { background: #f6f8fa; color: #6e7781; }
        .status-in-progress { background: #ddf4ff; color: #0969da; }
        .status-true-positive { background: #dafbe1; color: #1a7f37; }
        .status-false-positive { background: #ffebe9; color: #cf222e; }
        .status-closed { background: #f6f8fa; color: #6e7781; }
        .note { background: #f6f8fa; border-left: 3px solid #0969da; padding: 8px 12px; margin: 8px 0; font-size: 13px; }
        .tags span { background: #ddf4ff; color: #0969da; padding: 2px 8px; border-radius: 10px; font-size: 11px; margin-right: 4px; }
        @media print { body { padding: 20px; } }
      </style>
    </head>
    <body>
      <h1>🛡️ Threat Hunt Report</h1>
      <div class="meta">
        Generated: ${new Date().toLocaleString()}<br>
        Analyst: ${localStorage.getItem('analystName') || 'Not specified'}
      </div>

      <h2>Summary</h2>
      <table>
        <tr><th>Status</th><th>Count</th></tr>
        <tr><td>Open</td><td>${stats.open}</td></tr>
        <tr><td>In Progress</td><td>${stats.inProgress}</td></tr>
        <tr><td>True Positive</td><td>${stats.truePositive}</td></tr>
        <tr><td>False Positive</td><td>${stats.falsePositive}</td></tr>
        <tr><td>Closed</td><td>${stats.closed}</td></tr>
      </table>
  `

  if (sessions.length > 0) {
    html += `<h2>Hunt Sessions</h2>`
    sessions.forEach((s) => {
      const duration = s.endTime
        ? Math.round((new Date(s.endTime) - new Date(s.startTime)) / 60000)
        : 'Ongoing'
      html += `
        <div class="hyp-card">
          <strong>${s.name}</strong> - ${s.analyst}<br>
          <span class="meta">Started: ${new Date(s.startTime).toLocaleString()} | Duration: ${duration} min</span>
          ${s.conclusion ? `<br><span class="badge ${s.conclusion}">${s.conclusion}</span>` : ''}
          <p>${s.scope || ''}</p>
          ${s.findings ? `<div class="note"><strong>Findings:</strong> ${s.findings}</div>` : ''}
        </div>
      `
    })
  }

  html += `<h2>Hypotheses Detail</h2>`

  staticHypothesesData.forEach((h) => {
    const wf = getHypothesisWorkflow(h.id)
    const tacticChain = formatTacticChain(h.tacticChain)
    const logSources = Array.isArray(h.logSources) ? h.logSources.join(', ') : h.logSources || ''
    html += `
      <div class="hyp-card">
        <h3>${h.id} - ${h.title}</h3>
        <span class="badge ${h.priority}">${h.priority?.toUpperCase()}</span>
        <span class="badge status-${wf.status || 'open'}">${(wf.status || 'open').replace('-', ' ').toUpperCase()}</span>
        <p><strong>Tactic Chain:</strong> ${tacticChain}</p>
        <p><strong>Log Sources:</strong> ${logSources}</p>
        <p>${h.description}</p>
        <div class="tags">${(h.tags || []).map((t) => `<span>${t}</span>`).join('')}</div>
        ${wf.analyst ? `<p><strong>Analyst:</strong> ${wf.analyst}</p>` : ''}
        ${wf.notes ? `<div class="note"><strong>Notes:</strong> ${wf.notes}</div>` : ''}
        <p class="meta">Last updated: ${wf.updatedAt ? new Date(wf.updatedAt).toLocaleString() : 'Never'}</p>
      </div>
    `
  })

  html += `</body></html>`

  reportWindow.document.write(html)
  reportWindow.document.close()
  setTimeout(() => reportWindow.print(), 500)
}

function WorkflowStatusBadge({ status }) {
  const s = status || 'open'
  return (
    <span className={`workflow-status-badge workflow-${s}`}>
      {STATUS_LABELS[s] || 'Open'}
    </span>
  )
}

function WorkflowPanel({ hypId, onWorkflowChange, refreshKey = 0 }) {
  const workflow = getHypothesisWorkflow(hypId)
  const [analyst, setAnalyst] = useState(workflow.analyst)
  const [notes, setNotes] = useState(workflow.notes)
  const [showHistory, setShowHistory] = useState(false)

  useEffect(() => {
    const w = getHypothesisWorkflow(hypId)
    setAnalyst(w.analyst)
    setNotes(w.notes)
  }, [hypId, refreshKey])

  const handleStatus = (status) => {
    updateHypothesisStatus(hypId, status, notes, analyst)
    incrementQueriesRun()
    window.dispatchEvent(new Event('huntSessionUpdate'))
    onWorkflowChange?.()
  }

  const handleBlurSave = () => {
    updateHypothesisFields(hypId, notes, analyst)
    onWorkflowChange?.()
  }

  const history = [...(workflow.history || [])].reverse()

  return (
    <div className="workflow-panel">
      <div className="workflow-status-row">
        {WORKFLOW_STATUSES.map((opt) => (
          <button
            key={opt.id}
            type="button"
            className={`workflow-status-btn ${workflow.status === opt.id ? 'active' : ''}`}
            onClick={() => handleStatus(opt.id)}
          >
            {opt.label}
          </button>
        ))}
      </div>
      <div className="workflow-fields-row">
        <input
          type="text"
          className="workflow-analyst-input"
          placeholder="Analyst name"
          value={analyst}
          onChange={(e) => setAnalyst(e.target.value)}
          onBlur={handleBlurSave}
        />
        <textarea
          className="workflow-notes-input"
          rows={3}
          placeholder="Investigation notes..."
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          onBlur={handleBlurSave}
        />
      </div>
      <button
        type="button"
        className="workflow-history-toggle"
        onClick={() => setShowHistory((v) => !v)}
      >
        {showHistory ? '▼ Hide History' : '▶ Show History'}
        {history.length > 0 && ` (${history.length})`}
      </button>
      {showHistory && (
        <ul className="workflow-history-timeline">
          {history.length === 0 ? (
            <li className="workflow-history-empty">No status changes yet.</li>
          ) : (
            history.map((entry, i) => (
              <li key={`${entry.timestamp}-${i}`} className="workflow-history-item">
                <WorkflowStatusBadge status={entry.status} />
                <span className="workflow-history-time">
                  {new Date(entry.timestamp).toLocaleString()}
                </span>
                {entry.analyst && (
                  <span className="workflow-history-analyst">{entry.analyst}</span>
                )}
                {entry.notes && (
                  <p className="workflow-history-notes">{entry.notes}</p>
                )}
              </li>
            ))
          )}
        </ul>
      )}
    </div>
  )
}

function WorkflowStatsBar({ stats, statusFilter, onFilterChange }) {
  const cards = [
    { id: 'open', label: 'Open', count: stats.open, className: 'wf-stat-open' },
    { id: 'in-progress', label: 'In Progress', count: stats.inProgress, className: 'wf-stat-progress' },
    { id: 'true-positive', label: 'True Positive', count: stats.truePositive, className: 'wf-stat-tp' },
    { id: 'false-positive', label: 'False Positive', count: stats.falsePositive, className: 'wf-stat-fp' },
    { id: 'closed', label: 'Closed', count: stats.closed, className: 'wf-stat-closed' },
  ]

  return (
    <div className="workflow-stats-bar">
      {cards.map((card) => (
        <button
          key={card.id}
          type="button"
          className={`workflow-stat-card ${card.className} ${statusFilter === card.id ? 'active' : ''}`}
          onClick={() => onFilterChange(statusFilter === card.id ? null : card.id)}
        >
          <span className="workflow-stat-count">{card.count}</span>
          <span className="workflow-stat-label">{card.label}</span>
        </button>
      ))}
      <button
        type="button"
        className={`workflow-stat-all ${statusFilter === null ? 'active' : ''}`}
        onClick={() => onFilterChange(null)}
      >
        All
      </button>
    </div>
  )
}

function filterByWorkflowStatus(list, statusFilter) {
  if (!statusFilter) return list
  return list.filter((hyp) => {
    const status = getHypothesisWorkflow(hyp.id).status || 'open'
    return status === statusFilter
  })
}

function KqlQueryBlock({ query, copiedKey, onCopy }) {
  const key = query.id || query.title
  return (
    <article className="hyp-query-block">
      <div className="query-card-header">
        <h4>{query.title}</h4>
        <div className="query-badges">
          {query.severity && (
            <span className={`badge severity-${query.severity}`}>{query.severity}</span>
          )}
          {query.mitreTechnique && (
            <span className="badge badge-mitre">{query.mitreTechnique}</span>
          )}
          {query.logSource && (
            <span className="badge badge-log">{query.logSource}</span>
          )}
        </div>
      </div>
      <pre className="kql-block">
        <code>{query.kql}</code>
      </pre>
      <button
        type="button"
        className="copy-btn"
        onClick={() => onCopy(query.kql, key)}
      >
        {copiedKey === key ? 'Copied!' : 'Copy KQL'}
      </button>
    </article>
  )
}

function KqlQueriesSection({
  hyp,
  expanded,
  onToggle,
  queriesById,
  defaultOpen = false,
}) {
  const related = getQueriesForHypothesis(hyp, queriesById)
  const isOpen = expanded ?? defaultOpen
  const [copiedKey, setCopiedKey] = useState(null)

  const copyKql = async (kql, key) => {
    try {
      await navigator.clipboard.writeText(kql)
      setCopiedKey(key)
      setTimeout(() => setCopiedKey(null), 2000)
    } catch {
      setCopiedKey(null)
    }
  }

  if (!related.length && !onToggle) return null

  return (
    <div className="hyp-kql-section">
      {onToggle && (
        <button type="button" className="hyp-kql-toggle" onClick={onToggle}>
          {isOpen ? '▼ Hide KQL Queries' : '▶ View KQL Queries'}
          <span className="hyp-kql-count">({related.length})</span>
        </button>
      )}
      <div className={`kql-queries-expand ${isOpen ? 'open' : ''}`}>
        <div className="kql-queries-expand-inner">
          <div className="hyp-query-list">
            {related.map((q) => (
              <KqlQueryBlock
                key={q.id || q.title}
                query={q}
                copiedKey={copiedKey}
                onCopy={copyKql}
              />
            ))}
            {related.length === 0 && (
              <p className="hyp-empty-queries">No related KQL queries found.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function HypothesisCard({
  hyp,
  cardKey,
  expandedId,
  setExpandedId,
  queriesById,
  onRemove,
  extraBadges,
  kqlDefaultOpen = false,
  showExport = false,
  highlightFlash = false,
  onWorkflowChange,
  workflowTick = 0,
}) {
  const expandKey = `${cardKey}-${hyp.id}`
  const isExpanded = expandedId === expandKey || kqlDefaultOpen
  const priority = hyp.priority || 'medium'
  const workflow = getHypothesisWorkflow(hyp.id)

  return (
    <article
      id={`hypothesis-card-${hyp.id}`}
      className={`hypothesis-card hyp-card ${highlightFlash ? 'search-highlight-flash' : ''}`}
      style={{ borderLeftColor: PRIORITY_BORDER[priority] || PRIORITY_BORDER.medium }}
    >
      <div className="hypothesis-header">
        <div className="hypothesis-header-left">
          <span className="hypothesis-id">{hyp.id}</span>
          <span className={`priority-pill priority-${priority}`}>{priority}</span>
          {extraBadges}
        </div>
        <WorkflowStatusBadge status={workflow.status} />
      </div>
      <h3>{hyp.title}</h3>
      <p className="tactic-chain">
        <strong>Tactic chain:</strong> {formatTacticChain(hyp.tacticChain)}
      </p>
      <p className="log-sources">
        <strong>Log sources:</strong> {formatLogSources(hyp.logSources)}
      </p>
      <p className="hypothesis-description">{hyp.description}</p>
      {hyp.tags?.length > 0 && (
        <div className="tag-pills">
          {hyp.tags.map((tag) => (
            <span key={tag} className="tag-pill">
              {tag}
            </span>
          ))}
        </div>
      )}
      <div className="hyp-card-actions">
        {showExport && (
          <button
            type="button"
            className="export-btn small"
            onClick={() => exportHypothesisKql(hyp, queriesById)}
          >
            Export KQL
          </button>
        )}
        {onRemove && (
          <button
            type="button"
            className="hyp-remove-btn"
            onClick={() => onRemove(hyp.id)}
            aria-label="Remove hypothesis"
          >
            ✕
          </button>
        )}
      </div>
      <KqlQueriesSection
        hyp={hyp}
        expanded={isExpanded}
        onToggle={
          kqlDefaultOpen
            ? null
            : () => setExpandedId(isExpanded ? null : expandKey)
        }
        queriesById={queriesById}
        defaultOpen={kqlDefaultOpen}
      />
      <WorkflowPanel
        hypId={hyp.id}
        onWorkflowChange={onWorkflowChange}
        refreshKey={workflowTick}
      />
    </article>
  )
}

function Hypotheses({ highlightId, highlightTerm, onHighlightDone, onWorkflowChange }) {
  const [activeTab, setActiveTab] = useState('static')
  const [expandedId, setExpandedId] = useState(null)
  const [groqApiKey, setGroqApiKey] = useState(
    () => localStorage.getItem('groqApiKey') || ''
  )
  const [keyInput, setKeyInput] = useState(() => localStorage.getItem('groqApiKey') || '')

  const [threatActors, setThreatActors] = useState([])
  const [liveHypotheses, setLiveHypotheses] = useState([])

  const [loadingActors, setLoadingActors] = useState(false)
  const [loadingGenerate, setLoadingGenerate] = useState(false)
  const [selectedActor, setSelectedActor] = useState(null)
  const [error, setError] = useState(null)
  const [actorSearchFilter, setActorSearchFilter] = useState(null)

  const [statusFilter, setStatusFilter] = useState(null)
  const [workflowTick, setWorkflowTick] = useState(0)

  const handleWorkflowChange = useCallback(() => {
    setWorkflowTick((t) => t + 1)
    onWorkflowChange?.()
  }, [onWorkflowChange])

  const allHypothesesForExport = useMemo(
    () => [...staticHypothesesData, ...liveHypotheses],
    [liveHypotheses]
  )

  const staticFiltered = useMemo(() => {
    void workflowTick
    let list = filterByWorkflowStatus(staticHypothesesData, statusFilter)
    if (actorSearchFilter) {
      const term = actorSearchFilter.toLowerCase()
      list = list.filter(
        (hyp) =>
          hyp.title?.toLowerCase().includes(term) ||
          (hyp.tags || []).some((t) => t.toLowerCase().includes(term))
      )
    }
    return list
  }, [statusFilter, workflowTick, actorSearchFilter])

  const liveFiltered = useMemo(() => {
    void workflowTick
    let list = filterByWorkflowStatus(liveHypotheses, statusFilter)
    if (actorSearchFilter) {
      const term = actorSearchFilter.toLowerCase()
      list = list.filter(
        (hyp) =>
          hyp.title?.toLowerCase().includes(term) ||
          hyp.threatActor?.toLowerCase().includes(term) ||
          (hyp.tags || []).some((t) => t.toLowerCase().includes(term))
      )
    }
    return list
  }, [liveHypotheses, statusFilter, workflowTick, actorSearchFilter])

  const staticStats = useMemo(() => {
    void workflowTick
    return computeStatsForHypotheses(staticHypothesesData)
  }, [workflowTick])

  const liveStats = useMemo(() => {
    void workflowTick
    return computeStatsForHypotheses(liveHypotheses)
  }, [liveHypotheses, workflowTick])

  const queriesById = useMemo(
    () => Object.fromEntries(queries.map((q) => [q.id, q])),
    []
  )

  useEffect(() => {
    if (!highlightId) return
    setActiveTab('static')
    requestAnimationFrame(() => {
      document
        .getElementById(`hypothesis-card-${highlightId}`)
        ?.scrollIntoView({ behavior: 'smooth', block: 'center' })
      onHighlightDone?.()
    })
  }, [highlightId, onHighlightDone])

  useEffect(() => {
    try {
      const raw = sessionStorage.getItem('searchHighlight')
      if (!raw) return
      const { type, value, timestamp } = JSON.parse(raw)
      if (type !== 'hypothesis' || Date.now() - timestamp > 5000) return
      sessionStorage.removeItem('searchHighlight')
      setActiveTab('static')
      requestAnimationFrame(() => {
        const el = document.getElementById(`hypothesis-card-${value}`)
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

  useEffect(() => {
    try {
      const raw = sessionStorage.getItem('hypothesisActorSearch')
      if (!raw) return
      const { actor, timestamp } = JSON.parse(raw)
      if (Date.now() - timestamp > 10000) return
      sessionStorage.removeItem('hypothesisActorSearch')
      setActorSearchFilter(actor)
      const term = actor.toLowerCase()
      const liveSaved = JSON.parse(localStorage.getItem('liveHypotheses') || '[]')
      const liveMatches = liveSaved.filter(
        (hyp) =>
          hyp.title?.toLowerCase().includes(term) ||
          hyp.threatActor?.toLowerCase().includes(term) ||
          (hyp.tags || []).some((t) => t.toLowerCase().includes(term))
      )
      const staticMatches = staticHypothesesData.filter(
        (hyp) =>
          hyp.title?.toLowerCase().includes(term) ||
          (hyp.tags || []).some((t) => t.toLowerCase().includes(term))
      )
      setActiveTab(liveMatches.length > 0 ? 'live' : staticMatches.length > 0 ? 'static' : 'live')
    } catch {
      sessionStorage.removeItem('hypothesisActorSearch')
    }
  }, [])

  useEffect(() => {
    try {
      const saved = localStorage.getItem('liveHypotheses')
      if (saved) setLiveHypotheses(JSON.parse(saved))
    } catch {
      /* ignore */
    }
  }, [])

  const hasGroqKey = Boolean(groqApiKey.trim())

  const saveGroqKey = () => {
    const trimmed = keyInput.trim()
    localStorage.setItem('groqApiKey', trimmed)
    setGroqApiKey(trimmed)
    setError(null)
  }

  const handleFetchActors = async () => {
    if (!hasGroqKey) {
      setError('Groq API key required')
      return
    }
    setLoadingActors(true)
    setError(null)
    try {
      const actors = await fetchLiveThreatActors(groqApiKey)
      setThreatActors(Array.isArray(actors) ? actors : [])
    } catch (e) {
      setError(e.message || 'Failed to fetch threat actors')
      setThreatActors([])
    } finally {
      setLoadingActors(false)
    }
  }

  const handleGenerateFromActor = async (actor) => {
    if (!hasGroqKey) {
      setError('Groq API key required')
      return
    }
    setSelectedActor(actor.name)
    setLoadingGenerate(true)
    setError(null)
    try {
      const hyp = await generateHypothesisFromActor(actor, [], groqApiKey)
      hyp.id = hyp.id || `LIVE-${Date.now()}`
      hyp.generatedAt = hyp.generatedAt || new Date().toISOString()
      hyp.threatActor = actor.name
      setLiveHypotheses((prev) => {
        const updated = [hyp, ...prev]
        localStorage.setItem('liveHypotheses', JSON.stringify(updated))
        return updated
      })
    } catch (e) {
      setError(e.message || 'Failed to generate hypothesis')
    } finally {
      setLoadingGenerate(false)
      setSelectedActor(null)
    }
  }

  const actorSeverityColor = (severity) => {
    if (severity === 'critical') return 'var(--red)'
    if (severity === 'high') return 'var(--amber)'
    return 'var(--accent)'
  }

  return (
    <div className="hypotheses-page">
      <div className="hyp-top-bar">
        <h2 className="hyp-page-title">Hypotheses</h2>
        <div className="hyp-export-btns">
          <button
            type="button"
            className="export-btn hyp-export-report-btn"
            onClick={() => exportHuntReport(allHypothesesForExport)}
          >
            Export Hunt Report
          </button>
          <button
            type="button"
            className="export-btn hyp-export-report-btn"
            onClick={exportHuntReportPDF}
          >
            📄 Export as PDF
          </button>
        </div>
        <div className="hyp-tab-pills">
          <button
            type="button"
            className={`hyp-tab-pill ${activeTab === 'static' ? 'active' : ''}`}
            onClick={() => setActiveTab('static')}
          >
            Static ({STATIC_COUNT})
          </button>
          <button
            type="button"
            className={`hyp-tab-pill ${activeTab === 'live' ? 'active' : ''}`}
            onClick={() => setActiveTab('live')}
          >
            Live Threat Actors
          </button>
        </div>
      </div>

      {!hasGroqKey && (
        <div className="groq-key-banner">
          <span>
            Add your free Groq API key to enable AI-powered live hypotheses
          </span>
          <input
            type="password"
            className="groq-key-input"
            placeholder="gsk_..."
            value={keyInput}
            onChange={(e) => setKeyInput(e.target.value)}
          />
          <button type="button" className="groq-save-btn" onClick={saveGroqKey}>
            Save Key
          </button>
        </div>
      )}

      {error && <div className="hyp-error-alert">{error}</div>}

      {actorSearchFilter && (
        <div className="hyp-actor-search-banner">
          <span>Filtering hypotheses for threat actor: <strong>{actorSearchFilter}</strong></span>
          <button type="button" onClick={() => setActorSearchFilter(null)}>Clear filter</button>
        </div>
      )}

      <HuntSession hypotheses={staticHypothesesData} />

      {activeTab === 'static' && (
        <>
          <WorkflowStatsBar
            stats={staticStats}
            statusFilter={statusFilter}
            onFilterChange={setStatusFilter}
          />
          <div className="hypotheses-list">
            {staticFiltered.map((hyp) => (
              <HypothesisCard
                key={hyp.id}
                hyp={hyp}
                cardKey="static"
                expandedId={expandedId}
                setExpandedId={setExpandedId}
                queriesById={queriesById}
                highlightFlash={highlightId === hyp.id}
                onWorkflowChange={handleWorkflowChange}
                workflowTick={workflowTick}
              />
            ))}
            {staticFiltered.length === 0 && (
              <p className="hyp-empty-filter">No hypotheses match this status filter.</p>
            )}
          </div>
        </>
      )}

      {activeTab === 'live' && (
        <div className="hyp-live-tab">
          <section className="hyp-landscape-card">
            <h3>Current Threat Landscape</h3>
            {!hasGroqKey ? (
              <p className="hyp-key-required">Groq API key required</p>
            ) : (
              <>
                <button
                  type="button"
                  className="hyp-fetch-btn"
                  onClick={handleFetchActors}
                  disabled={loadingActors}
                >
                  Fetch Latest Threat Actors
                </button>
                {loadingActors && (
                  <div className="hyp-loading-row">
                    <span className="spinner" aria-hidden="true" />
                    Analyzing current threat landscape...
                  </div>
                )}
              </>
            )}

            {threatActors.length > 0 && (
              <div className="actor-grid">
                {threatActors.map((actor) => (
                  <article
                    key={actor.name}
                    className="actor-card"
                    style={{ borderTopColor: actorSeverityColor(actor.severity) }}
                  >
                    <div className="actor-card-header">
                      <h4 style={{ color: actorSeverityColor(actor.severity) }}>
                        {actor.name}
                      </h4>
                      <span className="actor-type-badge">{actor.type}</span>
                      <span className={`priority-pill priority-${actor.severity}`}>
                        {actor.severity}
                      </span>
                    </div>
                    <div className="actor-sectors">
                      {(actor.targetedSectors || []).map((s) => (
                        <span key={s} className="sector-pill">
                          {s}
                        </span>
                      ))}
                    </div>
                    <p className="actor-activity">{actor.recentActivity}</p>
                    <div className="actor-ttps">
                      {(actor.mitreTechniques || []).map((t) => (
                        <span key={t} className="ttp-badge">
                          {t}
                        </span>
                      ))}
                    </div>
                    <button
                      type="button"
                      className="hyp-generate-btn"
                      disabled={loadingGenerate || !hasGroqKey}
                      onClick={() => handleGenerateFromActor(actor)}
                    >
                      {loadingGenerate && selectedActor === actor.name ? (
                        <span className="spinner-wrap">
                          <span className="spinner" aria-hidden="true" />
                          Generating...
                        </span>
                      ) : (
                        'Generate Hunt Hypothesis'
                      )}
                    </button>
                  </article>
                ))}
              </div>
            )}
          </section>

          {liveHypotheses.length > 0 && (
            <section className="hyp-generated-section">
              <h3>Generated Hypotheses</h3>
              <WorkflowStatsBar
                stats={liveStats}
                statusFilter={statusFilter}
                onFilterChange={setStatusFilter}
              />
              <div className="hypotheses-list">
                {liveFiltered.map((hyp) => (
                  <HypothesisCard
                    key={hyp.id}
                    hyp={hyp}
                    cardKey="live"
                    expandedId={expandedId}
                    setExpandedId={setExpandedId}
                    queriesById={queriesById}
                    showExport
                    onRemove={(id) =>
                      setLiveHypotheses((prev) => prev.filter((h) => h.id !== id))
                    }
                    extraBadges={
                      hyp.threatActor ? (
                        <span className="actor-tag">Generated for: {hyp.threatActor}</span>
                      ) : null
                    }
                    onWorkflowChange={handleWorkflowChange}
                    workflowTick={workflowTick}
                  />
                ))}
                {liveFiltered.length === 0 && (
                  <p className="hyp-empty-filter">No hypotheses match this status filter.</p>
                )}
              </div>
            </section>
          )}
        </div>
      )}
    </div>
  )
}

export default Hypotheses
