import { useState, useEffect, useCallback } from 'react'
import staticHypotheses from '../data/hypotheses.json'
import {
  getHuntSessions,
  getActiveSession,
  createSession,
  updateActiveSession,
  completeSession,
  abandonSession,
  formatDuration,
  exportSessionMarkdown,
} from '../services/huntSession'

const CONCLUSION_OPTIONS = [
  { value: 'true-positive', label: 'True Positive' },
  { value: 'false-positive', label: 'False Positive' },
  { value: 'inconclusive', label: 'Inconclusive' },
]

function relativeTime(iso) {
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins} min ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs} hr ago`
  return `${Math.floor(hrs / 24)} d ago`
}

function conclusionBadge(conclusion) {
  if (!conclusion) return null
  const map = {
    'true-positive': { label: 'True Positive', cls: 'hunt-conclusion-tp' },
    'false-positive': { label: 'False Positive', cls: 'hunt-conclusion-fp' },
    inconclusive: { label: 'Inconclusive', cls: 'hunt-conclusion-inc' },
  }
  const c = map[conclusion] || { label: conclusion, cls: '' }
  return <span className={`hunt-conclusion-badge ${c.cls}`}>{c.label}</span>
}

export default function HuntSession({ hypotheses = staticHypotheses }) {
  const [sessions, setSessions] = useState(getHuntSessions)
  const [activeSession, setActiveSession] = useState(getActiveSession)
  const [showNewSession, setShowNewSession] = useState(false)
  const [showHistory, setShowHistory] = useState(false)
  const [showComplete, setShowComplete] = useState(false)
  const [expandedHistoryId, setExpandedHistoryId] = useState(null)
  const [duration, setDuration] = useState('00:00:00')
  const [findingsDraft, setFindingsDraft] = useState('')

  const [newName, setNewName] = useState('')
  const [newAnalyst, setNewAnalyst] = useState(localStorage.getItem('analystName') || '')
  const [newScope, setNewScope] = useState('')
  const [selectedHyps, setSelectedHyps] = useState([])

  const [completeConclusion, setCompleteConclusion] = useState('inconclusive')
  const [completeFindings, setCompleteFindings] = useState('')

  const refresh = useCallback(() => {
    setSessions(getHuntSessions())
    setActiveSession(getActiveSession())
  }, [])

  useEffect(() => {
    const onStorage = () => refresh()
    window.addEventListener('huntSessionUpdate', onStorage)
    return () => window.removeEventListener('huntSessionUpdate', onStorage)
  }, [refresh])

  useEffect(() => {
    if (!activeSession) return
    setFindingsDraft(activeSession.findings || '')
    const tick = () => {
      setDuration(formatDuration(Date.now() - new Date(activeSession.startTime).getTime()))
    }
    tick()
    const id = setInterval(tick, 1000)
    return () => clearInterval(id)
  }, [activeSession])

  const completedCount = sessions.filter((s) => s.status === 'completed').length

  function openNewSessionModal() {
    const n = sessions.length + 1
    setNewName(`Hunt Session #${n}`)
    setNewAnalyst(localStorage.getItem('analystName') || '')
    setNewScope('')
    setSelectedHyps([])
    setShowNewSession(true)
  }

  function startSession() {
    if (!newScope.trim()) return
    if (newAnalyst.trim()) localStorage.setItem('analystName', newAnalyst.trim())
    createSession({
      name: newName.trim() || `Hunt Session #${sessions.length + 1}`,
      analyst: newAnalyst.trim(),
      scope: newScope.trim(),
      hypothesesIncluded: selectedHyps,
    })
    setShowNewSession(false)
    refresh()
    window.dispatchEvent(new Event('huntSessionUpdate'))
  }

  function saveFindings() {
    updateActiveSession({ findings: findingsDraft })
    refresh()
    window.dispatchEvent(new Event('huntSessionUpdate'))
  }

  function handleComplete() {
    completeSession({
      conclusion: completeConclusion,
      findings: completeFindings,
    })
    setShowComplete(false)
    refresh()
    window.dispatchEvent(new Event('huntSessionUpdate'))
  }

  function handleAbandon() {
    if (!window.confirm('Abandon this hunt session? Progress will be lost.')) return
    abandonSession()
    refresh()
    window.dispatchEvent(new Event('huntSessionUpdate'))
  }

  function exportSession(session) {
    const md = exportSessionMarkdown(session)
    const blob = new Blob([md], { type: 'text/markdown' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `hunt-session-${session.id}.md`
    a.click()
  }

  const pastSessions = [...sessions]
    .filter((s) => s.status === 'completed')
    .sort((a, b) => new Date(b.startTime) - new Date(a.startTime))

  if (!activeSession) {
    return (
      <div className="hunt-session-card hunt-session-idle">
        <div className="hunt-session-header">
          <h3 className="hunt-session-title">Hunt Sessions</h3>
          <button type="button" className="hunt-session-start-btn" onClick={openNewSessionModal}>
            ▶ Start New Hunt Session
          </button>
        </div>
        <button type="button" className="hunt-session-history-link" onClick={() => setShowHistory(true)}>
          View History ({completedCount} sessions)
        </button>

        {showNewSession && (
          <div className="hunt-modal-overlay" onClick={() => setShowNewSession(false)}>
            <div className="hunt-modal" onClick={(e) => e.stopPropagation()}>
              <h4>New Hunt Session</h4>
              <label className="hunt-field-label">Session name</label>
              <input className="hunt-field-input" value={newName} onChange={(e) => setNewName(e.target.value)} />
              <label className="hunt-field-label">Analyst</label>
              <input className="hunt-field-input" value={newAnalyst} onChange={(e) => setNewAnalyst(e.target.value)} />
              <label className="hunt-field-label">Scope</label>
              <textarea
                className="hunt-field-textarea"
                rows={3}
                placeholder="What are we hunting for today?"
                value={newScope}
                onChange={(e) => setNewScope(e.target.value)}
              />
              <label className="hunt-field-label">Include hypotheses</label>
              <div className="hunt-hyp-checklist">
                {hypotheses.map((h) => (
                  <label key={h.id} className="hunt-hyp-check">
                    <input
                      type="checkbox"
                      checked={selectedHyps.includes(h.id)}
                      onChange={(e) => {
                        setSelectedHyps((prev) =>
                          e.target.checked ? [...prev, h.id] : prev.filter((id) => id !== h.id)
                        )
                      }}
                    />
                    <span>{h.id} — {h.title}</span>
                  </label>
                ))}
              </div>
              <div className="hunt-modal-actions">
                <button type="button" className="hunt-btn-secondary" onClick={() => setShowNewSession(false)}>
                  Cancel
                </button>
                <button type="button" className="hunt-btn-primary" onClick={startSession} disabled={!newScope.trim()}>
                  Start Session
                </button>
              </div>
            </div>
          </div>
        )}

        {showHistory && (
          <SessionHistoryModal
            sessions={pastSessions}
            expandedId={expandedHistoryId}
            onToggleExpand={(id) => setExpandedHistoryId(expandedHistoryId === id ? null : id)}
            onExport={exportSession}
            onClose={() => setShowHistory(false)}
          />
        )}
      </div>
    )
  }

  return (
    <div className="hunt-session-card hunt-session-active">
      <div className="hunt-active-banner">
        <div className="hunt-active-top">
          <span className="hunt-active-badge">🟢 Active Hunt Session</span>
          <strong className="hunt-active-name">{activeSession.name}</strong>
        </div>
        <div className="hunt-active-meta">
          Analyst: {activeSession.analyst || '—'} | Started: {relativeTime(activeSession.startTime)} | Duration:{' '}
          {duration}
        </div>
        <p className="hunt-active-scope">{activeSession.scope}</p>
        <div className="hunt-active-counters">
          <span>Hypotheses ({activeSession.hypothesesIncluded?.length || 0})</span>
          <span>Queries Run ({activeSession.queriesRun || 0})</span>
          <span>IOCs Reviewed ({activeSession.totalIOCsReviewed || 0})</span>
        </div>
        <div className="hunt-findings-row">
          <textarea
            className="hunt-findings-input"
            rows={2}
            placeholder="Add finding..."
            value={findingsDraft}
            onChange={(e) => setFindingsDraft(e.target.value)}
            onBlur={saveFindings}
          />
        </div>
        <div className="hunt-active-actions">
          <button
            type="button"
            className="hunt-btn-complete"
            onClick={() => {
              setCompleteFindings(findingsDraft)
              setShowComplete(true)
            }}
          >
            Complete Session
          </button>
          <button type="button" className="hunt-btn-abandon" onClick={handleAbandon}>
            Abandon
          </button>
        </div>
      </div>

      {showComplete && (
        <div className="hunt-modal-overlay" onClick={() => setShowComplete(false)}>
          <div className="hunt-modal" onClick={(e) => e.stopPropagation()}>
            <h4>Complete Hunt Session</h4>
            <p className="hunt-complete-summary">
              Duration: {duration} · Hypotheses: {activeSession.hypothesesIncluded?.length || 0} · Queries:{' '}
              {activeSession.queriesRun || 0}
            </p>
            <label className="hunt-field-label">Conclusion</label>
            <select
              className="hunt-field-input"
              value={completeConclusion}
              onChange={(e) => setCompleteConclusion(e.target.value)}
            >
              {CONCLUSION_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
            <label className="hunt-field-label">Findings</label>
            <textarea
              className="hunt-field-textarea"
              rows={5}
              value={completeFindings}
              onChange={(e) => setCompleteFindings(e.target.value)}
            />
            <div className="hunt-modal-actions">
              <button type="button" className="hunt-btn-secondary" onClick={() => setShowComplete(false)}>
                Cancel
              </button>
              <button type="button" className="hunt-btn-primary" onClick={handleComplete}>
                Save & Close Session
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function SessionHistoryModal({ sessions, expandedId, onToggleExpand, onExport, onClose }) {
  return (
    <div className="hunt-modal-overlay" onClick={onClose}>
      <div className="hunt-modal hunt-modal-wide" onClick={(e) => e.stopPropagation()}>
        <div className="hunt-modal-title-row">
          <h4>Session History</h4>
          <button type="button" className="hunt-modal-close" onClick={onClose}>
            ✕
          </button>
        </div>
        {sessions.length === 0 ? (
          <p className="hunt-empty">No completed sessions yet.</p>
        ) : (
          <ul className="hunt-history-list">
            {sessions.map((s) => {
              const dur =
                s.endTime && s.startTime
                  ? formatDuration(new Date(s.endTime) - new Date(s.startTime))
                  : '—'
              const expanded = expandedId === s.id
              return (
                <li key={s.id} className="hunt-history-item">
                  <button type="button" className="hunt-history-row" onClick={() => onToggleExpand(s.id)}>
                    <div className="hunt-history-main">
                      <strong>{s.name}</strong>
                      {conclusionBadge(s.conclusion)}
                    </div>
                    <div className="hunt-history-sub">
                      {s.analyst || '—'} · {new Date(s.startTime).toLocaleDateString()} · {dur}
                    </div>
                    <p className="hunt-history-snippet">
                      {(s.scope || '').length > 120 ? `${s.scope.slice(0, 120)}…` : s.scope}
                    </p>
                  </button>
                  {expanded && (
                    <div className="hunt-history-detail">
                      <p>
                        <strong>Scope:</strong> {s.scope}
                      </p>
                      <p>
                        <strong>Findings:</strong> {s.findings || '—'}
                      </p>
                      <p>
                        <strong>Queries:</strong> {s.queriesRun || 0} · <strong>IOCs:</strong>{' '}
                        {s.totalIOCsReviewed || 0}
                      </p>
                      <button type="button" className="hunt-btn-secondary" onClick={() => onExport(s)}>
                        Export Markdown
                      </button>
                    </div>
                  )}
                </li>
              )
            })}
          </ul>
        )}
      </div>
    </div>
  )
}
