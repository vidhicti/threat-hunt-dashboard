import { useState, useMemo, useCallback } from 'react'
import staticHypothesesData from '../data/hypotheses.json'
import queries from '../data/queries.json'
import {
  fetchLiveThreatActors,
  generateHypothesisFromActor,
  generateCustomHypothesis,
} from '../services/hypothesisGenerator'

const PRIORITY_BORDER = {
  critical: 'var(--red)',
  high: 'var(--red)',
  medium: 'var(--amber)',
  low: 'var(--green)',
}

const STATIC_COUNT = staticHypothesesData.length

const QUICK_SUGGESTIONS = [
  'Ransomware pre-staging activity',
  'Credential dumping and lateral movement',
  'Phishing to execution kill chain',
  'DNS tunneling C2 communication',
  'Supply chain compromise indicators',
  'Insider threat data exfiltration',
]

const PRIORITY_OPTIONS = ['Critical', 'High', 'Medium', 'Low']

const LOG_SOURCE_FOCUS = [
  { value: 'All', label: 'All' },
  { value: 'Fortigate', label: 'Fortigate' },
  { value: 'Palo Alto', label: 'Palo Alto' },
  { value: 'Sophos', label: 'Sophos' },
  { value: 'AD', label: 'AD' },
  { value: 'MDE', label: 'MDE' },
  { value: 'DNS', label: 'DNS' },
  { value: 'O365', label: 'O365' },
  { value: 'TrendMicro', label: 'TrendMicro' },
]

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
}) {
  const expandKey = `${cardKey}-${hyp.id}`
  const isExpanded = expandedId === expandKey || kqlDefaultOpen
  const priority = hyp.priority || 'medium'

  return (
    <article
      className="hypothesis-card"
      style={{ borderLeftColor: PRIORITY_BORDER[priority] || PRIORITY_BORDER.medium }}
    >
      <div className="hypothesis-header">
        <span className="hypothesis-id">{hyp.id}</span>
        <span className={`priority-pill priority-${priority}`}>{priority}</span>
        {extraBadges}
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
    </article>
  )
}

function Hypotheses() {
  const [activeTab, setActiveTab] = useState('static')
  const [expandedId, setExpandedId] = useState(null)
  const [groqApiKey, setGroqApiKey] = useState(
    () => localStorage.getItem('groqApiKey') || ''
  )
  const [keyInput, setKeyInput] = useState(() => localStorage.getItem('groqApiKey') || '')

  const [threatActors, setThreatActors] = useState([])
  const [liveHypotheses, setLiveHypotheses] = useState([])
  const [customHypotheses, setCustomHypotheses] = useState([])
  const [customResult, setCustomResult] = useState(null)

  const [loadingActors, setLoadingActors] = useState(false)
  const [loadingGenerate, setLoadingGenerate] = useState(false)
  const [loadingCustom, setLoadingCustom] = useState(false)
  const [selectedActor, setSelectedActor] = useState(null)
  const [error, setError] = useState(null)

  const [customInput, setCustomInput] = useState('')
  const [customPriority, setCustomPriority] = useState('High')
  const [customLogFocus, setCustomLogFocus] = useState('All')

  const queriesById = useMemo(
    () => Object.fromEntries(queries.map((q) => [q.id, q])),
    []
  )

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
      setLiveHypotheses((prev) => [hyp, ...prev])
    } catch (e) {
      setError(e.message || 'Failed to generate hypothesis')
    } finally {
      setLoadingGenerate(false)
      setSelectedActor(null)
    }
  }

  const buildCustomRequirements = useCallback(() => {
    return `${customInput.trim()}

Priority: ${customPriority}
Focus log source: ${customLogFocus}`
  }, [customInput, customPriority, customLogFocus])

  const handleGenerateCustom = async () => {
    if (!hasGroqKey) {
      setError('Groq API key required')
      return
    }
    if (!customInput.trim()) return
    setLoadingCustom(true)
    setError(null)
    setCustomResult(null)
    try {
      const hyp = await generateCustomHypothesis(buildCustomRequirements(), groqApiKey)
      hyp.id = hyp.id || `CUSTOM-${Date.now()}`
      hyp.generatedAt = hyp.generatedAt || new Date().toISOString()
      setCustomResult(hyp)
    } catch (e) {
      setError(e.message || 'Failed to generate custom hypothesis')
    } finally {
      setLoadingCustom(false)
    }
  }

  const saveCustomResult = () => {
    if (!customResult) return
    setCustomHypotheses((prev) => {
      if (prev.some((h) => h.id === customResult.id)) return prev
      return [customResult, ...prev]
    })
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
          <button
            type="button"
            className={`hyp-tab-pill ${activeTab === 'custom' ? 'active' : ''}`}
            onClick={() => setActiveTab('custom')}
          >
            Custom Generator
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

      {activeTab === 'static' && (
        <div className="hypotheses-list">
          {staticHypothesesData.map((hyp) => (
            <HypothesisCard
              key={hyp.id}
              hyp={hyp}
              cardKey="static"
              expandedId={expandedId}
              setExpandedId={setExpandedId}
              queriesById={queriesById}
            />
          ))}
        </div>
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
              <div className="hypotheses-list">
                {liveHypotheses.map((hyp) => (
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
                  />
                ))}
              </div>
            </section>
          )}
        </div>
      )}

      {activeTab === 'custom' && (
        <div className="hyp-custom-tab">
          <section className="hyp-custom-form-card">
            <h3>Generate Custom Hunt Hypothesis</h3>
            {!hasGroqKey && (
              <p className="hyp-key-required">Groq API key required</p>
            )}
            <textarea
              className="hyp-custom-textarea"
              rows={6}
              placeholder={`Describe what you want to hunt for. Examples:
- Hunt for lateral movement using RDP from non-server machines in our environment
- Detect data exfiltration via DNS tunneling targeting our finance department
- Find persistence mechanisms targeting our AD environment
- Hunt for ransomware pre-stage activity in our file servers`}
              value={customInput}
              onChange={(e) => setCustomInput(e.target.value)}
            />
            <div className="hyp-suggestion-chips">
              {QUICK_SUGGESTIONS.map((s) => (
                <button
                  key={s}
                  type="button"
                  className="suggestion-chip"
                  onClick={() => setCustomInput(s)}
                >
                  {s}
                </button>
              ))}
            </div>
            <div className="hyp-custom-controls">
              <label>
                Priority
                <select
                  value={customPriority}
                  onChange={(e) => setCustomPriority(e.target.value)}
                >
                  {PRIORITY_OPTIONS.map((p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Focus log source
                <select
                  value={customLogFocus}
                  onChange={(e) => setCustomLogFocus(e.target.value)}
                >
                  {LOG_SOURCE_FOCUS.map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <button
              type="button"
              className="hyp-generate-full-btn"
              disabled={!customInput.trim() || !hasGroqKey || loadingCustom}
              onClick={handleGenerateCustom}
            >
              Generate Hypothesis
            </button>
            {loadingCustom && (
              <div className="hyp-loading-row">
                <span className="spinner" aria-hidden="true" />
                AI is generating your custom hypothesis...
              </div>
            )}
          </section>

          {customResult && (
            <section className="hyp-custom-result">
              <HypothesisCard
                hyp={customResult}
                cardKey="custom-result"
                expandedId={expandedId}
                setExpandedId={setExpandedId}
                queriesById={queriesById}
                kqlDefaultOpen
                showExport
                extraBadges={<span className="ai-generated-badge">AI Generated</span>}
              />
              <div className="hyp-custom-result-actions">
                <button type="button" className="export-btn" onClick={saveCustomResult}>
                  Save to My Hypotheses
                </button>
                <button
                  type="button"
                  className="export-btn"
                  onClick={() => exportHypothesisKql(customResult, queriesById)}
                >
                  Export All KQL
                </button>
                <button
                  type="button"
                  className="hyp-regenerate-btn"
                  onClick={handleGenerateCustom}
                  disabled={loadingCustom || !hasGroqKey}
                >
                  Regenerate
                </button>
              </div>
            </section>
          )}

          {customHypotheses.length > 0 && (
            <section className="hyp-saved-custom">
              <h3>My Saved Hypotheses</h3>
              <div className="hypotheses-list">
                {customHypotheses.map((hyp) => (
                  <HypothesisCard
                    key={hyp.id}
                    hyp={hyp}
                    cardKey="custom"
                    expandedId={expandedId}
                    setExpandedId={setExpandedId}
                    queriesById={queriesById}
                    showExport
                    onRemove={(id) =>
                      setCustomHypotheses((prev) => prev.filter((h) => h.id !== id))
                    }
                    extraBadges={<span className="ai-generated-badge">AI Generated</span>}
                  />
                ))}
              </div>
            </section>
          )}
        </div>
      )}
    </div>
  )
}

export default Hypotheses
