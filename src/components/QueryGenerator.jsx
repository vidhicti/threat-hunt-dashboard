import { useState, useMemo } from 'react'
import techniques from '../data/techniques.json'
import queries from '../data/queries.json'
import { generateKQLFromTTP, generateBulkKQL } from '../services/autoQueryGenerator'

const GROQ_KEY_STORAGE = 'threat-hunt-groq-api-key'

const LOG_SOURCES = [
  { id: 'All', label: 'All Sources' },
  { id: 'Fortigate', label: 'Fortigate' },
  { id: 'PaloAlto', label: 'Palo Alto' },
  { id: 'Sophos', label: 'Sophos' },
  { id: 'AD', label: 'Active Directory' },
  { id: 'MDE', label: 'MDE' },
  { id: 'DNS', label: 'DNS' },
  { id: 'O365', label: 'Office 365' },
  { id: 'TrendMicro', label: 'Trend Micro' },
]

const TACTIC_ORDER = [
  'Reconnaissance',
  'Resource Development',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
]

const SENTINEL_URL =
  'https://portal.azure.com/#blade/Microsoft_Azure_Monitoring_Logs/LogsBlade'

function QueryGenerator() {
  const [ttpInput, setTtpInput] = useState('')
  const [logSource, setLogSource] = useState('All')
  const [groqKey, setGroqKey] = useState(() => localStorage.getItem(GROQ_KEY_STORAGE) || '')
  const [generatedKql, setGeneratedKql] = useState('')
  const [aiLoading, setAiLoading] = useState(false)
  const [aiError, setAiError] = useState(null)
  const [saveMsg, setSaveMsg] = useState('')
  const [expandedTactic, setExpandedTactic] = useState(null)
  const [selectedTechnique, setSelectedTechnique] = useState(null)
  const [bulkInput, setBulkInput] = useState('')
  const [bulkResults, setBulkResults] = useState([])
  const [bulkLoading, setBulkLoading] = useState(false)
  const [expandedBulk, setExpandedBulk] = useState({})

  const tacticsWithTechniques = useMemo(() => {
    const map = new Map()
    TACTIC_ORDER.forEach((t) => map.set(t, []))
    techniques.forEach((tech) => {
      if (!map.has(tech.tactic)) map.set(tech.tactic, [])
      map.get(tech.tactic).push(tech)
    })
    return TACTIC_ORDER.filter((t) => (map.get(t) || []).length > 0).map((tactic) => ({
      tactic,
      techniques: (map.get(tactic) || []).sort((a, b) => a.id.localeCompare(b.id)),
    }))
  }, [])

  const techniqueQueries = useMemo(() => {
    if (!selectedTechnique) return []
    return queries.filter(
      (q) =>
        q.mitreTechnique === selectedTechnique ||
        (q.mitreTechnique && q.mitreTechnique.startsWith(`${selectedTechnique}.`)) ||
        (selectedTechnique && selectedTechnique.startsWith(`${q.mitreTechnique}.`))
    )
  }, [selectedTechnique])

  const handleGroqKeyChange = (value) => {
    setGroqKey(value)
    localStorage.setItem(GROQ_KEY_STORAGE, value)
  }

  const handleGenerateAI = async () => {
    if (!groqKey.trim()) {
      setAiError('Add Groq API key to enable AI generation. Get a free key at console.groq.com')
      return
    }
    if (!ttpInput.trim()) {
      setAiError('Enter a MITRE TTP ID (e.g. T1059.001)')
      return
    }
    setAiLoading(true)
    setAiError(null)
    setGeneratedKql('')
    try {
      const kql = await generateKQLFromTTP(ttpInput.trim(), logSource, groqKey)
      setGeneratedKql(kql)
    } catch (err) {
      setAiError(err.message || 'Generation failed')
    } finally {
      setAiLoading(false)
    }
  }

  const copyText = async (text) => {
    try {
      await navigator.clipboard.writeText(text)
      setSaveMsg('Copied!')
      setTimeout(() => setSaveMsg(''), 2000)
    } catch {
      setSaveMsg('Copy failed')
    }
  }

  const saveToLibrary = () => {
    if (!generatedKql) return
    const saved = JSON.parse(localStorage.getItem('threat-hunt-saved-kql') || '[]')
    saved.unshift({
      id: `GEN-${Date.now()}`,
      ttp: ttpInput,
      logSource,
      kql: generatedKql,
      savedAt: new Date().toISOString(),
    })
    localStorage.setItem('threat-hunt-saved-kql', JSON.stringify(saved.slice(0, 50)))
    setSaveMsg('Saved to local library!')
    setTimeout(() => setSaveMsg(''), 2500)
  }

  const handleBulkGenerate = async () => {
    if (!groqKey.trim()) {
      setAiError('Add Groq API key to enable bulk generation.')
      return
    }
    const lines = bulkInput.split('\n').map((l) => l.trim()).filter(Boolean)
    if (!lines.length) return
    setBulkLoading(true)
    setAiError(null)
    try {
      const results = await generateBulkKQL(lines, logSource, groqKey)
      setBulkResults(results)
      setExpandedBulk({ [results[0]?.ttp]: true })
    } catch (err) {
      setAiError(err.message)
    } finally {
      setBulkLoading(false)
    }
  }

  const exportBulkTxt = () => {
    const content = bulkResults
      .map(
        (r) =>
          `${'='.repeat(60)}\n${r.ttp}\n${'='.repeat(60)}\n${r.error ? `ERROR: ${r.error}` : r.kql}\n`
      )
      .join('\n')
    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'bulk-generated-kql.txt'
    link.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="query-generator">
      <section className="qg-card">
        <h2>Auto-Generate KQL</h2>
        <p className="qg-hint">
          Uses free Groq API (Llama 3).{' '}
          <a href="https://console.groq.com" target="_blank" rel="noopener noreferrer">
            Get API key →
          </a>
        </p>

        <div className="qg-form-row">
          <label>
            MITRE TTP
            <input
              type="text"
              placeholder="e.g. T1059.001"
              value={ttpInput}
              onChange={(e) => setTtpInput(e.target.value)}
            />
          </label>
          <label>
            Log source
            <select value={logSource} onChange={(e) => setLogSource(e.target.value)}>
              {LOG_SOURCES.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.label}
                </option>
              ))}
            </select>
          </label>
        </div>

        <label className="groq-key-label">
          Groq API Key
          <input
            type="password"
            placeholder="gsk_…"
            value={groqKey}
            onChange={(e) => handleGroqKeyChange(e.target.value)}
            autoComplete="off"
          />
        </label>

        {!groqKey.trim() && (
          <p className="qg-disabled-msg">Add Groq API key to enable AI-powered KQL generation.</p>
        )}

        <button
          type="button"
          className="copy-btn qg-generate-btn"
          onClick={handleGenerateAI}
          disabled={aiLoading}
        >
          {aiLoading ? (
            <span className="spinner-wrap">
              <span className="spinner" aria-hidden="true" />
              Generating…
            </span>
          ) : (
            'Generate with AI'
          )}
        </button>

        {aiError && <p className="qg-error">{aiError}</p>}
        {saveMsg && <p className="qg-success">{saveMsg}</p>}

        {generatedKql && (
          <div className="qg-output">
            <pre className="kql-block">
              <code>{generatedKql}</code>
            </pre>
            <div className="qg-output-actions">
              <button type="button" className="export-btn secondary" onClick={() => copyText(generatedKql)}>
                Copy KQL
              </button>
              <button type="button" className="export-btn secondary" onClick={saveToLibrary}>
                Save to Library
              </button>
              <a
                className="sentinel-link-btn"
                href={SENTINEL_URL}
                target="_blank"
                rel="noopener noreferrer"
              >
                View in Sentinel
              </a>
            </div>
          </div>
        )}
      </section>

      <section className="qg-card">
        <h2>Browse by TTP</h2>
        <div className="tactic-grid">
          {tacticsWithTechniques.map(({ tactic, techniques: techs }) => (
            <div key={tactic} className="tactic-card">
              <button
                type="button"
                className="tactic-card-header"
                onClick={() =>
                  setExpandedTactic(expandedTactic === tactic ? null : tactic)
                }
              >
                <span>{tactic}</span>
                <span className="tactic-count">{techs.length}</span>
              </button>
              {expandedTactic === tactic && (
                <ul className="technique-list">
                  {techs.map((tech) => (
                    <li key={tech.id}>
                      <button
                        type="button"
                        className={`technique-btn ${selectedTechnique === tech.id ? 'active' : ''}`}
                        onClick={() =>
                          setSelectedTechnique(
                            selectedTechnique === tech.id ? null : tech.id
                          )
                        }
                      >
                        <strong>{tech.id}</strong> {tech.name}
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ))}
        </div>

        {selectedTechnique && (
          <div className="technique-queries">
            <h3>Queries for {selectedTechnique}</h3>
            {techniqueQueries.length === 0 ? (
              <p className="empty-state">No queries in library for this technique.</p>
            ) : (
              techniqueQueries.map((q) => (
                <article key={q.id} className="query-card compact">
                  <div className="query-card-header">
                    <h4>
                      {q.id}: {q.title}
                    </h4>
                    <span className={`badge severity-${q.severity}`}>{q.severity}</span>
                  </div>
                  <pre className="kql-block small">
                    <code>{q.kql}</code>
                  </pre>
                  <div className="qg-output-actions">
                    <button
                      type="button"
                      className="export-btn secondary"
                      onClick={() => copyText(q.kql)}
                    >
                      Copy KQL
                    </button>
                    <a
                      className="sentinel-link-btn"
                      href={SENTINEL_URL}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      View in Sentinel
                    </a>
                  </div>
                </article>
              ))
            )}
          </div>
        )}
      </section>

      <section className="qg-card">
        <h2>Bulk Generator</h2>
        <p className="qg-hint">Paste one MITRE TTP per line. Requires Groq API key.</p>
        <textarea
          className="bulk-textarea"
          rows={6}
          placeholder={'T1059.001\nT1003.001\nT1071.004'}
          value={bulkInput}
          onChange={(e) => setBulkInput(e.target.value)}
        />
        <button
          type="button"
          className="copy-btn qg-generate-btn"
          onClick={handleBulkGenerate}
          disabled={bulkLoading || !groqKey.trim()}
        >
          {bulkLoading ? 'Generating All…' : 'Generate All'}
        </button>

        {bulkResults.length > 0 && (
          <>
            <div className="bulk-results">
              {bulkResults.map((r) => (
                <div key={r.ttp} className="bulk-result-card">
                  <button
                    type="button"
                    className="bulk-result-header"
                    onClick={() =>
                      setExpandedBulk((prev) => ({
                        ...prev,
                        [r.ttp]: !prev[r.ttp],
                      }))
                    }
                  >
                    <strong>{r.ttp}</strong>
                    <span>{r.error ? 'Error' : 'KQL'}</span>
                  </button>
                  {expandedBulk[r.ttp] && (
                    <div className="bulk-result-body">
                      {r.error ? (
                        <p className="qg-error">{r.error}</p>
                      ) : (
                        <pre className="kql-block small">
                          <code>{r.kql}</code>
                        </pre>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
            <button type="button" className="export-btn" onClick={exportBulkTxt}>
              Export All as .txt
            </button>
          </>
        )}
      </section>
    </div>
  )
}

export default QueryGenerator
