import { useState } from 'react'
import { FEED_DEFINITIONS, FEED_GROUPS, FEED_BY_ID } from '../data/feedConfig'
import { FEED_COUNT } from '../services/threatIntel'

const API_BASE = window.location.hostname === 'localhost'
  ? 'http://localhost:3000'
  : 'https://threat-hunt-dashboard.vercel.app'

async function postToApi(path, body) {
  const res = await fetch(`${API_BASE}/api/${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  return res.json()
}

function getConsolidatedFeedEndpoint(feedId) {
  const feeds1 = ['threatfox', 'urlhaus', 'feodotracker', 'malwarebazaar']
  const feeds2 = ['emergingthreats', 'cinsarmy', 'sslblacklist']
  const feeds3 = ['alienvault', 'certpoland']
  if (feeds1.includes(feedId)) return `/api/feeds1?feed=${feedId}`
  if (feeds2.includes(feedId)) return `/api/feeds2?feed=${feedId}`
  if (feeds3.includes(feedId)) return `/api/feeds3?feed=${feedId}`
  return null
}

function tierBadgeClass(tier) {
  if (tier === 'free') return 'connector-tier-free'
  if (tier === 'free_limited') return 'connector-tier-key'
  if (tier === 'self_hosted') return 'connector-tier-self'
  return 'connector-tier-enterprise'
}

function tierBadgeLabel(tier) {
  if (tier === 'free') return 'Free'
  if (tier === 'free_limited') return 'Free + Key'
  if (tier === 'self_hosted') return 'Self-Hosted'
  return 'Enterprise'
}

function formatTestTime(iso) {
  if (!iso) return null
  try {
    return new Date(iso).toLocaleString()
  } catch {
    return iso
  }
}

function getFeedEnabled(feed, connectorConfig) {
  const cfg = connectorConfig[feed.id]
  if (!cfg) return !feed.requiresKey
  return cfg.enabled !== false
}

function canToggleFeed(feed, connectorConfig) {
  if (!feed.requiresKey) return true
  return !!(connectorConfig[feed.id]?.apiKey)
}

export default function Settings({ theme = 'dark', setTheme }) {
  const [groqApiKey, setGroqApiKey] = useState(localStorage.getItem('groqApiKey') || '')
  const [analystName, setAnalystName] = useState(localStorage.getItem('analystName') || '')
  const [groqModel, setGroqModel] = useState(localStorage.getItem('groqModel') || 'llama-3.3-70b-versatile')
  const [connectorConfig, setConnectorConfig] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('connectorConfig') || '{}')
    } catch {
      return {}
    }
  })
  const [testingFeed, setTestingFeed] = useState(null)
  const [expandedFeed, setExpandedFeed] = useState(null)
  const [testResults, setTestResults] = useState({})
  const [drafts, setDrafts] = useState({})
  const [showKeys, setShowKeys] = useState({})
  const [defaultLookback, setDefaultLookback] = useState(localStorage.getItem('defaultLookback') || '1d')
  const [lookbackSaved, setLookbackSaved] = useState(false)
  const [autoRefresh, setAutoRefresh] = useState(localStorage.getItem('autoRefresh') === 'true')
  const [refreshInterval, setRefreshInterval] = useState(parseInt(localStorage.getItem('refreshInterval') || '300000'))
  const [whitelist, setWhitelist] = useState(JSON.parse(localStorage.getItem('iocWhitelist') || '[]'))
  const [newWhitelistItem, setNewWhitelistItem] = useState('')
  const [apiTestResult, setApiTestResult] = useState(null)
  const [testingApi, setTestingApi] = useState(false)
  const [connectorMsg, setConnectorMsg] = useState(null)

  const lookbackOptions = [
    { value: '1h', label: '1 Hour' },
    { value: '6h', label: '6 Hours' },
    { value: '1d', label: '1 Day' },
    { value: '3d', label: '3 Days' },
    { value: '7d', label: '7 Days' },
    { value: '14d', label: '14 Days' },
    { value: '30d', label: '30 Days' },
  ]

  const refreshOptions = [
    { value: 60000, label: '1 minute' },
    { value: 300000, label: '5 minutes' },
    { value: 600000, label: '10 minutes' },
    { value: 1800000, label: '30 minutes' },
    { value: 3600000, label: '1 hour' },
  ]

  const modelOptions = [
    { value: 'llama-3.3-70b-versatile', label: 'Llama 3.3 70B Versatile' },
    { value: 'llama-3.1-70b-versatile', label: 'Llama 3.1 70B Versatile' },
    { value: 'mixtral-8x7b-32768', label: 'Mixtral 8x7B' },
    { value: 'gemma2-9b-it', label: 'Gemma 2 9B' },
  ]

  function getDraft(feedId) {
    const cfg = connectorConfig[feedId] || {}
    const feed = FEED_BY_ID[feedId]
    const base = { apiKey: cfg.apiKey || '' }
    feed?.extraFields?.forEach((f) => {
      base[f.id] = cfg[f.id] || ''
    })
    return { ...base, ...drafts[feedId] }
  }

  function updateDraft(feedId, field, value) {
    setDrafts((prev) => ({
      ...prev,
      [feedId]: { ...getDraft(feedId), ...prev[feedId], [field]: value },
    }))
  }

  function persistConnectorConfig(config) {
    setConnectorConfig(config)
    localStorage.setItem('connectorConfig', JSON.stringify(config))
  }

  function saveFeedConfig(feedId) {
    const feed = FEED_BY_ID[feedId]
    const draft = getDraft(feedId)
    const updated = {
      ...connectorConfig,
      [feedId]: {
        ...connectorConfig[feedId],
        apiKey: draft.apiKey,
        enabled: connectorConfig[feedId]?.enabled ?? !feed.requiresKey,
      },
    }
    feed?.extraFields?.forEach((f) => {
      updated[feedId][f.id] = draft[f.id] || ''
    })
    persistConnectorConfig(updated)
    setConnectorMsg({ type: 'success', message: `${feed.name} settings saved` })
    setTimeout(() => setConnectorMsg(null), 3000)
  }

  function saveAllConnectors() {
    const updated = { ...connectorConfig }
    FEED_DEFINITIONS.forEach((feed) => {
      const draft = getDraft(feed.id)
      const hasKey = !!draft.apiKey
      const hasExtra = feed.extraFields?.some((f) => draft[f.id])
      if (hasKey || hasExtra || updated[feed.id]) {
        updated[feed.id] = {
          ...updated[feed.id],
          apiKey: draft.apiKey,
          enabled: updated[feed.id]?.enabled ?? !feed.requiresKey,
        }
        feed.extraFields?.forEach((f) => {
          updated[feed.id][f.id] = draft[f.id] || ''
        })
      }
    })
    persistConnectorConfig(updated)
    setConnectorMsg({ type: 'success', message: 'All connector settings saved' })
    setTimeout(() => setConnectorMsg(null), 3000)
  }

  function resetConnectorsToDefaults() {
    const defaults = {}
    FEED_DEFINITIONS.forEach((feed) => {
      if (!feed.requiresKey) {
        defaults[feed.id] = { enabled: true }
      }
    })
    persistConnectorConfig(defaults)
    setDrafts({})
    setTestResults({})
    setConnectorMsg({ type: 'success', message: 'Reset to defaults — free feeds enabled' })
    setTimeout(() => setConnectorMsg(null), 3000)
  }

  function toggleFeedEnabled(feed) {
    if (!canToggleFeed(feed, connectorConfig)) return
    const enabled = getFeedEnabled(feed, connectorConfig)
    const updated = {
      ...connectorConfig,
      [feed.id]: { ...connectorConfig[feed.id], enabled: !enabled },
    }
    persistConnectorConfig(updated)
  }

  function getStatusDot(feed) {
    const enabled = getFeedEnabled(feed, connectorConfig)
    const cfg = connectorConfig[feed.id]
    if (!enabled) return 'gray'
    if (cfg?.testStatus === 'fail') return 'red'
    if (cfg?.testStatus === 'ok') return 'green'
    return enabled ? 'green' : 'gray'
  }

  async function testFeedConnection(feed) {
    setTestingFeed(feed.id)
    setTestResults((prev) => ({ ...prev, [feed.id]: null }))

    const draft = getDraft(feed.id)
    const apiKey = draft.apiKey || connectorConfig[feed.id]?.apiKey

    try {
      let result = { ok: false, message: 'Connection failed', iocCount: 0 }

      if (feed.usedFor === 'enrichment') {
        if (feed.id === 'abuseipdb') {
          const res = await fetch(`${API_BASE}/api/abuseipdb`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: '1.1.1.1', apiKey }),
          })
          const data = await res.json()
          if (!data.success) throw new Error(data.error || 'Connection failed')
          result = {
            ok: true,
            message: 'Connected',
            iocCount: `Abuse score ${data.result.abuseScore}/100 (${data.result.totalReports || 0} reports)`,
          }
        } else if (feed.id === 'virustotal') {
          const res = await fetch(`${API_BASE}/api/virustotal`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ indicator: '1.1.1.1', type: 'IP', apiKey }),
          })
          const data = await res.json()
          if (!data.success) throw new Error(data.error || 'Connection failed')
          result = {
            ok: true,
            message: 'Connected',
            iocCount: `VT score ${data.result.vtScore} (${data.result.vtMalicious} malicious)`,
          }
        } else if (feed.id === 'shodan') {
          const res = await fetch(`${API_BASE}/api/shodan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: '8.8.8.8', apiKey }),
          })
          const data = await res.json()
          if (!data.success) throw new Error(data.error || 'Connection failed')
          const portCount = data.result.openPorts?.length || 0
          const vulnCount = data.result.vulns?.length || 0
          result = {
            ok: true,
            message: 'Connected',
            iocCount: `${portCount} open ports, ${vulnCount} vulnerabilities`,
          }
        }
      } else if (feed.id === 'alienvault' && apiKey) {
        const data = await postToApi('feeds3', { feed: 'alienvaultkey', apiKey })
        if (!data.success) throw new Error(data.error || 'Invalid OTX API key')
        result = {
          ok: true,
          message: 'Connected',
          iocCount: data.count > 0 ? `${data.count} IOCs available` : 'Authenticated',
        }
      } else if (feed.id === 'misp') {
        const mispUrl = (draft.mispUrl || connectorConfig.misp?.mispUrl || '').replace(/\/$/, '')
        if (!apiKey || !mispUrl) throw new Error('API key and MISP URL required')
        const data = await postToApi('misp', { mispUrl, apiKey, action: 'test' })
        if (!data.success) throw new Error(data.error || 'MISP connection failed')
        const count = data.count ?? 0
        result = { ok: true, message: 'Connected', iocCount: count > 0 ? `${count}+ IOCs` : 'MISP reachable' }
      } else if (feed.id === 'opencti') {
        const openctiUrl = (draft.openctiUrl || connectorConfig.opencti?.openctiUrl || '').replace(/\/$/, '')
        if (!apiKey || !openctiUrl) throw new Error('API key and OpenCTI URL required')
        const data = await postToApi('opencti', { openctiUrl, apiKey, action: 'test' })
        if (!data.success) throw new Error(data.error || 'OpenCTI connection failed')
        result = { ok: true, message: 'Connected', iocCount: 'Instance reachable' }
      } else if (feed.id === 'recordedfuture' || feed.id === 'crowdstrike') {
        if (!apiKey) throw new Error('API key required')
        result = { ok: true, message: 'API key saved', iocCount: feed.iocCount }
      } else {
        const endpoint = getConsolidatedFeedEndpoint(feed.id)
        if (!endpoint) throw new Error('Unknown feed')
        const res = await fetch(`${API_BASE}${endpoint}`)
        const data = await res.json()
        if (!res.ok || data.success === false) throw new Error(data.error || 'Feed unavailable')
        const count = data.iocs?.length ?? data.count ?? 0
        result = { ok: true, message: 'Connected', iocCount: count }
      }

      const updated = {
        ...connectorConfig,
        [feed.id]: {
          ...connectorConfig[feed.id],
          lastTest: new Date().toISOString(),
          testStatus: 'ok',
        },
      }
      persistConnectorConfig(updated)
      setTestResults((prev) => ({
        ...prev,
        [feed.id]: { ok: true, text: `✓ ${result.message} - ${result.iocCount}` },
      }))
    } catch (err) {
      const updated = {
        ...connectorConfig,
        [feed.id]: {
          ...connectorConfig[feed.id],
          lastTest: new Date().toISOString(),
          testStatus: 'fail',
        },
      }
      persistConnectorConfig(updated)
      setTestResults((prev) => ({
        ...prev,
        [feed.id]: { ok: false, text: `✗ Failed: ${err.message || 'Connection failed'}` },
      }))
    } finally {
      setTestingFeed(null)
    }
  }

  function saveGroqApiKey() {
    localStorage.setItem('groqApiKey', groqApiKey)
    setApiTestResult({ type: 'success', message: 'API key saved' })
    setTimeout(() => setApiTestResult(null), 3000)
  }

  async function testGroqApiKey() {
    setTestingApi(true)
    setApiTestResult(null)
    try {
      const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${groqApiKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model: groqModel,
          messages: [{ role: 'user', content: 'Say hello' }],
          max_tokens: 10,
        }),
      })
      if (response.ok) {
        setApiTestResult({ type: 'success', message: 'API key is valid' })
      } else {
        setApiTestResult({ type: 'error', message: 'API key is invalid' })
      }
    } catch {
      setApiTestResult({ type: 'error', message: 'Connection failed' })
    } finally {
      setTestingApi(false)
    }
  }

  function addToWhitelist() {
    if (newWhitelistItem.trim()) {
      const list = [...whitelist, newWhitelistItem.trim()]
      setWhitelist(list)
      localStorage.setItem('iocWhitelist', JSON.stringify(list))
      setNewWhitelistItem('')
    }
  }

  function removeFromWhitelist(item) {
    const list = whitelist.filter((i) => i !== item)
    setWhitelist(list)
    localStorage.setItem('iocWhitelist', JSON.stringify(list))
  }

  function clearWhitelist() {
    setWhitelist([])
    localStorage.setItem('iocWhitelist', '[]')
  }

  function exportWhitelist() {
    const csv = whitelist.map((i) => `"${i}"`).join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = 'ioc-whitelist.csv'
    a.click()
  }

  function saveAnalystName() {
    localStorage.setItem('analystName', analystName)
  }

  function saveLookback(value) {
    const next = value ?? defaultLookback
    localStorage.setItem('defaultLookback', next)
    window.dispatchEvent(new Event('defaultLookbackChanged'))
    setLookbackSaved(true)
    setTimeout(() => setLookbackSaved(false), 2000)
  }

  function saveAutoRefresh() {
    localStorage.setItem('autoRefresh', autoRefresh.toString())
  }

  function saveRefreshInterval() {
    localStorage.setItem('refreshInterval', refreshInterval.toString())
  }

  function saveModel() {
    localStorage.setItem('groqModel', groqModel)
  }

  function applyTheme(next) {
    setTheme?.(next)
    localStorage.setItem('theme', next)
    document.documentElement.setAttribute('data-theme', next)
  }

  function renderFeedCard(feed) {
    const expanded = expandedFeed === feed.id
    const enabled = getFeedEnabled(feed, connectorConfig)
    const toggleDisabled = feed.requiresKey && !canToggleFeed(feed, connectorConfig)
    const draft = getDraft(feed.id)
    const cfg = connectorConfig[feed.id] || {}
    const statusDot = getStatusDot(feed)
    const liveResult = testResults[feed.id]

    return (
      <div
        key={feed.id}
        className={`connector-feed-card ${expanded ? 'expanded' : ''}`}
      >
        <div
          className="connector-feed-header"
          onClick={() => setExpandedFeed(expanded ? null : feed.id)}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => e.key === 'Enter' && setExpandedFeed(expanded ? null : feed.id)}
        >
          <div className="connector-feed-title-row">
            <div className="connector-feed-title">
              <span className={`connector-status-dot connector-status-${statusDot}`} />
              <span className="connector-feed-name">{feed.name}</span>
              <span className="connector-provider-badge">{feed.provider}</span>
            </div>
            <div className="connector-feed-actions">
              <label
                className={`connector-toggle ${toggleDisabled ? 'disabled' : ''}`}
                onClick={(e) => e.stopPropagation()}
              >
                <input
                  type="checkbox"
                  checked={enabled}
                  disabled={toggleDisabled}
                  onChange={() => toggleFeedEnabled(feed)}
                />
                <span className="connector-toggle-slider" />
              </label>
              <span className={`connector-chevron ${expanded ? 'open' : ''}`}>›</span>
            </div>
          </div>
          <div className="connector-feed-meta">
            <div className="connector-type-badges">
              {feed.types.map((t) => (
                <span key={t} className="connector-type-badge">{t}</span>
              ))}
            </div>
            <span className={`connector-tier-badge ${tierBadgeClass(feed.tier)}`}>
              {tierBadgeLabel(feed.tier)}
            </span>
            <span className="connector-ioc-count">{feed.iocCount}</span>
          </div>
        </div>

        {expanded && (
          <div className="connector-feed-body">
            <p className="connector-description">{feed.description}</p>

            {feed.usedFor === 'enrichment' && (
              <div className="connector-enrichment-note">
                Used for IOC enrichment, not bulk feed
                {feed.freeLimit && ` · ${feed.freeLimit}`}
              </div>
            )}

            {feed.requiresKey && (
              <>
                {feed.apiKeyLink && (
                  <a
                    href={feed.apiKeyLink}
                    target="_blank"
                    rel="noreferrer"
                    className="connector-api-link"
                  >
                    Get API Key →
                  </a>
                )}
                <div className="connector-field">
                  <label>{feed.apiKeyLabel || 'API Key'}</label>
                  <div className="connector-key-row">
                    <input
                      type={showKeys[feed.id] ? 'text' : 'password'}
                      value={draft.apiKey}
                      onChange={(e) => updateDraft(feed.id, 'apiKey', e.target.value)}
                      placeholder={feed.apiKeyPlaceholder || 'Enter API key'}
                    />
                    <button
                      type="button"
                      className="connector-btn-secondary"
                      onClick={() => setShowKeys((prev) => ({ ...prev, [feed.id]: !prev[feed.id] }))}
                    >
                      {showKeys[feed.id] ? 'Hide' : 'Show'}
                    </button>
                  </div>
                </div>
              </>
            )}

            {feed.extraFields?.map((field) => (
              <div key={field.id} className="connector-field">
                <label>{field.label}</label>
                <input
                  type="text"
                  value={draft[field.id] || ''}
                  onChange={(e) => updateDraft(feed.id, field.id, e.target.value)}
                  placeholder={field.placeholder}
                />
              </div>
            ))}

            <div className="connector-btn-row">
              <button type="button" className="connector-btn-primary" onClick={() => saveFeedConfig(feed.id)}>
                Save
              </button>
              <button
                type="button"
                className="connector-btn-test"
                disabled={testingFeed === feed.id || (feed.requiresKey && !draft.apiKey && !cfg.apiKey)}
                onClick={() => testFeedConnection(feed)}
              >
                {testingFeed === feed.id ? (
                  <span className="connector-spinner">Testing...</span>
                ) : (
                  'Test Connection'
                )}
              </button>
            </div>

            {(liveResult || cfg.lastTest) && (
              <div className="connector-test-result">
                {liveResult && (
                  <div className={liveResult.ok ? 'connector-test-ok' : 'connector-test-fail'}>
                    {liveResult.text}
                  </div>
                )}
                {cfg.lastTest && (
                  <div className="connector-last-tested">
                    Last tested: {formatTestTime(cfg.lastTest)}
                    {cfg.testStatus && (
                      <span className={`connector-test-badge connector-test-badge-${cfg.testStatus}`}>
                        {cfg.testStatus === 'ok' ? 'OK' : 'Failed'}
                      </span>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    )
  }

  return (
    <div>
      <h2 style={{ fontSize: 20, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 20 }}>Settings</h2>

      <div style={{ background: 'var(--card-bg)', border: '1px solid var(--border-primary)', borderRadius: 8, padding: 20, marginBottom: 16 }}>
        <h3 style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 12 }}>Appearance</h3>
        <label style={{ display: 'block', fontSize: 12, color: 'var(--text-tertiary)', marginBottom: 6 }}>Theme</label>
        <div className="settings-theme-row">
          <button
            type="button"
            className={`settings-theme-btn ${theme === 'dark' ? 'active' : ''}`}
            onClick={() => applyTheme('dark')}
          >
            🌙 Dark
          </button>
          <button
            type="button"
            className={`settings-theme-btn ${theme === 'light' ? 'active' : ''}`}
            onClick={() => applyTheme('light')}
          >
            ☀️ Light
          </button>
        </div>
      </div>

      <div style={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 8, padding: 20, marginBottom: 16 }}>
        <h3 style={{ fontSize: 14, fontWeight: 600, color: '#f0f6fc', marginBottom: 12 }}>API Configuration</h3>

        <div style={{ marginBottom: 16 }}>
          <label style={{ display: 'block', fontSize: 12, color: '#8b949e', marginBottom: 6 }}>Groq API Key</label>
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              type="password"
              value={groqApiKey}
              onChange={(e) => setGroqApiKey(e.target.value)}
              placeholder="gsk_..."
              style={{ flex: 1, padding: '8px 12px', background: '#0d1117', border: '1px solid #30363d', borderRadius: 6, color: '#c9d1d9', fontSize: 12, outline: 'none' }}
            />
            <button onClick={saveGroqApiKey} style={{ padding: '8px 16px', background: '#21262d', border: '1px solid #30363d', borderRadius: 6, color: '#c9d1d9', fontSize: 12, cursor: 'pointer' }}>Save</button>
            <button onClick={testGroqApiKey} disabled={testingApi || !groqApiKey} style={{ padding: '8px 16px', background: '#0d2045', border: '1px solid #58a6ff44', borderRadius: 6, color: '#58a6ff', fontSize: 12, cursor: testingApi || !groqApiKey ? 'default' : 'pointer', opacity: testingApi || !groqApiKey ? 0.5 : 1 }}>
              {testingApi ? 'Testing...' : 'Test'}
            </button>
          </div>
          {apiTestResult && (
            <div style={{ marginTop: 8, fontSize: 11, padding: '6px 10px', borderRadius: 4, background: apiTestResult.type === 'success' ? '#0d2d1a' : '#3d1a1a', color: apiTestResult.type === 'success' ? '#3fb950' : '#f85149' }}>
              {apiTestResult.message}
            </div>
          )}
        </div>

        <div style={{ marginBottom: 16 }}>
          <label style={{ display: 'block', fontSize: 12, color: '#8b949e', marginBottom: 6 }}>Analyst Name</label>
          <input
            type="text"
            value={analystName}
            onChange={(e) => setAnalystName(e.target.value)}
            placeholder="Your name"
            onBlur={saveAnalystName}
            style={{ width: '100%', padding: '8px 12px', background: '#0d1117', border: '1px solid #30363d', borderRadius: 6, color: '#c9d1d9', fontSize: 12, outline: 'none' }}
          />
        </div>

        <div>
          <label style={{ display: 'block', fontSize: 12, color: '#8b949e', marginBottom: 6 }}>AI Model</label>
          <select
            value={groqModel}
            onChange={(e) => { setGroqModel(e.target.value); saveModel() }}
            style={{ width: '100%', padding: '8px 12px', background: '#0d1117', border: '1px solid #30363d', borderRadius: 6, color: '#c9d1d9', fontSize: 12, outline: 'none' }}
          >
            {modelOptions.map((opt) => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
        </div>
      </div>

      <div className="connector-section">
        <div className="connector-section-header">
          <div>
            <h3>Threat Intel Feed Connectors</h3>
            <p className="connector-section-subtitle">
              {FEED_DEFINITIONS.length} connectors · {FEED_COUNT} bulk feeds
            </p>
          </div>
          <div className="connector-section-actions">
            <button type="button" className="connector-btn-primary" onClick={saveAllConnectors}>
              Save All
            </button>
            <button type="button" className="connector-btn-secondary" onClick={resetConnectorsToDefaults}>
              Reset to Defaults
            </button>
          </div>
        </div>

        {connectorMsg && (
          <div className={`connector-msg connector-msg-${connectorMsg.type}`}>
            {connectorMsg.message}
          </div>
        )}

        {FEED_GROUPS.map((group) => (
          <div key={group.title} className="connector-group">
            <h4 className="connector-group-title">{group.title}</h4>
            <div className="connector-feed-grid">
              {group.feedIds.map((feedId) => {
                const feed = FEED_BY_ID[feedId]
                return feed ? renderFeedCard(feed) : null
              })}
            </div>
          </div>
        ))}

        <p className="connector-footer-note">
          Disabled feeds are excluded from IOC tracker results. Key-required feeds need a saved API key before enabling.
        </p>
      </div>

      <div style={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 8, padding: 20, marginBottom: 16 }}>
        <h3 style={{ fontSize: 14, fontWeight: 600, color: '#f0f6fc', marginBottom: 12 }}>IOC Whitelist ({whitelist.length} items)</h3>

        <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
          <input
            type="text"
            value={newWhitelistItem}
            onChange={(e) => setNewWhitelistItem(e.target.value)}
            placeholder="Add indicator to whitelist (IP, domain, hash...)"
            onKeyDown={(e) => e.key === 'Enter' && addToWhitelist()}
            style={{ flex: 1, padding: '8px 12px', background: '#0d1117', border: '1px solid #30363d', borderRadius: 6, color: '#c9d1d9', fontSize: 12, outline: 'none' }}
          />
          <button onClick={addToWhitelist} style={{ padding: '8px 16px', background: '#21262d', border: '1px solid #30363d', borderRadius: 6, color: '#c9d1d9', fontSize: 12, cursor: 'pointer' }}>Add</button>
        </div>

        {whitelist.length > 0 ? (
          <>
            <div style={{ maxHeight: 200, overflow: 'auto', marginBottom: 12 }}>
              {whitelist.map((item, idx) => (
                <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 12px', background: '#0d1117', borderRadius: 4, marginBottom: 4, border: '1px solid #21262d' }}>
                  <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#c9d1d9', wordBreak: 'break-all' }}>{item}</span>
                  <button onClick={() => removeFromWhitelist(item)} style={{ padding: '2px 8px', background: '#f85149', border: 'none', borderRadius: 4, color: '#0d1117', fontSize: 10, cursor: 'pointer' }}>✕</button>
                </div>
              ))}
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button onClick={clearWhitelist} style={{ padding: '6px 12px', background: '#f85149', border: 'none', borderRadius: 6, color: '#0d1117', fontSize: 11, cursor: 'pointer' }}>Clear All</button>
              <button onClick={exportWhitelist} style={{ padding: '6px 12px', background: '#21262d', border: '1px solid #30363d', borderRadius: 6, color: '#c9d1d9', fontSize: 11, cursor: 'pointer' }}>Export CSV</button>
            </div>
          </>
        ) : (
          <p style={{ fontSize: 12, color: '#8b949e', fontStyle: 'italic' }}>No whitelisted indicators</p>
        )}
      </div>

      <div style={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 8, padding: 20, marginBottom: 16 }}>
        <h3 style={{ fontSize: 14, fontWeight: 600, color: '#f0f6fc', marginBottom: 12 }}>Hunt Preferences</h3>

        <div style={{ marginBottom: 16 }}>
          <label style={{ display: 'block', fontSize: 12, color: '#8b949e', marginBottom: 6 }}>Default Lookback</label>
          <select
            value={defaultLookback}
            onChange={(e) => {
              setDefaultLookback(e.target.value)
              saveLookback(e.target.value)
            }}
            style={{ width: '100%', padding: '8px 12px', background: '#0d1117', border: '1px solid #30363d', borderRadius: 6, color: '#c9d1d9', fontSize: 12, outline: 'none' }}
          >
            {lookbackOptions.map((opt) => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
          {lookbackSaved && (
            <span style={{ fontSize: 11, color: '#3fb950', marginTop: 6, display: 'block' }}>Saved ✓</span>
          )}
          <p style={{ fontSize: 11, color: '#8b949e', marginTop: 6, marginBottom: 0 }}>
            This sets the default time range in KQL Library
          </p>
        </div>

        <div style={{ marginBottom: 16 }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => { setAutoRefresh(e.target.checked); saveAutoRefresh() }}
              style={{ width: 16, height: 16, cursor: 'pointer' }}
            />
            <span style={{ fontSize: 12, color: '#c9d1d9' }}>Auto-refresh IOC data</span>
          </label>
        </div>

        {autoRefresh && (
          <div>
            <label style={{ display: 'block', fontSize: 12, color: '#8b949e', marginBottom: 6 }}>Refresh Interval</label>
            <select
              value={refreshInterval}
              onChange={(e) => { setRefreshInterval(parseInt(e.target.value)); saveRefreshInterval() }}
              style={{ width: '100%', padding: '8px 12px', background: '#0d1117', border: '1px solid #30363d', borderRadius: 6, color: '#c9d1d9', fontSize: 12, outline: 'none' }}
            >
              {refreshOptions.map((opt) => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
          </div>
        )}
      </div>

      <div style={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 8, padding: 20 }}>
        <h3 style={{ fontSize: 14, fontWeight: 600, color: '#f0f6fc', marginBottom: 12 }}>About</h3>
        <div style={{ fontSize: 12, color: '#8b949e', lineHeight: 1.6 }}>
          <p style={{ margin: 0, marginBottom: 8 }}>
            <strong style={{ color: '#c9d1d9' }}>Threat Hunting Automation Dashboard</strong>
          </p>
          <p style={{ margin: 0, marginBottom: 8 }}>
            A Microsoft Sentinel threat hunting dashboard with MITRE ATT&CK integration, IOC tracking, and AI-powered hypothesis generation.
          </p>
          <p style={{ margin: 0, marginBottom: 8 }}>
            <strong style={{ color: '#c9d1d9' }}>Features:</strong>
          </p>
          <ul style={{ margin: 0, marginBottom: 8, paddingLeft: 20 }}>
            <li>MITRE ATT&CK technique coverage heatmap</li>
            <li>KQL query library with time range selection</li>
            <li>Live IOC tracking from {FEED_COUNT} threat intel feeds</li>
            <li>AI-powered hypothesis generation (Groq API)</li>
            <li>Hunt workflow management</li>
          </ul>
          <p style={{ margin: 0 }}>
            <strong style={{ color: '#c9d1d9' }}>Version:</strong> 1.0.0
          </p>
        </div>
      </div>
    </div>
  )
}
