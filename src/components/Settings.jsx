import { useState, useEffect } from 'react'
import { FEED_LABELS, FEED_COUNT } from '../services/threatIntel'

export default function Settings({ theme = 'dark', setTheme }) {
  const [groqApiKey, setGroqApiKey] = useState(localStorage.getItem('groqApiKey') || '')
  const [analystName, setAnalystName] = useState(localStorage.getItem('analystName') || '')
  const [groqModel, setGroqModel] = useState(localStorage.getItem('groqModel') || 'llama-3.3-70b-versatile')
  const [feedConfig, setFeedConfig] = useState(JSON.parse(localStorage.getItem('feedConfig') || '{}'))
  const [defaultLookback, setDefaultLookback] = useState(localStorage.getItem('defaultLookback') || '1d')
  const [autoRefresh, setAutoRefresh] = useState(localStorage.getItem('autoRefresh') === 'true')
  const [refreshInterval, setRefreshInterval] = useState(parseInt(localStorage.getItem('refreshInterval') || '300000'))
  const [whitelist, setWhitelist] = useState(JSON.parse(localStorage.getItem('iocWhitelist') || '[]'))
  const [newWhitelistItem, setNewWhitelistItem] = useState('')
  const [apiTestResult, setApiTestResult] = useState(null)
  const [testingApi, setTestingApi] = useState(false)

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
          'Authorization': `Bearer ${groqApiKey}`,
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
    } catch (err) {
      setApiTestResult({ type: 'error', message: 'Connection failed' })
    } finally {
      setTestingApi(false)
    }
  }

  function toggleFeed(feedKey) {
    const newConfig = { ...feedConfig, [feedKey]: feedConfig[feedKey] === undefined ? true : !feedConfig[feedKey] }
    setFeedConfig(newConfig)
    localStorage.setItem('feedConfig', JSON.stringify(newConfig))
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
    const list = whitelist.filter(i => i !== item)
    setWhitelist(list)
    localStorage.setItem('iocWhitelist', JSON.stringify(list))
  }

  function clearWhitelist() {
    setWhitelist([])
    localStorage.setItem('iocWhitelist', '[]')
  }

  function exportWhitelist() {
    const csv = whitelist.map(i => `"${i}"`).join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = 'ioc-whitelist.csv'
    a.click()
  }

  function saveAnalystName() {
    localStorage.setItem('analystName', analystName)
  }

  function saveLookback() {
    localStorage.setItem('defaultLookback', defaultLookback)
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

  return (
    <div>
      <h2 style={{fontSize:20,fontWeight:600,color:'var(--text-primary)',marginBottom:20}}>Settings</h2>

      <div style={{background:'var(--card-bg)',border:'1px solid var(--border-primary)',borderRadius:8,padding:20,marginBottom:16}}>
        <h3 style={{fontSize:14,fontWeight:600,color:'var(--text-primary)',marginBottom:12}}>Appearance</h3>
        <label style={{display:'block',fontSize:12,color:'var(--text-tertiary)',marginBottom:6}}>Theme</label>
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

      {/* API Configuration */}
      <div style={{background:'#161b22',border:'1px solid #30363d',borderRadius:8,padding:20,marginBottom:16}}>
        <h3 style={{fontSize:14,fontWeight:600,color:'#f0f6fc',marginBottom:12}}>API Configuration</h3>
        
        <div style={{marginBottom:16}}>
          <label style={{display:'block',fontSize:12,color:'#8b949e',marginBottom:6}}>Groq API Key</label>
          <div style={{display:'flex',gap:8}}>
            <input
              type="password"
              value={groqApiKey}
              onChange={e => setGroqApiKey(e.target.value)}
              placeholder="gsk_..."
              style={{flex:1,padding:'8px 12px',background:'#0d1117',border:'1px solid #30363d',borderRadius:6,color:'#c9d1d9',fontSize:12,outline:'none'}}
            />
            <button onClick={saveGroqApiKey} style={{padding:'8px 16px',background:'#21262d',border:'1px solid #30363d',borderRadius:6,color:'#c9d1d9',fontSize:12,cursor:'pointer'}}>Save</button>
            <button onClick={testGroqApiKey} disabled={testingApi || !groqApiKey} style={{padding:'8px 16px',background:'#0d2045',border:'1px solid #58a6ff44',borderRadius:6,color:'#58a6ff',fontSize:12,cursor:testingApi || !groqApiKey ? 'default' : 'pointer',opacity:testingApi || !groqApiKey ? 0.5 : 1}}>
              {testingApi ? 'Testing...' : 'Test'}
            </button>
          </div>
          {apiTestResult && (
            <div style={{marginTop:8,fontSize:11,padding:'6px 10px',borderRadius:4,background:apiTestResult.type === 'success' ? '#0d2d1a' : '#3d1a1a',color:apiTestResult.type === 'success' ? '#3fb950' : '#f85149'}}>
              {apiTestResult.message}
            </div>
          )}
        </div>

        <div style={{marginBottom:16}}>
          <label style={{display:'block',fontSize:12,color:'#8b949e',marginBottom:6}}>Analyst Name</label>
          <div style={{display:'flex',gap:8}}>
            <input
              type="text"
              value={analystName}
              onChange={e => setAnalystName(e.target.value)}
              placeholder="Your name"
              onBlur={saveAnalystName}
              style={{flex:1,padding:'8px 12px',background:'#0d1117',border:'1px solid #30363d',borderRadius:6,color:'#c9d1d9',fontSize:12,outline:'none'}}
            />
          </div>
        </div>

        <div>
          <label style={{display:'block',fontSize:12,color:'#8b949e',marginBottom:6}}>AI Model</label>
          <select
            value={groqModel}
            onChange={e => { setGroqModel(e.target.value); saveModel() }}
            style={{width:'100%',padding:'8px 12px',background:'#0d1117',border:'1px solid #30363d',borderRadius:6,color:'#c9d1d9',fontSize:12,outline:'none'}}
          >
            {modelOptions.map(opt => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Threat Intel Feeds */}
      <div style={{background:'#161b22',border:'1px solid #30363d',borderRadius:8,padding:20,marginBottom:16}}>
        <h3 style={{fontSize:14,fontWeight:600,color:'#f0f6fc',marginBottom:12}}>Threat Intel Feeds ({FEED_COUNT} total)</h3>
        <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(280px,1fr))',gap:12}}>
          {Object.entries(FEED_LABELS).map(([key, label]) => (
            <div key={key} style={{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'10px 12px',background:'#0d1117',borderRadius:6,border:'1px solid #30363d'}}>
              <span style={{fontSize:12,color:'#c9d1d9'}}>{label}</span>
              <button
                onClick={() => toggleFeed(key)}
                style={{padding:'4px 12px',background:feedConfig[key] === false ? '#21262d' : '#0d2d1a',border:feedConfig[key] === false ? '1px solid #30363d' : '1px solid #3fb95040',borderRadius:4,color:feedConfig[key] === false ? '#8b949e' : '#3fb950',fontSize:11,cursor:'pointer'}}
              >
                {feedConfig[key] === false ? 'Disabled' : 'Enabled'}
              </button>
            </div>
          ))}
        </div>
        <div style={{marginTop:12,fontSize:11,color:'#8b949e'}}>
          Disabled feeds will not be included in IOC tracker results
        </div>
      </div>

      {/* IOC Whitelist */}
      <div style={{background:'#161b22',border:'1px solid #30363d',borderRadius:8,padding:20,marginBottom:16}}>
        <h3 style={{fontSize:14,fontWeight:600,color:'#f0f6fc',marginBottom:12}}>IOC Whitelist ({whitelist.length} items)</h3>
        
        <div style={{display:'flex',gap:8,marginBottom:12}}>
          <input
            type="text"
            value={newWhitelistItem}
            onChange={e => setNewWhitelistItem(e.target.value)}
            placeholder="Add indicator to whitelist (IP, domain, hash...)"
            onKeyDown={e => e.key === 'Enter' && addToWhitelist()}
            style={{flex:1,padding:'8px 12px',background:'#0d1117',border:'1px solid #30363d',borderRadius:6,color:'#c9d1d9',fontSize:12,outline:'none'}}
          />
          <button onClick={addToWhitelist} style={{padding:'8px 16px',background:'#21262d',border:'1px solid #30363d',borderRadius:6,color:'#c9d1d9',fontSize:12,cursor:'pointer'}}>Add</button>
        </div>

        {whitelist.length > 0 ? (
          <>
            <div style={{maxHeight:200,overflow:'auto',marginBottom:12}}>
              {whitelist.map((item, idx) => (
                <div key={idx} style={{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'8px 12px',background:'#0d1117',borderRadius:4,marginBottom:4,border:'1px solid #21262d'}}>
                  <span style={{fontFamily:'monospace',fontSize:11,color:'#c9d1d9',wordBreak:'break-all'}}>{item}</span>
                  <button onClick={() => removeFromWhitelist(item)} style={{padding:'2px 8px',background:'#f85149',border:'none',borderRadius:4,color:'#0d1117',fontSize:10,cursor:'pointer'}}>✕</button>
                </div>
              ))}
            </div>
            <div style={{display:'flex',gap:8}}>
              <button onClick={clearWhitelist} style={{padding:'6px 12px',background:'#f85149',border:'none',borderRadius:6,color:'#0d1117',fontSize:11,cursor:'pointer'}}>Clear All</button>
              <button onClick={exportWhitelist} style={{padding:'6px 12px',background:'#21262d',border:'1px solid #30363d',borderRadius:6,color:'#c9d1d9',fontSize:11,cursor:'pointer'}}>Export CSV</button>
            </div>
          </>
        ) : (
          <p style={{fontSize:12,color:'#8b949e',fontStyle:'italic'}}>No whitelisted indicators</p>
        )}
      </div>

      {/* Hunt Preferences */}
      <div style={{background:'#161b22',border:'1px solid #30363d',borderRadius:8,padding:20,marginBottom:16}}>
        <h3 style={{fontSize:14,fontWeight:600,color:'#f0f6fc',marginBottom:12}}>Hunt Preferences</h3>
        
        <div style={{marginBottom:16}}>
          <label style={{display:'block',fontSize:12,color:'#8b949e',marginBottom:6}}>Default Time Range</label>
          <select
            value={defaultLookback}
            onChange={e => { setDefaultLookback(e.target.value); saveLookback() }}
            style={{width:'100%',padding:'8px 12px',background:'#0d1117',border:'1px solid #30363d',borderRadius:6,color:'#c9d1d9',fontSize:12,outline:'none'}}
          >
            {lookbackOptions.map(opt => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
        </div>

        <div style={{marginBottom:16}}>
          <label style={{display:'flex',alignItems:'center',gap:8,cursor:'pointer'}}>
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={e => { setAutoRefresh(e.target.checked); saveAutoRefresh() }}
              style={{width:16,height:16,cursor:'pointer'}}
            />
            <span style={{fontSize:12,color:'#c9d1d9'}}>Auto-refresh IOC data</span>
          </label>
        </div>

        {autoRefresh && (
          <div>
            <label style={{display:'block',fontSize:12,color:'#8b949e',marginBottom:6}}>Refresh Interval</label>
            <select
              value={refreshInterval}
              onChange={e => { setRefreshInterval(parseInt(e.target.value)); saveRefreshInterval() }}
              style={{width:'100%',padding:'8px 12px',background:'#0d1117',border:'1px solid #30363d',borderRadius:6,color:'#c9d1d9',fontSize:12,outline:'none'}}
            >
              {refreshOptions.map(opt => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* About */}
      <div style={{background:'#161b22',border:'1px solid #30363d',borderRadius:8,padding:20}}>
        <h3 style={{fontSize:14,fontWeight:600,color:'#f0f6fc',marginBottom:12}}>About</h3>
        <div style={{fontSize:12,color:'#8b949e',lineHeight:1.6}}>
          <p style={{margin:0,marginBottom:8}}>
            <strong style={{color:'#c9d1d9'}}>Threat Hunting Automation Dashboard</strong>
          </p>
          <p style={{margin:0,marginBottom:8}}>
            A Microsoft Sentinel threat hunting dashboard with MITRE ATT&CK integration, IOC tracking, and AI-powered hypothesis generation.
          </p>
          <p style={{margin:0,marginBottom:8}}>
            <strong style={{color:'#c9d1d9'}}>Features:</strong>
          </p>
          <ul style={{margin:0,marginBottom:8,paddingLeft:20}}>
            <li>MITRE ATT&CK technique coverage heatmap</li>
            <li>KQL query library with time range selection</li>
            <li>Live IOC tracking from {FEED_COUNT} threat intel feeds</li>
            <li>AI-powered hypothesis generation (Groq API)</li>
            <li>Hunt workflow management</li>
          </ul>
          <p style={{margin:0}}>
            <strong style={{color:'#c9d1d9'}}>Version:</strong> 1.0.0
          </p>
        </div>
      </div>
    </div>
  )
}
