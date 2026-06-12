import { useState, useEffect, useMemo } from 'react'

const API_BASE = window.location.hostname === 'localhost'
  ? 'http://localhost:3000'
  : 'https://threat-hunt-dashboard.vercel.app'

const CACHE_TTL = 6 * 60 * 60 * 1000

const THREAT_CATEGORIES = [
  'Ransomware',
  'Nation-State APT',
  'Initial Access Broker',
  'Banking Trojan',
  'Infostealer',
  'Botnet',
  'Phishing/BEC',
  'Supply Chain',
  'LOLBin Campaign',
  'Cloud/SaaS Threat',
]

const CATEGORY_SLUG = {
  Ransomware: 'ransomware',
  'Nation-State APT': 'nation-state-apt',
  'Initial Access Broker': 'initial-access-broker',
  'Banking Trojan': 'banking-trojan',
  Infostealer: 'infostealer',
  Botnet: 'botnet',
  'Phishing/BEC': 'phishing-bec',
  'Supply Chain': 'supply-chain',
  'LOLBin Campaign': 'lolbin-campaign',
  'Cloud/SaaS Threat': 'cloud-saas-threat',
}

const EXPLOIT_FILTERS = ['Actively Exploited', 'PoC Available', 'Patch Available']

const CAMPAIGN_CATEGORIES = [
  'Data Breach',
  'Ransomware Attack',
  'Supply Chain',
  'Phishing Campaign',
  'Critical Infrastructure',
  'Espionage',
]

const CAMPAIGN_CATEGORY_SLUG = {
  'Data Breach': 'data-breach',
  'Ransomware Attack': 'ransomware-attack',
  'Supply Chain': 'supply-chain',
  'Phishing Campaign': 'phishing-campaign',
  'Critical Infrastructure': 'critical-infra',
  Espionage: 'espionage',
}

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2 }
const EXPLOIT_ORDER = { 'Actively Exploited': 0, 'PoC Available': 1, 'Patch Available': 2 }

const QUICK_CHIPS = [
  'Ransomware pre-staging activity',
  'Credential dumping and lateral movement',
  'Phishing to execution kill chain',
  'DNS tunneling C2',
  'Insider threat data exfiltration',
  'Supply chain compromise',
]

const ORIGIN_FLAGS = {
  Russia: '🇷🇺',
  China: '🇨🇳',
  'North Korea': '🇰🇵',
  Iran: '🇮🇷',
  Vietnam: '🇻🇳',
  Israel: '🇮🇱',
  USA: '🇺🇸',
  'United States': '🇺🇸',
  Ukraine: '🇺🇦',
  Pakistan: '🇵🇰',
  India: '🇮🇳',
}

function severityColor(severity) {
  if (severity === 'critical') return 'var(--red)'
  if (severity === 'high') return 'var(--amber)'
  return 'var(--accent)'
}

function formatOrigin(origin) {
  if (!origin || origin === 'Unknown') return '🌍 Unknown'
  const flag = ORIGIN_FLAGS[origin] || '🌍'
  return `${flag} ${origin}`
}

function formatCacheAge(ts) {
  if (!ts) return 'Not yet fetched'
  const hours = Math.floor((Date.now() - ts) / 3600000)
  if (hours < 1) return 'Updated less than an hour ago'
  if (hours === 1) return 'Updated 1 hour ago'
  return `Updated ${hours} hours ago`
}

function formatGeneratedTime(iso) {
  if (!iso) return ''
  try {
    return new Date(iso).toLocaleString()
  } catch {
    return iso
  }
}

function loadCache(key, setter, timeSetter) {
  try {
    const raw = localStorage.getItem(key)
    if (!raw) return
    const { data, time } = JSON.parse(raw)
    if (Date.now() - time < CACHE_TTL) {
      setter(data)
      timeSetter(time)
    }
  } catch {
    /* ignore */
  }
}

function filterByCategory(actors, categoryFilter) {
  if (!categoryFilter || categoryFilter === 'All') return actors
  return actors.filter((a) => a.category === categoryFilter)
}

function categoriesInData(actors, categoryList) {
  const present = new Set((actors || []).map((a) => a.category).filter(Boolean))
  return categoryList.filter((c) => present.has(c))
}

function sortVulnerabilities(vulns) {
  return [...vulns].sort((a, b) => {
    const sev =
      (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)
    if (sev !== 0) return sev
    return (
      (EXPLOIT_ORDER[a.exploitStatus] ?? 9) - (EXPLOIT_ORDER[b.exploitStatus] ?? 9)
    )
  })
}

function filterByExploitStatus(vulns, filter) {
  if (!filter || filter === 'All') return vulns
  return vulns.filter((v) => v.exploitStatus === filter)
}

function cvssBarClass(score) {
  const n = Number(score)
  if (n >= 9) return 'lti-cvss-red'
  if (n >= 7) return 'lti-cvss-amber'
  if (n >= 4) return 'lti-cvss-yellow'
  return 'lti-cvss-gray'
}

function isCveLinkedHypothesis(hyp) {
  return hyp.tags?.includes('cve') || hyp.threatActor?.startsWith('CVE-')
}

function CategoryBadge({ category }) {
  if (!category) return null
  const slug = CATEGORY_SLUG[category] || 'default'
  return <span className={`lti-category-badge lti-cat-${slug}`}>{category}</span>
}

function LogSourceBadges({ sources }) {
  if (!sources?.length) return null
  return (
    <div className="lti-log-sources">
      <span className="lti-log-sources-label">Hunt in:</span>
      {sources.map((s) => (
        <span key={s} className="lti-log-source-badge">
          {s}
        </span>
      ))}
    </div>
  )
}

function CategoryFilterRow({ actors, activeFilter, onFilterChange, categoryList = THREAT_CATEGORIES }) {
  const available = categoriesInData(actors, categoryList)
  if (available.length === 0) return null
  const slugMap = categoryList === CAMPAIGN_CATEGORIES ? CAMPAIGN_CATEGORY_SLUG : CATEGORY_SLUG
  return (
    <div className="lti-category-filters">
      <button
        type="button"
        className={`lti-cat-filter-pill ${activeFilter === 'All' ? 'active' : ''}`}
        onClick={() => onFilterChange('All')}
      >
        All
      </button>
      {available.map((cat) => (
        <button
          key={cat}
          type="button"
          className={`lti-cat-filter-pill lti-cat-filter-${slugMap[cat] || 'default'} ${activeFilter === cat ? 'active' : ''}`}
          onClick={() => onFilterChange(cat)}
        >
          {cat}
        </button>
      ))}
    </div>
  )
}

function ExploitFilterRow({ activeFilter, onFilterChange }) {
  return (
    <div className="lti-category-filters">
      <button
        type="button"
        className={`lti-cat-filter-pill ${activeFilter === 'All' ? 'active' : ''}`}
        onClick={() => onFilterChange('All')}
      >
        All
      </button>
      {EXPLOIT_FILTERS.map((status) => (
        <button
          key={status}
          type="button"
          className={`lti-cat-filter-pill ${activeFilter === status ? 'active' : ''}`}
          onClick={() => onFilterChange(status)}
        >
          {status}
        </button>
      ))}
    </div>
  )
}

function CampaignCategoryBadge({ category }) {
  if (!category) return null
  const slug = CAMPAIGN_CATEGORY_SLUG[category] || 'default'
  return <span className={`lti-campaign-cat-badge lti-camp-cat-${slug}`}>{category}</span>
}

function ExploitStatusBadge({ status }) {
  if (!status) return null
  const cls =
    status === 'Actively Exploited'
      ? 'lti-exploit-active'
      : status === 'PoC Available'
        ? 'lti-exploit-poc'
        : 'lti-exploit-patch'
  const icon = status === 'Actively Exploited' ? '🔴' : status === 'PoC Available' ? '🟡' : '🟢'
  return (
    <span className={`lti-exploit-badge ${cls}`}>
      {icon} {status}
    </span>
  )
}

function CvssGauge({ score }) {
  const n = Math.min(10, Math.max(0, Number(score) || 0))
  const pct = (n / 10) * 100
  return (
    <div className="lti-cvss-gauge">
      <div className="lti-cvss-bar-track">
        <div
          className={`lti-cvss-bar-fill ${cvssBarClass(n)}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className={`lti-cvss-score ${cvssBarClass(n)}`}>{n.toFixed(1)}</span>
    </div>
  )
}

function GenerateHypothesisButton({ itemKey, generatingFor, onGenerate, data, label = 'Generate Hunt Hypothesis' }) {
  return (
    <button
      type="button"
      className="hyp-generate-btn"
      disabled={generatingFor === itemKey}
      onClick={() => onGenerate(data)}
    >
      {generatingFor === itemKey ? (
        <span className="spinner-wrap">
          <span className="spinner" aria-hidden="true" />
          Generating...
        </span>
      ) : (
        label
      )}
    </button>
  )
}

function SkeletonCards({ count = 4 }) {
  return (
    <div className="actor-grid">
      {Array.from({ length: count }, (_, i) => (
        <div key={i} className="lti-skeleton-card" aria-hidden="true" />
      ))}
    </div>
  )
}

export default function LiveThreatIntel({ onGoToSettings }) {
  const groqKey = localStorage.getItem('groqApiKey') || ''

  const [activeView, setActiveView] = useState('trends')
  const [trendingActors, setTrendingActors] = useState([])
  const [historicalActors, setHistoricalActors] = useState([])
  const [loadingTrends, setLoadingTrends] = useState(false)
  const [loadingHistorical, setLoadingHistorical] = useState(false)
  const [error, setError] = useState(null)
  const [generatedHypotheses, setGeneratedHypotheses] = useState([])
  const [generatingFor, setGeneratingFor] = useState(null)
  const [customInput, setCustomInput] = useState('')
  const [customPriority, setCustomPriority] = useState('high')
  const [generatingCustom, setGeneratingCustom] = useState(false)
  const [expandedHyp, setExpandedHyp] = useState(null)
  const [trendsCacheTime, setTrendsCacheTime] = useState(null)
  const [historicalCacheTime, setHistoricalCacheTime] = useState(null)
  const [trendsCategoryFilter, setTrendsCategoryFilter] = useState('All')
  const [historicalCategoryFilter, setHistoricalCategoryFilter] = useState('All')
  const [vulnerabilities, setVulnerabilities] = useState([])
  const [attackCampaigns, setAttackCampaigns] = useState([])
  const [loadingVulns, setLoadingVulns] = useState(false)
  const [loadingCampaigns, setLoadingCampaigns] = useState(false)
  const [vulnsCacheTime, setVulnsCacheTime] = useState(null)
  const [campaignsCacheTime, setCampaignsCacheTime] = useState(null)
  const [vulnsExploitFilter, setVulnsExploitFilter] = useState('All')
  const [campaignsCategoryFilter, setCampaignsCategoryFilter] = useState('All')

  const filteredTrendingActors = useMemo(
    () => filterByCategory(trendingActors, trendsCategoryFilter),
    [trendingActors, trendsCategoryFilter]
  )

  const filteredHistoricalActors = useMemo(
    () => filterByCategory(historicalActors, historicalCategoryFilter),
    [historicalActors, historicalCategoryFilter]
  )

  const sortedFilteredVulns = useMemo(() => {
    const filtered = filterByExploitStatus(vulnerabilities, vulnsExploitFilter)
    return sortVulnerabilities(filtered)
  }, [vulnerabilities, vulnsExploitFilter])

  const filteredCampaigns = useMemo(
    () => filterByCategory(attackCampaigns, campaignsCategoryFilter),
    [attackCampaigns, campaignsCategoryFilter]
  )

  useEffect(() => {
    try {
      const saved = localStorage.getItem('liveHypotheses')
      if (saved) setGeneratedHypotheses(JSON.parse(saved))
    } catch {
      /* ignore */
    }
    loadCache('trendingActorsCache', setTrendingActors, setTrendsCacheTime)
    loadCache('historicalActorsCache', setHistoricalActors, setHistoricalCacheTime)
    loadCache('vulnsCache', setVulnerabilities, setVulnsCacheTime)
    loadCache('campaignsCache', setAttackCampaigns, setCampaignsCacheTime)
  }, [])

  async function fetchTrends() {
    setLoadingTrends(true)
    setError(null)
    try {
      const r = await fetch(`${API_BASE}/api/threatactors`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ groqApiKey: groqKey, mode: 'trends' }),
      })
      const data = await r.json()
      if (!data.success) throw new Error(data.error)
      setTrendingActors(data.data)
      setTrendsCategoryFilter('All')
      const now = Date.now()
      setTrendsCacheTime(now)
      localStorage.setItem('trendingActorsCache', JSON.stringify({ data: data.data, time: now }))
    } catch (e) {
      setError(e.message)
    } finally {
      setLoadingTrends(false)
    }
  }

  async function fetchHistorical() {
    setLoadingHistorical(true)
    setError(null)
    try {
      const r = await fetch(`${API_BASE}/api/threatactors`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ groqApiKey: groqKey, mode: 'historical' }),
      })
      const data = await r.json()
      if (!data.success) throw new Error(data.error)
      setHistoricalActors(data.data)
      setHistoricalCategoryFilter('All')
      const now = Date.now()
      setHistoricalCacheTime(now)
      localStorage.setItem('historicalActorsCache', JSON.stringify({ data: data.data, time: now }))
    } catch (e) {
      setError(e.message)
    } finally {
      setLoadingHistorical(false)
    }
  }

  async function fetchVulnerabilities() {
    setLoadingVulns(true)
    setError(null)
    try {
      const r = await fetch(`${API_BASE}/api/threatactors`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ groqApiKey: groqKey, mode: 'vulnerabilities' }),
      })
      const data = await r.json()
      if (!data.success) throw new Error(data.error)
      setVulnerabilities(data.data)
      setVulnsExploitFilter('All')
      const now = Date.now()
      setVulnsCacheTime(now)
      localStorage.setItem('vulnsCache', JSON.stringify({ data: data.data, time: now }))
    } catch (e) {
      setError(e.message)
    } finally {
      setLoadingVulns(false)
    }
  }

  async function fetchAttackCampaigns() {
    setLoadingCampaigns(true)
    setError(null)
    try {
      const r = await fetch(`${API_BASE}/api/threatactors`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ groqApiKey: groqKey, mode: 'attackcampaigns' }),
      })
      const data = await r.json()
      if (!data.success) throw new Error(data.error)
      setAttackCampaigns(data.data)
      setCampaignsCategoryFilter('All')
      const now = Date.now()
      setCampaignsCacheTime(now)
      localStorage.setItem('campaignsCache', JSON.stringify({ data: data.data, time: now }))
    } catch (e) {
      setError(e.message)
    } finally {
      setLoadingCampaigns(false)
    }
  }

  async function generateHypothesisForActor(actor) {
    setGeneratingFor(actor.name)
    setError(null)
    try {
      const r = await fetch(`${API_BASE}/api/threatactors`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          groqApiKey: groqKey,
          mode: 'hypothesis',
          actorName: actor.name,
          logSourceHint: actor.relevantLogSources,
        }),
      })
      const data = await r.json()
      if (!data.success) throw new Error(data.error)
      const updated = [data.data, ...generatedHypotheses]
      setGeneratedHypotheses(updated)
      localStorage.setItem('liveHypotheses', JSON.stringify(updated))
    } catch (e) {
      setError(e.message)
    } finally {
      setGeneratingFor(null)
    }
  }

  async function generateCveHypothesis(cve) {
    setGeneratingFor(cve.cveId)
    setError(null)
    try {
      const r = await fetch(`${API_BASE}/api/threatactors`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          groqApiKey: groqKey,
          mode: 'cvehypothesis',
          actorName: cve.cveId,
        }),
      })
      const data = await r.json()
      if (!data.success) throw new Error(data.error)
      const updated = [data.data, ...generatedHypotheses]
      setGeneratedHypotheses(updated)
      localStorage.setItem('liveHypotheses', JSON.stringify(updated))
    } catch (e) {
      setError(e.message)
    } finally {
      setGeneratingFor(null)
    }
  }

  async function generateHypothesisForCampaign(campaign) {
    setGeneratingFor(campaign.name)
    setError(null)
    try {
      const r = await fetch(`${API_BASE}/api/threatactors`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          groqApiKey: groqKey,
          mode: 'hypothesis',
          actorName: campaign.name,
          logSourceHint: campaign.relevantLogSources,
        }),
      })
      const data = await r.json()
      if (!data.success) throw new Error(data.error)
      const updated = [data.data, ...generatedHypotheses]
      setGeneratedHypotheses(updated)
      localStorage.setItem('liveHypotheses', JSON.stringify(updated))
    } catch (e) {
      setError(e.message)
    } finally {
      setGeneratingFor(null)
    }
  }

  async function generateCustomHypothesis() {
    if (!customInput.trim()) return
    setGeneratingCustom(true)
    setError(null)
    try {
      const r = await fetch(`${API_BASE}/api/threatactors`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          groqApiKey: groqKey,
          mode: 'custom',
          requirements: `${customInput} (Priority: ${customPriority})`,
        }),
      })
      const data = await r.json()
      if (!data.success) throw new Error(data.error)
      const updated = [data.data, ...generatedHypotheses]
      setGeneratedHypotheses(updated)
      localStorage.setItem('liveHypotheses', JSON.stringify(updated))
      setCustomInput('')
    } catch (e) {
      setError(e.message)
    } finally {
      setGeneratingCustom(false)
    }
  }

  function removeHypothesis(id) {
    const updated = generatedHypotheses.filter((h) => h.id !== id)
    setGeneratedHypotheses(updated)
    localStorage.setItem('liveHypotheses', JSON.stringify(updated))
    if (expandedHyp === id) setExpandedHyp(null)
  }

  function copyText(text) {
    navigator.clipboard.writeText(text).catch(() => {})
  }

  function exportHypothesisKQL(hyp) {
    const content = (hyp.kqlQueries || [])
      .map(
        (q) =>
          `// ${q.title}\n// MITRE: ${q.mitreTechnique} | Log Source: ${q.logSource} | Severity: ${q.severity}\n${q.kql}\n\n`
      )
      .join('---\n\n')
    const blob = new Blob([content], { type: 'text/plain' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `${hyp.threatActor || 'custom'}-hunt-queries.txt`
    a.click()
  }

  if (!groqKey) {
    return (
      <div className="lti-page">
        <div className="lti-no-key">
          <p>
            🔑 Add your free Groq API key in the Settings tab to enable AI-powered threat
            intelligence. Get one free at{' '}
            <a href="https://console.groq.com" target="_blank" rel="noreferrer">
              console.groq.com
            </a>
          </p>
          {onGoToSettings && (
            <button type="button" className="hyp-fetch-btn" onClick={onGoToSettings}>
              Go to Settings
            </button>
          )}
        </div>
      </div>
    )
  }

  return (
    <div className="lti-page">
      {error && (
        <div className="lti-error-banner">
          <span>{error}</span>
          <button type="button" onClick={() => setError(null)}>
            Dismiss
          </button>
        </div>
      )}

      <div className="hyp-tab-pills lti-view-pills">
        <button
          type="button"
          className={`hyp-tab-pill ${activeView === 'trends' ? 'active' : ''}`}
          onClick={() => setActiveView('trends')}
        >
          📈 Current Trends
        </button>
        <button
          type="button"
          className={`hyp-tab-pill ${activeView === 'historical' ? 'active' : ''}`}
          onClick={() => setActiveView('historical')}
        >
          📚 Historical Database
        </button>
        <button
          type="button"
          className={`hyp-tab-pill ${activeView === 'vulnerabilities' ? 'active' : ''}`}
          onClick={() => setActiveView('vulnerabilities')}
        >
          🔓 Vulnerabilities
        </button>
        <button
          type="button"
          className={`hyp-tab-pill ${activeView === 'campaigns' ? 'active' : ''}`}
          onClick={() => setActiveView('campaigns')}
        >
          ⚡ Attack Campaigns
        </button>
        <button
          type="button"
          className={`hyp-tab-pill ${activeView === 'custom' ? 'active' : ''}`}
          onClick={() => setActiveView('custom')}
        >
          ✨ Custom Generator
        </button>
      </div>

      {activeView === 'trends' && (
        <section className="hyp-landscape-card">
          <div className="lti-section-header">
            <h3>Current Threat Landscape</h3>
            <div className="lti-header-actions">
              <span className="lti-cache-age">{formatCacheAge(trendsCacheTime)}</span>
              <button
                type="button"
                className="hyp-fetch-btn"
                onClick={fetchTrends}
                disabled={loadingTrends}
              >
                Fetch Latest
              </button>
            </div>
          </div>

          {loadingTrends && (
            <>
              <div className="hyp-loading-row">
                <span className="spinner" aria-hidden="true" />
                Analyzing current threat landscape via AI...
              </div>
              <SkeletonCards count={10} />
            </>
          )}

          {!loadingTrends && trendingActors.length > 0 && (
            <>
              <CategoryFilterRow
                actors={trendingActors}
                activeFilter={trendsCategoryFilter}
                onFilterChange={setTrendsCategoryFilter}
              />
              <div className="actor-grid">
                {filteredTrendingActors.map((actor) => (
                  <article
                    key={actor.name}
                    className="actor-card"
                    style={{ borderTopColor: severityColor(actor.severity) }}
                  >
                    <div className="actor-card-header">
                      <h4 style={{ color: severityColor(actor.severity) }}>{actor.name}</h4>
                      <CategoryBadge category={actor.category} />
                      <span className="actor-type-badge">{actor.type}</span>
                      <span className={`priority-pill priority-${actor.severity}`}>
                        {actor.severity}
                      </span>
                    </div>
                    {actor.firstSeen && (
                      <div className="lti-meta">Active since: {actor.firstSeen}</div>
                    )}
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
                    <LogSourceBadges sources={actor.relevantLogSources} />
                    <GenerateHypothesisButton
                      itemKey={actor.name}
                      generatingFor={generatingFor}
                      onGenerate={generateHypothesisForActor}
                      data={actor}
                    />
                  </article>
                ))}
              </div>
              {filteredTrendingActors.length === 0 && (
                <p className="lti-empty-filter">No threats match this category filter.</p>
              )}
            </>
          )}
        </section>
      )}

      {activeView === 'historical' && (
        <section className="hyp-landscape-card">
          <div className="lti-section-header">
            <h3>Threat Actor Reference Database</h3>
            <div className="lti-header-actions">
              <span className="lti-cache-age">{formatCacheAge(historicalCacheTime)}</span>
              <button
                type="button"
                className="hyp-fetch-btn"
                onClick={fetchHistorical}
                disabled={loadingHistorical}
              >
                Load Database
              </button>
            </div>
          </div>

          {loadingHistorical && (
            <>
              <div className="hyp-loading-row">
                <span className="spinner" aria-hidden="true" />
                Loading historical threat actor database...
              </div>
              <SkeletonCards count={12} />
            </>
          )}

          {!loadingHistorical && historicalActors.length > 0 && (
            <>
              <CategoryFilterRow
                actors={historicalActors}
                activeFilter={historicalCategoryFilter}
                onFilterChange={setHistoricalCategoryFilter}
              />
              <div className="actor-grid">
                {filteredHistoricalActors.map((actor) => (
                  <article key={actor.name} className="actor-card lti-historical-card">
                    <div className="actor-card-header">
                      <h4>{actor.name}</h4>
                      <CategoryBadge category={actor.category} />
                      <span className="actor-type-badge">{actor.type}</span>
                    </div>
                    <div className="lti-meta">{formatOrigin(actor.origin)}</div>
                    {actor.activeYears && (
                      <div className="lti-meta">Active: {actor.activeYears}</div>
                    )}
                    {(actor.notableCampaigns || []).length > 0 && (
                      <ul className="lti-campaign-list">
                        {actor.notableCampaigns.map((c) => (
                          <li key={c}>{c}</li>
                        ))}
                      </ul>
                    )}
                    <div className="actor-sectors">
                      {(actor.targetedSectors || []).map((s) => (
                        <span key={s} className="sector-pill">
                          {s}
                        </span>
                      ))}
                    </div>
                    <div className="actor-ttps">
                      {(actor.mitreTechniques || []).map((t) => (
                        <span key={t} className="ttp-badge">
                          {t}
                        </span>
                      ))}
                    </div>
                    <LogSourceBadges sources={actor.relevantLogSources} />
                    {actor.description && <p className="actor-activity">{actor.description}</p>}
                    <GenerateHypothesisButton
                      itemKey={actor.name}
                      generatingFor={generatingFor}
                      onGenerate={generateHypothesisForActor}
                      data={actor}
                    />
                  </article>
                ))}
              </div>
              {filteredHistoricalActors.length === 0 && (
                <p className="lti-empty-filter">No threats match this category filter.</p>
              )}
            </>
          )}
        </section>
      )}

      {activeView === 'vulnerabilities' && (
        <section className="hyp-landscape-card">
          <div className="lti-section-header">
            <h3>Active Vulnerability Intelligence</h3>
            <div className="lti-header-actions">
              <span className="lti-cache-age">{formatCacheAge(vulnsCacheTime)}</span>
              <button
                type="button"
                className="hyp-fetch-btn"
                onClick={fetchVulnerabilities}
                disabled={loadingVulns}
              >
                Fetch Latest CVEs
              </button>
            </div>
          </div>

          {loadingVulns && (
            <>
              <div className="hyp-loading-row">
                <span className="spinner" aria-hidden="true" />
                Fetching latest vulnerability intelligence...
              </div>
              <SkeletonCards count={10} />
            </>
          )}

          {!loadingVulns && vulnerabilities.length > 0 && (
            <>
              <ExploitFilterRow
                activeFilter={vulnsExploitFilter}
                onFilterChange={setVulnsExploitFilter}
              />
              <div className="actor-grid">
                {sortedFilteredVulns.map((cve) => (
                  <article
                    key={cve.cveId}
                    className="actor-card lti-cve-card"
                    style={{ borderTopColor: severityColor(cve.severity) }}
                  >
                    <div className="actor-card-header">
                      <span className="lti-cve-id">{cve.cveId}</span>
                      <span className={`priority-pill priority-${cve.severity}`}>
                        {cve.severity}
                      </span>
                    </div>
                    {cve.name && <h4 className="lti-cve-name">{cve.name}</h4>}
                    <CvssGauge score={cve.cvssScore} />
                    {cve.product && <div className="lti-meta">Product: {cve.product}</div>}
                    <ExploitStatusBadge status={cve.exploitStatus} />
                    {cve.description && <p className="actor-activity">{cve.description}</p>}
                    {cve.affectedVersions && (
                      <div className="lti-meta">Affected: {cve.affectedVersions}</div>
                    )}
                    {cve.huntingGuidance && (
                      <div className="lti-hunting-guidance">
                        <strong>Hunting Guidance:</strong> {cve.huntingGuidance}
                      </div>
                    )}
                    <div className="actor-ttps">
                      {(cve.mitreTechniques || []).map((t) => (
                        <span key={t} className="ttp-badge">
                          {t}
                        </span>
                      ))}
                    </div>
                    <LogSourceBadges sources={cve.relevantLogSources} />
                    {cve.disclosedPeriod && (
                      <div className="lti-meta">Disclosed: {cve.disclosedPeriod}</div>
                    )}
                    <GenerateHypothesisButton
                      itemKey={cve.cveId}
                      generatingFor={generatingFor}
                      onGenerate={generateCveHypothesis}
                      data={cve}
                      label="Generate Detection Hypothesis"
                    />
                  </article>
                ))}
              </div>
              {sortedFilteredVulns.length === 0 && (
                <p className="lti-empty-filter">No CVEs match this exploit status filter.</p>
              )}
            </>
          )}
        </section>
      )}

      {activeView === 'campaigns' && (
        <section className="hyp-landscape-card">
          <div className="lti-section-header">
            <h3>Recent Attack Campaigns</h3>
            <div className="lti-header-actions">
              <span className="lti-cache-age">{formatCacheAge(campaignsCacheTime)}</span>
              <button
                type="button"
                className="hyp-fetch-btn"
                onClick={fetchAttackCampaigns}
                disabled={loadingCampaigns}
              >
                Fetch Latest
              </button>
            </div>
          </div>

          {loadingCampaigns && (
            <>
              <div className="hyp-loading-row">
                <span className="spinner" aria-hidden="true" />
                Loading recent attack campaigns...
              </div>
              <SkeletonCards count={8} />
            </>
          )}

          {!loadingCampaigns && attackCampaigns.length > 0 && (
            <>
              <CategoryFilterRow
                actors={attackCampaigns}
                activeFilter={campaignsCategoryFilter}
                onFilterChange={setCampaignsCategoryFilter}
                categoryList={CAMPAIGN_CATEGORIES}
              />
              <div className="actor-grid">
                {filteredCampaigns.map((campaign) => (
                  <article
                    key={campaign.name}
                    className="actor-card lti-campaign-card"
                    style={{ borderTopColor: severityColor(campaign.severity) }}
                  >
                    <div className="actor-card-header">
                      <h4 style={{ color: severityColor(campaign.severity) }}>{campaign.name}</h4>
                      <CampaignCategoryBadge category={campaign.category} />
                      <span className={`priority-pill priority-${campaign.severity}`}>
                        {campaign.severity}
                      </span>
                    </div>
                    <div className="lti-meta">
                      Attributed to: {campaign.attributedTo || 'Unknown'}
                    </div>
                    <div className="lti-meta">
                      Target sector: {campaign.targetSector || '—'}
                      {campaign.timeframe && ` · Timeframe: ${campaign.timeframe}`}
                    </div>
                    {campaign.summary && <p className="actor-activity">{campaign.summary}</p>}
                    {campaign.initialAccessVector && (
                      <div className="lti-initial-access">
                        <strong>Initial Access:</strong> {campaign.initialAccessVector}
                      </div>
                    )}
                    <div className="actor-ttps">
                      {(campaign.mitreTechniques || []).map((t) => (
                        <span key={t} className="ttp-badge">
                          {t}
                        </span>
                      ))}
                    </div>
                    <LogSourceBadges sources={campaign.relevantLogSources} />
                    <GenerateHypothesisButton
                      itemKey={campaign.name}
                      generatingFor={generatingFor}
                      onGenerate={generateHypothesisForCampaign}
                      data={campaign}
                    />
                  </article>
                ))}
              </div>
              {filteredCampaigns.length === 0 && (
                <p className="lti-empty-filter">No campaigns match this category filter.</p>
              )}
            </>
          )}
        </section>
      )}

      {activeView === 'custom' && (
        <section className="hyp-custom-form-card">
          <h3>Generate Custom Hunt Hypothesis</h3>
          <textarea
            className="hyp-custom-textarea"
            rows={4}
            placeholder="Describe what you want to hunt for..."
            value={customInput}
            onChange={(e) => setCustomInput(e.target.value)}
          />
          <div className="hyp-suggestion-chips">
            {QUICK_CHIPS.map((chip) => (
              <button
                key={chip}
                type="button"
                className="suggestion-chip"
                onClick={() => setCustomInput(chip)}
              >
                {chip}
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
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </label>
          </div>
          <button
            type="button"
            className="hyp-generate-full-btn"
            disabled={!customInput.trim() || generatingCustom}
            onClick={generateCustomHypothesis}
          >
            {generatingCustom ? (
              <span className="spinner-wrap">
                <span className="spinner" aria-hidden="true" />
                Generating...
              </span>
            ) : (
              'Generate Hypothesis'
            )}
          </button>
        </section>
      )}

      {generatedHypotheses.length > 0 && (
        <section className="hyp-generated-section lti-generated-section">
          <h3>AI-Generated Hypotheses ({generatedHypotheses.length})</h3>
          <div className="hypotheses-list">
            {generatedHypotheses.map((hyp) => {
              const queryCount = hyp.kqlQueries?.length || 0
              const isExpanded = expandedHyp === hyp.id
              return (
                <article
                  key={hyp.id}
                  className="hypothesis-card lti-hyp-card"
                  style={{ borderLeftColor: severityColor(hyp.priority) }}
                >
                  <div className="hypothesis-header">
                    <div className="hypothesis-header-left">
                      <span className="lti-ai-badge">AI Generated</span>
                      {isCveLinkedHypothesis(hyp) && (
                        <span className="lti-cve-linked-badge">CVE-LINKED</span>
                      )}
                      {hyp.threatActor && (
                        <span className="actor-tag">For: {hyp.threatActor}</span>
                      )}
                      {hyp.generatedAt && (
                        <span className="lti-generated-time">
                          {formatGeneratedTime(hyp.generatedAt)}
                        </span>
                      )}
                    </div>
                    <button
                      type="button"
                      className="lti-remove-btn"
                      onClick={() => removeHypothesis(hyp.id)}
                      title="Remove"
                    >
                      ✕
                    </button>
                  </div>
                  <h3>{hyp.title}</h3>
                  <div className="lti-hyp-badges">
                    <span className={`priority-pill priority-${hyp.priority}`}>
                      {hyp.priority}
                    </span>
                    {hyp.tacticChain && (
                      <span className="lti-tactic-chain">{hyp.tacticChain}</span>
                    )}
                  </div>
                  {(hyp.logSources || []).length > 0 && (
                    <div className="actor-sectors">
                      {hyp.logSources.map((s) => (
                        <span key={s} className="sector-pill">
                          {s}
                        </span>
                      ))}
                    </div>
                  )}
                  {hyp.description && <p className="hypothesis-description">{hyp.description}</p>}
                  {(hyp.tags || []).length > 0 && (
                    <div className="actor-sectors">
                      {hyp.tags.map((t) => (
                        <span key={t} className="sector-pill lti-tag-pill">
                          {t}
                        </span>
                      ))}
                    </div>
                  )}
                  {queryCount > 0 && (
                    <button
                      type="button"
                      className="hyp-kql-toggle"
                      onClick={() => setExpandedHyp(isExpanded ? null : hyp.id)}
                    >
                      View KQL Queries ({queryCount})
                      <span className="hyp-kql-count">{isExpanded ? '▲' : '▼'}</span>
                    </button>
                  )}
                  {isExpanded && (
                    <div className="hyp-query-list">
                      {(hyp.kqlQueries || []).map((q, idx) => (
                        <div key={idx} className="hyp-query-block">
                          <h4>{q.title}</h4>
                          <div className="lti-query-meta">
                            <span className={`priority-pill priority-${q.severity}`}>
                              {q.severity}
                            </span>
                            <span className="ttp-badge">{q.mitreTechnique}</span>
                            <span className="sector-pill">{q.logSource}</span>
                          </div>
                          <pre className="lti-kql-block">{q.kql}</pre>
                          <button
                            type="button"
                            className="copy-btn"
                            onClick={() => copyText(q.kql)}
                          >
                            Copy KQL
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                  <div className="hyp-card-actions">
                    <button
                      type="button"
                      className="export-btn"
                      onClick={() => exportHypothesisKQL(hyp)}
                    >
                      Export KQL
                    </button>
                  </div>
                </article>
              )
            })}
          </div>
        </section>
      )}
    </div>
  )
}
