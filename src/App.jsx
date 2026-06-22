import { useState, useMemo, useEffect, useCallback, useContext } from 'react'
import MetricCards from './components/MetricCards'
import MitreHeatmap from './components/MitreHeatmap'
import KqlLibrary from './components/KqlLibrary'
import Hypotheses from './components/Hypotheses'
import LiveThreatIntel from './components/LiveThreatIntel'
import IocTracker from './components/IocTracker'
import QueryGenerator from './components/QueryGenerator'
import GlobalSearch from './components/GlobalSearch'
import Settings from './components/Settings'
import Overview from './components/Overview'
import techniques from './data/techniques.json'
import queries from './data/queries.json'
import hypothesesData from './data/hypotheses.json'
import localIocs from './data/iocs.json'
import { fetchAllIOCs, mergeIocLists } from './services/threatIntel'
import { getCoveragePercent } from './utils/techniqueCoverage'
import {
  getWorkflowStats,
  getClosedThisWeek,
  countActiveHypotheses,
} from './services/huntWorkflow'
import { initKeyboardShortcuts } from './services/keyboardShortcuts'
import NotificationCenter from './components/NotificationCenter'
import KeyboardShortcutsHelp from './components/KeyboardShortcutsHelp'
import { ThreatDataProvider, ThreatDataContext } from './context/ThreatDataContext'
import './App.css'

const LAST_VISIT_KEY = 'iocLastVisitTimestamp'

function countNewIocs(iocList) {
  const baseline = localStorage.getItem(LAST_VISIT_KEY) || '1970-01-01'
  const base = String(baseline).slice(0, 10)
  return iocList.filter((ioc) => {
    const added = String(ioc.dateAdded || '').slice(0, 10)
    return added >= base
  }).length
}

const TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'heatmap', label: 'MITRE Heatmap' },
  { id: 'kql', label: 'KQL Library' },
  { id: 'hypotheses', label: 'Hypotheses' },
  { id: 'live-intel', label: '🌐 Live Intel' },
  { id: 'iocs', label: 'IOC Tracker' },
  { id: 'generator', label: 'KQL Generator' },
  { id: 'settings', label: '⚙ Settings' },
]

function AppContent() {
  const { setLiveIOCs, setIocLoaded } = useContext(ThreatDataContext)
  const [activeTab, setActiveTab] = useState('overview')
  const [iocCount, setIocCount] = useState(localIocs.length)
  const [searchIocs, setSearchIocs] = useState(localIocs)
  const [iocsLoading, setIocsLoading] = useState(true)
  const [newIocCount, setNewIocCount] = useState(0)
  const [searchHighlight, setSearchHighlight] = useState(null)
  const [workflowRevision, setWorkflowRevision] = useState(0)
  
  const [analystName, setAnalystName] = useState(localStorage.getItem('analystName') || '')
  const [defaultLookback, setDefaultLookback] = useState(localStorage.getItem('defaultLookback') || '1d')
  const [autoRefresh, setAutoRefresh] = useState(localStorage.getItem('autoRefresh') === 'true')
  const [refreshInterval, setRefreshInterval] = useState(parseInt(localStorage.getItem('refreshInterval') || '300000'))
  const [theme, setTheme] = useState(() => localStorage.getItem('theme') || 'dark')
  const [showShortcutsHelp, setShowShortcutsHelp] = useState(false)

  const coveragePercent = useMemo(() => getCoveragePercent(), [])

  useEffect(() => {
    const cleanup = initKeyboardShortcuts(setActiveTab)
    return cleanup
  }, [])

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('theme', theme)
  }, [theme])

  const toggleTheme = useCallback(() => {
    setTheme((t) => (t === 'dark' ? 'light' : 'dark'))
  }, [])

  const workflowStats = useMemo(() => {
    void workflowRevision
    return getWorkflowStats()
  }, [workflowRevision])

  const activeHypCount = useMemo(() => {
    void workflowRevision
    return countActiveHypotheses(hypothesesData.map((h) => h.id))
  }, [workflowRevision])

  const closedThisWeek = useMemo(() => {
    void workflowRevision
    return getClosedThisWeek()
  }, [workflowRevision])

  const handleWorkflowChange = useCallback(() => {
    setWorkflowRevision((r) => r + 1)
  }, [])

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const { iocs: live } = await fetchAllIOCs()
        if (!cancelled) {
          const merged = mergeIocLists(live, localIocs)
          setIocCount(merged.length)
          setSearchIocs(merged)
          setLiveIOCs(merged)
          setIocLoaded(true)
          localStorage.setItem('iocLastRefresh', new Date().toISOString())
        }
      } catch {
        if (!cancelled) {
          const merged = mergeIocLists([], localIocs)
          setIocCount(merged.length)
          setSearchIocs(merged)
          setLiveIOCs(merged)
          setIocLoaded(true)
          localStorage.setItem('iocLastRefresh', new Date().toISOString())
        }
      } finally {
        if (!cancelled) setIocsLoading(false)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    const handleIocCountUpdate = (e) => {
      setIocCount(e.detail.count)
    }
    window.addEventListener('iocCountUpdate', handleIocCountUpdate)
    return () => window.removeEventListener('iocCountUpdate', handleIocCountUpdate)
  }, [])

  useEffect(() => {
    if (activeTab !== 'iocs' && searchIocs.length > 0) {
      setNewIocCount(countNewIocs(searchIocs))
    }
  }, [searchIocs, activeTab])

  useEffect(() => {
    if (activeTab === 'iocs') {
      localStorage.setItem(LAST_VISIT_KEY, new Date().toISOString())
      setNewIocCount(0)
    }
  }, [activeTab])

  const handleSearchResult = useCallback((result) => {
    setActiveTab(result.tab)
    setSearchHighlight({ id: result.id, term: result.term })
  }, [])

  const clearSearchHighlight = useCallback(() => {
    setSearchHighlight(null)
  }, [])

  const renderTab = () => {
    const highlightProps = {
      highlightId: searchHighlight?.id ?? null,
      highlightTerm: searchHighlight?.term ?? null,
      onHighlightDone: clearSearchHighlight,
    }

    switch (activeTab) {
      case 'overview':
        return (
          <Overview
            setActiveTab={setActiveTab}
            iocCount={iocCount}
            iocsLoading={iocsLoading}
            workflowStats={workflowStats}
            activeHunts={workflowStats.inProgress}
            closedThisWeek={closedThisWeek}
          />
        )
      case 'heatmap':
        return <MitreHeatmap {...highlightProps} />
      case 'kql':
        return <KqlLibrary {...highlightProps} defaultLookback={defaultLookback} />
      case 'hypotheses':
        return (
          <Hypotheses {...highlightProps} onWorkflowChange={handleWorkflowChange} analystName={analystName} />
        )
      case 'live-intel':
        return <LiveThreatIntel onGoToSettings={() => setActiveTab('settings')} />
      case 'iocs':
        return <IocTracker setActiveTab={setActiveTab} />
      case 'generator':
        return <QueryGenerator />
      case 'settings':
        return <Settings theme={theme} setTheme={setTheme} />
      default:
        return (
          <Overview
            setActiveTab={setActiveTab}
            iocCount={iocCount}
            iocsLoading={iocsLoading}
            workflowStats={workflowStats}
            activeHunts={workflowStats.inProgress}
            closedThisWeek={closedThisWeek}
          />
        )
    }
  }

  return (
    <div className="app">
      <header className="app-header app-header-with-search">
        <div className="header-brand">
          <span className="brand-icon" aria-hidden="true">
            🛡️
          </span>
          <div>
            <h1>Threat Hunting Automation</h1>
            <p className="header-subtitle">Microsoft Sentinel · MITRE ATT&CK</p>
          </div>
        </div>
        <div className="header-actions">
          <GlobalSearch iocs={searchIocs} onResultSelect={handleSearchResult} />
          <NotificationCenter setActiveTab={setActiveTab} />
          <button
            type="button"
            className="shortcuts-help-btn"
            onClick={() => setShowShortcutsHelp(true)}
            title="Keyboard shortcuts"
            aria-label="Keyboard shortcuts"
            style={{
              width: 20,
              height: 20,
              padding: 0,
              background: 'none',
              border: 'none',
              color: 'var(--text-tertiary)',
              fontSize: 14,
              fontWeight: 600,
              cursor: 'pointer',
              lineHeight: 1,
              opacity: 0.7,
            }}
          >
            ?
          </button>
          <button
            type="button"
            className="theme-toggle-btn"
            onClick={toggleTheme}
            title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            {theme === 'dark' ? '☀️' : '🌙'}
          </button>
        </div>
      </header>

      {activeTab !== 'overview' && (
        <MetricCards
          totalTTPs={techniques.length}
          huntQueries={queries.length}
          hypotheses={hypothesesData.length}
          iocsTracked={iocsLoading ? '…' : iocCount}
          coveragePercent={coveragePercent}
          activeHunts={workflowStats.inProgress}
          closedThisWeek={closedThisWeek}
        />
      )}

      <nav className="tab-nav" aria-label="Dashboard sections">
        {TABS.map((tab) => {
          const label =
            tab.id === 'hypotheses' && activeHypCount > 0
              ? `Hypotheses (${activeHypCount} active)`
              : tab.label
          return (
            <button
              key={tab.id}
              type="button"
              className={`tab-btn ${activeTab === tab.id ? 'active' : ''}`}
              onClick={() => setActiveTab(tab.id)}
            >
              {label}
              {tab.id === 'iocs' && newIocCount > 0 && (
                <span className="tab-new-dot" aria-label={`${newIocCount} new IOCs`} />
              )}
              {tab.id === 'hypotheses' && workflowStats.inProgress > 0 && (
                <span
                  className="tab-progress-dot"
                  aria-label={`${workflowStats.inProgress} in progress`}
                />
              )}
            </button>
          )
        })}
      </nav>

      <main className="tab-content">{renderTab()}</main>

      <KeyboardShortcutsHelp open={showShortcutsHelp} onClose={() => setShowShortcutsHelp(false)} />

      <footer
        style={{
          borderTop: '1px solid var(--border-primary)',
          padding: '12px 0',
          marginTop: '2rem',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 8,
        }}
      >
        <div style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>
          🛡️ Threat Hunting Dashboard v1.2.0 — Microsoft Sentinel
        </div>
        <div style={{ display: 'flex', gap: 16, fontSize: 11, color: 'var(--text-tertiary)' }}>
          <a
            href="https://github.com/vidhicti/threat-hunt-dashboard"
            target="_blank"
            rel="noreferrer"
            style={{ color: 'var(--accent-blue)', textDecoration: 'none' }}
          >
            GitHub
          </a>
          <a
            href="https://attack.mitre.org"
            target="_blank"
            rel="noreferrer"
            style={{ color: 'var(--accent-blue)', textDecoration: 'none' }}
          >
            MITRE ATT&CK
          </a>
          <a
            href="https://threat-hunt-dashboard.vercel.app/api/index"
            target="_blank"
            rel="noreferrer"
            style={{ color: 'var(--accent-blue)', textDecoration: 'none' }}
          >
            API Status
          </a>
          <span>Built with React + Vercel</span>
        </div>
      </footer>
    </div>
  )
}

function App() {
  return (
    <ThreatDataProvider>
      <AppContent />
    </ThreatDataProvider>
  )
}

export default App
