import { useState, useMemo, useEffect, useCallback } from 'react'
import MetricCards from './components/MetricCards'
import MitreHeatmap from './components/MitreHeatmap'
import KqlLibrary from './components/KqlLibrary'
import Hypotheses from './components/Hypotheses'
import IocTracker from './components/IocTracker'
import QueryGenerator from './components/QueryGenerator'
import GlobalSearch from './components/GlobalSearch'
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
import { useContext } from 'react'
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
  { id: 'heatmap', label: 'MITRE Heatmap' },
  { id: 'kql', label: 'KQL Library' },
  { id: 'hypotheses', label: 'Hypotheses' },
  { id: 'iocs', label: 'IOC Tracker' },
  { id: 'generator', label: 'KQL Generator' },
]

function AppContent() {
  const { setLiveIOCs, setIocLoaded } = useContext(ThreatDataContext)
  const [activeTab, setActiveTab] = useState('heatmap')
  const [iocCount, setIocCount] = useState(localIocs.length)
  const [searchIocs, setSearchIocs] = useState(localIocs)
  const [iocsLoading, setIocsLoading] = useState(true)
  const [newIocCount, setNewIocCount] = useState(0)
  const [searchHighlight, setSearchHighlight] = useState(null)
  const [workflowRevision, setWorkflowRevision] = useState(0)

  const coveragePercent = useMemo(() => getCoveragePercent(), [])

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
        }
      } catch {
        if (!cancelled) {
          const merged = mergeIocLists([], localIocs)
          setIocCount(merged.length)
          setSearchIocs(merged)
          setLiveIOCs(merged)
          setIocLoaded(true)
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
      case 'heatmap':
        return <MitreHeatmap {...highlightProps} />
      case 'kql':
        return <KqlLibrary {...highlightProps} />
      case 'hypotheses':
        return (
          <Hypotheses {...highlightProps} onWorkflowChange={handleWorkflowChange} />
        )
      case 'iocs':
        return (
          <IocTracker
            onIocCountChange={setIocCount}
            onNewIocCountChange={setNewIocCount}
            iocTabActive={activeTab === 'iocs'}
            {...highlightProps}
          />
        )
      case 'generator':
        return <QueryGenerator />
      default:
        return <MitreHeatmap {...highlightProps} />
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
        <GlobalSearch iocs={searchIocs} onResultSelect={handleSearchResult} />
      </header>

      <MetricCards
        totalTTPs={techniques.length}
        huntQueries={queries.length}
        hypotheses={hypothesesData.length}
        iocsTracked={iocsLoading ? '…' : iocCount}
        coveragePercent={coveragePercent}
        activeHunts={workflowStats.inProgress}
        closedThisWeek={closedThisWeek}
      />

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

      <footer className="app-footer">
        <span>Sentinel Threat Hunt Dashboard</span>
        <span className="footer-meta">
          {techniques.length} techniques · {queries.length} queries ·{' '}
          {hypothesesData.length} hypotheses · {iocCount} IOCs
        </span>
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
