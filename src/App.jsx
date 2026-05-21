import { useState, useMemo, useEffect } from 'react'
import MetricCards from './components/MetricCards'
import MitreHeatmap from './components/MitreHeatmap'
import KqlLibrary from './components/KqlLibrary'
import Hypotheses from './components/Hypotheses'
import IocTracker from './components/IocTracker'
import QueryGenerator from './components/QueryGenerator'
import techniques from './data/techniques.json'
import queries from './data/queries.json'
import hypothesesData from './data/hypotheses.json'
import localIocs from './data/iocs.json'
import { fetchAllIOCs, mergeIocLists } from './services/threatIntel'
import './App.css'

const TABS = [
  { id: 'heatmap', label: 'MITRE Heatmap' },
  { id: 'kql', label: 'KQL Library' },
  { id: 'hypotheses', label: 'Hypotheses' },
  { id: 'iocs', label: 'IOC Tracker' },
  { id: 'generator', label: 'KQL Generator' },
]

function App() {
  const [activeTab, setActiveTab] = useState('heatmap')
  const [iocCount, setIocCount] = useState(localIocs.length)
  const [iocsLoading, setIocsLoading] = useState(true)

  const coveragePercent = useMemo(() => {
    const covered = techniques.filter((t) => t.coverage !== 'none').length
    return Math.round((covered / techniques.length) * 100)
  }, [])

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const { iocs: live } = await fetchAllIOCs()
        if (!cancelled) {
          const merged = mergeIocLists(live, localIocs)
          setIocCount(merged.length)
        }
      } catch {
        if (!cancelled) setIocCount(localIocs.length)
      } finally {
        if (!cancelled) setIocsLoading(false)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

  const renderTab = () => {
    switch (activeTab) {
      case 'heatmap':
        return <MitreHeatmap />
      case 'kql':
        return <KqlLibrary />
      case 'hypotheses':
        return <Hypotheses />
      case 'iocs':
        return <IocTracker onIocCountChange={setIocCount} />
      case 'generator':
        return <QueryGenerator />
      default:
        return <MitreHeatmap />
    }
  }

  return (
    <div className="app">
      <header className="app-header">
        <div className="header-brand">
          <span className="brand-icon" aria-hidden="true">
            🛡️
          </span>
          <div>
            <h1>Threat Hunting Automation</h1>
            <p className="header-subtitle">Microsoft Sentinel · MITRE ATT&CK</p>
          </div>
        </div>
      </header>

      <MetricCards
        totalTTPs={techniques.length}
        huntQueries={queries.length}
        hypotheses={hypothesesData.length}
        iocsTracked={iocsLoading ? '…' : iocCount}
        coveragePercent={coveragePercent}
      />

      <nav className="tab-nav" aria-label="Dashboard sections">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            className={`tab-btn ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
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

export default App
