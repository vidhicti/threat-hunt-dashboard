import { useState, useEffect, useMemo } from 'react'
import MetricCards from './MetricCards'
import techniques from '../data/techniques.json'
import queries from '../data/queries.json'
import hypothesesData from '../data/hypotheses.json'
import { FEED_DEFINITIONS } from '../data/feedConfig'
import { getCoveragePercent } from '../utils/techniqueCoverage'
import { getWorkflowStats } from '../services/huntWorkflow'
import { getActiveSession, formatDuration } from '../services/huntSession'

function loadConnectorConfig() {
  try {
    return JSON.parse(localStorage.getItem('connectorConfig') || '{}')
  } catch {
    return {}
  }
}

function loadLiveHypotheses() {
  try {
    return JSON.parse(localStorage.getItem('liveHypotheses') || '[]')
  } catch {
    return []
  }
}

function isFeedHealthy(feed, config) {
  const cfg = config[feed.id] || {}
  if (feed.usedFor === 'enrichment') return !!cfg.apiKey && cfg.enabled !== false
  if (feed.requiresKey) return cfg.enabled !== false && !!cfg.lastTest
  return cfg.enabled !== false
}

function Overview({
  setActiveTab,
  iocCount,
  iocsLoading,
  workflowStats,
  activeHunts,
  closedThisWeek,
}) {
  const [liveIocCount, setLiveIocCount] = useState(iocCount)
  const [lastUpdated, setLastUpdated] = useState(new Date())
  const [connectorConfig, setConnectorConfig] = useState(loadConnectorConfig)
  const [liveHypotheses, setLiveHypotheses] = useState(loadLiveHypotheses)
  const [theme, setTheme] = useState(() => localStorage.getItem('theme') || 'dark')

  const analystName = localStorage.getItem('analystName') || ''
  const coveragePercent = useMemo(() => getCoveragePercent(), [])
  const activeSession = useMemo(() => getActiveSession(), [])

  const feedFeeds = useMemo(
    () => FEED_DEFINITIONS.filter((f) => f.usedFor !== 'enrichment'),
    []
  )

  useEffect(() => {
    const handleIocCount = (e) => {
      setLiveIocCount(e.detail.count)
      setLastUpdated(new Date())
    }
    window.addEventListener('iocCountUpdate', handleIocCount)
    return () => window.removeEventListener('iocCountUpdate', handleIocCount)
  }, [])

  useEffect(() => {
    setLiveIocCount(iocCount)
  }, [iocCount])

  useEffect(() => {
    const refresh = () => {
      setConnectorConfig(loadConnectorConfig())
      setLiveHypotheses(loadLiveHypotheses())
      setTheme(localStorage.getItem('theme') || 'dark')
    }
    window.addEventListener('storage', refresh)
    const interval = setInterval(refresh, 5000)
    return () => {
      window.removeEventListener('storage', refresh)
      clearInterval(interval)
    }
  }, [])

  const stats = workflowStats || getWorkflowStats()
  const barTotal = Math.max(
    1,
    stats.open + stats.inProgress + stats.truePositive + stats.falsePositive + stats.closed
  )

  const recentHypotheses = [...liveHypotheses]
    .sort((a, b) => new Date(b.generatedAt || 0) - new Date(a.generatedAt || 0))
    .slice(0, 5)

  const sessionDuration = activeSession
    ? formatDuration(Date.now() - new Date(activeSession.startTime).getTime())
    : null

  const cardStyle = {
    background: theme === 'light' ? '#ffffff' : '#161b22',
    border: `1px solid ${theme === 'light' ? '#d0d7de' : '#30363d'}`,
    borderRadius: 8,
    padding: '1rem',
  }

  const actionBtn = {
    padding: '10px 16px',
    background: theme === 'light' ? '#f6f8fa' : '#21262d',
    border: `1px solid ${theme === 'light' ? '#d0d7de' : '#30363d'}`,
    borderRadius: 8,
    color: theme === 'light' ? '#1f2328' : '#c9d1d9',
    fontSize: 13,
    cursor: 'pointer',
    fontWeight: 500,
  }

  return (
    <div className="overview-page">
      <section className="overview-welcome" style={{ ...cardStyle, marginBottom: 16 }}>
        <h2 style={{ margin: '0 0 4px', fontSize: 22 }}>🛡️ Threat Hunting Dashboard</h2>
        <p style={{ margin: 0, color: '#8b949e', fontSize: 13 }}>
          Microsoft Sentinel | Last updated: {lastUpdated.toLocaleTimeString()}
          {analystName && (
            <>
              {' '}
              | Analyst: <strong style={{ color: '#c9d1d9' }}>{analystName}</strong>
            </>
          )}
        </p>
      </section>

      <MetricCards
        totalTTPs={techniques.length}
        huntQueries={queries.length}
        hypotheses={hypothesesData.length}
        iocsTracked={iocsLoading ? '…' : liveIocCount}
        coveragePercent={coveragePercent}
        activeHunts={activeHunts}
        closedThisWeek={closedThisWeek}
      />

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: 16,
          marginTop: 16,
          marginBottom: 16,
        }}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={cardStyle}>
            <h3 style={{ margin: '0 0 12px', fontSize: 15 }}>Hunt Status</h3>
            <div
              style={{
                display: 'flex',
                height: 20,
                borderRadius: 10,
                overflow: 'hidden',
                marginBottom: 12,
              }}
            >
              <div style={{ flex: stats.open, background: '#8b949e' }} title="Open" />
              <div style={{ flex: stats.inProgress, background: '#58a6ff' }} title="In Progress" />
              <div style={{ flex: stats.truePositive, background: '#3fb950' }} title="True Positive" />
              <div style={{ flex: stats.falsePositive, background: '#f85149' }} title="False Positive" />
              <div style={{ flex: stats.closed, background: '#484f58' }} title="Closed" />
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, fontSize: 11, color: '#8b949e' }}>
              <span><span style={{ color: '#8b949e' }}>●</span> Open ({stats.open})</span>
              <span><span style={{ color: '#58a6ff' }}>●</span> In Progress ({stats.inProgress})</span>
              <span><span style={{ color: '#3fb950' }}>●</span> True Positive ({stats.truePositive})</span>
              <span><span style={{ color: '#f85149' }}>●</span> False Positive ({stats.falsePositive})</span>
              <span><span style={{ color: '#484f58' }}>●</span> Closed ({stats.closed})</span>
            </div>
            {barTotal === 1 && (
              <p style={{ fontSize: 11, color: '#484f58', margin: '8px 0 0' }}>No workflow data yet</p>
            )}
          </div>

          <div style={cardStyle}>
            <h3 style={{ margin: '0 0 12px', fontSize: 15 }}>Active Hunt Session</h3>
            {activeSession ? (
              <div style={{ fontSize: 13 }}>
                <div style={{ fontWeight: 600, marginBottom: 4 }}>{activeSession.name}</div>
                <div style={{ color: '#8b949e', fontSize: 12, marginBottom: 4 }}>
                  Analyst: {activeSession.analyst || '—'} | Duration: {sessionDuration}
                </div>
                <p style={{ margin: 0, fontSize: 12, color: '#c9d1d9' }}>{activeSession.scope || 'No scope defined'}</p>
              </div>
            ) : (
              <div>
                <p style={{ margin: '0 0 12px', color: '#8b949e', fontSize: 13 }}>No active hunt session</p>
                <button type="button" style={actionBtn} onClick={() => setActiveTab('hypotheses')}>
                  Start Hunt Session
                </button>
              </div>
            )}
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={cardStyle}>
            <h3 style={{ margin: '0 0 12px', fontSize: 15 }}>IOC Feed Health</h3>
            <div style={{ fontSize: 28, fontWeight: 700, color: '#58a6ff', marginBottom: 8 }}>
              {iocsLoading ? '…' : liveIocCount}
            </div>
            <div style={{ fontSize: 11, color: '#8b949e', marginBottom: 12 }}>Total IOCs tracked</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 12, maxHeight: 140, overflow: 'auto' }}>
              {feedFeeds.map((feed) => {
                const healthy = isFeedHealthy(feed, connectorConfig)
                return (
                  <div key={feed.id} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12 }}>
                    <span
                      style={{
                        width: 8,
                        height: 8,
                        borderRadius: '50%',
                        background: healthy ? '#3fb950' : '#f85149',
                        display: 'inline-block',
                      }}
                    />
                    <span style={{ color: '#c9d1d9' }}>{feed.name}</span>
                  </div>
                )
              })}
            </div>
            <div style={{ fontSize: 11, color: '#8b949e', marginBottom: 12 }}>
              Last refresh: {lastUpdated.toLocaleTimeString()}
            </div>
            <button type="button" style={actionBtn} onClick={() => setActiveTab('iocs')}>
              Open IOC Tracker
            </button>
          </div>

          <div style={cardStyle}>
            <h3 style={{ margin: '0 0 12px', fontSize: 15 }}>Recent Threat Activity</h3>
            {recentHypotheses.length > 0 ? (
              <>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 12 }}>
                  {recentHypotheses.map((hyp) => (
                    <div
                      key={hyp.id}
                      style={{
                        padding: '8px 10px',
                        background: theme === 'light' ? '#f6f8fa' : '#0d1117',
                        borderRadius: 6,
                        border: `1px solid ${theme === 'light' ? '#d0d7de' : '#21262d'}`,
                      }}
                    >
                      {hyp.threatActor && (
                        <div style={{ fontSize: 10, color: '#a371f7', fontWeight: 600, marginBottom: 2 }}>
                          {hyp.threatActor}
                        </div>
                      )}
                      <div style={{ fontSize: 12, fontWeight: 500, color: '#c9d1d9' }}>{hyp.title}</div>
                      <div style={{ fontSize: 10, color: '#8b949e', marginTop: 2 }}>
                        {hyp.generatedAt ? new Date(hyp.generatedAt).toLocaleString() : '—'}
                      </div>
                    </div>
                  ))}
                </div>
                <button type="button" style={actionBtn} onClick={() => setActiveTab('live-intel')}>
                  View All
                </button>
              </>
            ) : (
              <div>
                <p style={{ margin: '0 0 12px', color: '#8b949e', fontSize: 13 }}>No AI hypotheses generated yet</p>
                <button type="button" style={actionBtn} onClick={() => setActiveTab('live-intel')}>
                  Go to Live Intel →
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      <section style={{ ...cardStyle, marginBottom: 16 }}>
        <h3 style={{ margin: '0 0 12px', fontSize: 15 }}>Quick Actions</h3>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10 }}>
          <button
            type="button"
            style={actionBtn}
            onClick={() => {
              sessionStorage.setItem('iocFocusSearch', '1')
              setActiveTab('iocs')
            }}
          >
            🔍 Investigate IOC
          </button>
          <button type="button" style={actionBtn} onClick={() => setActiveTab('generator')}>
            ⚡ Generate KQL
          </button>
          <button type="button" style={actionBtn} onClick={() => setActiveTab('live-intel')}>
            🌐 Fetch Threat Intel
          </button>
          <button type="button" style={actionBtn} onClick={() => setActiveTab('hypotheses')}>
            📋 Start Hunt Session
          </button>
          <button type="button" style={actionBtn} onClick={() => setActiveTab('settings')}>
            ⚙️ Configure Feeds
          </button>
        </div>
      </section>

      <section style={cardStyle}>
        <h3 style={{ margin: '0 0 10px', fontSize: 14 }}>Feed Status Quick View</h3>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {feedFeeds.map((feed) => {
            const healthy = isFeedHealthy(feed, connectorConfig)
            return (
              <span
                key={feed.id}
                style={{
                  fontSize: 10,
                  padding: '2px 8px',
                  borderRadius: 20,
                  background: healthy ? '#0d2d1a' : '#3d1a1a',
                  color: healthy ? '#3fb950' : '#f85149',
                  border: `1px solid ${healthy ? '#3fb95040' : '#f8514940'}`,
                }}
              >
                {feed.name} {healthy ? '✓' : '✗'}
              </span>
            )
          })}
        </div>
      </section>
    </div>
  )
}

export default Overview
