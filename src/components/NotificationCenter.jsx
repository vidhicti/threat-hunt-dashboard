import { useState, useEffect, useRef, useCallback } from 'react'

const STATE_KEY = 'notificationState'

function loadNotificationState() {
  try {
    return JSON.parse(localStorage.getItem(STATE_KEY) || '{}')
  } catch {
    return { read: [], dismissed: [] }
  }
}

function saveNotificationState(state) {
  localStorage.setItem(STATE_KEY, JSON.stringify(state))
}

function getRelativeTime(timestamp) {
  if (!timestamp) return ''
  const mins = Math.floor((Date.now() - new Date(timestamp).getTime()) / 60000)
  if (mins < 1) return 'Just now'
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return `${Math.floor(hrs / 24)}d ago`
}

export function generateNotifications() {
  const notifs = []
  const today = new Date().toISOString().split('T')[0]

  try {
    const spikes = JSON.parse(localStorage.getItem('iocSpikes') || '[]')
    if (spikes.length > 0) {
      const latest = spikes[0]
      notifs.push({
        id: 'ioc-spike',
        type: 'warning',
        icon: '📈',
        title: 'IOC volume spike detected',
        detail: latest?.message || `${spikes.length} spike event(s) recorded`,
        time: latest?.time || new Date().toISOString(),
        read: false,
        tab: 'iocs',
      })
    }
  } catch {
    /* ignore */
  }

  const sessions = JSON.parse(localStorage.getItem('huntSessions') || '[]')
  const activeSessions = sessions.filter((s) => s.status === 'active')
  if (activeSessions.length > 0) {
    notifs.push({
      id: 'active-session',
      type: 'hunt',
      icon: '🎯',
      title: `${activeSessions.length} active hunt session${activeSessions.length > 1 ? 's' : ''}`,
      detail: activeSessions[0].name,
      time: activeSessions[0].startTime,
      read: false,
      tab: 'hypotheses',
    })
  }

  const liveHyps = JSON.parse(localStorage.getItem('liveHypotheses') || '[]')
  const todayHyps = liveHyps.filter((h) => h.generatedAt?.startsWith(today))
  if (todayHyps.length > 0) {
    notifs.push({
      id: 'new-hypotheses',
      type: 'intel',
      icon: '💡',
      title: `${todayHyps.length} new AI hypothesis${todayHyps.length > 1 ? 'es' : ''} generated today`,
      detail: todayHyps[0].title,
      time: todayHyps[0].generatedAt,
      read: false,
      tab: 'live-intel',
    })
  }

  const config = JSON.parse(localStorage.getItem('connectorConfig') || '{}')
  const failedFeeds = Object.entries(config)
    .filter(([, v]) => v.testStatus === 'fail')
    .map(([k]) => k)
  if (failedFeeds.length > 0) {
    notifs.push({
      id: 'feed-failures',
      type: 'warning',
      icon: '⚠️',
      title: `${failedFeeds.length} threat intel feed${failedFeeds.length > 1 ? 's' : ''} failing`,
      detail: failedFeeds.slice(0, 3).join(', '),
      time: new Date().toISOString(),
      read: false,
      tab: 'settings',
    })
  }

  return notifs
}

function applyNotificationState(notifs, state) {
  const readSet = new Set(state.read || [])
  const dismissedSet = new Set(state.dismissed || [])
  return notifs
    .filter((n) => !dismissedSet.has(n.id))
    .map((n) => ({ ...n, read: readSet.has(n.id) || n.read }))
}

export default function NotificationCenter({ setActiveTab }) {
  const [isOpen, setIsOpen] = useState(false)
  const [notifications, setNotifications] = useState([])
  const panelRef = useRef(null)

  const refreshNotifications = useCallback(() => {
    const generated = generateNotifications()
    const state = loadNotificationState()
    setNotifications(applyNotificationState(generated, state))
  }, [])

  useEffect(() => {
    refreshNotifications()
    const interval = setInterval(refreshNotifications, 30000)
    return () => clearInterval(interval)
  }, [refreshNotifications])

  useEffect(() => {
    if (!isOpen) return
    function handleClickOutside(e) {
      if (panelRef.current && !panelRef.current.contains(e.target)) {
        setIsOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [isOpen])

  const unreadCount = notifications.filter((n) => !n.read).length

  function persistRead(readIds) {
    const state = loadNotificationState()
    state.read = [...new Set([...(state.read || []), ...readIds])]
    saveNotificationState(state)
  }

  function persistDismiss(dismissIds) {
    const state = loadNotificationState()
    state.dismissed = [...new Set([...(state.dismissed || []), ...dismissIds])]
    saveNotificationState(state)
  }

  function markAllRead() {
    const ids = notifications.map((n) => n.id)
    persistRead(ids)
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })))
  }

  function handleNotificationClick(notif) {
    persistRead([notif.id])
    setNotifications((prev) =>
      prev.map((n) => (n.id === notif.id ? { ...n, read: true } : n))
    )
    setActiveTab(notif.tab)
    setIsOpen(false)
  }

  function dismissNotification(e, id) {
    e.stopPropagation()
    persistDismiss([id])
    setNotifications((prev) => prev.filter((n) => n.id !== id))
  }

  function clearAll() {
    const ids = notifications.map((n) => n.id)
    persistDismiss(ids)
    setNotifications([])
  }

  return (
    <div className="notification-center" ref={panelRef} style={{ position: 'relative' }}>
      <button
        type="button"
        className="notification-bell-btn"
        onClick={() => {
          setIsOpen((v) => !v)
          if (!isOpen) refreshNotifications()
        }}
        aria-label={`Notifications${unreadCount > 0 ? `, ${unreadCount} unread` : ''}`}
        style={{
          position: 'relative',
          background: 'none',
          border: 'none',
          cursor: 'pointer',
          fontSize: 18,
          padding: '4px 8px',
          lineHeight: 1,
        }}
      >
        🔔
        {unreadCount > 0 && (
          <span
            style={{
              position: 'absolute',
              top: 0,
              right: 2,
              minWidth: 16,
              height: 16,
              borderRadius: 8,
              background: '#f85149',
              color: '#fff',
              fontSize: 10,
              fontWeight: 700,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              padding: '0 4px',
            }}
          >
            {unreadCount}
          </span>
        )}
      </button>

      {isOpen && (
        <div
          className="notification-dropdown"
          style={{
            position: 'absolute',
            top: 'calc(100% + 8px)',
            right: 0,
            width: 300,
            maxHeight: 400,
            overflowY: 'auto',
            background: '#161b22',
            border: '1px solid #30363d',
            borderRadius: 8,
            boxShadow: '0 8px 24px rgba(0,0,0,0.4)',
            zIndex: 1000,
          }}
        >
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '10px 12px',
              borderBottom: '1px solid #30363d',
            }}
          >
            <span style={{ fontWeight: 600, fontSize: 13, color: '#f0f6fc' }}>Notifications</span>
            {notifications.length > 0 && (
              <button
                type="button"
                onClick={markAllRead}
                style={{
                  background: 'none',
                  border: 'none',
                  color: '#58a6ff',
                  fontSize: 11,
                  cursor: 'pointer',
                  padding: 0,
                }}
              >
                Mark all read
              </button>
            )}
          </div>

          {notifications.length === 0 ? (
            <div style={{ padding: '24px 12px', textAlign: 'center', color: '#3fb950', fontSize: 13 }}>
              All clear ✓
            </div>
          ) : (
            <ul style={{ listStyle: 'none', margin: 0, padding: 0 }}>
              {notifications.map((notif) => (
                <li key={notif.id}>
                  <div
                    role="button"
                    tabIndex={0}
                    onClick={() => handleNotificationClick(notif)}
                    onKeyDown={(e) => e.key === 'Enter' && handleNotificationClick(notif)}
                    style={{
                      width: '100%',
                      display: 'flex',
                      gap: 10,
                      alignItems: 'flex-start',
                      padding: '10px 12px',
                      background: notif.read ? 'transparent' : '#1c2128',
                      borderBottom: '1px solid #21262d',
                      cursor: 'pointer',
                      textAlign: 'left',
                    }}
                  >
                    <span style={{ fontSize: 16, flexShrink: 0 }}>{notif.icon}</span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div
                        style={{
                          fontSize: 12,
                          fontWeight: notif.read ? 400 : 700,
                          color: '#f0f6fc',
                          marginBottom: 2,
                        }}
                      >
                        {notif.title}
                      </div>
                      <div
                        style={{
                          fontSize: 11,
                          color: '#8b949e',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {notif.detail}
                      </div>
                      <div style={{ fontSize: 10, color: '#484f58', marginTop: 2 }}>
                        {getRelativeTime(notif.time)}
                      </div>
                    </div>
                    {!notif.read && (
                      <span
                        style={{
                          width: 8,
                          height: 8,
                          borderRadius: '50%',
                          background: '#58a6ff',
                          flexShrink: 0,
                          marginTop: 4,
                        }}
                      />
                    )}
                    <button
                      type="button"
                      onClick={(e) => dismissNotification(e, notif.id)}
                      aria-label="Dismiss"
                      style={{
                        background: 'none',
                        border: 'none',
                        color: '#8b949e',
                        cursor: 'pointer',
                        fontSize: 14,
                        padding: 0,
                        lineHeight: 1,
                        flexShrink: 0,
                      }}
                    >
                      ×
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          )}

          {notifications.length > 0 && (
            <div style={{ padding: '8px 12px', borderTop: '1px solid #30363d' }}>
              <button
                type="button"
                onClick={clearAll}
                style={{
                  width: '100%',
                  background: 'none',
                  border: 'none',
                  color: '#8b949e',
                  fontSize: 11,
                  cursor: 'pointer',
                  padding: '4px 0',
                }}
              >
                Clear all
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
