const SESSIONS_KEY = 'huntSessions'
const ACTIVE_KEY = 'activeHuntSessionId'

function loadSessions() {
  try {
    return JSON.parse(localStorage.getItem(SESSIONS_KEY) || '[]')
  } catch {
    return []
  }
}

function saveSessions(sessions) {
  localStorage.setItem(SESSIONS_KEY, JSON.stringify(sessions))
}

export function getHuntSessions() {
  return loadSessions()
}

export function getActiveSessionId() {
  return localStorage.getItem(ACTIVE_KEY)
}

export function getActiveSession() {
  const id = getActiveSessionId()
  if (!id) return null
  return loadSessions().find((s) => s.id === Number(id) && s.status === 'active') || null
}

export function setActiveSessionId(id) {
  if (id == null) localStorage.removeItem(ACTIVE_KEY)
  else localStorage.setItem(ACTIVE_KEY, String(id))
}

export function createSession({ name, analyst, scope, hypothesesIncluded }) {
  const sessions = loadSessions()
  const session = {
    id: Date.now(),
    name,
    analyst: analyst || localStorage.getItem('analystName') || '',
    startTime: new Date().toISOString(),
    endTime: null,
    scope,
    hypothesesIncluded: hypothesesIncluded || [],
    status: 'active',
    findings: '',
    conclusion: null,
    totalIOCsReviewed: 0,
    queriesRun: 0,
  }
  sessions.push(session)
  saveSessions(sessions)
  setActiveSessionId(session.id)
  return session
}

export function updateActiveSession(updates) {
  const id = getActiveSessionId()
  if (!id) return null
  const sessions = loadSessions()
  const idx = sessions.findIndex((s) => s.id === Number(id))
  if (idx === -1) return null
  sessions[idx] = { ...sessions[idx], ...updates }
  saveSessions(sessions)
  return sessions[idx]
}

export function completeSession({ conclusion, findings }) {
  const session = getActiveSession()
  if (!session) return null
  const sessions = loadSessions()
  const idx = sessions.findIndex((s) => s.id === session.id)
  if (idx === -1) return null
  sessions[idx] = {
    ...sessions[idx],
    status: 'completed',
    endTime: new Date().toISOString(),
    conclusion,
    findings: findings ?? sessions[idx].findings,
  }
  saveSessions(sessions)
  setActiveSessionId(null)
  return sessions[idx]
}

export function abandonSession() {
  const session = getActiveSession()
  if (!session) return
  const sessions = loadSessions().filter((s) => s.id !== session.id)
  saveSessions(sessions)
  setActiveSessionId(null)
}

export function incrementQueriesRun() {
  const session = getActiveSession()
  if (!session) return
  updateActiveSession({ queriesRun: (session.queriesRun || 0) + 1 })
}

export function formatDuration(ms) {
  const totalSec = Math.floor(ms / 1000)
  const h = Math.floor(totalSec / 3600)
  const m = Math.floor((totalSec % 3600) / 60)
  const s = totalSec % 60
  return [h, m, s].map((n) => String(n).padStart(2, '0')).join(':')
}

export function exportSessionMarkdown(session) {
  const duration =
    session.endTime && session.startTime
      ? formatDuration(new Date(session.endTime) - new Date(session.startTime))
      : '—'
  let md = `# Hunt Session: ${session.name}\n\n`
  md += `**Analyst:** ${session.analyst || '—'}  \n`
  md += `**Started:** ${new Date(session.startTime).toLocaleString()}  \n`
  md += `**Ended:** ${session.endTime ? new Date(session.endTime).toLocaleString() : '—'}  \n`
  md += `**Duration:** ${duration}  \n`
  md += `**Conclusion:** ${session.conclusion || '—'}  \n`
  md += `**Queries Run:** ${session.queriesRun || 0}  \n`
  md += `**IOCs Reviewed:** ${session.totalIOCsReviewed || 0}  \n\n`
  md += `## Scope\n${session.scope || '—'}\n\n`
  md += `## Findings\n${session.findings || '—'}\n\n`
  if (session.hypothesesIncluded?.length) {
    md += `## Hypotheses Included\n${session.hypothesesIncluded.join(', ')}\n`
  }
  return md
}
