const STORAGE_KEY = 'huntWorkflow'

export function getWorkflowState() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY)) || {}
  } catch {
    return {}
  }
}

export function saveWorkflowState(state) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state))
}

export function updateHypothesisStatus(id, status, notes, analyst) {
  const state = getWorkflowState()
  state[id] = {
    status,
    notes: notes || '',
    analyst: analyst || '',
    updatedAt: new Date().toISOString(),
    history: [
      ...(state[id]?.history || []),
      { status, timestamp: new Date().toISOString(), notes, analyst },
    ],
  }
  saveWorkflowState(state)
  return state
}

export function getHypothesisWorkflow(id) {
  return (
    getWorkflowState()[id] || {
      status: 'open',
      notes: '',
      analyst: '',
      history: [],
    }
  )
}

export function getWorkflowStats() {
  const state = getWorkflowState()
  const all = Object.values(state)
  return {
    open: all.filter((h) => h.status === 'open' || !h.status).length,
    inProgress: all.filter((h) => h.status === 'in-progress').length,
    truePositive: all.filter((h) => h.status === 'true-positive').length,
    falsePositive: all.filter((h) => h.status === 'false-positive').length,
    closed: all.filter((h) => h.status === 'closed').length,
  }
}

export function updateHypothesisFields(id, notes, analyst) {
  const state = getWorkflowState()
  const prev = state[id] || {
    status: 'open',
    notes: '',
    analyst: '',
    history: [],
  }
  state[id] = {
    ...prev,
    notes: notes ?? prev.notes,
    analyst: analyst ?? prev.analyst,
    updatedAt: new Date().toISOString(),
  }
  saveWorkflowState(state)
  return state
}

export function getClosedThisWeek() {
  const state = getWorkflowState()
  const weekAgo = new Date()
  weekAgo.setDate(weekAgo.getDate() - 7)
  return Object.values(state).filter((h) => {
    if (h.status !== 'closed') return false
    const updated = new Date(h.updatedAt || 0)
    return updated >= weekAgo
  }).length
}

export function countActiveHypotheses(staticHypothesisIds = []) {
  const state = getWorkflowState()
  const staticSet = new Set(staticHypothesisIds)
  let count = 0
  staticHypothesisIds.forEach((id) => {
    const s = state[id]?.status || 'open'
    if (s === 'open' || s === 'in-progress') count += 1
  })
  Object.entries(state).forEach(([id, entry]) => {
    if (staticSet.has(id)) return
    const s = entry.status || 'open'
    if (s === 'open' || s === 'in-progress') count += 1
  })
  return count
}

export function computeStatsForHypotheses(hypothesisList) {
  const counts = {
    open: 0,
    inProgress: 0,
    truePositive: 0,
    falsePositive: 0,
    closed: 0,
  }
  hypothesisList.forEach((hyp) => {
    const status = getHypothesisWorkflow(hyp.id).status || 'open'
    if (status === 'in-progress') counts.inProgress += 1
    else if (status === 'true-positive') counts.truePositive += 1
    else if (status === 'false-positive') counts.falsePositive += 1
    else if (status === 'closed') counts.closed += 1
    else counts.open += 1
  })
  return counts
}
