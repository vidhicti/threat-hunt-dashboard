import techniques from '../data/techniques.json'
import queries from '../data/queries.json'

export function countQueriesForTechnique(techId, queryList = queries) {
  return queryList.filter(
    (q) =>
      q.mitreTechnique === techId ||
      q.mitreTechnique.startsWith(`${techId}.`) ||
      techId.startsWith(`${q.mitreTechnique}.`)
  ).length
}

export function coverageFromQueryCount(count, originalCoverage) {
  if (originalCoverage === 'baselining') return 'baselining'
  if (count === 0) return 'none'
  if (count === 1) return 'low'
  if (count === 2) return 'medium'
  if (count === 3) return 'high'
  return 'critical'
}

export function getTechniquesWithCoverage() {
  return techniques.map((tech) => {
    const queryCount = countQueriesForTechnique(tech.id)
    return {
      ...tech,
      queryCount,
      coverage: coverageFromQueryCount(queryCount, tech.coverage),
    }
  })
}

export function getCoveragePercent() {
  const enriched = getTechniquesWithCoverage()
  const covered = enriched.filter((t) => t.queryCount >= 1).length
  return Math.round((covered / enriched.length) * 100)
}
