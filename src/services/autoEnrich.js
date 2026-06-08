import { enrichIOC, getCachedEnrichment, setCachedEnrichment } from './iocEnrichment'

export async function autoEnrichIPs(iocs, onProgress, onUpdate) {
  const ips = iocs
    .filter((i) => i.type === 'IP')
    .filter((i) => !getCachedEnrichment(i.indicator))
    .slice(0, 100)

  if (ips.length === 0) return

  onProgress?.(0, ips.length)

  let enriched = 0
  const updates = {}

  for (const ioc of ips) {
    try {
      await new Promise((r) => setTimeout(r, 1400))

      const data = await enrichIOC(ioc)
      if (data.enriched) {
        setCachedEnrichment(ioc.indicator, data)
        updates[ioc.indicator] = data
        enriched++
        onUpdate?.(ioc.indicator, data)
        onProgress?.(enriched, ips.length)
      }
    } catch {
      // Skip failed enrichments silently
    }
  }

  return updates
}
