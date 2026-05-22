function MetricCards({
  totalTTPs,
  huntQueries,
  hypotheses,
  iocsTracked,
  coveragePercent,
  activeHunts = 0,
  closedThisWeek = 0,
}) {
  const cards = [
    { label: 'Total TTPs Mapped', value: totalTTPs, icon: '🎯' },
    { label: 'Hunt Queries', value: huntQueries, icon: '🔍' },
    { label: 'Hypotheses', value: hypotheses, icon: '💡' },
    { label: 'IOCs Tracked', value: iocsTracked, icon: '⚠️' },
    { label: 'Coverage %', value: `${coveragePercent}%`, icon: '📊' },
    {
      label: 'Active Hunts',
      value: activeHunts,
      icon: '🏹',
      sub: `${closedThisWeek} closed this week`,
      accent: activeHunts > 0 ? 'blue' : 'muted',
    },
  ]

  return (
    <div className="metric-cards metric-cards-6">
      {cards.map((card) => (
        <div
          key={card.label}
          className={`metric-card${card.accent === 'blue' ? ' metric-card-blue' : card.accent === 'muted' ? ' metric-card-muted' : ''}`}
        >
          <span className="metric-icon" aria-hidden="true">
            {card.icon}
          </span>
          <div className="metric-content">
            <span className="metric-value">{card.value}</span>
            <span className="metric-label">{card.label}</span>
            {card.sub && <span className="metric-sub">{card.sub}</span>}
          </div>
        </div>
      ))}
    </div>
  )
}

export default MetricCards
