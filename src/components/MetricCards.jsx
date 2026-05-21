function MetricCards({ totalTTPs, huntQueries, hypotheses, iocsTracked, coveragePercent }) {
  const cards = [
    { label: 'Total TTPs Mapped', value: totalTTPs, icon: '🎯' },
    { label: 'Hunt Queries', value: huntQueries, icon: '🔍' },
    { label: 'Hypotheses', value: hypotheses, icon: '💡' },
    { label: 'IOCs Tracked', value: iocsTracked, icon: '⚠️' },
    { label: 'Coverage %', value: `${coveragePercent}%`, icon: '📊' },
  ]

  return (
    <div className="metric-cards">
      {cards.map((card) => (
        <div key={card.label} className="metric-card">
          <span className="metric-icon" aria-hidden="true">
            {card.icon}
          </span>
          <div className="metric-content">
            <span className="metric-value">{card.value}</span>
            <span className="metric-label">{card.label}</span>
          </div>
        </div>
      ))}
    </div>
  )
}

export default MetricCards
