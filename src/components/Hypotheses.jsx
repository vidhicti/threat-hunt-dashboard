import hypotheses from '../data/hypotheses.json'

const PRIORITY_BORDER = {
  critical: 'var(--red)',
  medium: 'var(--amber)',
  low: 'var(--green)',
}

function Hypotheses() {
  return (
    <div className="hypotheses-list">
      {hypotheses.map((hyp) => (
        <article
          key={hyp.id}
          className="hypothesis-card"
          style={{ borderLeftColor: PRIORITY_BORDER[hyp.priority] }}
        >
          <div className="hypothesis-header">
            <span className="hypothesis-id">{hyp.id}</span>
            <span className={`priority-pill priority-${hyp.priority}`}>
              {hyp.priority}
            </span>
          </div>
          <h3>{hyp.title}</h3>
          <p className="tactic-chain">
            <strong>Tactic chain:</strong> {hyp.tacticChain.join(' → ')}
          </p>
          <p className="log-sources">
            <strong>Log sources:</strong> {hyp.logSources.join(', ')}
          </p>
          <p className="hypothesis-description">{hyp.description}</p>
          <div className="tag-pills">
            {hyp.tags.map((tag) => (
              <span key={tag} className="tag-pill">
                {tag}
              </span>
            ))}
          </div>
        </article>
      ))}
    </div>
  )
}

export default Hypotheses
