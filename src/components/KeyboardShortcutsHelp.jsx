import { useEffect } from 'react'

const SHORTCUTS = [
  { section: 'NAVIGATION (press G then key)' },
  { keys: 'G + O', desc: 'Overview' },
  { keys: 'G + H', desc: 'MITRE Heatmap' },
  { keys: 'G + Q', desc: 'KQL Library' },
  { keys: 'G + P', desc: 'Hypotheses' },
  { keys: 'G + L', desc: 'Live Intel' },
  { keys: 'G + I', desc: 'IOC Tracker' },
  { keys: 'G + K', desc: 'KQL Generator' },
  { keys: 'G + S', desc: 'Settings' },
  { section: 'SEARCH' },
  { keys: '/', desc: 'Focus search bar' },
  { keys: 'Esc', desc: 'Clear search focus' },
]

export default function KeyboardShortcutsHelp({ open, onClose }) {
  useEffect(() => {
    if (!open) return
    function onKey(e) {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  if (!open) return null

  return (
    <div
      className="shortcuts-modal-backdrop"
      onClick={onClose}
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.75)',
        zIndex: 2000,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 16,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: 400,
          maxWidth: '100%',
          background: '#161b22',
          border: '1px solid #30363d',
          borderRadius: 10,
          padding: '1.25rem',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <h2 style={{ margin: 0, fontSize: 16, color: '#f0f6fc' }}>Keyboard Shortcuts</h2>
          <button
            type="button"
            onClick={onClose}
            style={{ background: 'none', border: 'none', color: '#8b949e', fontSize: 20, cursor: 'pointer' }}
          >
            ×
          </button>
        </div>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <tbody>
            {SHORTCUTS.map((row, i) =>
              row.section ? (
                <tr key={i}>
                  <td
                    colSpan={2}
                    style={{
                      padding: '10px 0 6px',
                      color: '#8b949e',
                      fontSize: 11,
                      fontWeight: 600,
                      textTransform: 'uppercase',
                      letterSpacing: '.05em',
                    }}
                  >
                    {row.section}
                  </td>
                </tr>
              ) : (
                <tr key={i} style={{ borderBottom: '1px solid #21262d' }}>
                  <td
                    style={{
                      padding: '8px 12px 8px 0',
                      fontFamily: 'monospace',
                      color: '#58a6ff',
                      whiteSpace: 'nowrap',
                      width: 100,
                    }}
                  >
                    {row.keys}
                  </td>
                  <td style={{ padding: '8px 0', color: '#c9d1d9' }}>{row.desc}</td>
                </tr>
              )
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
