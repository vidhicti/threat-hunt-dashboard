const TAB_MAP = {
  o: 'overview',
  h: 'heatmap',
  q: 'kql',
  p: 'hypotheses',
  l: 'live-intel',
  i: 'iocs',
  k: 'generator',
  s: 'settings',
}

export function initKeyboardShortcuts(setActiveTab) {
  let lastKey = ''
  let lastKeyTime = 0

  function handleKeyDown(e) {
    const tag = e.target.tagName.toLowerCase()
    if (tag === 'input' || tag === 'textarea' || e.target.isContentEditable) return

    const now = Date.now()
    const key = e.key.toLowerCase()

    if (lastKey === 'g' && now - lastKeyTime < 1000) {
      const tab = TAB_MAP[key]
      if (tab) setActiveTab(tab)
      lastKey = ''
      return
    }

    if (key === '/' && !e.ctrlKey && !e.metaKey) {
      e.preventDefault()
      document.querySelector('.global-search-input')?.focus()
      return
    }

    if (key === 'escape') {
      document.querySelector('.global-search-input')?.blur()
      return
    }

    lastKey = key
    lastKeyTime = now
  }

  window.addEventListener('keydown', handleKeyDown)
  return () => window.removeEventListener('keydown', handleKeyDown)
}
