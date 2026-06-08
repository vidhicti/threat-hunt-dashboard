import { useState, useEffect } from 'react'
import { fetchAllIOCs, generateWatchlistKQL, FEED_COUNT, isFeedEnabled } from '../services/threatIntel'
import {
  getCachedEnrichment,
  setCachedEnrichment,
  enrichIOC,
  enrichIPWithAbuseIPDB,
  enrichIPWithShodan,
  enrichWithVirusTotal,
} from '../services/iocEnrichment'
import { SOURCE_TO_FEED_ID } from '../data/feedConfig'
import { autoEnrichIPs } from '../services/autoEnrich'
import IocInvestigator from './IocInvestigator'
import localIOCs from '../data/iocs.json'

const PER_PAGE = 50

function mergeCachedEnrichment(iocList) {
  return iocList.map((ioc) => {
    const cached = getCachedEnrichment(ioc.indicator)
    if (!cached) return ioc
    return { ...ioc, ...cached, enriched: true }
  })
}

function applyEnrichmentUpdate(ioc, data) {
  return { ...ioc, ...data, enriched: true }
}

function getConnectorConfig() {
  try {
    return JSON.parse(localStorage.getItem('connectorConfig') || '{}')
  } catch {
    return {}
  }
}

function abuseRiskLabel(score) {
  if (score > 50) return 'High Risk'
  if (score > 20) return 'Medium Risk'
  return 'Low Risk'
}

function abuseBarColor(score) {
  if (score > 50) return '#f85149'
  if (score > 20) return '#d29922'
  return '#3fb950'
}

function sortIOCs(iocs, column, direction) {
  return [...iocs].sort((a, b) => {
    let va = a[column] || ''
    let vb = b[column] || ''
    if (column === 'ttp') {
      va = a.ttpId || a.ttp || ''
      vb = b.ttpId || b.ttp || ''
    }
    if (column === 'confidence') {
      const order = { High: 3, Medium: 2, Low: 1 }
      va = order[va] || 0
      vb = order[vb] || 0
    }
    if (column === 'dateAdded') {
      va = new Date(va).getTime() || 0
      vb = new Date(vb).getTime() || 0
    }
    const cmp = va > vb ? 1 : va < vb ? -1 : 0
    return direction === 'desc' ? -cmp : cmp
  })
}

const countryFlag = (code) =>
  code
    ? String.fromCodePoint(...[...code.toUpperCase()].map((c) => 0x1f1e0 + c.charCodeAt(0) - 65))
    : '—'

export default function IocTracker() {
  const [iocs, setIocs] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [feedStatus, setFeedStatus] = useState({})
  const [lastUpdated, setLastUpdated] = useState(null)
  const [search, setSearch] = useState('')
  const [filterType, setFilterType] = useState('All')
  const [filterSource, setFilterSource] = useState('All')
  const [filterConfidence, setFilterConfidence] = useState('All')
  const [filterStatus, setFilterStatus] = useState('All')
  const [page, setPage] = useState(1)
  const [selected, setSelected] = useState(new Set())
  const [expandedRow, setExpandedRow] = useState(null)
  const [showKQLModal, setShowKQLModal] = useState(false)
  const [generatedKQL, setGeneratedKQL] = useState('')
  const [sort, setSort] = useState({ column: 'dateAdded', direction: 'desc' })
  const [enrichProgress, setEnrichProgress] = useState({ done: 0, total: 0 })
  const [whitelistedIPs, setWhitelistedIPs] = useState(
    JSON.parse(localStorage.getItem('iocWhitelist') || '[]')
  )
  const [showWhitelist, setShowWhitelist] = useState(false)
  const [copyMsg, setCopyMsg] = useState('')
  const [whitelistConfirm, setWhitelistConfirm] = useState(null)
  const [enrichingSource, setEnrichingSource] = useState(null)
  const [investigatingIOC, setInvestigatingIOC] = useState(null)

  useEffect(() => {
    loadIOCs()
  }, [])

  async function loadIOCs() {
    setLoading(true)
    setError(null)
    try {
      const result = await fetchAllIOCs()
      const combined = result?.iocs?.length > 0 ? result.iocs : localIOCs
      
      const filteredByConfig = combined.filter((ioc) => {
        if (!ioc.source) return true
        const feedId = SOURCE_TO_FEED_ID[ioc.source]
        if (!feedId) return true
        return isFeedEnabled(feedId)
      })
      
      // Filter out whitelisted indicators
      const filtered = filteredByConfig.filter(ioc => !whitelistedIPs.includes(ioc.indicator))
      const withCache = mergeCachedEnrichment(filtered)

      setIocs(withCache)
      setFeedStatus(result?.feedStatus || {})
      setLastUpdated(new Date())
      window.dispatchEvent(new CustomEvent('iocCountUpdate', { detail: { count: withCache.length } }))

      setTimeout(() => {
        setEnrichProgress({ done: 0, total: 0 })
        autoEnrichIPs(
          withCache,
          (done, total) => setEnrichProgress({ done, total }),
          (indicator, data) => {
            setIocs((prev) =>
              prev.map((i) =>
                i.indicator === indicator ? applyEnrichmentUpdate(i, data) : i
              )
            )
          }
        )
      }, 2000)
    } catch (err) {
      console.error('IOC fetch error:', err)
      const filtered = mergeCachedEnrichment(
        localIOCs.filter(ioc => !whitelistedIPs.includes(ioc.indicator))
      )
      setIocs(filtered)
      setError('Live feeds unavailable - showing cached data')
      window.dispatchEvent(new CustomEvent('iocCountUpdate', { detail: { count: filtered.length } }))

      setTimeout(() => {
        setEnrichProgress({ done: 0, total: 0 })
        autoEnrichIPs(
          filtered,
          (done, total) => setEnrichProgress({ done, total }),
          (indicator, data) => {
            setIocs((prev) =>
              prev.map((i) =>
                i.indicator === indicator ? applyEnrichmentUpdate(i, data) : i
              )
            )
          }
        )
      }, 2000)
    } finally {
      setLoading(false)
    }
  }

  function addToWhitelist(indicator) {
    const list = [...whitelistedIPs, indicator]
    setWhitelistedIPs(list)
    localStorage.setItem('iocWhitelist', JSON.stringify(list))
    setIocs(prev => prev.filter(i => i.indicator !== indicator))
    setWhitelistConfirm(null)
  }

  function removeFromWhitelist(indicator) {
    const list = whitelistedIPs.filter(i => i !== indicator)
    setWhitelistedIPs(list)
    localStorage.setItem('iocWhitelist', JSON.stringify(list))
    loadIOCs()
  }

  async function enrichWithSource(ioc, source) {
    const config = getConnectorConfig()
    setEnrichingSource(source)
    try {
      let data = null
      if (source === 'abuseipdb' && config.abuseipdb?.apiKey) {
        data = await enrichIPWithAbuseIPDB(ioc.indicator, config.abuseipdb.apiKey)
      } else if (source === 'shodan' && config.shodan?.apiKey) {
        data = await enrichIPWithShodan(ioc.indicator, config.shodan.apiKey)
      } else if (source === 'virustotal' && config.virustotal?.apiKey) {
        data = await enrichWithVirusTotal(ioc.indicator, ioc.type, config.virustotal.apiKey)
      } else if (source === 'all') {
        data = await enrichIOC(ioc)
      }
      if (data) {
        const merged = { ...getCachedEnrichment(ioc.indicator), ...data, enriched: true }
        setCachedEnrichment(ioc.indicator, merged)
        setIocs((prev) =>
          prev.map((i) => (i.indicator === ioc.indicator ? applyEnrichmentUpdate(i, merged) : i))
        )
      }
    } finally {
      setEnrichingSource(null)
    }
  }

  function generateIOCKQL(ioc) {
    if (ioc.type === 'IP') return `CommonSecurityLog\n| where SourceIP == "${ioc.indicator}" or DestinationIP == "${ioc.indicator}"\n| where DeviceVendor in ("Fortinet","Palo Alto Networks","Sophos","Trend Micro")\n| where TimeGenerated > ago(1d)\n| project TimeGenerated, DeviceVendor, SourceIP, DestinationIP, Activity, DeviceAction\n| order by TimeGenerated desc` 
    if (ioc.type === 'Domain') return `ASimDnsActivityLogs\n| where DnsQuery has "${ioc.indicator}"\n| where TimeGenerated > ago(1d)\n| project TimeGenerated, DnsQuery, SrcIpAddr, DnsResponseCode\n| order by TimeGenerated desc` 
    if (ioc.type === 'SHA256') return `DeviceFileEvents\n| where SHA256 == "${ioc.indicator}"\n| where TimeGenerated > ago(1d)\n| project TimeGenerated, DeviceName, FileName, SHA256, InitiatingProcessFileName\n| order by TimeGenerated desc` 
    if (ioc.type === 'URL') return `DeviceNetworkEvents\n| where RemoteUrl has "${ioc.indicator}"\n| where TimeGenerated > ago(1d)\n| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName\n| order by TimeGenerated desc` 
    return `CommonSecurityLog\n| where Message has "${ioc.indicator}"\n| where TimeGenerated > ago(1d)\n| order by TimeGenerated desc` 
  }

  function copyText(text) {
    navigator.clipboard.writeText(text).catch(() => {})
    setCopyMsg('Copied!')
    setTimeout(() => setCopyMsg(''), 2000)
  }

  function exportCSV() {
    const headers = ['Indicator','Type','TTP','TTPId','Malware Family','Log Source','Confidence','Status','Source','Date Added']
    const rows = filtered.map(i => 
      [i.indicator,i.type,i.ttp,i.ttpId,i.malwareFamily,i.logSource,i.confidence,i.status,i.source,i.dateAdded]
      .map(v => `"${(v||'').replace(/"/g,'""')}"`)
      .join(',')
    )
    const csv = [headers.join(','), ...rows].join('\n')
    const blob = new Blob([csv], {type:'text/csv'})
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `iocs-${new Date().toISOString().split('T')[0]}.csv` 
    a.click()
  }

  const filtered = sortIOCs(
    iocs.filter((ioc) => {
      const term = search.toLowerCase()
      if (term && !JSON.stringify(ioc).toLowerCase().includes(term)) return false
      if (filterType !== 'All' && ioc.type !== filterType) return false
      if (filterSource !== 'All' && ioc.source !== filterSource) return false
      if (filterConfidence !== 'All' && ioc.confidence !== filterConfidence) return false
      if (filterStatus !== 'All' && ioc.status !== filterStatus) return false
      return true
    }),
    sort.column,
    sort.direction
  )

  const totalPages = Math.ceil(filtered.length / PER_PAGE)
  const paginated = filtered.slice((page-1)*PER_PAGE, page*PER_PAGE)
  const sources = ['All', ...new Set(iocs.map(i => i.source).filter(Boolean))]
  const types = ['All', ...new Set(iocs.map(i => i.type).filter(Boolean))]
  const feedsOnline = Object.values(feedStatus).filter(Boolean).length
  const minutesAgo = lastUpdated ? Math.max(0, Math.floor((Date.now() - lastUpdated.getTime()) / 60000)) : null

  const stats = {
    total: iocs.length,
    ips: iocs.filter(i => i.type === 'IP').length,
    domainsUrls: iocs.filter(i => ['Domain','URL'].includes(i.type)).length,
    hashes: iocs.filter(i => i.type === 'SHA256').length,
    active: iocs.filter(i => i.status === 'active').length,
    today: iocs.filter(i => i.dateAdded === new Date().toISOString().split('T')[0]).length,
  }

  function toggleSelect(indicator) {
    const s = new Set(selected)
    s.has(indicator) ? s.delete(indicator) : s.add(indicator)
    setSelected(s)
  }

  function toggleSelectAll() {
    const allSelected = paginated.every(i => selected.has(i.indicator))
    setSelected(allSelected ? new Set() : new Set(paginated.map(i => i.indicator)))
  }

  function clearFilters() {
    setSearch('')
    setFilterType('All')
    setFilterSource('All')
    setFilterConfidence('All')
    setFilterStatus('All')
    setPage(1)
  }

  function handleColumnSort(column) {
    setSort((prev) => {
      if (prev.column === column) {
        return { column, direction: prev.direction === 'desc' ? 'asc' : 'desc' }
      }
      return { column, direction: 'desc' }
    })
    setPage(1)
  }

  function SortableTh({ label, column }) {
    const active = sort.column === column
    const icon = active ? (sort.direction === 'asc' ? ' ▲' : ' ▼') : ' ↕'
    return (
      <th
        onClick={() => handleColumnSort(column)}
        style={{
          padding: '8px',
          textAlign: 'left',
          color: '#8b949e',
          fontSize: 10,
          textTransform: 'uppercase',
          letterSpacing: '.06em',
          fontWeight: 500,
          cursor: 'pointer',
          userSelect: 'none',
        }}
      >
        {label}
        <span style={{ color: active ? '#58a6ff' : '#484f58' }}>{icon}</span>
      </th>
    )
  }

  const confColor = c => c==='High'?'#f85149':c==='Medium'?'#d29922':'#8b949e'
  const statusColor = s => s==='active'?'#f85149':s==='investigating'?'#d29922':'#3fb950'

  if (loading) {
    return (
      <div style={{textAlign:"center",padding:"3rem",color:"#8b949e"}}>
        <div style={{fontSize:32,marginBottom:16}}>⟳</div>
        <div style={{fontSize:14}}>Fetching from threat intel feeds...</div>
        <div style={{fontSize:12,marginTop:8}}>ThreatFox · URLhaus · FeodoTracker · MalwareBazaar · EmergingThreats · CINS Army · AlienVault</div>
      </div>
    )
  }

  return (
    <div>
      {error && <div style={{background:"#3d1a1a",border:"1px solid #f85149",borderRadius:6,padding:"8px 12px",marginBottom:12,fontSize:12,color:"#f85149"}}>{error}</div>}
      
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12,flexWrap:"wrap",gap:8}}>
        <div style={{display:"flex",alignItems:"center",gap:8}}>
          <span style={{fontSize:16,fontWeight:600,color:"#f0f6fc"}}>IOC Tracker</span>
          <span style={{width:8,height:8,borderRadius:"50%",background:"#3fb950",display:"inline-block",boxShadow:"0 0 6px #3fb950",animation:"pulse 2s infinite"}}></span>
          <span style={{fontSize:11,color:"#8b949e"}}>LIVE</span>
          <span style={{fontSize:11,padding:"2px 8px",background:"#0d2045",color:"#58a6ff",borderRadius:20,border:"1px solid #58a6ff44"}}>
            {iocs.length} IOCs from {FEED_COUNT} feeds ({feedsOnline} online)
          </span>
        </div>
        <div style={{display:"flex",gap:8,alignItems:"center"}}>
          <span style={{fontSize:11,color:"#8b949e"}}>Updated: {minutesAgo === 0 ? 'just now' : `${minutesAgo} mins ago`}</span>
          <button onClick={loadIOCs} style={{padding:"5px 12px",background:"#58a6ff",border:"none",borderRadius:6,color:"#0d1117",fontSize:12,fontWeight:600,cursor:"pointer"}}>↻ Refresh</button>
          <button onClick={exportCSV} style={{padding:"5px 12px",background:"#21262d",border:"1px solid #30363d",borderRadius:6,color:"#c9d1d9",fontSize:12,cursor:"pointer"}}>Export CSV</button>
          <button onClick={() => setShowWhitelist(true)} style={{padding:"5px 12px",background:"#21262d",border:"1px solid #30363d",borderRadius:6,color:"#c9d1d9",fontSize:12,cursor:"pointer"}}>Whitelist ({whitelistedIPs.length})</button>
        </div>
      </div>

      <div style={{display:"flex",gap:6,flexWrap:"wrap",marginBottom:12}}>
        {Object.entries(feedStatus).map(([feed,ok]) => (
          <span key={feed} style={{fontSize:10,padding:"2px 8px",borderRadius:20,background:ok?"#0d2d1a":"#3d1a1a",color:ok?"#3fb950":"#f85149",border:`1px solid ${ok?"#3fb95040":"#f8514940"}`}}>
            {feed} {ok?'✓':'✗'}
          </span>
        ))}
      </div>

      {enrichProgress.total > 0 && enrichProgress.done < enrichProgress.total && (
        <div style={{ marginBottom: 12 }}>
          <div style={{ fontSize: 11, color: '#8b949e', marginBottom: 4 }}>
            Auto-enriching IPs: {enrichProgress.done}/{enrichProgress.total}
          </div>
          <div style={{ height: 3, background: '#21262d', borderRadius: 2, overflow: 'hidden' }}>
            <div
              style={{
                height: '100%',
                width: `${(enrichProgress.done / enrichProgress.total) * 100}%`,
                background: '#58a6ff',
                borderRadius: 2,
                transition: 'width 0.3s ease',
              }}
            />
          </div>
        </div>
      )}

      <div style={{display:"grid",gridTemplateColumns:"repeat(6,1fr)",gap:8,marginBottom:12}}>
        {[
          ['Total', stats.total, '#58a6ff'],
          ['IPs', stats.ips, '#d29922'],
          ['Domains/URLs', stats.domainsUrls, '#3fb950'],
          ['Hashes', stats.hashes, '#a371f7'],
          ['Active', stats.active, '#f85149'],
          ['Today', stats.today, '#39d3bb'],
        ].map(([label,val,color]) => (
          <div key={label} style={{background:"#161b22",border:"1px solid #30363d",borderRadius:8,padding:"10px 12px"}}>
            <div style={{fontSize:20,fontWeight:600,color}}>{val}</div>
            <div style={{fontSize:10,color:"#8b949e",textTransform:"uppercase",letterSpacing:".06em"}}>{label}</div>
          </div>
        ))}
      </div>

      <div style={{display:"flex",gap:8,marginBottom:12,flexWrap:"wrap"}}>
        <input value={search} onChange={e=>{setSearch(e.target.value);setPage(1)}} placeholder="Search indicators, TTPs, sources..." style={{flex:1,minWidth:200,padding:"7px 12px",background:"#0d1117",border:"1px solid #30363d",borderRadius:6,color:"#c9d1d9",fontSize:12,outline:"none"}} />
        <select value={filterType} onChange={e=>{setFilterType(e.target.value);setPage(1)}} style={{padding:"7px 10px",background:"#161b22",border:"1px solid #30363d",borderRadius:6,color:"#c9d1d9",fontSize:12}}>
          {types.map(t=><option key={t}>{t}</option>)}
        </select>
        <select value={filterSource} onChange={e=>{setFilterSource(e.target.value);setPage(1)}} style={{padding:"7px 10px",background:"#161b22",border:"1px solid #30363d",borderRadius:6,color:"#c9d1d9",fontSize:12}}>
          {sources.map(s=><option key={s}>{s}</option>)}
        </select>
        <select value={filterConfidence} onChange={e=>{setFilterConfidence(e.target.value);setPage(1)}} style={{padding:"7px 10px",background:"#161b22",border:"1px solid #30363d",borderRadius:6,color:"#c9d1d9",fontSize:12}}>
          {['All','High','Medium','Low'].map(c=><option key={c}>{c}</option>)}
        </select>
        <select value={filterStatus} onChange={e=>{setFilterStatus(e.target.value);setPage(1)}} style={{padding:"7px 10px",background:"#161b22",border:"1px solid #30363d",borderRadius:6,color:"#c9d1d9",fontSize:12}}>
          {['All','active','watchlist','investigating'].map(s=><option key={s}>{s}</option>)}
        </select>
        <button onClick={clearFilters} style={{padding:"7px 10px",background:"#21262d",border:"1px solid #30363d",borderRadius:6,color:"#8b949e",fontSize:12,cursor:"pointer"}}>Clear</button>
      </div>

      <div style={{overflowX:"auto",marginBottom:12}}>
        <table style={{width:"100%",borderCollapse:"collapse",fontSize:12}}>
          <thead>
            <tr style={{borderBottom:"1px solid #30363d"}}>
              <th style={{padding:"8px",textAlign:"left",width:32}}><input type="checkbox" checked={paginated.length>0 && paginated.every(i=>selected.has(i.indicator))} onChange={toggleSelectAll} /></th>
              <SortableTh label="Indicator" column="indicator" />
              <SortableTh label="Type" column="type" />
              <th style={{padding:"8px",textAlign:"left",color:"#8b949e",fontSize:10,textTransform:"uppercase",letterSpacing:".06em",fontWeight:500}}>Country</th>
              <SortableTh label="TTP" column="ttp" />
              <th style={{padding:"8px",textAlign:"left",color:"#8b949e",fontSize:10,textTransform:"uppercase",letterSpacing:".06em",fontWeight:500}}>Malware</th>
              <th style={{padding:"8px",textAlign:"left",color:"#8b949e",fontSize:10,textTransform:"uppercase",letterSpacing:".06em",fontWeight:500}}>Log Source</th>
              <SortableTh label="Confidence" column="confidence" />
              <SortableTh label="Status" column="status" />
              <SortableTh label="Source" column="source" />
              <SortableTh label="Date" column="dateAdded" />
              <th style={{padding:"8px",textAlign:"left",color:"#8b949e",fontSize:10,textTransform:"uppercase",letterSpacing:".06em",fontWeight:500}}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {paginated.map((ioc,i) => (
              <>
                <tr key={ioc.indicator+i} onClick={()=>setExpandedRow(expandedRow===i?null:i)} style={{borderBottom:"1px solid #21262d",cursor:"pointer",background:expandedRow===i?"#1c2128":"transparent"}} onMouseEnter={e=>e.currentTarget.style.background="#1c2128"} onMouseLeave={e=>e.currentTarget.style.background=expandedRow===i?"#1c2128":"transparent"}>
                  <td style={{padding:"8px"}} onClick={e=>e.stopPropagation()}><input type="checkbox" checked={selected.has(ioc.indicator)} onChange={()=>toggleSelect(ioc.indicator)} /></td>
                  <td style={{padding:"8px",color:"#58a6ff",maxWidth:180,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",fontFamily:"monospace",fontSize:11}} title={ioc.indicator}>{ioc.indicator}</td>
                  <td style={{padding:"8px"}}><span style={{fontSize:10,padding:"2px 6px",borderRadius:4,background:"#21262d",color:"#c9d1d9",border:"1px solid #30363d"}}>{ioc.type}</span></td>
                  <td style={{padding:"8px",fontSize:11,color:"#c9d1d9",whiteSpace:"nowrap"}}>
                    {ioc.type === 'IP' && ioc.enriched && ioc.countryCode
                      ? <span title={ioc.country}>{countryFlag(ioc.countryCode)} {ioc.countryCode}</span>
                      : '—'}
                  </td>
                  <td style={{padding:"8px",fontSize:11,color:"#c9d1d9",maxWidth:120,overflow:"hidden",textOverflow:"ellipsis"}}>{ioc.ttpId||ioc.ttp}</td>
                  <td style={{padding:"8px",fontSize:11,color:"#8b949e",maxWidth:120,overflow:"hidden",textOverflow:"ellipsis"}}>{ioc.malwareFamily||'—'}</td>
                  <td style={{padding:"8px",fontSize:11,color:"#8b949e"}}>{ioc.logSource}</td>
                  <td style={{padding:"8px"}}><span style={{color:confColor(ioc.confidence),fontWeight:600,fontSize:11}}>{ioc.confidence}</span></td>
                  <td style={{padding:"8px"}}><span style={{display:"inline-block",width:6,height:6,borderRadius:"50%",background:statusColor(ioc.status),marginRight:6}}></span><span style={{fontSize:11,color:"#c9d1d9",textTransform:"capitalize"}}>{ioc.status}</span></td>
                  <td style={{padding:"8px",fontSize:11,color:"#8b949e"}}>{ioc.source}</td>
                  <td style={{padding:"8px",fontSize:11,color:"#8b949e",whiteSpace:"nowrap"}}>{ioc.dateAdded}</td>
                  <td style={{padding:"8px"}}>
                    <div style={{display:"flex",gap:4}}>
                      <button onClick={e=>{e.stopPropagation();setInvestigatingIOC(ioc)}} style={{padding:"2px 6px",background:"#21262d",border:"1px solid #30363d",borderRadius:4,color:"#c9d1d9",fontSize:10,cursor:"pointer"}} title="Investigate">🔍</button>
                      <button onClick={e=>{e.stopPropagation();copyText(generateIOCKQL(ioc))}} style={{padding:"2px 6px",background:"#21262d",border:"1px solid #30363d",borderRadius:4,color:"#c9d1d9",fontSize:10,cursor:"pointer"}}>📋</button>
                      <button onClick={e=>{e.stopPropagation();setWhitelistConfirm(ioc.indicator)}} style={{padding:"2px 6px",background:"#21262d",border:"1px solid #30363d",borderRadius:4,color:"#c9d1d9",fontSize:10,cursor:"pointer"}}>🚫</button>
                    </div>
                  </td>
                </tr>
                {expandedRow===i && (
                  <tr key={'exp'+i} style={{background:"#0d1117"}}>
                    <td colSpan={12} style={{padding:"12px 16px"}}>
                      <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:16}}>
                        <div>
                          <div style={{fontSize:11,color:"#8b949e",marginBottom:8,textTransform:"uppercase",letterSpacing:".06em"}}>Full Indicator</div>
                          <div style={{fontFamily:"monospace",fontSize:12,color:"#58a6ff",wordBreak:"break-all",marginBottom:8}}>{ioc.indicator}</div>
                          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:6,fontSize:11}}>
                            <div><span style={{color:"#8b949e"}}>Type:</span> <span style={{color:"#c9d1d9"}}>{ioc.type}</span></div>
                            <div><span style={{color:"#8b949e"}}>Source:</span> <span style={{color:"#c9d1d9"}}>{ioc.source}</span></div>
                            <div><span style={{color:"#8b949e"}}>TTP:</span> <span style={{color:"#c9d1d9"}}>{ioc.ttp}</span></div>
                            <div><span style={{color:"#8b949e"}}>Malware:</span> <span style={{color:"#c9d1d9"}}>{ioc.malwareFamily||'Unknown'}</span></div>
                            <div><span style={{color:"#8b949e"}}>Confidence:</span> <span style={{color:confColor(ioc.confidence)}}>{ioc.confidence}</span></div>
                            <div><span style={{color:"#8b949e"}}>Status:</span> <span style={{color:"#c9d1d9"}}>{ioc.status}</span></div>
                          </div>
                          <div style={{marginTop:12,paddingTop:12,borderTop:"1px solid #21262d"}}>
                            <div style={{fontSize:11,color:"#8b949e",marginBottom:8,textTransform:"uppercase",letterSpacing:".06em"}}>Threat Intel Enrichment</div>
                            {ioc.type === 'IP' && ioc.enriched ? (
                              <>
                                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:6,fontSize:11,marginBottom:8}}>
                                  <div><span style={{color:"#8b949e"}}>Country:</span> <span style={{color:"#c9d1d9"}}>{countryFlag(ioc.countryCode)} {ioc.country} ({ioc.countryCode})</span></div>
                                  <div><span style={{color:"#8b949e"}}>City:</span> <span style={{color:"#c9d1d9"}}>{ioc.city || '—'}</span></div>
                                  <div><span style={{color:"#8b949e"}}>ISP:</span> <span style={{color:"#c9d1d9"}}>{ioc.isp || '—'}</span></div>
                                  <div><span style={{color:"#8b949e"}}>ASN:</span> <span style={{color:"#c9d1d9"}}>{ioc.asn || '—'}</span></div>
                                </div>
                                {ioc.abuseScore != null && (
                                  <div className="ioc-abuse-score" style={{marginBottom:8}}>
                                    <div style={{fontSize:11,color:"#8b949e",marginBottom:4}}>
                                      Abuse Score: {ioc.abuseScore}/100 ({abuseRiskLabel(ioc.abuseScore)})
                                    </div>
                                    <div style={{height:6,background:"#21262d",borderRadius:3,overflow:"hidden"}}>
                                      <div style={{height:"100%",width:`${ioc.abuseScore}%`,background:abuseBarColor(ioc.abuseScore),borderRadius:3}} />
                                    </div>
                                  </div>
                                )}
                                {ioc.vtScore != null && (
                                  <div style={{fontSize:11,marginBottom:8,color: ioc.vtMalicious > 0 ? '#f85149' : '#c9d1d9'}}>
                                    VT: {ioc.vtMalicious}/{ioc.vtTotal} engines flagged
                                  </div>
                                )}
                                {ioc.openPorts?.length > 0 && (
                                  <div style={{fontSize:11,marginBottom:4,color:"#c9d1d9"}}>
                                    Open Ports: {ioc.openPorts.join(', ')}
                                  </div>
                                )}
                                {ioc.vulns?.length > 0 && (
                                  <div style={{fontSize:11,marginBottom:8,color:"#f85149"}}>
                                    Vulnerabilities: {ioc.vulns.slice(0, 5).join(', ')}{ioc.vulns.length > 5 ? '...' : ''}
                                  </div>
                                )}
                                <div style={{display:"flex",gap:6,flexWrap:"wrap",marginBottom:8}}>
                                  {ioc.isTor && <span style={{fontSize:10,padding:"2px 8px",background:"#3d1a1a",color:"#f85149",borderRadius:4,border:"1px solid #f8514940",fontWeight:600}}>TOR EXIT NODE</span>}
                                  {ioc.isProxy && <span style={{fontSize:10,padding:"2px 8px",background:"#3d1a1a",color:"#f85149",borderRadius:4,border:"1px solid #f8514940",fontWeight:600}}>PROXY</span>}
                                  {ioc.isHosting && <span style={{fontSize:10,padding:"2px 8px",background:"#3d2e0a",color:"#d29922",borderRadius:4,border:"1px solid #d2992240",fontWeight:600}}>VPS/HOSTING</span>}
                                  {ioc.usageType && <span style={{fontSize:10,padding:"2px 8px",background:"#3d2e0a",color:"#d29922",borderRadius:4,border:"1px solid #d2992240"}}>{ioc.usageType}</span>}
                                </div>
                              </>
                            ) : ioc.type === 'IP' ? (
                              <span style={{fontSize:11,color:"#484f58"}}>Not yet enriched</span>
                            ) : ioc.vtScore != null ? (
                              <div style={{fontSize:11,marginBottom:8,color: ioc.vtMalicious > 0 ? '#f85149' : '#c9d1d9'}}>
                                VT: {ioc.vtMalicious}/{ioc.vtTotal} engines flagged
                              </div>
                            ) : (
                              <span style={{fontSize:11,color:"#484f58"}}>No enrichment data yet</span>
                            )}
                            {(() => {
                              const cfg = getConnectorConfig()
                              const enrichButtons = []
                              if (cfg.abuseipdb?.apiKey && cfg.abuseipdb?.enabled !== false && ioc.type === 'IP') {
                                enrichButtons.push({ id: 'abuseipdb', label: 'AbuseIPDB' })
                              }
                              if (cfg.shodan?.apiKey && cfg.shodan?.enabled !== false && ioc.type === 'IP') {
                                enrichButtons.push({ id: 'shodan', label: 'Shodan' })
                              }
                              if (cfg.virustotal?.apiKey && cfg.virustotal?.enabled !== false) {
                                enrichButtons.push({ id: 'virustotal', label: 'VirusTotal' })
                              }
                              if (enrichButtons.length === 0) return null
                              return (
                                <div style={{display:"flex",gap:6,flexWrap:"wrap",marginTop:8}}>
                                  {enrichButtons.map((btn) => (
                                    <button
                                      key={btn.id}
                                      onClick={() => enrichWithSource(ioc, btn.id)}
                                      disabled={enrichingSource === btn.id}
                                      style={{padding:"4px 10px",background:"#0d2045",border:"1px solid #58a6ff44",borderRadius:6,color:"#58a6ff",fontSize:10,cursor:enrichingSource === btn.id ? 'default' : 'pointer',opacity:enrichingSource === btn.id ? 0.6 : 1}}
                                    >
                                      {enrichingSource === btn.id ? 'Enriching...' : `Enrich with ${btn.label}`}
                                    </button>
                                  ))}
                                </div>
                              )
                            })()}
                          </div>
                          <div style={{display:"flex",gap:8,marginTop:12}}>
                            <button onClick={()=>copyText(ioc.indicator)} style={{padding:"5px 10px",background:"#21262d",border:"1px solid #30363d",borderRadius:6,color:"#c9d1d9",fontSize:11,cursor:"pointer"}}>Copy IOC</button>
                          </div>
                        </div>
                        <div>
                          <div style={{fontSize:11,color:"#8b949e",marginBottom:8,textTransform:"uppercase",letterSpacing:".06em"}}>Sentinel KQL</div>
                          <pre style={{background:"#161b22",border:"1px solid #30363d",borderRadius:6,padding:"10px",fontSize:10,fontFamily:"monospace",color:"#c9d1d9",whiteSpace:"pre-wrap",wordBreak:"break-all",margin:0,maxHeight:150,overflow:"auto"}}>{generateIOCKQL(ioc)}</pre>
                          <div style={{display:"flex",gap:8,marginTop:8}}>
                            <button onClick={()=>copyText(generateIOCKQL(ioc))} style={{padding:"5px 10px",background:"#21262d",border:"1px solid #30363d",borderRadius:6,color:"#c9d1d9",fontSize:11,cursor:"pointer"}}>Copy KQL</button>
                            <a href="https://portal.azure.com/#blade/Microsoft_Azure_Monitoring_Logs/LogsBlade" target="_blank" rel="noreferrer" style={{padding:"5px 10px",background:"#0d2045",border:"1px solid #58a6ff44",borderRadius:6,color:"#58a6ff",fontSize:11,textDecoration:"none"}}>Open in Sentinel →</a>
                          </div>
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </>
            ))}
          </tbody>
        </table>
      </div>

      <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",flexWrap:"wrap",gap:8}}>
        <div style={{fontSize:12,color:"#8b949e"}}>
          Showing {Math.min((page-1)*PER_PAGE+1, filtered.length)}–{Math.min(page*PER_PAGE, filtered.length)} of {filtered.length}
          {selected.size>0 && <span style={{marginLeft:12,color:"#58a6ff"}}>{selected.size} selected</span>}
        </div>
        <div style={{display:"flex",gap:4,alignItems:"center"}}>
          <button onClick={()=>setPage(p=>Math.max(1,p-1))} disabled={page===1} style={{padding:"5px 10px",background:"#21262d",border:"1px solid #30363d",borderRadius:6,color:page===1?"#484f58":"#c9d1d9",fontSize:12,cursor:page===1?"default":"pointer"}}>← Prev</button>
          {Array.from({length:Math.min(5,totalPages)},(_,i)=>{
            let p = page<=3?i+1:page+i-2
            if(p>totalPages) return null
            return <button key={p} onClick={()=>setPage(p)} style={{padding:"5px 10px",background:page===p?"#58a6ff":"#21262d",border:"1px solid #30363d",borderRadius:6,color:page===p?"#0d1117":"#c9d1d9",fontSize:12,cursor:"pointer"}}>{p}</button>
          })}
          <button onClick={()=>setPage(p=>Math.min(totalPages,p+1))} disabled={page===totalPages} style={{padding:"5px 10px",background:"#21262d",border:"1px solid #30363d",borderRadius:6,color:page===totalPages?"#484f58":"#c9d1d9",fontSize:12,cursor:page===totalPages?"default":"pointer"}}>Next →</button>
        </div>
        {selected.size>0 && (
          <button onClick={()=>{
            const sel = iocs.filter(i=>selected.has(i.indicator))
            setGeneratedKQL(generateWatchlistKQL(sel))
            setShowKQLModal(true)
          }} style={{padding:"6px 14px",background:"#0d2045",border:"1px solid #58a6ff44",borderRadius:6,color:"#58a6ff",fontSize:12,cursor:"pointer"}}>
            Generate Watchlist KQL ({selected.size})
          </button>
        )}
      </div>

      {showKQLModal && (
        <div style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,0.8)",zIndex:1000,display:"flex",alignItems:"center",justifyContent:"center"}} onClick={()=>setShowKQLModal(false)}>
          <div style={{background:"#161b22",border:"1px solid #30363d",borderRadius:10,padding:"1.5rem",maxWidth:700,width:"90%",maxHeight:"80vh",overflow:"auto"}} onClick={e=>e.stopPropagation()}>
            <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:12}}>
              <span style={{fontSize:14,fontWeight:600,color:"#f0f6fc"}}>Sentinel Watchlist KQL</span>
              <button onClick={()=>setShowKQLModal(false)} style={{background:"none",border:"none",color:"#8b949e",fontSize:18,cursor:"pointer"}}>✕</button>
            </div>
            <pre style={{background:"#0d1117",border:"1px solid #30363d",borderRadius:6,padding:"12px",fontSize:11,fontFamily:"monospace",color:"#c9d1d9",whiteSpace:"pre-wrap",marginBottom:12}}>{generatedKQL}</pre>
            <div style={{display:"flex",gap:8}}>
              <button onClick={()=>copyText(generatedKQL)} style={{padding:"6px 14px",background:"#21262d",border:"1px solid #30363d",borderRadius:6,color:"#c9d1d9",fontSize:12,cursor:"pointer"}}>Copy KQL</button>
              <a href="https://portal.azure.com/#blade/Microsoft_Azure_Monitoring_Logs/LogsBlade" target="_blank" rel="noreferrer" style={{padding:"6px 14px",background:"#0d2045",border:"1px solid #58a6ff44",borderRadius:6,color:"#58a6ff",fontSize:12,textDecoration:"none"}}>Open in Sentinel →</a>
            </div>
          </div>
        </div>
      )}

      {showWhitelist && (
        <div style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,0.8)",zIndex:1000,display:"flex",alignItems:"center",justifyContent:"center"}} onClick={()=>setShowWhitelist(false)}>
          <div style={{background:"#161b22",border:"1px solid #30363d",borderRadius:10,padding:"1.5rem",maxWidth:500,width:"90%",maxHeight:"80vh",overflow:"auto"}} onClick={e=>e.stopPropagation()}>
            <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:12}}>
              <span style={{fontSize:14,fontWeight:600,color:"#f0f6fc"}}>IOC Whitelist</span>
              <button onClick={()=>setShowWhitelist(false)} style={{background:"none",border:"none",color:"#8b949e",fontSize:18,cursor:"pointer"}}>✕</button>
            </div>
            {whitelistedIPs.length === 0 ? (
              <p style={{color:"#8b949e",fontSize:12}}>No whitelisted indicators</p>
            ) : (
              <div style={{maxHeight:300,overflow:"auto",marginBottom:12}}>
                {whitelistedIPs.map((ip, idx) => (
                  <div key={idx} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"8px",background:"#0d1117",borderRadius:4,marginBottom:4}}>
                    <span style={{fontFamily:"monospace",fontSize:11,color:"#c9d1d9"}}>{ip}</span>
                    <button onClick={()=>removeFromWhitelist(ip)} style={{padding:"2px 8px",background:"#f85149",border:"none",borderRadius:4,color:"#0d1117",fontSize:10,cursor:"pointer"}}>✕</button>
                  </div>
                ))}
              </div>
            )}
            {whitelistedIPs.length > 0 && (
              <button onClick={()=>{
                setWhitelistedIPs([])
                localStorage.setItem('iocWhitelist', '[]')
                loadIOCs()
              }} style={{width:"100%",padding:"8px",background:"#f85149",border:"none",borderRadius:6,color:"#0d1117",fontSize:12,cursor:"pointer",marginBottom:12}}>
                Clear All Whitelist
              </button>
            )}
          </div>
        </div>
      )}

      {whitelistConfirm && (
        <div style={{position:"fixed",top:0,left:0,right:0,bottom:0,background:"rgba(0,0,0,0.8)",zIndex:1001,display:"flex",alignItems:"center",justifyContent:"center"}} onClick={()=>setWhitelistConfirm(null)}>
          <div style={{background:"#161b22",border:"1px solid #30363d",borderRadius:10,padding:"1.5rem",maxWidth:400,width:"90%"}} onClick={e=>e.stopPropagation()}>
            <div style={{fontSize:14,fontWeight:600,color:"#f0f6fc",marginBottom:12}}>Add to Whitelist?</div>
            <p style={{color:"#8b949e",fontSize:12,marginBottom:16}}>
              This will hide <span style={{fontFamily:"monospace",color:"#58a6ff"}}>{whitelistConfirm}</span> from the IOC tracker. You can remove it from the whitelist in Settings.
            </p>
            <div style={{display:"flex",gap:8,justifyContent:"flex-end"}}>
              <button onClick={()=>setWhitelistConfirm(null)} style={{padding:"6px 14px",background:"#21262d",border:"1px solid #30363d",borderRadius:6,color:"#c9d1d9",fontSize:12,cursor:"pointer"}}>Cancel</button>
              <button onClick={()=>addToWhitelist(whitelistConfirm)} style={{padding:"6px 14px",background:"#f85149",border:"none",borderRadius:6,color:"#0d1117",fontSize:12,cursor:"pointer"}}>Add to Whitelist</button>
            </div>
          </div>
        </div>
      )}

      {investigatingIOC && (
        <IocInvestigator
          ioc={investigatingIOC}
          onClose={() => setInvestigatingIOC(null)}
          onAddToWatchlist={(ioc) => {
            setSelected((prev) => new Set([...prev, ioc.indicator]))
          }}
          onWhitelist={(indicator) => {
            addToWhitelist(indicator)
            setInvestigatingIOC(null)
          }}
        />
      )}

      {copyMsg && (
        <div style={{position:"fixed",bottom:20,right:20,background:"#3fb950",color:"#0d1117",padding:"8px 16px",borderRadius:6,fontSize:12,zIndex:1002}}>
          {copyMsg}
        </div>
      )}

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
      `}</style>
    </div>
  )
}
