import { createContext, useState, useMemo } from 'react'

export const ThreatDataContext = createContext(null)

export function ThreatDataProvider({ children }) {
  const [liveIOCs, setLiveIOCs] = useState([])
  const [iocLoaded, setIocLoaded] = useState(false)

  const value = useMemo(
    () => ({ liveIOCs, setLiveIOCs, iocLoaded, setIocLoaded }),
    [liveIOCs, iocLoaded]
  )

  return (
    <ThreatDataContext.Provider value={value}>{children}</ThreatDataContext.Provider>
  )
}
