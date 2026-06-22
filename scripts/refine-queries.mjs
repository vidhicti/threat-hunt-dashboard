import { readFileSync, writeFileSync } from 'fs'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'

const __dirname = dirname(fileURLToPath(import.meta.url))
const queriesPath = join(__dirname, '../src/data/queries.json')

const BASELINE =
  '// BASELINE: Adjust thresholds based on your environment\n// LOOKBACK: Change ago() value based on hunt scope\n'

const SPECIFIC_KQL = {
  Q01: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ('winword.exe','excel.exe','powerpnt.exe','outlook.exe','mspub.exe','visio.exe')
| where FileName in~ ('powershell.exe','pwsh.exe','wscript.exe','cscript.exe','cmd.exe','mshta.exe','rundll32.exe','regsvr32.exe','certutil.exe','bitsadmin.exe')
| where InitiatingProcessCommandLine !contains "OfficeClickToRun"
| where InitiatingProcessFileName !in~ ('MsMpEng.exe','SenseIR.exe','csrss.exe','services.exe','svchost.exe')
| extend SuspiciousIndicators = case(
    ProcessCommandLine has_any ('-enc','-encodedcommand','-ec','-en'), 'EncodedCommand',
    ProcessCommandLine has_any ('http','https','ftp'), 'NetworkConnection', 
    ProcessCommandLine has_any ('IEX','Invoke-Expression','DownloadString','DownloadFile'), 'Download',
    ProcessCommandLine has_any ('bypass','hidden','noninteractive','-nop'), 'Evasion',
    'SuspiciousExecution')
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, 
    FileName, ProcessCommandLine, SuspiciousIndicators,
    InitiatingProcessCommandLine
| order by Timestamp desc`,
  Q02: `SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4688
| extend ProcessName = tostring(split(NewProcessName,'\\\\')[-1])
| where ProcessName in~ ('certutil.exe','msiexec.exe','regsvr32.exe','rundll32.exe','wmic.exe','mshta.exe','bitsadmin.exe','installutil.exe','regasm.exe','regsvcs.exe','cmstp.exe','msbuild.exe','dnscmd.exe','odbcconf.exe','pcalua.exe')
| where CommandLine has_any ('-urlcache','-decode','-encode','http://','https://','ftp://','\\\\\\\\','javascript:','vbscript:','/i:http','/sta','scrobj.dll')
| where SubjectUserName !endswith '$'
| where SubjectUserName !in ('Administrator', 'admin', 'svc_backup', 'breakglass')
| where NewProcessName !startswith 'C:\\\\Windows\\\\WinSxS\\\\'
| extend ThreatIndicator = case(
    CommandLine has '-urlcache', 'FileDownload',
    CommandLine has '-decode', 'Base64Decode',
    CommandLine has 'javascript:', 'JavaScriptExecution',
    CommandLine has '\\\\\\\\', 'UNCPathExecution',
    'SuspiciousLOLBin')
| project TimeGenerated, Computer, SubjectUserName, NewProcessName, CommandLine, ThreatIndicator, ParentProcessName
| order by TimeGenerated desc`,
  Q03: `SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID in (4698, 4702)
| extend TaskName = tostring(EventData.TaskName)
| extend TaskContent = tostring(EventData.TaskContent)
| extend ClientProcessId = tostring(EventData.ClientProcessId)
| where TaskContent has_any ('powershell','cmd','wscript','cscript','mshta','regsvr32','rundll32','certutil','bitsadmin')
| where TaskContent has_any ('%temp%','%appdata%','%public%','\\\\users\\\\','\\\\programdata\\\\','c:\\\\windows\\\\temp')
    or TaskContent has_any ('http','https','ftp','\\\\\\\\')
| extend SuspiciousPath = extract(@'(?i)(c:\\\\users\\\\[^\\\\]+\\\\appdata|%temp%|c:\\\\windows\\\\temp|c:\\\\programdata)', 0, TaskContent)
| extend HasNetworkIndicator = TaskContent has_any ('http','https','ftp','\\\\\\\\')
| project TimeGenerated, Computer, Account, TaskName, SuspiciousPath, HasNetworkIndicator, TaskContent
| order by TimeGenerated desc`,
  Q07: `DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ 'powershell.exe' or FileName =~ 'pwsh.exe'
| where ProcessCommandLine matches regex @'(?i)[-/][Ee][Nn][Cc][Oo]?[Dd]?[Ee]?[Dd]?[Cc]?[Oo]?[Mm]?[Mm]?[Aa]?[Nn]?[Dd]?'
    or ProcessCommandLine has '-ec '
    or ProcessCommandLine has ' -en '
| where InitiatingProcessFileName !in~ ('MsMpEng.exe','SenseIR.exe','csrss.exe','services.exe','svchost.exe')
| extend EncodedPayload = extract(@'(?i)[-/][Ee][Nn][Cc][a-zA-Z]* ([A-Za-z0-9+/=]{20,})', 1, ProcessCommandLine)
| extend DecodedPayload = base64_decode_tostring(EncodedPayload)
| extend HasSuspiciousDecoded = DecodedPayload has_any ('IEX','Invoke-Expression','DownloadString','WebClient','Net.WebClient','System.Net','DownloadFile','bypass','hidden','Start-Process','Invoke-Command','Enter-PSSession')
| extend CommandLength = strlen(ProcessCommandLine)
| where isnotempty(EncodedPayload)
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, 
    EncodedPayload, DecodedPayload, HasSuspiciousDecoded, CommandLength
| order by Timestamp desc`,
  Q29: `DeviceEvents
| where Timestamp > ago(1d)
| where ActionType == 'OpenProcess'
| where FileName =~ 'lsass.exe'
| where InitiatingProcessFileName !in~ (
    'MsMpEng.exe','SenseIR.exe','csrss.exe','werfault.exe','WerFaultSecure.exe',
    'taskmgr.exe','procexp.exe','procexp64.exe','perfmon.exe','mmc.exe',
    'services.exe','lsm.exe','svchost.exe','SecurityHealthService.exe')
| extend IsKnownHackTool = InitiatingProcessFileName in~ ('procdump.exe','procdump64.exe','mimikatz.exe','pwdump.exe','fgdump.exe','wce.exe','gsecdump.exe')
| extend SuspiciousPath = InitiatingProcessFolderPath !startswith 'C:\\\\Windows\\\\System32\\\\'
    and InitiatingProcessFolderPath !startswith 'C:\\\\Windows\\\\SysWOW64\\\\'
    and InitiatingProcessFolderPath !startswith 'C:\\\\Program Files\\\\'
| extend RiskLevel = case(
    IsKnownHackTool, 'CRITICAL - Known Credential Dump Tool',
    SuspiciousPath, 'HIGH - Process from suspicious path',
    'MEDIUM - Unexpected LSASS access')
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
    InitiatingProcessFolderPath, InitiatingProcessCommandLine, 
    IsKnownHackTool, RiskLevel
| order by Timestamp desc`,
  Q43: `SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4624
| where LogonType == 3
| where AuthenticationPackageName == 'NTLM'
| where AccountName !endswith '$'
| where AccountName !in ('Administrator', 'admin', 'svc_backup', 'breakglass')
| where WorkstationName != ComputerName
| where IpAddress !in ('::1','127.0.0.1','')
| where IpAddress !startswith '169.254'
| extend IsInternalIP = ipv4_is_private(IpAddress)
| where IsInternalIP == true
| summarize 
    LogonCount = count(),
    DistinctTargets = dcount(ComputerName),
    DistinctSourceIPs = dcount(IpAddress),
    TargetComputers = make_set(ComputerName, 10),
    TimeRange = strcat(format_datetime(min(TimeGenerated),'HH:mm'), '-', format_datetime(max(TimeGenerated),'HH:mm'))
    by AccountName, IpAddress, bin(TimeGenerated, 1h)
| where DistinctTargets >= 3 or LogonCount >= 10
| extend RiskScore = (DistinctTargets * 20) + (LogonCount * 2)
| order by RiskScore desc`,
  Q57: `DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType in ('FileCreated','FileRenamed','FileModified')
| where FolderPath !startswith 'C:\\\\Windows\\\\'
| where FolderPath !startswith 'C:\\\\Program Files\\\\'
| extend FileExtension = tostring(split(FileName,'.')[-1])
| extend IsSuspiciousExtension = FileExtension in~ (
    'encrypted','enc','locked','crypto','crypt','locky','zepto','odin','aes',
    'cerber','ctb','ccc','xxx','ttt','micro','thor','zzz','xyz','abc','ecc',
    'ezz','exx','vvv','wtt','lcked','rekt','gg','good','ransomware',
    'wncry','wcry','wncryt','onion','happy','satan','crypted')
| summarize 
    TotalFileChanges = count(),
    SuspiciousExtCount = countif(IsSuspiciousExtension),
    UniqueExtensions = dcount(FileExtension),
    AffectedFolders = dcount(FolderPath),
    SampleFiles = make_set(FileName, 5)
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, 5m)
| where TotalFileChanges >= 50 or SuspiciousExtCount >= 5
| extend RansomwareRisk = case(
    SuspiciousExtCount >= 5, 'CRITICAL - Known ransomware extension detected',
    TotalFileChanges >= 200, 'HIGH - Mass file modification',
    'MEDIUM - Unusual file activity')
| order by TotalFileChanges desc`,
}

const TITLE_UPDATES = {
  Q01: {
    title: 'Phishing Macro Execution Chain',
    logSource: 'MDE',
    mitreTechnique: 'T1566.001',
    description:
      'Detects Office applications spawning suspicious scripting binaries indicative of macro-based phishing execution chains.',
  },
  Q02: {
    title: 'LOLBin Execution',
    logSource: 'SecurityEvents',
    mitreTechnique: 'T1218',
    description:
      'Identifies living-off-the-land binaries with suspicious command-line indicators in Security Event 4688 logs.',
  },
  Q03: {
    title: 'Scheduled Task Creation',
    logSource: 'SecurityEvents',
    mitreTechnique: 'T1053.005',
    description:
      'Detects scheduled tasks created or modified with suspicious paths, scripting engines, or network indicators.',
  },
}

const LOGON_EXCLUSION_SECURITY =
  "| where SubjectUserName !in ('Administrator', 'admin', 'svc_backup', 'breakglass')"
const LOGON_EXCLUSION_ACCOUNT =
  "| where Account !in ('Administrator', 'admin', 'svc_backup', 'breakglass')"
const LOGON_EXCLUSION_SIGNIN =
  "| where UserPrincipalName !in ('admin@company.com', 'breakglass@company.com')"
const LOGON_EXCLUSION_MDE =
  "| where AccountName !in ('Administrator', 'admin', 'svc_backup', 'breakglass')"

const PROCESS_EXCLUSION_MDE =
  "| where InitiatingProcessFileName !in~ ('MsMpEng.exe','SenseIR.exe','csrss.exe','services.exe','svchost.exe','explorer.exe')"
const PROCESS_EXCLUSION_4688 =
  "| where NewProcessName !startswith 'C:\\\\Windows\\\\WinSxS\\\\'"

const NETWORK_EXCLUSION_CSL =
  '| where not(ipv4_is_private(tostring(DestinationIP))) or not(ipv4_is_private(tostring(SourceIP)))'
const NETWORK_EXCLUSION_MDE =
  '| where not(ipv4_is_private(RemoteIP))'

function hasExclusion(kql, pattern) {
  return kql.includes(pattern.slice(0, 30))
}

function injectAfterFirstWhere(kql, line) {
  if (hasExclusion(kql, line)) return kql
  const lines = kql.split('\n')
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].trim().startsWith('| where')) {
      lines.splice(i + 1, 0, line)
      return lines.join('\n')
    }
  }
  if (lines.length > 1) {
    lines.splice(1, 0, line)
  }
  return lines.join('\n')
}

function isLogonQuery(kql) {
  return (
    /EventID == 4624|EventID == 4625|EventID in \(4624|SigninLogs|LogonType/.test(kql) &&
    !/EventID == 4688/.test(kql)
  )
}

function isProcessQuery(kql) {
  return /DeviceProcessEvents|EventID == 4688/.test(kql)
}

function isNetworkQuery(kql) {
  return (
    /DeviceNetworkEvents|CommonSecurityLog|ASimDnsActivityLogs/.test(kql) &&
    !/ipv4_is_private/.test(kql) &&
    !/DistinctPorts|internal/.test(kql)
  )
}

function refineKql(query) {
  if (SPECIFIC_KQL[query.id]) {
    return BASELINE + SPECIFIC_KQL[query.id]
  }

  let kql = query.kql.replace(/^\/\/ BASELINE:[\s\S]*?\n\n?/, '')

  if (isLogonQuery(kql)) {
    if (kql.includes('SigninLogs') || kql.includes('UserPrincipalName')) {
      kql = injectAfterFirstWhere(kql, LOGON_EXCLUSION_SIGNIN)
    } else if (kql.includes('AccountName') && kql.includes('Device')) {
      kql = injectAfterFirstWhere(kql, LOGON_EXCLUSION_MDE)
    } else if (kql.includes('extend Account =')) {
      kql = injectAfterFirstWhere(kql, LOGON_EXCLUSION_ACCOUNT)
    } else if (kql.includes('SecurityEvent')) {
      kql = injectAfterFirstWhere(kql, LOGON_EXCLUSION_SECURITY)
    }
  }

  if (isProcessQuery(kql)) {
    if (kql.includes('DeviceProcessEvents')) {
      kql = injectAfterFirstWhere(kql, PROCESS_EXCLUSION_MDE)
    }
    if (kql.includes('EventID == 4688')) {
      kql = injectAfterFirstWhere(kql, PROCESS_EXCLUSION_4688)
    }
  }

  if (isNetworkQuery(kql)) {
    if (kql.includes('DeviceNetworkEvents')) {
      kql = injectAfterFirstWhere(kql, NETWORK_EXCLUSION_MDE)
    } else if (kql.includes('CommonSecurityLog')) {
      kql = injectAfterFirstWhere(kql, NETWORK_EXCLUSION_CSL)
    }
  }

  return BASELINE + kql
}

const queries = JSON.parse(readFileSync(queriesPath, 'utf8'))
const updated = queries.map((q) => {
  const meta = TITLE_UPDATES[q.id] || {}
  return {
    ...q,
    ...meta,
    kql: refineKql(q),
  }
})

writeFileSync(queriesPath, JSON.stringify(updated, null, 2) + '\n')
console.log(`Updated ${updated.length} queries`)
