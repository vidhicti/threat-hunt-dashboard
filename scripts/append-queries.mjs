import { readFileSync, writeFileSync } from 'fs'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'

const __dirname = dirname(fileURLToPath(import.meta.url))
const queriesPath = join(__dirname, '../src/data/queries.json')
const techniquesPath = join(__dirname, '../src/data/techniques.json')

const NEW_QUERIES = [
  {
    id: 'Q61',
    title: 'Active Scanning - Port Scan from Internal Host',
    tactic: 'Reconnaissance',
    tacticId: 'TA0043',
    mitreTechnique: 'T1595.001',
    logSource: 'CommonSecurityLog',
    severity: 'medium',
    category: 'reconnaissance',
    description:
      'Detects internal hosts performing port scans against multiple destinations via Fortigate/Palo Alto logs',
    kql: "CommonSecurityLog\n| where TimeGenerated > ago(1d)\n| where DeviceVendor in ('Fortinet','Palo Alto Networks','Sophos')\n| where DeviceAction !in ('deny','block','drop')\n| summarize DistinctPorts=dcount(DestinationPort), DistinctDests=dcount(DestinationIP), ConnectionCount=count() by SourceIP, bin(TimeGenerated,5m)\n| where DistinctPorts > 20 or DistinctDests > 50\n| extend ScanType = case(DistinctPorts > 20, 'Port Scan', DistinctDests > 50, 'Host Sweep', 'Unknown')\n| order by DistinctPorts desc",
  },
  {
    id: 'Q62',
    title: 'Suspicious New DNS Domain Registration Pattern',
    tactic: 'Resource Development',
    tacticId: 'TA0042',
    mitreTechnique: 'T1583.001',
    logSource: 'ASimDnsActivityLogs',
    severity: 'medium',
    category: 'resource-development',
    description:
      'Detects DNS queries to newly registered or typosquat domains that may indicate attacker infrastructure',
    kql: "ASimDnsActivityLogs\n| where TimeGenerated > ago(1d)\n| where DnsQueryTypeName == 'A'\n| where DnsQuery matches regex @'[0-9a-z]{8,}\\.(?:xyz|top|click|online|site|icu|tk|ml|ga|cf|gq)$'\n    or DnsQuery matches regex @'(?:login|secure|account|update|verify|support|helpdesk|microsoft|google|apple|paypal|amazon)[0-9-]+\\.'\n| summarize QueryCount=count(), UniqueClients=dcount(SrcIpAddr) by DnsQuery, DnsResponseCode\n| where QueryCount > 3\n| order by QueryCount desc",
  },
  {
    id: 'Q63',
    title: 'Valid Account - Service Account Used from New Location',
    tactic: 'Initial Access',
    tacticId: 'TA0001',
    mitreTechnique: 'T1078.002',
    logSource: 'SecurityEvents',
    severity: 'high',
    category: 'initial-access',
    description:
      'Detects service accounts authenticating from workstations or unusual source IPs indicating credential theft',
    kql: "SecurityEvent\n| where TimeGenerated > ago(1d)\n| where EventID == 4624\n| where AccountName endswith 'svc' or AccountName endswith 'service' or AccountName startswith 'svc'\n| where LogonType in (2, 10)\n| where IpAddress !in ('::1','127.0.0.1','-')\n| summarize LogonCount=count(), DistinctIPs=dcount(IpAddress), Computers=make_set(Computer,5) by AccountName, IpAddress\n| where DistinctIPs > 1 or LogonCount > 10\n| order by LogonCount desc",
  },
  {
    id: 'Q64',
    title: 'Suspicious WMIC Remote Execution',
    tactic: 'Execution',
    tacticId: 'TA0002',
    mitreTechnique: 'T1047',
    logSource: 'MDE',
    severity: 'high',
    category: 'execution',
    description:
      'Detects WMIC used for remote command execution - common lateral movement and execution technique',
    kql: "DeviceProcessEvents\n| where Timestamp > ago(1d)\n| where FileName =~ 'wmic.exe'\n| where ProcessCommandLine has_any ('/node:','process call create','os get','computersystem','shadowcopy')\n| where ProcessCommandLine !contains '127.0.0.1'\n| where ProcessCommandLine !contains 'localhost'\n| extend RemoteTarget = extract(@'/node:([\\w\\d\\.]+)', 1, ProcessCommandLine)\n| extend Command = extract(@'call create [\"\\']?([^\"\\']+)', 1, ProcessCommandLine)\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine, RemoteTarget, Command\n| order by Timestamp desc",
  },
  {
    id: 'Q65',
    title: 'Office Application Startup Persistence',
    tactic: 'Persistence',
    tacticId: 'TA0003',
    mitreTechnique: 'T1137.001',
    logSource: 'MDE',
    severity: 'medium',
    category: 'persistence',
    description:
      'Detects files dropped in Office startup folders for persistence via add-ins or templates',
    kql: "DeviceFileEvents\n| where Timestamp > ago(7d)\n| where ActionType in ('FileCreated','FileModified')\n| where FolderPath has_any (\n    '\\\\Microsoft\\\\Word\\\\STARTUP',\n    '\\\\Microsoft\\\\Excel\\\\XLSTART',\n    '\\\\Microsoft\\\\Outlook\\\\',\n    '\\\\Microsoft\\\\AddIns',\n    'STARTUP\\\\'\n)\n| where FileName endswith_cs '.dotm' or FileName endswith_cs '.xlam' or FileName endswith_cs '.xla' \n    or FileName endswith_cs '.ppam' or FileName endswith_cs '.com' or FileName endswith_cs '.dll'\n| project Timestamp, DeviceName, AccountName, FileName, FolderPath, InitiatingProcessFileName\n| order by Timestamp desc",
  },
  {
    id: 'Q66',
    title: 'Scheduled Task Privilege Escalation via SYSTEM Account',
    tactic: 'Privilege Escalation',
    tacticId: 'TA0004',
    mitreTechnique: 'T1053.005',
    logSource: 'SecurityEvents',
    severity: 'high',
    category: 'privilege-escalation',
    description:
      'Detects scheduled tasks created to run as SYSTEM from non-administrative contexts',
    kql: "SecurityEvent\n| where TimeGenerated > ago(1d)\n| where EventID == 4698\n| extend TaskName = tostring(EventData.TaskName)\n| extend TaskContent = tostring(EventData.TaskContent)\n| extend RunAs = extract(@'<UserId>([^<]+)</UserId>', 1, TaskContent)\n| where RunAs contains 'S-1-5-18' or TaskContent contains 'SYSTEM'\n| where Account !contains 'SYSTEM'\n| where Account !endswith '$'\n| project TimeGenerated, Computer, Account, TaskName, RunAs, TaskContent\n| order by TimeGenerated desc",
  },
  {
    id: 'Q67',
    title: 'AMSI Bypass Attempt',
    tactic: 'Defense Evasion',
    tacticId: 'TA0005',
    mitreTechnique: 'T1562.001',
    logSource: 'MDE',
    severity: 'high',
    category: 'defense-evasion',
    description: 'Detects common AMSI bypass techniques in PowerShell commands',
    kql: "DeviceProcessEvents\n| where Timestamp > ago(1d)\n| where FileName in~ ('powershell.exe','pwsh.exe')\n| where ProcessCommandLine has_any (\n    'AmsiUtils','amsiInitFailed','AmsiScanBuffer',\n    '[Ref].Assembly.GetType','System.Management.Automation.AmsiUtils',\n    'amsi.dll','AmsiOpenSession','Patching'\n)\n| extend AMSIBypassTechnique = case(\n    ProcessCommandLine has 'AmsiScanBuffer', 'Patch AmsiScanBuffer',\n    ProcessCommandLine has 'amsiInitFailed', 'Set amsiInitFailed',\n    ProcessCommandLine has 'AmsiUtils', 'Reflection AmsiUtils',\n    'Unknown AMSI Bypass'\n)\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine, AMSIBypassTechnique\n| order by Timestamp desc",
  },
  {
    id: 'Q68',
    title: 'Credential Access via Registry - SAM Database',
    tactic: 'Credential Access',
    tacticId: 'TA0006',
    mitreTechnique: 'T1003.002',
    logSource: 'MDE',
    severity: 'critical',
    category: 'credential-access',
    description: 'Detects attempts to access or dump the SAM registry hive for credential theft',
    kql: "DeviceRegistryEvents\n| where Timestamp > ago(1d)\n| where RegistryKey has_any ('HKLM\\\\SAM','HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Lsa')\n| where ActionType in ('RegistryKeyCreated','RegistryValueSet','RegistryKeyDeleted')\n| where InitiatingProcessFileName !in~ ('svchost.exe','services.exe','lsass.exe','csrss.exe','winlogon.exe')\n| project Timestamp, DeviceName, AccountName, RegistryKey, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine\n| order by Timestamp desc",
  },
  {
    id: 'Q69',
    title: 'DCOM Lateral Movement',
    tactic: 'Lateral Movement',
    tacticId: 'TA0008',
    mitreTechnique: 'T1021.003',
    logSource: 'SecurityEvents',
    severity: 'high',
    category: 'lateral-movement',
    description:
      'Detects DCOM-based lateral movement via MMC20, ShellWindows or ShellBrowserWindow objects',
    kql: "SecurityEvent\n| where TimeGenerated > ago(1d)\n| where EventID == 4688\n| where ParentProcessName has 'svchost.exe'\n| where NewProcessName has_any ('mmc.exe','excel.exe','visio.exe','word.exe','outlook.exe')\n| where CommandLine has_any ('-Embedding','/automation','-server')\n| join kind=inner (\n    SecurityEvent\n    | where EventID == 4624\n    | where LogonType == 3\n    | project LogonTime=TimeGenerated, Computer, IpAddress, AccountName\n) on Computer\n| where abs(datetime_diff('minute', TimeGenerated, LogonTime)) < 5\n| project TimeGenerated, Computer, NewProcessName, CommandLine, IpAddress, AccountName\n| order by TimeGenerated desc",
  },
  {
    id: 'Q70',
    title: 'Clipboard Data Collection',
    tactic: 'Collection',
    tacticId: 'TA0009',
    mitreTechnique: 'T1115',
    logSource: 'MDE',
    severity: 'medium',
    category: 'collection',
    description:
      'Detects processes accessing clipboard data which may indicate credential or data harvesting',
    kql: "DeviceEvents\n| where Timestamp > ago(1d)\n| where ActionType == 'GetAsyncKeyState' or ActionType == 'ClipboardChanged'\n| where InitiatingProcessFileName !in~ ('explorer.exe','svchost.exe','ctfmon.exe','RuntimeBroker.exe','TextInputHost.exe','pwsh.exe','powershell.exe')\n| summarize ClipboardAccess=count() by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, bin(Timestamp,5m)\n| where ClipboardAccess > 10\n| order by ClipboardAccess desc",
  },
  {
    id: 'Q71',
    title: 'C2 Beaconing - Regular Interval Outbound Connections',
    tactic: 'Command and Control',
    tacticId: 'TA0011',
    mitreTechnique: 'T1071.001',
    logSource: 'CommonSecurityLog',
    severity: 'high',
    category: 'c2',
    description:
      'Detects beaconing behavior via statistical analysis of connection intervals to external IPs',
    kql: "CommonSecurityLog\n| where TimeGenerated > ago(6h)\n| where DeviceVendor in ('Fortinet','Palo Alto Networks','Sophos')\n| where DestinationIP !startswith '10.' and DestinationIP !startswith '172.' and DestinationIP !startswith '192.168.'\n| where DestinationPort in (80,443,8080,8443)\n| summarize ConnectionCount=count(), BytesSent=sum(SentBytes), BytesReceived=sum(ReceivedBytes), TimeList=make_list(TimeGenerated,100) by SourceIP, DestinationIP, DestinationPort\n| where ConnectionCount > 20\n| extend AvgBytesSent = BytesSent / ConnectionCount\n| extend AvgBytesReceived = BytesReceived / ConnectionCount\n| extend IsSmallPayload = AvgBytesSent < 1000 and AvgBytesReceived < 5000\n| where IsSmallPayload == true\n| extend BeaconingScore = case(ConnectionCount > 100, 'HIGH', ConnectionCount > 50, 'MEDIUM', 'LOW')\n| project SourceIP, DestinationIP, DestinationPort, ConnectionCount, AvgBytesSent, AvgBytesReceived, BeaconingScore\n| order by ConnectionCount desc",
  },
  {
    id: 'Q72',
    title: 'Disk Wipe / MBR Overwrite Attempt',
    tactic: 'Impact',
    tacticId: 'TA0040',
    mitreTechnique: 'T1561.002',
    logSource: 'MDE',
    severity: 'critical',
    category: 'impact',
    description:
      'Detects disk wiping tools or MBR overwrite attempts - often used in destructive attacks',
    kql: "DeviceProcessEvents\n| where Timestamp > ago(1d)\n| where FileName in~ ('cipher.exe','sdelete.exe','eraser.exe','diskpart.exe','format.exe','dd.exe','wiper.exe')\n    or ProcessCommandLine has_any ('overwrite','wipe','zero','shred','nuke')\n    or (FileName =~ 'diskpart.exe' and ProcessCommandLine has_any ('clean','override'))\n| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName\n| order by Timestamp desc",
  },
  {
    id: 'Q73',
    title: 'O365 - Suspicious Mail Forwarding Rule Created',
    tactic: 'Collection',
    tacticId: 'TA0009',
    mitreTechnique: 'T1114.003',
    logSource: 'OfficeActivity',
    severity: 'high',
    category: 'collection',
    description: 'Detects email forwarding rules that may exfiltrate mail to external addresses',
    kql: "OfficeActivity\n| where TimeGenerated > ago(7d)\n| where Operation in ('New-InboxRule','Set-InboxRule','New-TransportRule')\n| extend RuleParameters = tostring(Parameters)\n| where RuleParameters has_any ('ForwardTo','RedirectTo','ForwardAsAttachmentTo','BlindCopyTo')\n| where RuleParameters has_any ('@gmail.','@yahoo.','@hotmail.','@outlook.','@proton.')\n    or RuleParameters matches regex @'ForwardTo.*@(?!yourdomain\\.com)'\n| extend ForwardDest = extract(@'ForwardTo.*?([\\w\\.-]+@[\\w\\.-]+)', 1, RuleParameters)\n| project TimeGenerated, UserId, Operation, ForwardDest, RuleParameters, ClientIP\n| order by TimeGenerated desc",
  },
  {
    id: 'Q74',
    title: 'O365 - Bulk Email Download / Exfiltration',
    tactic: 'Collection',
    tacticId: 'TA0009',
    mitreTechnique: 'T1114.002',
    logSource: 'OfficeActivity',
    severity: 'high',
    category: 'collection',
    description: 'Detects bulk email access or download that may indicate BEC or data exfiltration',
    kql: "OfficeActivity\n| where TimeGenerated > ago(1d)\n| where Operation in ('MailItemsAccessed','MessageBind','Copy','Move')\n| summarize OperationCount=count(), UniqueItems=dcount(AffectedItems) by UserId, Operation, ClientIP, bin(TimeGenerated,1h)\n| where OperationCount > 100\n| extend RiskLevel = case(OperationCount > 1000, 'CRITICAL', OperationCount > 500, 'HIGH', 'MEDIUM')\n| order by OperationCount desc",
  },
  {
    id: 'Q75',
    title: 'Trend Micro - Malware Detection with No Cleanup Action',
    tactic: 'Execution',
    tacticId: 'TA0002',
    mitreTechnique: 'T1204',
    logSource: 'TrendMicro',
    severity: 'critical',
    category: 'execution',
    description:
      'Detects Trend Micro alerts where malware was detected but not cleaned - indicates active infection',
    kql: "CommonSecurityLog\n| where TimeGenerated > ago(1d)\n| where DeviceVendor == 'Trend Micro'\n| where DeviceEventClassID has_any ('Virus','Malware','Spyware','Ransomware')\n| where DeviceAction !in~ ('Cleaned','Deleted','Quarantined','Blocked')\n| where DeviceAction in~ ('Passed','Not Cleaned','Access Denied','No Action','Skipped')\n| extend InfectionRisk = case(\n    DeviceAction =~ 'Passed', 'CRITICAL - Malware allowed through',\n    DeviceAction =~ 'Not Cleaned', 'HIGH - Cleanup failed',\n    'MEDIUM - Action unclear'\n)\n| project TimeGenerated, DeviceVendor, SourceIP, DestinationIP, Activity, DeviceAction, InfectionRisk, Message\n| order by TimeGenerated desc",
  },
  {
    id: 'Q76',
    title: 'Firewall - Outbound Connection to Known Malicious Country',
    tactic: 'Command and Control',
    tacticId: 'TA0011',
    mitreTechnique: 'T1071',
    logSource: 'CommonSecurityLog',
    severity: 'medium',
    category: 'c2',
    description:
      'Detects outbound connections to countries with high threat actor activity - tune to your risk tolerance',
    kql: "CommonSecurityLog\n| where TimeGenerated > ago(1d)\n| where DeviceVendor in ('Fortinet','Palo Alto Networks','Sophos','Trend Micro')\n| where DeviceAction !in ('deny','block','drop','reset')\n| where DestinationIP !startswith '10.' and DestinationIP !startswith '172.16.' and DestinationIP !startswith '192.168.'\n// Tune this list to your organisation's risk policy\n| where AdditionalExtensions has_any ('country=CN','country=RU','country=KP','country=IR')\n    or DestinationHostName endswith '.ru' or DestinationHostName endswith '.cn'\n    or DestinationHostName endswith '.ir' or DestinationHostName endswith '.kp'\n| summarize ConnectionCount=count(), BytesTransferred=sum(SentBytes+ReceivedBytes) by SourceIP, DestinationIP, DestinationPort, AdditionalExtensions\n| where ConnectionCount > 3\n| order by BytesTransferred desc",
  },
  {
    id: 'Q77',
    title: 'Palo Alto - Threat Log Critical Severity Events',
    tactic: 'Initial Access',
    tacticId: 'TA0001',
    mitreTechnique: 'T1190',
    logSource: 'CommonSecurityLog',
    severity: 'critical',
    category: 'initial-access',
    description: 'Surfaces critical severity threat events from Palo Alto threat logs for immediate triage',
    kql: "CommonSecurityLog\n| where TimeGenerated > ago(1d)\n| where DeviceVendor == 'Palo Alto Networks'\n| where LogSeverity in ('critical','high')\n| where DeviceEventClassID has_any ('threat','vulnerability','wildfire')\n| extend ThreatName = tostring(split(Message,'\\\"')[1])\n| extend Direction = case(\n    DestinationIP startswith '10.' or DestinationIP startswith '192.168.', 'Inbound',\n    SourceIP startswith '10.' or SourceIP startswith '192.168.', 'Outbound',\n    'Unknown'\n)\n| project TimeGenerated, SourceIP, DestinationIP, DestinationPort, LogSeverity, ThreatName, DeviceAction, Direction, Message\n| order by TimeGenerated desc",
  },
  {
    id: 'Q78',
    title: 'Fortigate - IPS Critical Attack Signatures',
    tactic: 'Initial Access',
    tacticId: 'TA0001',
    mitreTechnique: 'T1190',
    logSource: 'CommonSecurityLog',
    severity: 'critical',
    category: 'initial-access',
    description: 'Surfaces Fortigate IPS alerts for critical attack signatures requiring immediate investigation',
    kql: "CommonSecurityLog\n| where TimeGenerated > ago(1d)\n| where DeviceVendor == 'Fortinet'\n| where DeviceEventClassID has_any ('intrusion','ips','ids','attack')\n| where LogSeverity in ('critical','high') or AdditionalExtensions has 'severity=critical'\n| extend AttackName = extract(@'attack_name=([^;]+)', 1, AdditionalExtensions)\n| extend AttackID = extract(@'attackid=(\\d+)', 1, AdditionalExtensions)\n| summarize HitCount=count(), UniqueTargets=dcount(DestinationIP) by SourceIP, AttackName, AttackID, DeviceAction\n| where HitCount > 1\n| order by HitCount desc",
  },
  {
    id: 'Q79',
    title: 'Azure AD - Suspicious Sign-in Risk Events',
    tactic: 'Initial Access',
    tacticId: 'TA0001',
    mitreTechnique: 'T1078.004',
    logSource: 'SigninLogs',
    severity: 'high',
    category: 'initial-access',
    description: 'Detects high risk sign-in events from Azure AD Identity Protection',
    kql: "SigninLogs\n| where TimeGenerated > ago(1d)\n| where RiskLevelDuringSignIn in ('high','medium')\n    or RiskLevelAggregated in ('high','medium')\n    or RiskState in ('atRisk','confirmedCompromised')\n| extend RiskReasons = tostring(RiskEventTypes)\n| extend LocationInfo = strcat(LocationDetails.city, ', ', LocationDetails.countryOrRegion)\n| project TimeGenerated, UserPrincipalName, AppDisplayName, RiskLevelDuringSignIn, RiskState, RiskReasons, LocationInfo, IPAddress, ClientAppUsed\n| order by TimeGenerated desc",
  },
  {
    id: 'Q80',
    title: 'Kerberoasting - RC4 Encrypted Service Ticket Requests',
    tactic: 'Credential Access',
    tacticId: 'TA0006',
    mitreTechnique: 'T1558.003',
    logSource: 'SecurityEvents',
    severity: 'high',
    category: 'credential-access',
    description:
      'Detects Kerberoasting attacks by identifying RC4 encrypted TGS requests for service accounts',
    kql: "SecurityEvent\n| where TimeGenerated > ago(1d)\n| where EventID == 4769\n| where TicketEncryptionType == '0x17'\n| where ServiceName !endswith '$'\n| where ServiceName !in ('krbtgt','kadmin')\n| where AccountName !endswith '$'\n| where TargetUserName !contains 'ANONYMOUS'\n| summarize RequestCount=count(), UniqueServices=dcount(ServiceName), Services=make_set(ServiceName,5) by AccountName, IpAddress, bin(TimeGenerated,1h)\n| where RequestCount > 2\n| extend KerberoastingRisk = case(RequestCount > 10, 'HIGH - Bulk Kerberoasting', RequestCount > 5, 'MEDIUM - Multiple targets', 'LOW - Single attempt')\n| order by RequestCount desc",
  },
]

const NEW_TECHNIQUES = [
  { id: 'T1595.001', name: 'Active Scanning: Scanning IP Blocks', tactic: 'Reconnaissance', tacticId: 'TA0043', coverage: 'baselining' },
  { id: 'T1583.001', name: 'Acquire Infrastructure: Domains', tactic: 'Resource Development', tacticId: 'TA0042', coverage: 'baselining' },
  { id: 'T1078.002', name: 'Valid Accounts: Domain Accounts', tactic: 'Initial Access', tacticId: 'TA0001', coverage: 'baselining' },
  { id: 'T1137.001', name: 'Office Application Startup: Office Templates', tactic: 'Persistence', tacticId: 'TA0003', coverage: 'baselining' },
  { id: 'T1003.002', name: 'OS Credential Dumping: Security Account Manager', tactic: 'Credential Access', tacticId: 'TA0006', coverage: 'baselining' },
  { id: 'T1021.003', name: 'Remote Services: Distributed Component Object Model', tactic: 'Lateral Movement', tacticId: 'TA0008', coverage: 'baselining' },
  { id: 'T1115', name: 'Clipboard Data', tactic: 'Collection', tacticId: 'TA0009', coverage: 'baselining' },
  { id: 'T1561.002', name: 'Disk Wipe: Disk Structure Wipe', tactic: 'Impact', tacticId: 'TA0040', coverage: 'baselining' },
  { id: 'T1114.003', name: 'Email Collection: Email Forwarding Rule', tactic: 'Collection', tacticId: 'TA0009', coverage: 'baselining' },
  { id: 'T1114.002', name: 'Email Collection: Remote Email Collection', tactic: 'Collection', tacticId: 'TA0009', coverage: 'baselining' },
  { id: 'T1078.004', name: 'Valid Accounts: Cloud Accounts', tactic: 'Initial Access', tacticId: 'TA0001', coverage: 'baselining' },
  { id: 'T1204', name: 'User Execution', tactic: 'Execution', tacticId: 'TA0002', coverage: 'baselining' },
]

const UPDATE_TO_BASELINING = new Set([
  'T1047',
  'T1053.005',
  'T1562.001',
  'T1071.001',
  'T1558.003',
])

const queries = JSON.parse(readFileSync(queriesPath, 'utf8'))
const existingIds = new Set(queries.map((q) => q.id))
const toAdd = NEW_QUERIES.filter((q) => !existingIds.has(q.id))
writeFileSync(queriesPath, JSON.stringify([...queries, ...toAdd], null, 2) + '\n')
console.log(`Added ${toAdd.length} queries (total ${queries.length + toAdd.length})`)

const techniques = JSON.parse(readFileSync(techniquesPath, 'utf8'))
const techIds = new Set(techniques.map((t) => t.id))
const updatedTechniques = techniques.map((t) =>
  UPDATE_TO_BASELINING.has(t.id) ? { ...t, coverage: 'baselining' } : t
)
for (const nt of NEW_TECHNIQUES) {
  if (!techIds.has(nt.id)) {
    updatedTechniques.push(nt)
    techIds.add(nt.id)
  }
}
writeFileSync(techniquesPath, JSON.stringify(updatedTechniques, null, 2) + '\n')
console.log(`Techniques: ${updatedTechniques.length}`)
