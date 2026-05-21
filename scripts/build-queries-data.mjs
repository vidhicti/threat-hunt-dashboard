import { writeFileSync } from 'fs'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

const queries = [
  {
    id: 'Q01',
    title: 'Spearphishing Attachment via O365',
    tactic: 'Initial Access',
    tacticId: 'TA0001',
    mitreTechnique: 'T1566.001',
    logSource: 'OfficeActivity',
    severity: 'high',
    category: 'initial-access',
    description: 'Detects suspicious attachment downloads or mail access for executable and script file types via Office 365.',
    kql: `OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation in ("FileDownloaded", "MailItemsAccessed")
| extend FileName = tostring(AttachmentData.FileName)
| where FileName endswith ".exe" or FileName endswith ".js" or FileName endswith ".vbs" or FileName endswith ".iso" or FileName endswith ".lnk"
| summarize EventCount = count() by UserId, Operation, FileName, bin(TimeGenerated, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q02',
    title: 'Spearphishing Link Clicked via O365',
    tactic: 'Initial Access',
    tacticId: 'TA0001',
    mitreTechnique: 'T1566.002',
    logSource: 'OfficeActivity',
    severity: 'high',
    category: 'initial-access',
    description: 'Identifies users clicking URLs in email where the destination is outside trusted Microsoft domains.',
    kql: `OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation == "UrlClicked"
| extend Url = tostring(UrlClicked.Url)
| where isnotempty(Url)
| where Url !contains "sharepoint.com" and Url !contains "microsoft.com" and Url !contains "office.com"
| summarize ClickCount = count(), Urls = make_set(Url, 5) by UserId, bin(TimeGenerated, 1h)
| order by ClickCount desc`,
  },
  {
    id: 'Q03',
    title: 'Exploit Public-Facing App - Fortigate',
    tactic: 'Initial Access',
    tacticId: 'TA0001',
    mitreTechnique: 'T1190',
    logSource: 'CommonSecurityLog',
    severity: 'critical',
    category: 'initial-access',
    description: 'Surfaces high-severity Fortinet firewall events on web ports from external sources indicative of exploitation attempts.',
    kql: `CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "Fortinet"
| where DestinationPort in ("80", "443")
| where DeviceSeverity in ("high", "critical", "warning")
| extend SrcIp = SourceIP
| where isnotempty(SrcIp) and not(ipv4_is_private(tostring(SrcIp)))
| summarize EventCount = count(), Signatures = make_set(Activity, 10) by SrcIp, DestinationIP, DestinationPort, DeviceSeverity, bin(TimeGenerated, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q04',
    title: 'Exploit Public-Facing App - Palo Alto',
    tactic: 'Initial Access',
    tacticId: 'TA0001',
    mitreTechnique: 'T1190',
    logSource: 'CommonSecurityLog',
    severity: 'critical',
    category: 'initial-access',
    description: 'Detects critical Palo Alto threat logs targeting public-facing services.',
    kql: `CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor == "Palo Alto Networks"
| where LogSeverity == "critical" or ThreatCategory has_any ("exploit", "vulnerability", "exploit-kit")
| summarize EventCount = count(), Threats = make_set(ThreatCategory, 10) by SourceIP, DestinationIP, DestinationPort, LogSeverity, bin(TimeGenerated, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q05',
    title: 'Valid Accounts - Impossible Travel Login',
    tactic: 'Initial Access',
    tacticId: 'TA0001',
    mitreTechnique: 'T1078',
    logSource: 'SigninLogs',
    severity: 'critical',
    category: 'initial-access',
    description: 'Flags successful sign-ins for the same user from multiple countries within one hour.',
    kql: `SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize Countries = make_set(Country), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(Countries) > 1
| extend TimeSpanMinutes = datetime_diff('minute', LastSeen, FirstSeen)
| where TimeSpanMinutes <= 60
| project UserPrincipalName, Countries, TimeSpanMinutes, FirstSeen, LastSeen
| order by TimeSpanMinutes asc`,
  },
  {
    id: 'Q06',
    title: 'Valid Accounts - Off-Hours Login Anomaly',
    tactic: 'Initial Access',
    tacticId: 'TA0001',
    mitreTechnique: 'T1078',
    logSource: 'SecurityEvents',
    severity: 'medium',
    category: 'initial-access',
    description: 'Detects interactive logons outside business hours from non-service accounts.',
    kql: `SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4624
| extend LogonType = toint(EventData.LogonType)
| extend Account = tostring(EventData.TargetUserName)
| where LogonType in (2, 10)
| where not(Account endswith "$" or Account contains "SERVICE")
| extend Hour = datetime_part("hour", TimeGenerated)
| where Hour >= 22 or Hour < 6
| summarize LogonCount = count() by Account, Computer, bin(TimeGenerated, 1d)
| order by LogonCount desc`,
  },
  {
    id: 'Q07',
    title: 'PowerShell Encoded Command',
    tactic: 'Execution',
    tacticId: 'TA0002',
    mitreTechnique: 'T1059.001',
    logSource: 'MDE',
    severity: 'high',
    category: 'execution',
    description: 'Detects PowerShell execution with encoded command-line arguments in MDE process events.',
    kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has "-enc" or ProcessCommandLine has "-EncodedCommand"
| summarize EventCount = count() by DeviceName, AccountName, ProcessCommandLine, bin(Timestamp, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q08',
    title: 'Suspicious Windows Command Shell Usage',
    tactic: 'Execution',
    tacticId: 'TA0002',
    mitreTechnique: 'T1059.003',
    logSource: 'MDE',
    severity: 'high',
    category: 'execution',
    description: 'Identifies cmd.exe invocations with download cradles or remote execution patterns.',
    kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "cmd.exe"
| where ProcessCommandLine has "/c"
| where ProcessCommandLine has_any ("curl", "wget", "bitsadmin", "certutil", "http://", "https://", "powershell")
| summarize EventCount = count() by DeviceName, AccountName, ProcessCommandLine, bin(Timestamp, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q09',
    title: 'VBScript/WScript Execution',
    tactic: 'Execution',
    tacticId: 'TA0002',
    mitreTechnique: 'T1059.005',
    logSource: 'MDE',
    severity: 'high',
    category: 'execution',
    description: 'Detects wscript or cscript spawned from Office applications or user temp directories.',
    kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("wscript.exe", "cscript.exe")
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe")
    or FolderPath has_any ("\\\\Temp\\\\", "\\\\Downloads\\\\", "\\\\AppData\\\\")
| summarize EventCount = count() by DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, bin(Timestamp, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q10',
    title: 'Malicious File Execution from Downloads/Temp',
    tactic: 'Execution',
    tacticId: 'TA0002',
    mitreTechnique: 'T1204.002',
    logSource: 'MDE',
    severity: 'high',
    category: 'execution',
    description: 'Surfaces processes started from Downloads, Temp, or AppData folders.',
    kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where FolderPath has_any ("\\\\Downloads\\\\", "\\\\Temp\\\\", "\\\\AppData\\\\")
| where ActionType == "ProcessCreated"
| summarize EventCount = count(), Processes = make_set(FileName, 10) by DeviceName, FolderPath, AccountName, bin(Timestamp, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q11',
    title: 'WMI Execution for Lateral Movement',
    tactic: 'Execution',
    tacticId: 'TA0002',
    mitreTechnique: 'T1047',
    logSource: 'MDE',
    severity: 'medium',
    category: 'execution',
    description: 'Detects wmiprvse.exe spawning command shells or PowerShell.',
    kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "wmiprvse.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe")
| summarize EventCount = count() by DeviceName, FileName, ProcessCommandLine, bin(Timestamp, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q12',
    title: 'LOLBin Abuse - Certutil Msiexec Regsvr32 Rundll32',
    tactic: 'Execution',
    tacticId: 'TA0002',
    mitreTechnique: 'T1218',
    logSource: 'SecurityEvents',
    severity: 'high',
    category: 'execution',
    description: 'Identifies living-off-the-land binaries used for download, decode, or proxy execution in 4688 events.',
    kql: `SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4688
| extend CommandLine = tostring(EventData.CommandLine)
| extend ProcessName = tostring(EventData.ProcessName)
| where ProcessName has_any ("certutil.exe", "msiexec.exe", "regsvr32.exe", "rundll32.exe")
| where CommandLine has_any ("-urlcache", "-verifyctl", "-decode", "/i http", "/s /u", "http://", "https://")
| summarize EventCount = count() by Computer, ProcessName, CommandLine, bin(TimeGenerated, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q13',
    title: 'Scheduled Task Creation - Suspicious Path',
    tactic: 'Persistence',
    tacticId: 'TA0003',
    mitreTechnique: 'T1053.005',
    logSource: 'SecurityEvents',
    severity: 'high',
    category: 'persistence',
    description: 'Detects scheduled tasks created or modified pointing to temp or user-writable directories.',
    kql: `SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4698, 4702)
| extend TaskContent = tostring(EventData.TaskContent)
| extend TaskName = tostring(EventData.TaskName)
| where TaskContent has_any ("\\\\Temp\\\\", "\\\\AppData\\\\", "\\\\Users\\\\", "\\\\ProgramData\\\\")
| summarize EventCount = count() by Computer, TaskName, bin(TimeGenerated, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q14',
    title: 'Registry Run Key Persistence',
    tactic: 'Persistence',
    tacticId: 'TA0003',
    mitreTechnique: 'T1547.001',
    logSource: 'MDE',
    severity: 'high',
    category: 'persistence',
    description: 'Detects modifications to Run/RunOnce registry keys for autostart persistence.',
    kql: `DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has_any ("\\\\CurrentVersion\\\\Run", "\\\\CurrentVersion\\\\RunOnce")
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| summarize EventCount = count() by DeviceName, RegistryKey, RegistryValueName, RegistryValueData, bin(Timestamp, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q15',
    title: 'New Local Account Created and Added to Admins',
    tactic: 'Persistence',
    tacticId: 'TA0003',
    mitreTechnique: 'T1136.001',
    logSource: 'SecurityEvents',
    severity: 'critical',
    category: 'persistence',
    description: 'Correlates local account creation with Administrators group membership within five minutes.',
    kql: `let AccountCreated = SecurityEvent
    | where TimeGenerated > ago(7d)
    | where EventID == 4720
    | extend NewAccount = tostring(EventData.TargetUserName)
    | project CreateTime = TimeGenerated, Computer, NewAccount;
let AdminAdded = SecurityEvent
    | where TimeGenerated > ago(7d)
    | where EventID == 4732
    | extend MemberName = tostring(EventData.MemberName)
    | extend GroupName = tostring(EventData.TargetUserName)
    | where GroupName contains "Administrators"
    | project AddTime = TimeGenerated, Computer, MemberName;
AccountCreated
| join kind=inner AdminAdded on Computer
| where MemberName contains NewAccount
| where AddTime between (CreateTime .. (CreateTime + 5m))
| project CreateTime, AddTime, Computer, NewAccount
| order by CreateTime desc`,
  },
  {
    id: 'Q16',
    title: 'New Domain Account Created',
    tactic: 'Persistence',
    tacticId: 'TA0003',
    mitreTechnique: 'T1136.002',
    logSource: 'SecurityEvents',
    severity: 'high',
    category: 'persistence',
    description: 'Detects domain account creation events on domain controllers.',
    kql: `SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4720
| extend TargetDomain = tostring(EventData.TargetDomainName)
| extend NewAccount = tostring(EventData.TargetUserName)
| extend Creator = tostring(EventData.SubjectUserName)
| where isnotempty(TargetDomain) and TargetDomain !~ "-"
| summarize EventCount = count() by Computer, TargetDomain, NewAccount, Creator, bin(TimeGenerated, 1d)
| order by EventCount desc`,
  },
  {
    id: 'Q17',
    title: 'New Windows Service - Suspicious Binary Path',
    tactic: 'Persistence',
    tacticId: 'TA0003',
    mitreTechnique: 'T1543.003',
    logSource: 'MDE',
    severity: 'high',
    category: 'persistence',
    description: 'Detects new services with binaries in temp, AppData, or user profile paths.',
    kql: `DeviceEvents
| where Timestamp > ago(7d)
| where ActionType has "Service"
| extend ServicePath = tostring(AdditionalFields.ServicePath)
| where ServicePath has_any ("\\\\Temp\\\\", "\\\\AppData\\\\", "\\\\Users\\\\")
| summarize EventCount = count() by DeviceName, ActionType, ServicePath, bin(Timestamp, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q18',
    title: 'Account Privilege Escalation - Admin Group Add',
    tactic: 'Persistence',
    tacticId: 'TA0003',
    mitreTechnique: 'T1098',
    logSource: 'SecurityEvents',
    severity: 'critical',
    category: 'persistence',
    description: 'Detects users added to Administrators or Domain Admins groups.',
    kql: `SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4732, 4756)
| extend MemberName = tostring(EventData.MemberName)
| extend GroupName = tostring(EventData.TargetUserName)
| extend Subject = tostring(EventData.SubjectUserName)
| where GroupName has_any ("Administrators", "Domain Admins")
| summarize EventCount = count() by Computer, GroupName, MemberName, Subject, bin(TimeGenerated, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q19',
    title: 'Process Injection - Suspicious Parent-Child',
    tactic: 'Privilege Escalation',
    tacticId: 'TA0004',
    mitreTechnique: 'T1055',
    logSource: 'MDE',
    severity: 'critical',
    category: 'privilege-escalation',
    description: 'Detects unusual parent processes spawning svchost or lsass.',
    kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("svchost.exe", "lsass.exe")
| where InitiatingProcessFileName !in~ ("services.exe", "wininit.exe", "csrss.exe")
| summarize EventCount = count() by DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, bin(Timestamp, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q20',
    title: 'UAC Bypass via Fodhelper or Eventvwr',
    tactic: 'Privilege Escalation',
    tacticId: 'TA0004',
    mitreTechnique: 'T1548.002',
    logSource: 'MDE',
    severity: 'high',
    category: 'privilege-escalation',
    description: 'Detects fodhelper.exe or eventvwr.exe spawning child processes for UAC bypass.',
    kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("fodhelper.exe", "eventvwr.exe")
| where FileName !in~ ("fodhelper.exe", "eventvwr.exe", "mmc.exe")
| summarize EventCount = count() by DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, bin(Timestamp, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q21',
    title: 'Token Impersonation - SeImpersonatePrivilege',
    tactic: 'Privilege Escalation',
    tacticId: 'TA0004',
    mitreTechnique: 'T1134',
    logSource: 'MDE',
    severity: 'high',
    category: 'privilege-escalation',
    description: 'Detects SeImpersonatePrivilege assignment to non-system processes.',
    kql: `DeviceEvents
| where Timestamp > ago(7d)
| where ActionType has_any ("PrivilegeEscalation", "SensitivePrivilege")
| extend Privilege = tostring(AdditionalFields.Privilege)
| where Privilege has "SeImpersonatePrivilege"
| where InitiatingProcessAccountName !endswith "$"
| summarize EventCount = count() by DeviceName, InitiatingProcessFileName, Privilege, bin(Timestamp, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q22',
    title: 'Kernel Exploit Attempt - Unsigned Driver Load',
    tactic: 'Privilege Escalation',
    tacticId: 'TA0004',
    mitreTechnique: 'T1068',
    logSource: 'MDE',
    severity: 'critical',
    category: 'privilege-escalation',
    description: 'Detects unsigned drivers loaded from temp or user-writable paths.',
    kql: `DeviceEvents
| where Timestamp > ago(7d)
| where ActionType has "Driver"
| extend DriverPath = tostring(AdditionalFields.DriverPath)
| where DriverPath has_any ("\\\\Temp\\\\", "\\\\Users\\\\", "\\\\AppData\\\\")
| summarize EventCount = count() by DeviceName, DriverPath, ActionType, bin(Timestamp, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q23',
    title: 'AV/EDR Tampering - Trend Micro Service Stopped',
    tactic: 'Defense Evasion',
    tacticId: 'TA0005',
    mitreTechnique: 'T1562.001',
    logSource: 'TrendMicro',
    severity: 'critical',
    category: 'defense-evasion',
    description: 'Correlates Trend Micro security events with Windows service stop events for EDR tampering.',
    kql: `let TrendAlerts = CommonSecurityLog
    | where TimeGenerated > ago(7d)
    | where DeviceVendor == "Trend Micro"
    | where Activity has_any ("stop", "disabled", "tamper");
let ServiceStop = SecurityEvent
    | where TimeGenerated > ago(7d)
    | where EventID == 7036
    | extend ServiceName = tostring(EventData.ServiceName)
    | where ServiceName has_any ("Trend", "ds_agent", "Endpoint");
union TrendAlerts, ServiceStop
| summarize EventCount = count() by Computer, Activity, ServiceName = tostring(EventData.ServiceName), bin(TimeGenerated, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q24',
    title: 'Windows Defender Disabled via Registry',
    tactic: 'Defense Evasion',
    tacticId: 'TA0005',
    mitreTechnique: 'T1562.001',
    logSource: 'MDE',
    severity: 'critical',
    category: 'defense-evasion',
    description: 'Detects registry changes disabling Windows Defender real-time protection.',
    kql: `DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has "Windows Defender"
| where RegistryValueName in ("DisableAntiSpyware", "DisableRealtimeMonitoring")
| where RegistryValueData in ("1", "0x1")
| summarize EventCount = count() by DeviceName, RegistryKey, RegistryValueName, AccountName, bin(Timestamp, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q25',
    title: 'Security Event Log Cleared',
    tactic: 'Defense Evasion',
    tacticId: 'TA0005',
    mitreTechnique: 'T1070.001',
    logSource: 'SecurityEvents',
    severity: 'critical',
    category: 'defense-evasion',
    description: 'Detects audit or security log clearing events.',
    kql: `SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (1102, 104)
| extend Subject = tostring(EventData.SubjectUserName)
| summarize EventCount = count() by Computer, EventID, Subject, bin(TimeGenerated, 1d)
| order by EventCount desc`,
  },
  {
    id: 'Q26',
    title: 'Process Masquerading - Svchost Wrong Path',
    tactic: 'Defense Evasion',
    tacticId: 'TA0005',
    mitreTechnique: 'T1036.005',
    logSource: 'MDE',
    severity: 'high',
    category: 'defense-evasion',
    description: 'Detects svchost.exe executing outside the System32 directory.',
    kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "svchost.exe"
| where not(FolderPath has "\\\\Windows\\\\System32\\\\")
| summarize EventCount = count() by DeviceName, FolderPath, ProcessCommandLine, AccountName, bin(Timestamp, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q27',
    title: 'Obfuscated PowerShell - High Entropy CommandLine',
    tactic: 'Defense Evasion',
    tacticId: 'TA0005',
    mitreTechnique: 'T1027',
    logSource: 'MDE',
    severity: 'high',
    category: 'defense-evasion',
    description: 'Detects PowerShell with very long command lines or char() obfuscation patterns.',
    kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where strlen(ProcessCommandLine) > 1000 or ProcessCommandLine has "char("
| summarize EventCount = count() by DeviceName, AccountName, bin(Timestamp, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q28',
    title: 'Rundll32 Remote or Non-DLL Execution',
    tactic: 'Defense Evasion',
    tacticId: 'TA0005',
    mitreTechnique: 'T1218.011',
    logSource: 'MDE',
    severity: 'high',
    category: 'defense-evasion',
    description: 'Detects rundll32 executing remote URLs or UNC paths.',
    kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine has_any ("http://", "https://", "\\\\\\\\")
| summarize EventCount = count() by DeviceName, ProcessCommandLine, bin(Timestamp, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q29',
    title: 'LSASS Memory Dump Attempt',
    tactic: 'Credential Access',
    tacticId: 'TA0006',
    mitreTechnique: 'T1003.001',
    logSource: 'MDE',
    severity: 'critical',
    category: 'credential-access',
    description: 'Detects non-system processes accessing LSASS or known credential dumping tools.',
    kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has_any ("mimikatz", "procdump", "comsvcs.dll")
    or ProcessCommandLine has "lsass"
| where FileName =~ "lsass.exe" or ProcessCommandLine has "lsass"
| summarize EventCount = count() by DeviceName, InitiatingProcessFileName, ProcessCommandLine, bin(Timestamp, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q30',
    title: 'Password Spray - Many Accounts Same IP',
    tactic: 'Credential Access',
    tacticId: 'TA0006',
    mitreTechnique: 'T1110.001',
    logSource: 'SecurityEvents',
    severity: 'critical',
    category: 'credential-access',
    description: 'Detects password spraying with many unique accounts failing from one source IP.',
    kql: `SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4625
| extend TargetUser = tostring(EventData.TargetUserName)
| extend IpAddress = tostring(EventData.IpAddress)
| where IpAddress !in ("-", "::1", "127.0.0.1")
| summarize UniqueAccounts = dcount(TargetUser), FailCount = count() by IpAddress, bin(TimeGenerated, 10m)
| where UniqueAccounts > 20
| order by UniqueAccounts desc`,
  },
  {
    id: 'Q31',
    title: 'Password Spray via O365',
    tactic: 'Credential Access',
    tacticId: 'TA0006',
    mitreTechnique: 'T1110.003',
    logSource: 'OfficeActivity',
    severity: 'high',
    category: 'credential-access',
    description: 'Correlates distributed failed O365 sign-in attempts across many accounts.',
    kql: `SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType != 0
| summarize FailedAttempts = count(), Users = dcount(UserPrincipalName) by IPAddress = tostring(IPAddress), bin(TimeGenerated, 10m)
| where Users > 15 and FailedAttempts > 30
| order by Users desc`,
  },
  {
    id: 'Q32',
    title: 'Kerberoasting - RC4 SPN Ticket Requests',
    tactic: 'Credential Access',
    tacticId: 'TA0006',
    mitreTechnique: 'T1558.003',
    logSource: 'SecurityEvents',
    severity: 'high',
    category: 'credential-access',
    description: 'Detects Kerberos TGS requests using RC4 encryption indicative of Kerberoasting.',
    kql: `SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4769
| extend TicketEncryption = tostring(EventData.TicketEncryptionType)
| extend ServiceName = tostring(EventData.ServiceName)
| where TicketEncryption == "0x17"
| summarize RequestCount = count() by Computer, ServiceName, Account = tostring(EventData.TargetUserName), bin(TimeGenerated, 1h)
| order by RequestCount desc`,
  },
  {
    id: 'Q33',
    title: 'Credentials in Files - Sensitive Path Access',
    tactic: 'Credential Access',
    tacticId: 'TA0006',
    mitreTechnique: 'T1552.001',
    logSource: 'MDE',
    severity: 'medium',
    category: 'credential-access',
    description: 'Detects file access to credential-like filenames in sensitive directories.',
    kql: `DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName has_any ("password", "credential", "config", "secret", ".kdbx", ".pfx")
| where FolderPath has_any ("\\\\Users\\\\", "\\\\ProgramData\\\\", "\\\\inetpub\\\\")
| summarize AccessCount = count() by DeviceName, FileName, FolderPath, InitiatingProcessFileName, bin(Timestamp, 1h)
| order by AccessCount desc`,
  },
  {
    id: 'Q34',
    title: 'Network Sniffing Tool Detected',
    tactic: 'Credential Access',
    tacticId: 'TA0006',
    mitreTechnique: 'T1040',
    logSource: 'MDE',
    severity: 'high',
    category: 'credential-access',
    description: 'Detects execution of packet capture tools by non-administrative users.',
    kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("wireshark.exe", "tcpdump.exe", "windump.exe", "dumpcap.exe")
| where not(InitiatingProcessAccountName has "admin")
| summarize EventCount = count() by DeviceName, FileName, AccountName, ProcessCommandLine, bin(Timestamp, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q35',
    title: 'Domain Account Enumeration',
    tactic: 'Discovery',
    tacticId: 'TA0007',
    mitreTechnique: 'T1087.002',
    logSource: 'MDE',
    severity: 'medium',
    category: 'discovery',
    description: 'Detects net commands enumerating domain users and privileged groups.',
    kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("net.exe", "net1.exe")
| where ProcessCommandLine has_any ("/domain", "domain admins", "group \"domain")
| summarize EventCount = count() by DeviceName, ProcessCommandLine, AccountName, bin(Timestamp, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q36',
    title: 'Network Port Scan from Internal Host',
    tactic: 'Discovery',
    tacticId: 'TA0007',
    mitreTechnique: 'T1046',
    logSource: 'CommonSecurityLog',
    severity: 'high',
    category: 'discovery',
    description: 'Detects a single internal source hitting many destination ports within five minutes on Fortinet or Palo Alto logs.',
    kql: `CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DeviceVendor in ("Fortinet", "Palo Alto Networks")
| where isnotempty(SourceIP) and ipv4_is_private(tostring(SourceIP))
| summarize DistinctPorts = dcount(DestinationPort) by SourceIP, bin(TimeGenerated, 5m)
| where DistinctPorts > 50
| order by DistinctPorts desc`,
  },
  {
    id: 'Q37',
    title: 'Remote System Discovery Commands',
    tactic: 'Discovery',
    tacticId: 'TA0007',
    mitreTechnique: 'T1018',
    logSource: 'MDE',
    severity: 'medium',
    category: 'discovery',
    description: 'Detects rapid execution of network discovery utilities.',
    kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("ping.exe", "nslookup.exe", "arp.exe", "net.exe")
| where ProcessCommandLine has_any ("-a", "view", "arp", "nslookup")
| summarize CommandCount = dcount(FileName) by DeviceName, AccountName, bin(Timestamp, 5m)
| where CommandCount >= 3
| order by CommandCount desc`,
  },
  {
    id: 'Q38',
    title: 'System Information Discovery',
    tactic: 'Discovery',
    tacticId: 'TA0007',
    mitreTechnique: 'T1082',
    logSource: 'MDE',
    severity: 'low',
    category: 'discovery',
    description: 'Detects systeminfo, whoami, ipconfig, and hostname executed in quick succession.',
    kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("systeminfo.exe", "whoami.exe", "ipconfig.exe", "hostname.exe")
| summarize ToolCount = dcount(FileName) by DeviceName, AccountName, bin(Timestamp, 5m)
| where ToolCount >= 3
| order by ToolCount desc`,
  },
  {
    id: 'Q39',
    title: 'Network Configuration Discovery',
    tactic: 'Discovery',
    tacticId: 'TA0007',
    mitreTechnique: 'T1016',
    logSource: 'MDE',
    severity: 'low',
    category: 'discovery',
    description: 'Detects ipconfig /all, route print, and netstat executed together.',
    kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("/all", "route print", "netstat -ano", "netstat -anb")
| summarize EventCount = count() by DeviceName, ProcessCommandLine, AccountName, bin(Timestamp, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q40',
    title: 'Permission Group Discovery',
    tactic: 'Discovery',
    tacticId: 'TA0007',
    mitreTechnique: 'T1069',
    logSource: 'MDE',
    severity: 'medium',
    category: 'discovery',
    description: 'Detects net localgroup and whoami group membership enumeration.',
    kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("localgroup", "whoami /groups", "whoami /priv")
| summarize EventCount = count() by DeviceName, ProcessCommandLine, AccountName, bin(Timestamp, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q41',
    title: 'RDP Lateral Movement',
    tactic: 'Lateral Movement',
    tacticId: 'TA0008',
    mitreTechnique: 'T1021.001',
    logSource: 'SecurityEvents',
    severity: 'high',
    category: 'lateral-movement',
    description: 'Detects RDP logons (type 10) sourced from internal workstations.',
    kql: `SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4624
| extend LogonType = toint(EventData.LogonType)
| extend IpAddress = tostring(EventData.IpAddress)
| extend Workstation = tostring(EventData.WorkstationName)
| where LogonType == 10
| where isnotempty(Workstation) and Workstation !~ "-"
| summarize LogonCount = count() by Computer, Workstation, IpAddress, Account = tostring(EventData.TargetUserName), bin(TimeGenerated, 1h)
| order by LogonCount desc`,
  },
  {
    id: 'Q42',
    title: 'SMB Lateral Movement Workstation to Workstation',
    tactic: 'Lateral Movement',
    tacticId: 'TA0008',
    mitreTechnique: 'T1021.002',
    logSource: 'SecurityEvents',
    severity: 'high',
    category: 'lateral-movement',
    description: 'Detects NTLM network logons between workstations.',
    kql: `SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4624
| extend LogonType = toint(EventData.LogonType)
| extend AuthPackage = tostring(EventData.AuthenticationPackageName)
| extend Workstation = tostring(EventData.WorkstationName)
| where LogonType == 3
| where AuthPackage =~ "NTLM"
| where isnotempty(Workstation)
| summarize LogonCount = count() by Computer, Workstation, Account = tostring(EventData.TargetUserName), bin(TimeGenerated, 1h)
| order by LogonCount desc`,
  },
  {
    id: 'Q43',
    title: 'Pass-the-Hash NTLM Authentication',
    tactic: 'Lateral Movement',
    tacticId: 'TA0008',
    mitreTechnique: 'T1550.002',
    logSource: 'SecurityEvents',
    severity: 'critical',
    category: 'lateral-movement',
    description: 'Detects NTLM logons without preceding Kerberos from non-domain-controller sources.',
    kql: `SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4624
| extend LogonType = toint(EventData.LogonType)
| extend AuthPackage = tostring(EventData.AuthenticationPackageName)
| extend IpAddress = tostring(EventData.IpAddress)
| where LogonType == 3
| where AuthPackage =~ "NTLM"
| where IpAddress !in ("-", "::1")
| summarize LogonCount = count() by Computer, Account = tostring(EventData.TargetUserName), IpAddress, bin(TimeGenerated, 1h)
| where LogonCount > 5
| order by LogonCount desc`,
  },
  {
    id: 'Q44',
    title: 'WinRM Lateral Movement',
    tactic: 'Lateral Movement',
    tacticId: 'TA0008',
    mitreTechnique: 'T1021.006',
    logSource: 'MDE',
    severity: 'high',
    category: 'lateral-movement',
    description: 'Detects WinRM connections on ports 5985/5986 between internal hosts.',
    kql: `DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort in (5985, 5986)
| where ActionType == "ConnectionSuccess"
| summarize ConnectionCount = count() by DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, bin(Timestamp, 1h)
| order by ConnectionCount desc`,
  },
  {
    id: 'Q45',
    title: 'Removable Media Execution',
    tactic: 'Lateral Movement',
    tacticId: 'TA0008',
    mitreTechnique: 'T1091',
    logSource: 'MDE',
    severity: 'medium',
    category: 'lateral-movement',
    description: 'Detects processes started from removable drive letters.',
    kql: `DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "ProcessCreated"
| extend ProcessPath = tostring(AdditionalFields.ProcessPath)
| where ProcessPath matches regex @"[E-Z]:\\\\"
| where not(ProcessPath startswith "C:")
| summarize EventCount = count() by DeviceName, ProcessPath, bin(Timestamp, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q46',
    title: 'Mailbox Data Access O365',
    tactic: 'Collection',
    tacticId: 'TA0009',
    mitreTechnique: 'T1114.001',
    logSource: 'OfficeActivity',
    severity: 'high',
    category: 'collection',
    description: 'Detects bulk mailbox access or bind operations exceeding 100 items.',
    kql: `OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation in ("MailItemsAccessed", "MessageBind")
| summarize ItemCount = count() by UserId, Operation, ClientIP, bin(TimeGenerated, 1h)
| where ItemCount > 100
| order by ItemCount desc`,
  },
  {
    id: 'Q47',
    title: 'Data Staged in Temp Folder',
    tactic: 'Collection',
    tacticId: 'TA0009',
    mitreTechnique: 'T1074.001',
    logSource: 'MDE',
    severity: 'medium',
    category: 'collection',
    description: 'Detects large files written to Temp or AppData directories.',
    kql: `DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has_any ("\\\\Temp\\\\", "\\\\AppData\\\\")
| where ActionType == "FileCreated"
| summarize TotalSizeMB = sum(FileSize) / 1048576.0, FileCount = count() by DeviceName, FolderPath, bin(Timestamp, 1h)
| where TotalSizeMB > 50
| order by TotalSizeMB desc`,
  },
  {
    id: 'Q48',
    title: 'Archive/Compress Before Exfiltration',
    tactic: 'Collection',
    tacticId: 'TA0009',
    mitreTechnique: 'T1560.001',
    logSource: 'MDE',
    severity: 'high',
    category: 'collection',
    description: 'Detects archive utilities run with password protection flags.',
    kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("7z.exe", "rar.exe", "winrar.exe", "zip.exe")
| where ProcessCommandLine has_any ("-p", "-hp", "password")
| summarize EventCount = count() by DeviceName, FileName, ProcessCommandLine, bin(Timestamp, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q49',
    title: 'Exfiltration Over C2 - Large Outbound Fortigate',
    tactic: 'Exfiltration',
    tacticId: 'TA0010',
    mitreTechnique: 'T1041',
    logSource: 'CommonSecurityLog',
    severity: 'critical',
    category: 'exfiltration',
    description: 'Detects outbound transfers exceeding 50MB to a single external IP on Fortinet firewalls.',
    kql: `CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DeviceVendor == "Fortinet"
| extend SentBytes = tolong(SentBytes)
| where SentBytes > 52428800
| where not(ipv4_is_private(tostring(DestinationIP)))
| summarize TotalMB = sum(SentBytes) / 1048576.0, Sessions = count() by SourceIP, DestinationIP, bin(TimeGenerated, 1h)
| order by TotalMB desc`,
  },
  {
    id: 'Q50',
    title: 'Exfiltration Over DNS',
    tactic: 'Exfiltration',
    tacticId: 'TA0010',
    mitreTechnique: 'T1048.003',
    logSource: 'ASimDnsActivity',
    severity: 'critical',
    category: 'exfiltration',
    description: 'Detects abnormally long DNS queries or high query rates to the same domain.',
    kql: `ASimDnsActivityLogs
| where TimeGenerated > ago(1d)
| extend QueryLength = strlen(DnsQuery)
| summarize QueryCount = count(), AvgLength = avg(QueryLength) by SrcIpAddr, DnsQuery, bin(TimeGenerated, 1m)
| where QueryCount > 200 or AvgLength > 100
| order by QueryCount desc`,
  },
  {
    id: 'Q51',
    title: 'Exfiltration to Cloud Storage',
    tactic: 'Exfiltration',
    tacticId: 'TA0010',
    mitreTechnique: 'T1567.002',
    logSource: 'MDE',
    severity: 'high',
    category: 'exfiltration',
    description: 'Detects connections to common cloud storage and file-sharing domains.',
    kql: `DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any ("dropbox.com", "onedrive.live.com", "mega.nz", "wetransfer.com", "drive.google.com")
| where ActionType == "ConnectionSuccess"
| summarize ConnectionCount = count() by DeviceName, RemoteUrl, InitiatingProcessFileName, bin(Timestamp, 1h)
| order by ConnectionCount desc`,
  },
  {
    id: 'Q52',
    title: 'C2 over HTTP/S - Beaconing Pattern',
    tactic: 'Command and Control',
    tacticId: 'TA0011',
    mitreTechnique: 'T1071.001',
    logSource: 'CommonSecurityLog',
    severity: 'high',
    category: 'c2',
    description: 'Detects regular interval beaconing between the same source and destination on firewalls.',
    kql: `CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DeviceVendor in ("Palo Alto Networks", "Fortinet")
| where DestinationPort in ("80", "443")
| summarize ConnectionCount = count(), AvgIntervalSec = avg(datetime_diff('second', TimeGenerated, prev(TimeGenerated))) by SourceIP, DestinationIP, bin(TimeGenerated, 1m)
| where ConnectionCount > 30
| where AvgIntervalSec between (50 .. 70)
| order by ConnectionCount desc`,
  },
  {
    id: 'Q53',
    title: 'DNS C2 Beaconing',
    tactic: 'Command and Control',
    tacticId: 'TA0011',
    mitreTechnique: 'T1071.004',
    logSource: 'ASimDnsActivity',
    severity: 'critical',
    category: 'c2',
    description: 'Detects high-frequency DNS queries to the same domain with long subdomains or NX responses.',
    kql: `ASimDnsActivityLogs
| where TimeGenerated > ago(1d)
| extend SubdomainLen = strlen(DnsQuery)
| summarize QueryCount = count(), NXCount = countif(EventResult != "Success"), MaxSubdomainLen = max(SubdomainLen) by SrcIpAddr, DnsQuery, bin(TimeGenerated, 1h)
| where QueryCount > 100 or MaxSubdomainLen > 50
| order by QueryCount desc`,
  },
  {
    id: 'Q54',
    title: 'Non-Standard Port C2',
    tactic: 'Command and Control',
    tacticId: 'TA0011',
    mitreTechnique: 'T1095',
    logSource: 'CommonSecurityLog',
    severity: 'high',
    category: 'c2',
    description: 'Detects outbound connections on commonly abused non-standard C2 ports.',
    kql: `CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DestinationPort in ("4444", "1337", "8888", "9999", "31337")
| where DeviceAction in ("allow", "allowed", "Accept")
| summarize ConnectionCount = count() by SourceIP, DestinationIP, DestinationPort, DeviceVendor, bin(TimeGenerated, 1h)
| order by ConnectionCount desc`,
  },
  {
    id: 'Q55',
    title: 'Protocol Tunneling - DNS over HTTPS',
    tactic: 'Command and Control',
    tacticId: 'TA0011',
    mitreTechnique: 'T1572',
    logSource: 'MDE',
    severity: 'medium',
    category: 'c2',
    description: 'Detects connections to known DNS-over-HTTPS providers on port 443.',
    kql: `DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort == 443
| where RemoteIP in ("1.1.1.1", "8.8.8.8", "9.9.9.9") or RemoteUrl has_any ("cloudflare-dns.com", "dns.google")
| summarize ConnectionCount = count() by DeviceName, RemoteIP, RemoteUrl, InitiatingProcessFileName, bin(Timestamp, 1h)
| order by ConnectionCount desc`,
  },
  {
    id: 'Q56',
    title: 'Remote Access Tool - AnyDesk TeamViewer',
    tactic: 'Command and Control',
    tacticId: 'TA0011',
    mitreTechnique: 'T1219',
    logSource: 'MDE',
    severity: 'medium',
    category: 'c2',
    description: 'Detects execution or network activity from common remote access tools.',
    kql: `DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("anydesk.exe", "teamviewer.exe", "tv_w32.exe", "rustdesk.exe")
| summarize EventCount = count() by DeviceName, FileName, ProcessCommandLine, bin(Timestamp, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q57',
    title: 'Ransomware - Mass File Extension Change',
    tactic: 'Impact',
    tacticId: 'TA0040',
    mitreTechnique: 'T1486',
    logSource: 'MDE',
    severity: 'critical',
    category: 'impact',
    description: 'Detects rapid mass file renames or extension changes on a single host.',
    kql: `DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileRenamed", "FileModified")
| extend NewExt = extract(@"\\.([^.]+)$", 1, RenameTarget)
| summarize ExtChangeCount = count() by DeviceName, NewExt, InitiatingProcessFileName, bin(Timestamp, 5m)
| where ExtChangeCount > 100
| order by ExtChangeCount desc`,
  },
  {
    id: 'Q58',
    title: 'Shadow Copy Deletion Pre-Ransomware',
    tactic: 'Impact',
    tacticId: 'TA0040',
    mitreTechnique: 'T1490',
    logSource: 'SecurityEvents',
    severity: 'critical',
    category: 'impact',
    description: 'Detects vssadmin, wmic, or bcdedit commands used to inhibit system recovery.',
    kql: `SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4688
| extend CommandLine = tostring(EventData.CommandLine)
| extend ProcessName = tostring(EventData.ProcessName)
| where ProcessName in~ ("vssadmin.exe", "wmic.exe", "bcdedit.exe", "powershell.exe")
| where CommandLine has_any ("delete shadows", "shadowcopy delete", "recoveryenabled no", "ignoreallfailures")
| summarize EventCount = count() by Computer, ProcessName, CommandLine, bin(TimeGenerated, 1h)
| order by EventCount desc`,
  },
  {
    id: 'Q59',
    title: 'Service Stop - Backup/AV Services Killed',
    tactic: 'Impact',
    tacticId: 'TA0040',
    mitreTechnique: 'T1489',
    logSource: 'SecurityEvents',
    severity: 'critical',
    category: 'impact',
    description: 'Detects backup and security services stopped in rapid sequence.',
    kql: `SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 7036
| extend ServiceName = tostring(EventData.ServiceName)
| extend State = tostring(EventData.ServiceState)
| where State has "stopped"
| where ServiceName has_any ("Veeam", "Backup", "MSSQL", "Defender", "Trend", "Sophos")
| summarize StopCount = count() by Computer, ServiceName, bin(TimeGenerated, 1h)
| where StopCount >= 2
| order by StopCount desc`,
  },
  {
    id: 'Q60',
    title: 'Data Destruction - Mass File Delete',
    tactic: 'Impact',
    tacticId: 'TA0040',
    mitreTechnique: 'T1485',
    logSource: 'MDE',
    severity: 'critical',
    category: 'impact',
    description: 'Detects more than 200 file deletions within two minutes from the same process.',
    kql: `DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType == "FileDeleted"
| summarize DeleteCount = count() by DeviceName, InitiatingProcessFileName, bin(Timestamp, 2m)
| where DeleteCount > 200
| order by DeleteCount desc`,
  },
]

const techniques = [
  { id: 'T1566.001', name: 'Spearphishing Attachment', tactic: 'Initial Access', tacticId: 'TA0001', coverage: 'critical' },
  { id: 'T1566.002', name: 'Spearphishing Link', tactic: 'Initial Access', tacticId: 'TA0001', coverage: 'critical' },
  { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access', tacticId: 'TA0001', coverage: 'critical' },
  { id: 'T1078', name: 'Valid Accounts', tactic: 'Initial Access', tacticId: 'TA0001', coverage: 'high' },
  { id: 'T1059.001', name: 'PowerShell', tactic: 'Execution', tacticId: 'TA0002', coverage: 'critical' },
  { id: 'T1059.003', name: 'Windows Command Shell', tactic: 'Execution', tacticId: 'TA0002', coverage: 'high' },
  { id: 'T1059.005', name: 'Visual Basic', tactic: 'Execution', tacticId: 'TA0002', coverage: 'high' },
  { id: 'T1204.002', name: 'Malicious File', tactic: 'Execution', tacticId: 'TA0002', coverage: 'high' },
  { id: 'T1047', name: 'Windows Management Instrumentation', tactic: 'Execution', tacticId: 'TA0002', coverage: 'medium' },
  { id: 'T1218', name: 'System Binary Proxy Execution', tactic: 'Execution', tacticId: 'TA0002', coverage: 'high' },
  { id: 'T1053.005', name: 'Scheduled Task', tactic: 'Persistence', tacticId: 'TA0003', coverage: 'high' },
  { id: 'T1547.001', name: 'Registry Run Keys', tactic: 'Persistence', tacticId: 'TA0003', coverage: 'high' },
  { id: 'T1136.001', name: 'Local Account', tactic: 'Persistence', tacticId: 'TA0003', coverage: 'critical' },
  { id: 'T1136.002', name: 'Domain Account', tactic: 'Persistence', tacticId: 'TA0003', coverage: 'high' },
  { id: 'T1543.003', name: 'Windows Service', tactic: 'Persistence', tacticId: 'TA0003', coverage: 'high' },
  { id: 'T1098', name: 'Account Manipulation', tactic: 'Persistence', tacticId: 'TA0003', coverage: 'critical' },
  { id: 'T1055', name: 'Process Injection', tactic: 'Privilege Escalation', tacticId: 'TA0004', coverage: 'critical' },
  { id: 'T1548.002', name: 'Bypass User Account Control', tactic: 'Privilege Escalation', tacticId: 'TA0004', coverage: 'high' },
  { id: 'T1134', name: 'Access Token Manipulation', tactic: 'Privilege Escalation', tacticId: 'TA0004', coverage: 'high' },
  { id: 'T1068', name: 'Exploitation for Privilege Escalation', tactic: 'Privilege Escalation', tacticId: 'TA0004', coverage: 'critical' },
  { id: 'T1562.001', name: 'Disable or Modify Tools', tactic: 'Defense Evasion', tacticId: 'TA0005', coverage: 'critical' },
  { id: 'T1070.001', name: 'Clear Windows Event Logs', tactic: 'Defense Evasion', tacticId: 'TA0005', coverage: 'critical' },
  { id: 'T1036.005', name: 'Match Legitimate Name or Location', tactic: 'Defense Evasion', tacticId: 'TA0005', coverage: 'high' },
  { id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'Defense Evasion', tacticId: 'TA0005', coverage: 'high' },
  { id: 'T1218.011', name: 'Rundll32', tactic: 'Defense Evasion', tacticId: 'TA0005', coverage: 'high' },
  { id: 'T1003.001', name: 'LSASS Memory', tactic: 'Credential Access', tacticId: 'TA0006', coverage: 'critical' },
  { id: 'T1110.001', name: 'Password Guessing', tactic: 'Credential Access', tacticId: 'TA0006', coverage: 'critical' },
  { id: 'T1110.003', name: 'Password Spraying', tactic: 'Credential Access', tacticId: 'TA0006', coverage: 'high' },
  { id: 'T1558.003', name: 'Kerberoasting', tactic: 'Credential Access', tacticId: 'TA0006', coverage: 'high' },
  { id: 'T1552.001', name: 'Credentials In Files', tactic: 'Credential Access', tacticId: 'TA0006', coverage: 'medium' },
  { id: 'T1040', name: 'Network Sniffing', tactic: 'Credential Access', tacticId: 'TA0006', coverage: 'high' },
  { id: 'T1087.002', name: 'Domain Account', tactic: 'Discovery', tacticId: 'TA0007', coverage: 'medium' },
  { id: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery', tacticId: 'TA0007', coverage: 'high' },
  { id: 'T1018', name: 'Remote System Discovery', tactic: 'Discovery', tacticId: 'TA0007', coverage: 'medium' },
  { id: 'T1082', name: 'System Information Discovery', tactic: 'Discovery', tacticId: 'TA0007', coverage: 'baselining' },
  { id: 'T1016', name: 'System Network Configuration Discovery', tactic: 'Discovery', tacticId: 'TA0007', coverage: 'low' },
  { id: 'T1069', name: 'Permission Groups Discovery', tactic: 'Discovery', tacticId: 'TA0007', coverage: 'medium' },
  { id: 'T1021.001', name: 'Remote Desktop Protocol', tactic: 'Lateral Movement', tacticId: 'TA0008', coverage: 'high' },
  { id: 'T1021.002', name: 'SMB/Windows Admin Shares', tactic: 'Lateral Movement', tacticId: 'TA0008', coverage: 'high' },
  { id: 'T1550.002', name: 'Pass the Hash', tactic: 'Lateral Movement', tacticId: 'TA0008', coverage: 'critical' },
  { id: 'T1021.006', name: 'Windows Remote Management', tactic: 'Lateral Movement', tacticId: 'TA0008', coverage: 'high' },
  { id: 'T1091', name: 'Replication Through Removable Media', tactic: 'Lateral Movement', tacticId: 'TA0008', coverage: 'medium' },
  { id: 'T1114.001', name: 'Local Email Collection', tactic: 'Collection', tacticId: 'TA0009', coverage: 'high' },
  { id: 'T1074.001', name: 'Local Data Staging', tactic: 'Collection', tacticId: 'TA0009', coverage: 'medium' },
  { id: 'T1560.001', name: 'Archive via Utility', tactic: 'Collection', tacticId: 'TA0009', coverage: 'high' },
  { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration', tacticId: 'TA0010', coverage: 'critical' },
  { id: 'T1048.003', name: 'Exfiltration Over Unencrypted Non-C2 Protocol', tactic: 'Exfiltration', tacticId: 'TA0010', coverage: 'critical' },
  { id: 'T1567.002', name: 'Exfiltration to Cloud Storage', tactic: 'Exfiltration', tacticId: 'TA0010', coverage: 'high' },
  { id: 'T1071.001', name: 'Web Protocols', tactic: 'Command and Control', tacticId: 'TA0011', coverage: 'high' },
  { id: 'T1071.004', name: 'DNS', tactic: 'Command and Control', tacticId: 'TA0011', coverage: 'critical' },
  { id: 'T1095', name: 'Non-Application Layer Protocol', tactic: 'Command and Control', tacticId: 'TA0011', coverage: 'high' },
  { id: 'T1572', name: 'Protocol Tunneling', tactic: 'Command and Control', tacticId: 'TA0011', coverage: 'medium' },
  { id: 'T1219', name: 'Remote Access Software', tactic: 'Command and Control', tacticId: 'TA0011', coverage: 'medium' },
  { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact', tacticId: 'TA0040', coverage: 'critical' },
  { id: 'T1490', name: 'Inhibit System Recovery', tactic: 'Impact', tacticId: 'TA0040', coverage: 'critical' },
  { id: 'T1489', name: 'Service Stop', tactic: 'Impact', tacticId: 'TA0040', coverage: 'critical' },
  { id: 'T1485', name: 'Data Destruction', tactic: 'Impact', tacticId: 'TA0040', coverage: 'critical' },
  { id: 'T1566', name: 'Phishing', tactic: 'Initial Access', tacticId: 'TA0001', coverage: 'critical' },
  { id: 'T1133', name: 'External Remote Services', tactic: 'Initial Access', tacticId: 'TA0001', coverage: 'medium' },
  { id: 'T1189', name: 'Drive-by Compromise', tactic: 'Initial Access', tacticId: 'TA0001', coverage: 'low' },
  { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution', tacticId: 'TA0002', coverage: 'critical' },
  { id: 'T1203', name: 'Exploitation for Client Execution', tactic: 'Execution', tacticId: 'TA0002', coverage: 'medium' },
  { id: 'T1053', name: 'Scheduled Task/Job', tactic: 'Execution', tacticId: 'TA0002', coverage: 'high' },
  { id: 'T1547', name: 'Boot or Logon Autostart Execution', tactic: 'Persistence', tacticId: 'TA0003', coverage: 'medium' },
  { id: 'T1136', name: 'Create Account', tactic: 'Persistence', tacticId: 'TA0003', coverage: 'critical' },
  { id: 'T1543', name: 'Create or Modify System Process', tactic: 'Persistence', tacticId: 'TA0003', coverage: 'high' },
  { id: 'T1505', name: 'Server Software Component', tactic: 'Persistence', tacticId: 'TA0003', coverage: 'none' },
  { id: 'T1548', name: 'Abuse Elevation Control Mechanism', tactic: 'Privilege Escalation', tacticId: 'TA0004', coverage: 'high' },
  { id: 'T1574', name: 'Hijack Execution Flow', tactic: 'Privilege Escalation', tacticId: 'TA0004', coverage: 'low' },
  { id: 'T1546', name: 'Event Triggered Execution', tactic: 'Privilege Escalation', tacticId: 'TA0004', coverage: 'none' },
  { id: 'T1562', name: 'Impair Defenses', tactic: 'Defense Evasion', tacticId: 'TA0005', coverage: 'critical' },
  { id: 'T1070', name: 'Indicator Removal', tactic: 'Defense Evasion', tacticId: 'TA0005', coverage: 'high' },
  { id: 'T1036', name: 'Masquerading', tactic: 'Defense Evasion', tacticId: 'TA0005', coverage: 'baselining' },
  { id: 'T1003', name: 'OS Credential Dumping', tactic: 'Credential Access', tacticId: 'TA0006', coverage: 'critical' },
  { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access', tacticId: 'TA0006', coverage: 'critical' },
  { id: 'T1555', name: 'Credentials from Password Stores', tactic: 'Credential Access', tacticId: 'TA0006', coverage: 'medium' },
  { id: 'T1558', name: 'Steal or Forge Kerberos Tickets', tactic: 'Credential Access', tacticId: 'TA0006', coverage: 'high' },
  { id: 'T1552', name: 'Unsecured Credentials', tactic: 'Credential Access', tacticId: 'TA0006', coverage: 'medium' },
  { id: 'T1087', name: 'Account Discovery', tactic: 'Discovery', tacticId: 'TA0007', coverage: 'baselining' },
  { id: 'T1083', name: 'File and Directory Discovery', tactic: 'Discovery', tacticId: 'TA0007', coverage: 'medium' },
  { id: 'T1021', name: 'Remote Services', tactic: 'Lateral Movement', tacticId: 'TA0008', coverage: 'high' },
  { id: 'T1570', name: 'Lateral Tool Transfer', tactic: 'Lateral Movement', tacticId: 'TA0008', coverage: 'medium' },
  { id: 'T1550', name: 'Use Alternate Authentication Material', tactic: 'Lateral Movement', tacticId: 'TA0008', coverage: 'critical' },
  { id: 'T1080', name: 'Taint Shared Content', tactic: 'Lateral Movement', tacticId: 'TA0008', coverage: 'none' },
  { id: 'T1210', name: 'Exploitation of Remote Services', tactic: 'Lateral Movement', tacticId: 'TA0008', coverage: 'low' },
  { id: 'T1560', name: 'Archive Collected Data', tactic: 'Collection', tacticId: 'TA0009', coverage: 'high' },
  { id: 'T1114', name: 'Email Collection', tactic: 'Collection', tacticId: 'TA0009', coverage: 'high' },
  { id: 'T1113', name: 'Screen Capture', tactic: 'Collection', tacticId: 'TA0009', coverage: 'low' },
  { id: 'T1074', name: 'Data Staged', tactic: 'Collection', tacticId: 'TA0009', coverage: 'medium' },
  { id: 'T1048', name: 'Exfiltration Over Alternative Protocol', tactic: 'Exfiltration', tacticId: 'TA0010', coverage: 'critical' },
  { id: 'T1567', name: 'Exfiltration Over Web Service', tactic: 'Exfiltration', tacticId: 'TA0010', coverage: 'high' },
  { id: 'T1020', name: 'Automated Exfiltration', tactic: 'Exfiltration', tacticId: 'TA0010', coverage: 'low' },
  { id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command and Control', tacticId: 'TA0011', coverage: 'critical' },
  { id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'Command and Control', tacticId: 'TA0011', coverage: 'high' },
  { id: 'T1499', name: 'Endpoint Denial of Service', tactic: 'Impact', tacticId: 'TA0040', coverage: 'low' },
]

writeFileSync(join(root, 'src/data/queries.json'), JSON.stringify(queries, null, 2) + '\n')
writeFileSync(join(root, 'src/data/techniques.json'), JSON.stringify(techniques, null, 2) + '\n')
console.log(`Wrote ${queries.length} queries and ${techniques.length} techniques`)
