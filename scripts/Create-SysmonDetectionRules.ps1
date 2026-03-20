# Create-SysmonDetectionRules.ps1
# Creates 100 custom Sysmon-based detection rules in Kibana via API
# Target: Elastic 8.17 | Index: logs-* | Dataset: windows.sysmon_operational
# Run as Administrator from E:\soc-homelab
# Usage: .\Create-SysmonDetectionRules.ps1

$KibanaUrl  = "http://localhost:5601"
$Username   = "elastic"
$Password   = "SOCHomelab2026!"
$Headers    = @{
    "Content-Type"  = "application/json"
    "kbn-xsrf"      = "true"
}

$Credentials = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${Username}:${Password}"))
$Headers["Authorization"] = "Basic $Credentials"

$Index = @("logs-*")

# Helper to post a rule
function New-DetectionRule {
    param([hashtable]$Rule)
    $Body = $Rule | ConvertTo-Json -Depth 10
    try {
        $Response = Invoke-RestMethod `
            -Uri "$KibanaUrl/api/detection_engine/rules" `
            -Method POST `
            -Headers $Headers `
            -Body $Body
        Write-Host "[+] Created: $($Rule.name)" -ForegroundColor Green
    } catch {
        $Err = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
        Write-Host "[-] Failed: $($Rule.name) - $($Err.message)" -ForegroundColor Red
    }
}

$Rules = @(

    # =========================================================
    # EXECUTION - T1059.001 PowerShell
    # =========================================================
    @{
        name = "[Sysmon] PowerShell Encoded Command Execution"
        description = "Detects PowerShell launched with -enc or -EncodedCommand flag, commonly used to obfuscate malicious payloads."
        risk_score = 73; severity = "high"; enabled = $true
        index = $Index; rule_id = "sysmon-t1059-001-enc"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "powershell.exe" AND process.command_line: (*-enc* OR *-EncodedCommand* OR *-e *)'
        tags = @("Sysmon","T1059.001","Execution","PowerShell")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0002"; name = "Execution"; reference = "https://attack.mitre.org/tactics/TA0002" }; technique = @(@{ id = "T1059"; name = "Command and Scripting Interpreter"; reference = "https://attack.mitre.org/techniques/T1059"; subtechnique = @(@{ id = "T1059.001"; name = "PowerShell"; reference = "https://attack.mitre.org/techniques/T1059/001" }) }) })
    },
    @{
        name = "[Sysmon] PowerShell Download Cradle"
        description = "Detects PowerShell using WebClient or Invoke-Expression to download and execute remote code."
        risk_score = 85; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1059-001-download"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "powershell.exe" AND process.command_line: (*DownloadString* OR *DownloadFile* OR *IEX* OR *Invoke-Expression* OR *WebClient* OR *iwr* OR *wget*)'
        tags = @("Sysmon","T1059.001","Execution","PowerShell","Download")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0002"; name = "Execution"; reference = "https://attack.mitre.org/tactics/TA0002" }; technique = @(@{ id = "T1059"; name = "Command and Scripting Interpreter"; reference = "https://attack.mitre.org/techniques/T1059" }) })
    },
    @{
        name = "[Sysmon] PowerShell Bypass Execution Policy"
        description = "Detects PowerShell launched with execution policy bypass flags."
        risk_score = 47; severity = "medium"; enabled = $true
        index = $Index; rule_id = "sysmon-t1059-001-bypass"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "powershell.exe" AND process.command_line: (*bypass* OR *-nop* OR *-NonInteractive* OR *-WindowStyle Hidden*)'
        tags = @("Sysmon","T1059.001","Execution","PowerShell")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0002"; name = "Execution"; reference = "https://attack.mitre.org/tactics/TA0002" }; technique = @(@{ id = "T1059"; name = "Command and Scripting Interpreter"; reference = "https://attack.mitre.org/techniques/T1059" }) })
    },
    @{
        name = "[Sysmon] PowerShell Spawned by Suspicious Parent"
        description = "Detects PowerShell spawned by Office apps, browsers, or scripting hosts - common malware delivery pattern."
        risk_score = 85; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1059-001-parent"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "powershell.exe" AND process.parent.name: (winword.exe OR excel.exe OR outlook.exe OR mshta.exe OR wscript.exe OR cscript.exe OR regsvr32.exe)'
        tags = @("Sysmon","T1059.001","Execution","Phishing")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0002"; name = "Execution"; reference = "https://attack.mitre.org/tactics/TA0002" }; technique = @(@{ id = "T1059"; name = "Command and Scripting Interpreter"; reference = "https://attack.mitre.org/techniques/T1059" }) })
    },

    # =========================================================
    # EXECUTION - T1059.003 CMD
    # =========================================================
    @{
        name = "[Sysmon] CMD Spawned by Suspicious Parent"
        description = "Detects cmd.exe spawned by Office apps or script interpreters."
        risk_score = 73; severity = "high"; enabled = $true
        index = $Index; rule_id = "sysmon-t1059-003-parent"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "cmd.exe" AND process.parent.name: (winword.exe OR excel.exe OR outlook.exe OR mshta.exe OR wscript.exe OR cscript.exe)'
        tags = @("Sysmon","T1059.003","Execution","CMD")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0002"; name = "Execution"; reference = "https://attack.mitre.org/tactics/TA0002" }; technique = @(@{ id = "T1059"; name = "Command and Scripting Interpreter"; reference = "https://attack.mitre.org/techniques/T1059" }) })
    },
    @{
        name = "[Sysmon] Certutil Decode or Download"
        description = "Detects certutil.exe used to decode or download files, a common LOLBin abuse technique."
        risk_score = 73; severity = "high"; enabled = $true
        index = $Index; rule_id = "sysmon-t1059-certutil"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "certutil.exe" AND process.command_line: (*decode* OR *-urlcache* OR *-split* OR *http*)'
        tags = @("Sysmon","T1059","LOLBin","Execution")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0002"; name = "Execution"; reference = "https://attack.mitre.org/tactics/TA0002" }; technique = @(@{ id = "T1059"; name = "Command and Scripting Interpreter"; reference = "https://attack.mitre.org/techniques/T1059" }) })
    },
    @{
        name = "[Sysmon] MSHTA Executing Remote Script"
        description = "Detects mshta.exe executing remote scripts via HTTP/HTTPS, commonly used in phishing attacks."
        risk_score = 85; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1059-mshta"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "mshta.exe" AND process.command_line: (*http* OR *vbscript* OR *javascript*)'
        tags = @("Sysmon","T1059","LOLBin","MSHTA")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0002"; name = "Execution"; reference = "https://attack.mitre.org/tactics/TA0002" }; technique = @(@{ id = "T1059"; name = "Command and Scripting Interpreter"; reference = "https://attack.mitre.org/techniques/T1059" }) })
    },

    # =========================================================
    # EXECUTION - T1047 WMI
    # =========================================================
    @{
        name = "[Sysmon] WMIC Process Creation"
        description = "Detects wmic.exe used to create processes, commonly used for lateral movement."
        risk_score = 47; severity = "medium"; enabled = $true
        index = $Index; rule_id = "sysmon-t1047-wmic"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "wmic.exe" AND process.command_line: (*process call create* OR *os get* OR *shadowcopy*)'
        tags = @("Sysmon","T1047","WMI","Execution")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0002"; name = "Execution"; reference = "https://attack.mitre.org/tactics/TA0002" }; technique = @(@{ id = "T1047"; name = "Windows Management Instrumentation"; reference = "https://attack.mitre.org/techniques/T1047" }) })
    },

    # =========================================================
    # PERSISTENCE - T1543.003 Windows Service
    # =========================================================
    @{
        name = "[Sysmon] New Windows Service Created via SC"
        description = "Detects sc.exe used to create a new Windows service, commonly used for persistence."
        risk_score = 73; severity = "high"; enabled = $true
        index = $Index; rule_id = "sysmon-t1543-003-sc-create"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "sc.exe" AND process.command_line: *create*'
        tags = @("Sysmon","T1543.003","Persistence","Service")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0003"; name = "Persistence"; reference = "https://attack.mitre.org/tactics/TA0003" }; technique = @(@{ id = "T1543"; name = "Create or Modify System Process"; reference = "https://attack.mitre.org/techniques/T1543"; subtechnique = @(@{ id = "T1543.003"; name = "Windows Service"; reference = "https://attack.mitre.org/techniques/T1543/003" }) }) })
    },
    @{
        name = "[Sysmon] Service Started from Suspicious Path"
        description = "Detects a Windows service binary path pointing to temp, appdata, or public directories."
        risk_score = 85; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1543-003-suspicious-path"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "sc.exe" AND process.command_line: (*\\Temp\\* OR *\\AppData\\* OR *\\Public\\* OR *\\Downloads\\*)'
        tags = @("Sysmon","T1543.003","Persistence","Service")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0003"; name = "Persistence"; reference = "https://attack.mitre.org/tactics/TA0003" }; technique = @(@{ id = "T1543"; name = "Create or Modify System Process"; reference = "https://attack.mitre.org/techniques/T1543" }) })
    },

    # =========================================================
    # PERSISTENCE - T1547.001 Registry Run Keys
    # =========================================================
    @{
        name = "[Sysmon] Registry Run Key Modification"
        description = "Detects modification of common autorun registry keys used for persistence."
        risk_score = 73; severity = "high"; enabled = $true
        index = $Index; rule_id = "sysmon-t1547-001-runkey"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: ("12" OR "13" OR "14") AND registry.path: (*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run* OR *\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce*)'
        tags = @("Sysmon","T1547.001","Persistence","Registry")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0003"; name = "Persistence"; reference = "https://attack.mitre.org/tactics/TA0003" }; technique = @(@{ id = "T1547"; name = "Boot or Logon Autostart Execution"; reference = "https://attack.mitre.org/techniques/T1547"; subtechnique = @(@{ id = "T1547.001"; name = "Registry Run Keys"; reference = "https://attack.mitre.org/techniques/T1547/001" }) }) })
    },
    @{
        name = "[Sysmon] Startup Folder File Created"
        description = "Detects file creation in Windows Startup folders used for persistence."
        risk_score = 73; severity = "high"; enabled = $true
        index = $Index; rule_id = "sysmon-t1547-001-startup"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "11" AND file.path: (*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\* OR *\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*)'
        tags = @("Sysmon","T1547.001","Persistence","Startup")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0003"; name = "Persistence"; reference = "https://attack.mitre.org/tactics/TA0003" }; technique = @(@{ id = "T1547"; name = "Boot or Logon Autostart Execution"; reference = "https://attack.mitre.org/techniques/T1547" }) })
    },

    # =========================================================
    # PERSISTENCE - T1053.005 Scheduled Task
    # =========================================================
    @{
        name = "[Sysmon] Scheduled Task Created via Schtasks"
        description = "Detects schtasks.exe used to create a scheduled task for persistence."
        risk_score = 73; severity = "high"; enabled = $true
        index = $Index; rule_id = "sysmon-t1053-005-schtasks"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "schtasks.exe" AND process.command_line: */create*'
        tags = @("Sysmon","T1053.005","Persistence","ScheduledTask")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0003"; name = "Persistence"; reference = "https://attack.mitre.org/tactics/TA0003" }; technique = @(@{ id = "T1053"; name = "Scheduled Task/Job"; reference = "https://attack.mitre.org/techniques/T1053" }) })
    },
    @{
        name = "[Sysmon] Scheduled Task Running from Temp"
        description = "Detects a scheduled task executing a binary from temp or download directories."
        risk_score = 85; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1053-005-temp"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "schtasks.exe" AND process.command_line: (*\\Temp\\* OR *\\Downloads\\* OR *\\AppData\\*)'
        tags = @("Sysmon","T1053.005","Persistence","ScheduledTask")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0003"; name = "Persistence"; reference = "https://attack.mitre.org/tactics/TA0003" }; technique = @(@{ id = "T1053"; name = "Scheduled Task/Job"; reference = "https://attack.mitre.org/techniques/T1053" }) })
    },

    # =========================================================
    # PRIVILEGE ESCALATION - T1055 Process Injection
    # =========================================================
    @{
        name = "[Sysmon] Remote Thread Injection Detected"
        description = "Detects CreateRemoteThread calls targeting a different process, a classic process injection indicator."
        risk_score = 85; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1055-createremotethread"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "8"'
        tags = @("Sysmon","T1055","ProcessInjection","PrivilegeEscalation")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0004"; name = "Privilege Escalation"; reference = "https://attack.mitre.org/tactics/TA0004" }; technique = @(@{ id = "T1055"; name = "Process Injection"; reference = "https://attack.mitre.org/techniques/T1055" }) })
    },
    @{
        name = "[Sysmon] LSASS Process Access"
        description = "Detects process access to lsass.exe, a primary indicator of credential dumping."
        risk_score = 99; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1055-lsass-access"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "10" AND winlog.event_data.TargetImage: *lsass.exe*'
        tags = @("Sysmon","T1003","CredentialDumping","LSASS")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0006"; name = "Credential Access"; reference = "https://attack.mitre.org/tactics/TA0006" }; technique = @(@{ id = "T1003"; name = "OS Credential Dumping"; reference = "https://attack.mitre.org/techniques/T1003" }) })
    },

    # =========================================================
    # DEFENSE EVASION - T1562 Disable Security Tools
    # =========================================================
    @{
        name = "[Sysmon] Windows Defender Disabled via PowerShell"
        description = "Detects PowerShell commands disabling Windows Defender real-time monitoring."
        risk_score = 99; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1562-defender-disable"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "powershell.exe" AND process.command_line: (*DisableRealtimeMonitoring* OR *DisableBehaviorMonitoring* OR *DisableIOAVProtection* OR *Set-MpPreference*)'
        tags = @("Sysmon","T1562","DefenseEvasion","Defender")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0005"; name = "Defense Evasion"; reference = "https://attack.mitre.org/tactics/TA0005" }; technique = @(@{ id = "T1562"; name = "Impair Defenses"; reference = "https://attack.mitre.org/techniques/T1562" }) })
    },
    @{
        name = "[Sysmon] Windows Firewall Disabled via Netsh"
        description = "Detects netsh commands used to disable Windows Firewall."
        risk_score = 85; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1562-firewall-disable"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "netsh.exe" AND process.command_line: (*firewall* AND (*disable* OR *off*))'
        tags = @("Sysmon","T1562","DefenseEvasion","Firewall")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0005"; name = "Defense Evasion"; reference = "https://attack.mitre.org/tactics/TA0005" }; technique = @(@{ id = "T1562"; name = "Impair Defenses"; reference = "https://attack.mitre.org/techniques/T1562" }) })
    },
    @{
        name = "[Sysmon] Event Log Cleared"
        description = "Detects wevtutil or PowerShell used to clear Windows event logs."
        risk_score = 85; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1562-eventlog-clear"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND (process.name: "wevtutil.exe" AND process.command_line: *cl*) OR (process.name: "powershell.exe" AND process.command_line: *Clear-EventLog*)'
        tags = @("Sysmon","T1562","DefenseEvasion","EventLog")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0005"; name = "Defense Evasion"; reference = "https://attack.mitre.org/tactics/TA0005" }; technique = @(@{ id = "T1562"; name = "Impair Defenses"; reference = "https://attack.mitre.org/techniques/T1562" }) })
    },

    # =========================================================
    # DEFENSE EVASION - T1036 Masquerading
    # =========================================================
    @{
        name = "[Sysmon] Svchost Running from Non-System32 Path"
        description = "Detects svchost.exe running from a path other than System32, a common masquerading technique."
        risk_score = 99; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1036-svchost-path"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "svchost.exe" AND NOT process.executable: *\\Windows\\System32\\svchost.exe'
        tags = @("Sysmon","T1036","Masquerading","DefenseEvasion")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0005"; name = "Defense Evasion"; reference = "https://attack.mitre.org/tactics/TA0005" }; technique = @(@{ id = "T1036"; name = "Masquerading"; reference = "https://attack.mitre.org/techniques/T1036" }) })
    },
    @{
        name = "[Sysmon] Explorer Running from Suspicious Path"
        description = "Detects explorer.exe running from a non-standard path."
        risk_score = 85; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1036-explorer-path"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "explorer.exe" AND NOT process.executable: *\\Windows\\explorer.exe'
        tags = @("Sysmon","T1036","Masquerading","DefenseEvasion")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0005"; name = "Defense Evasion"; reference = "https://attack.mitre.org/tactics/TA0005" }; technique = @(@{ id = "T1036"; name = "Masquerading"; reference = "https://attack.mitre.org/techniques/T1036" }) })
    },

    # =========================================================
    # CREDENTIAL ACCESS - T1003 Credential Dumping
    # =========================================================
    @{
        name = "[Sysmon] SAM Registry Hive Access"
        description = "Detects attempts to save or access the SAM registry hive containing password hashes."
        risk_score = 99; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1003-sam-access"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.command_line: (*reg save*HKLM\\SAM* OR *reg save*HKLM\\SYSTEM* OR *reg save*HKLM\\SECURITY*)'
        tags = @("Sysmon","T1003","CredentialDumping","SAM")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0006"; name = "Credential Access"; reference = "https://attack.mitre.org/tactics/TA0006" }; technique = @(@{ id = "T1003"; name = "OS Credential Dumping"; reference = "https://attack.mitre.org/techniques/T1003" }) })
    },
    @{
        name = "[Sysmon] Mimikatz Indicators in Command Line"
        description = "Detects common Mimikatz command patterns in process command lines."
        risk_score = 99; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1003-mimikatz-cmdline"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.command_line: (*sekurlsa* OR *lsadump* OR *kerberos::* OR *privilege::debug* OR *crypto::* OR *mimikatz*)'
        tags = @("Sysmon","T1003","Mimikatz","CredentialDumping")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0006"; name = "Credential Access"; reference = "https://attack.mitre.org/tactics/TA0006" }; technique = @(@{ id = "T1003"; name = "OS Credential Dumping"; reference = "https://attack.mitre.org/techniques/T1003" }) })
    },
    @{
        name = "[Sysmon] Procdump Targeting LSASS"
        description = "Detects procdump.exe or taskmgr.exe being used to dump the LSASS process memory."
        risk_score = 99; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1003-procdump-lsass"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: ("procdump.exe" OR "procdump64.exe") AND process.command_line: *lsass*'
        tags = @("Sysmon","T1003","CredentialDumping","Procdump")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0006"; name = "Credential Access"; reference = "https://attack.mitre.org/tactics/TA0006" }; technique = @(@{ id = "T1003"; name = "OS Credential Dumping"; reference = "https://attack.mitre.org/techniques/T1003" }) })
    },

    # =========================================================
    # DISCOVERY - T1087 Account Discovery
    # =========================================================
    @{
        name = "[Sysmon] Net User Enumeration"
        description = "Detects net.exe used to enumerate local or domain user accounts."
        risk_score = 21; severity = "low"; enabled = $true
        index = $Index; rule_id = "sysmon-t1087-net-user"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: ("net.exe" OR "net1.exe") AND process.command_line: *user*'
        tags = @("Sysmon","T1087","Discovery","Reconnaissance")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0007"; name = "Discovery"; reference = "https://attack.mitre.org/tactics/TA0007" }; technique = @(@{ id = "T1087"; name = "Account Discovery"; reference = "https://attack.mitre.org/techniques/T1087" }) })
    },
    @{
        name = "[Sysmon] Net Localgroup Enumeration"
        description = "Detects net.exe used to enumerate local groups including administrators."
        risk_score = 21; severity = "low"; enabled = $true
        index = $Index; rule_id = "sysmon-t1069-net-localgroup"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: ("net.exe" OR "net1.exe") AND process.command_line: *localgroup*'
        tags = @("Sysmon","T1069","Discovery","Reconnaissance")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0007"; name = "Discovery"; reference = "https://attack.mitre.org/tactics/TA0007" }; technique = @(@{ id = "T1069"; name = "Permission Groups Discovery"; reference = "https://attack.mitre.org/techniques/T1069" }) })
    },
    @{
        name = "[Sysmon] Whoami Execution"
        description = "Detects whoami.exe execution, commonly used for privilege discovery post-exploitation."
        risk_score = 21; severity = "low"; enabled = $true
        index = $Index; rule_id = "sysmon-t1033-whoami"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "whoami.exe"'
        tags = @("Sysmon","T1033","Discovery","Reconnaissance")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0007"; name = "Discovery"; reference = "https://attack.mitre.org/tactics/TA0007" }; technique = @(@{ id = "T1033"; name = "System Owner/User Discovery"; reference = "https://attack.mitre.org/techniques/T1033" }) })
    },
    @{
        name = "[Sysmon] Systeminfo Execution"
        description = "Detects systeminfo.exe execution used to gather OS and hardware information."
        risk_score = 21; severity = "low"; enabled = $true
        index = $Index; rule_id = "sysmon-t1082-systeminfo"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "systeminfo.exe"'
        tags = @("Sysmon","T1082","Discovery","Reconnaissance")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0007"; name = "Discovery"; reference = "https://attack.mitre.org/tactics/TA0007" }; technique = @(@{ id = "T1082"; name = "System Information Discovery"; reference = "https://attack.mitre.org/techniques/T1082" }) })
    },
    @{
        name = "[Sysmon] IPConfig Network Discovery"
        description = "Detects ipconfig.exe used for network configuration discovery."
        risk_score = 21; severity = "low"; enabled = $true
        index = $Index; rule_id = "sysmon-t1016-ipconfig"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "ipconfig.exe"'
        tags = @("Sysmon","T1016","Discovery","Network")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0007"; name = "Discovery"; reference = "https://attack.mitre.org/tactics/TA0007" }; technique = @(@{ id = "T1016"; name = "System Network Configuration Discovery"; reference = "https://attack.mitre.org/techniques/T1016" }) })
    },
    @{
        name = "[Sysmon] Tasklist Process Discovery"
        description = "Detects tasklist.exe used to enumerate running processes."
        risk_score = 21; severity = "low"; enabled = $true
        index = $Index; rule_id = "sysmon-t1057-tasklist"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "tasklist.exe"'
        tags = @("Sysmon","T1057","Discovery","Process")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0007"; name = "Discovery"; reference = "https://attack.mitre.org/tactics/TA0007" }; technique = @(@{ id = "T1057"; name = "Process Discovery"; reference = "https://attack.mitre.org/techniques/T1057" }) })
    },
    @{
        name = "[Sysmon] ARP Cache Enumeration"
        description = "Detects arp.exe used to discover network neighbors."
        risk_score = 21; severity = "low"; enabled = $true
        index = $Index; rule_id = "sysmon-t1016-arp"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "arp.exe"'
        tags = @("Sysmon","T1016","Discovery","Network")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0007"; name = "Discovery"; reference = "https://attack.mitre.org/tactics/TA0007" }; technique = @(@{ id = "T1016"; name = "System Network Configuration Discovery"; reference = "https://attack.mitre.org/techniques/T1016" }) })
    },
    @{
        name = "[Sysmon] Netstat Active Connection Discovery"
        description = "Detects netstat.exe used to enumerate active network connections."
        risk_score = 21; severity = "low"; enabled = $true
        index = $Index; rule_id = "sysmon-t1049-netstat"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "netstat.exe"'
        tags = @("Sysmon","T1049","Discovery","Network")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0007"; name = "Discovery"; reference = "https://attack.mitre.org/tactics/TA0007" }; technique = @(@{ id = "T1049"; name = "System Network Connections Discovery"; reference = "https://attack.mitre.org/techniques/T1049" }) })
    },
    @{
        name = "[Sysmon] Route Table Discovery"
        description = "Detects route.exe used to enumerate the routing table."
        risk_score = 21; severity = "low"; enabled = $true
        index = $Index; rule_id = "sysmon-t1016-route"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "route.exe" AND process.command_line: *print*'
        tags = @("Sysmon","T1016","Discovery","Network")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0007"; name = "Discovery"; reference = "https://attack.mitre.org/tactics/TA0007" }; technique = @(@{ id = "T1016"; name = "System Network Configuration Discovery"; reference = "https://attack.mitre.org/techniques/T1016" }) })
    },

    # =========================================================
    # LATERAL MOVEMENT - T1021 Remote Services
    # =========================================================
    @{
        name = "[Sysmon] PsExec Lateral Movement"
        description = "Detects PsExec execution, commonly used for lateral movement."
        risk_score = 73; severity = "high"; enabled = $true
        index = $Index; rule_id = "sysmon-t1021-psexec"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: ("psexec.exe" OR "psexec64.exe" OR "PsExec.exe")'
        tags = @("Sysmon","T1021","LateralMovement","PsExec")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0008"; name = "Lateral Movement"; reference = "https://attack.mitre.org/tactics/TA0008" }; technique = @(@{ id = "T1021"; name = "Remote Services"; reference = "https://attack.mitre.org/techniques/T1021" }) })
    },
    @{
        name = "[Sysmon] RDP Session Initiated"
        description = "Detects mstsc.exe launched to initiate a Remote Desktop connection."
        risk_score = 47; severity = "medium"; enabled = $true
        index = $Index; rule_id = "sysmon-t1021-rdp"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "mstsc.exe"'
        tags = @("Sysmon","T1021.001","LateralMovement","RDP")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0008"; name = "Lateral Movement"; reference = "https://attack.mitre.org/tactics/TA0008" }; technique = @(@{ id = "T1021"; name = "Remote Services"; reference = "https://attack.mitre.org/techniques/T1021" }) })
    },

    # =========================================================
    # COMMAND AND CONTROL - T1071 Application Layer Protocol
    # =========================================================
    @{
        name = "[Sysmon] Process Network Connection to Unusual Port"
        description = "Detects processes making outbound connections to uncommon ports that may indicate C2 traffic."
        risk_score = 47; severity = "medium"; enabled = $true
        index = $Index; rule_id = "sysmon-t1071-unusual-port"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "3" AND NOT destination.port: (80 OR 443 OR 53 OR 8080 OR 8443 OR 22 OR 25 OR 587 OR 993 OR 995) AND process.name: (powershell.exe OR cmd.exe OR wscript.exe OR cscript.exe OR mshta.exe)'
        tags = @("Sysmon","T1071","C2","Network")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0011"; name = "Command and Control"; reference = "https://attack.mitre.org/tactics/TA0011" }; technique = @(@{ id = "T1071"; name = "Application Layer Protocol"; reference = "https://attack.mitre.org/techniques/T1071" }) })
    },
    @{
        name = "[Sysmon] PowerShell Outbound Network Connection"
        description = "Detects PowerShell initiating outbound network connections, potential C2 beaconing."
        risk_score = 73; severity = "high"; enabled = $true
        index = $Index; rule_id = "sysmon-t1071-ps-network"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "3" AND process.name: "powershell.exe"'
        tags = @("Sysmon","T1071","C2","PowerShell","Network")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0011"; name = "Command and Control"; reference = "https://attack.mitre.org/tactics/TA0011" }; technique = @(@{ id = "T1071"; name = "Application Layer Protocol"; reference = "https://attack.mitre.org/techniques/T1071" }) })
    },
    @{
        name = "[Sysmon] DNS Query for Long Domain Name"
        description = "Detects DNS queries with unusually long subdomain names, potential DNS tunneling indicator."
        risk_score = 47; severity = "medium"; enabled = $true
        index = $Index; rule_id = "sysmon-t1071-dns-tunnel"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "22" AND dns.question.name: *.????????????????????????????????????????*'
        tags = @("Sysmon","T1071","DNSTunneling","C2")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0011"; name = "Command and Control"; reference = "https://attack.mitre.org/tactics/TA0011" }; technique = @(@{ id = "T1071"; name = "Application Layer Protocol"; reference = "https://attack.mitre.org/techniques/T1071" }) })
    },
    @{
        name = "[Sysmon] Netcat or Ncat Network Tool"
        description = "Detects netcat or ncat execution which may indicate reverse shell or port forwarding activity."
        risk_score = 85; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1071-netcat"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: ("nc.exe" OR "ncat.exe" OR "netcat.exe")'
        tags = @("Sysmon","T1071","C2","Netcat")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0011"; name = "Command and Control"; reference = "https://attack.mitre.org/tactics/TA0011" }; technique = @(@{ id = "T1071"; name = "Application Layer Protocol"; reference = "https://attack.mitre.org/techniques/T1071" }) })
    },

    # =========================================================
    # EXFILTRATION - T1048
    # =========================================================
    @{
        name = "[Sysmon] Curl or Wget Data Transfer"
        description = "Detects curl.exe or wget.exe used to transfer data out, potential exfiltration."
        risk_score = 47; severity = "medium"; enabled = $true
        index = $Index; rule_id = "sysmon-t1048-curl-wget"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: ("curl.exe" OR "wget.exe") AND process.command_line: (*upload* OR *-T* OR *--data* OR *-d*)'
        tags = @("Sysmon","T1048","Exfiltration","Network")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0010"; name = "Exfiltration"; reference = "https://attack.mitre.org/tactics/TA0010" }; technique = @(@{ id = "T1048"; name = "Exfiltration Over Alternative Protocol"; reference = "https://attack.mitre.org/techniques/T1048" }) })
    },

    # =========================================================
    # IMPACT - T1486 Ransomware Indicators
    # =========================================================
    @{
        name = "[Sysmon] Volume Shadow Copy Deletion"
        description = "Detects vssadmin or wmic used to delete volume shadow copies, a common ransomware pre-step."
        risk_score = 99; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1490-vss-delete"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND ((process.name: "vssadmin.exe" AND process.command_line: (*delete shadows* OR *resize shadowstorage*)) OR (process.name: "wmic.exe" AND process.command_line: *shadowcopy delete*))'
        tags = @("Sysmon","T1490","Ransomware","Impact","VSS")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0040"; name = "Impact"; reference = "https://attack.mitre.org/tactics/TA0040" }; technique = @(@{ id = "T1490"; name = "Inhibit System Recovery"; reference = "https://attack.mitre.org/techniques/T1490" }) })
    },
    @{
        name = "[Sysmon] BCDEdit Disabling Recovery"
        description = "Detects bcdedit.exe used to disable Windows recovery options, a ransomware indicator."
        risk_score = 99; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1490-bcdedit"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "bcdedit.exe" AND process.command_line: (*recoveryenabled No* OR *bootstatuspolicy ignoreallfailures*)'
        tags = @("Sysmon","T1490","Ransomware","Impact","BCDEdit")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0040"; name = "Impact"; reference = "https://attack.mitre.org/tactics/TA0040" }; technique = @(@{ id = "T1490"; name = "Inhibit System Recovery"; reference = "https://attack.mitre.org/techniques/T1490" }) })
    },

    # =========================================================
    # INITIAL ACCESS - T1566 Phishing / Office Macros
    # =========================================================
    @{
        name = "[Sysmon] Office Application Spawning Script Host"
        description = "Detects Office apps spawning wscript or cscript, indicator of macro-based malware."
        risk_score = 85; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1566-office-script"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.parent.name: (winword.exe OR excel.exe OR powerpnt.exe OR outlook.exe) AND process.name: (wscript.exe OR cscript.exe OR powershell.exe OR cmd.exe OR mshta.exe)'
        tags = @("Sysmon","T1566","InitialAccess","Phishing","OfficeMacro")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0001"; name = "Initial Access"; reference = "https://attack.mitre.org/tactics/TA0001" }; technique = @(@{ id = "T1566"; name = "Phishing"; reference = "https://attack.mitre.org/techniques/T1566" }) })
    },

    # =========================================================
    # NETWORK - Suspicious Connections
    # =========================================================
    @{
        name = "[Sysmon] SMB Connection to External Host"
        description = "Detects outbound SMB connections (port 445) to external IPs, potential lateral movement or data exfil."
        risk_score = 73; severity = "high"; enabled = $true
        index = $Index; rule_id = "sysmon-t1021-smb-external"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "3" AND destination.port: 445 AND NOT destination.ip: (10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16 OR 127.0.0.1)'
        tags = @("Sysmon","T1021","SMB","LateralMovement")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0008"; name = "Lateral Movement"; reference = "https://attack.mitre.org/tactics/TA0008" }; technique = @(@{ id = "T1021"; name = "Remote Services"; reference = "https://attack.mitre.org/techniques/T1021" }) })
    },
    @{
        name = "[Sysmon] Tor Network Ports Contacted"
        description = "Detects connections to common Tor ports 9001 and 9050."
        risk_score = 73; severity = "high"; enabled = $true
        index = $Index; rule_id = "sysmon-t1090-tor-ports"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "3" AND destination.port: (9001 OR 9050 OR 9150)'
        tags = @("Sysmon","T1090","C2","Tor","Network")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0011"; name = "Command and Control"; reference = "https://attack.mitre.org/tactics/TA0011" }; technique = @(@{ id = "T1090"; name = "Proxy"; reference = "https://attack.mitre.org/techniques/T1090" }) })
    },

    # =========================================================
    # LOLBins - Living Off the Land
    # =========================================================
    @{
        name = "[Sysmon] Regsvr32 Script Execution"
        description = "Detects regsvr32.exe used to execute scripts via scrobj.dll, a LOLBin technique."
        risk_score = 73; severity = "high"; enabled = $true
        index = $Index; rule_id = "sysmon-lolbin-regsvr32"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "regsvr32.exe" AND process.command_line: (*scrobj* OR */u* OR *http*)'
        tags = @("Sysmon","T1218","LOLBin","DefenseEvasion")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0005"; name = "Defense Evasion"; reference = "https://attack.mitre.org/tactics/TA0005" }; technique = @(@{ id = "T1218"; name = "System Binary Proxy Execution"; reference = "https://attack.mitre.org/techniques/T1218" }) })
    },
    @{
        name = "[Sysmon] Rundll32 Suspicious Execution"
        description = "Detects rundll32.exe with suspicious arguments commonly used to proxy malicious DLL execution."
        risk_score = 73; severity = "high"; enabled = $true
        index = $Index; rule_id = "sysmon-lolbin-rundll32"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "rundll32.exe" AND process.command_line: (*javascript* OR *vbscript* OR *http* OR *shell32* OR *..\\*)'
        tags = @("Sysmon","T1218","LOLBin","DefenseEvasion")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0005"; name = "Defense Evasion"; reference = "https://attack.mitre.org/tactics/TA0005" }; technique = @(@{ id = "T1218"; name = "System Binary Proxy Execution"; reference = "https://attack.mitre.org/techniques/T1218" }) })
    },
    @{
        name = "[Sysmon] InstallUtil Used for Code Execution"
        description = "Detects InstallUtil.exe used to execute code, bypassing application whitelisting."
        risk_score = 73; severity = "high"; enabled = $true
        index = $Index; rule_id = "sysmon-lolbin-installutil"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "installutil.exe"'
        tags = @("Sysmon","T1218","LOLBin","DefenseEvasion")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0005"; name = "Defense Evasion"; reference = "https://attack.mitre.org/tactics/TA0005" }; technique = @(@{ id = "T1218"; name = "System Binary Proxy Execution"; reference = "https://attack.mitre.org/techniques/T1218" }) })
    },
    @{
        name = "[Sysmon] MSBuild Code Execution"
        description = "Detects msbuild.exe used to execute inline code, a known LOLBin technique."
        risk_score = 73; severity = "high"; enabled = $true
        index = $Index; rule_id = "sysmon-lolbin-msbuild"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "msbuild.exe" AND process.parent.name: (cmd.exe OR powershell.exe OR wscript.exe)'
        tags = @("Sysmon","T1127","LOLBin","DefenseEvasion")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0005"; name = "Defense Evasion"; reference = "https://attack.mitre.org/tactics/TA0005" }; technique = @(@{ id = "T1127"; name = "Trusted Developer Utilities Proxy Execution"; reference = "https://attack.mitre.org/techniques/T1127" }) })
    },

    # =========================================================
    # PRIVILEGE ESCALATION - T1548 UAC Bypass
    # =========================================================
    @{
        name = "[Sysmon] UAC Bypass via Fodhelper"
        description = "Detects fodhelper.exe used for UAC bypass via registry key manipulation."
        risk_score = 85; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1548-fodhelper"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: ("12" OR "13") AND registry.path: *\\Software\\Classes\\ms-settings\\shell\\open\\command*'
        tags = @("Sysmon","T1548","UACBypass","PrivilegeEscalation")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0004"; name = "Privilege Escalation"; reference = "https://attack.mitre.org/tactics/TA0004" }; technique = @(@{ id = "T1548"; name = "Abuse Elevation Control Mechanism"; reference = "https://attack.mitre.org/techniques/T1548" }) })
    },
    @{
        name = "[Sysmon] UAC Bypass via Eventvwr"
        description = "Detects eventvwr.exe UAC bypass technique via registry hijack."
        risk_score = 85; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1548-eventvwr"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: ("12" OR "13") AND registry.path: *\\Software\\Classes\\mscfile\\shell\\open\\command*'
        tags = @("Sysmon","T1548","UACBypass","PrivilegeEscalation")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0004"; name = "Privilege Escalation"; reference = "https://attack.mitre.org/tactics/TA0004" }; technique = @(@{ id = "T1548"; name = "Abuse Elevation Control Mechanism"; reference = "https://attack.mitre.org/techniques/T1548" }) })
    },

    # =========================================================
    # FILE SYSTEM - Suspicious File Activity
    # =========================================================
    @{
        name = "[Sysmon] Executable Dropped in Temp Directory"
        description = "Detects executable files created in Temp or Downloads directories."
        risk_score = 47; severity = "medium"; enabled = $true
        index = $Index; rule_id = "sysmon-t1105-exe-temp"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "11" AND file.extension: ("exe" OR "dll" OR "bat" OR "ps1" OR "vbs") AND file.path: (*\\Temp\\* OR *\\Downloads\\* OR *\\AppData\\Local\\Temp\\*)'
        tags = @("Sysmon","T1105","FileDropped","SuspiciousFile")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0002"; name = "Execution"; reference = "https://attack.mitre.org/tactics/TA0002" }; technique = @(@{ id = "T1105"; name = "Ingress Tool Transfer"; reference = "https://attack.mitre.org/techniques/T1105" }) })
    },
    @{
        name = "[Sysmon] PowerShell Script Dropped to Disk"
        description = "Detects .ps1 files written to disk, potential malicious script staging."
        risk_score = 47; severity = "medium"; enabled = $true
        index = $Index; rule_id = "sysmon-t1105-ps1-drop"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "11" AND file.extension: "ps1"'
        tags = @("Sysmon","T1105","FileDropped","PowerShell")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0002"; name = "Execution"; reference = "https://attack.mitre.org/tactics/TA0002" }; technique = @(@{ id = "T1105"; name = "Ingress Tool Transfer"; reference = "https://attack.mitre.org/techniques/T1105" }) })
    },

    # =========================================================
    # CREDENTIAL ACCESS - T1110 Brute Force
    # =========================================================
    @{
        name = "[Sysmon] Hydra or Medusa Brute Force Tool"
        description = "Detects execution of known brute force tools like hydra or medusa."
        risk_score = 85; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1110-brute-tool"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: ("hydra.exe" OR "medusa.exe" OR "brutus.exe" OR "THC-Hydra.exe")'
        tags = @("Sysmon","T1110","BruteForce","CredentialAccess")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0006"; name = "Credential Access"; reference = "https://attack.mitre.org/tactics/TA0006" }; technique = @(@{ id = "T1110"; name = "Brute Force"; reference = "https://attack.mitre.org/techniques/T1110" }) })
    },
    @{
        name = "[Sysmon] Net User Account Created"
        description = "Detects net.exe used to create a new local user account."
        risk_score = 73; severity = "high"; enabled = $true
        index = $Index; rule_id = "sysmon-t1136-net-user-add"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: ("net.exe" OR "net1.exe") AND process.command_line: (*user* AND */add*)'
        tags = @("Sysmon","T1136","Persistence","AccountCreation")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0003"; name = "Persistence"; reference = "https://attack.mitre.org/tactics/TA0003" }; technique = @(@{ id = "T1136"; name = "Create Account"; reference = "https://attack.mitre.org/techniques/T1136" }) })
    },
    @{
        name = "[Sysmon] User Added to Administrators Group"
        description = "Detects net.exe used to add a user to the local Administrators group."
        risk_score = 85; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1136-admin-add"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: ("net.exe" OR "net1.exe") AND process.command_line: (*localgroup* AND *administrators* AND */add*)'
        tags = @("Sysmon","T1136","PrivilegeEscalation","AccountManipulation")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0004"; name = "Privilege Escalation"; reference = "https://attack.mitre.org/tactics/TA0004" }; technique = @(@{ id = "T1136"; name = "Create Account"; reference = "https://attack.mitre.org/techniques/T1136" }) })
    },

    # =========================================================
    # RECON - Additional Discovery
    # =========================================================
    @{
        name = "[Sysmon] NLTEST Domain Trust Discovery"
        description = "Detects nltest.exe used to enumerate domain trusts."
        risk_score = 47; severity = "medium"; enabled = $true
        index = $Index; rule_id = "sysmon-t1482-nltest"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "nltest.exe"'
        tags = @("Sysmon","T1482","Discovery","DomainTrust")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0007"; name = "Discovery"; reference = "https://attack.mitre.org/tactics/TA0007" }; technique = @(@{ id = "T1482"; name = "Domain Trust Discovery"; reference = "https://attack.mitre.org/techniques/T1482" }) })
    },
    @{
        name = "[Sysmon] Ping Sweep Activity"
        description = "Detects ping.exe used repeatedly, potential network sweep."
        risk_score = 21; severity = "low"; enabled = $true
        index = $Index; rule_id = "sysmon-t1018-ping"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "ping.exe"'
        tags = @("Sysmon","T1018","Discovery","NetworkScan")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0007"; name = "Discovery"; reference = "https://attack.mitre.org/tactics/TA0007" }; technique = @(@{ id = "T1018"; name = "Remote System Discovery"; reference = "https://attack.mitre.org/techniques/T1018" }) })
    },
    @{
        name = "[Sysmon] WMIC Querying Installed Software"
        description = "Detects wmic.exe used to enumerate installed software."
        risk_score = 21; severity = "low"; enabled = $true
        index = $Index; rule_id = "sysmon-t1518-wmic-software"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "wmic.exe" AND process.command_line: (*product get* OR *qfe get*)'
        tags = @("Sysmon","T1518","Discovery","SoftwareDiscovery")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0007"; name = "Discovery"; reference = "https://attack.mitre.org/tactics/TA0007" }; technique = @(@{ id = "T1518"; name = "Software Discovery"; reference = "https://attack.mitre.org/techniques/T1518" }) })
    },
    @{
        name = "[Sysmon] Dir Command Sensitive Directory Listing"
        description = "Detects dir command targeting sensitive directories like SAM, NTDS, or credential stores."
        risk_score = 47; severity = "medium"; enabled = $true
        index = $Index; rule_id = "sysmon-t1083-dir-sensitive"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "cmd.exe" AND process.command_line: (*dir* AND (*\\Windows\\System32\\config* OR *\\NTDS* OR *\\Users\\*\\AppData*))'
        tags = @("Sysmon","T1083","Discovery","FileDiscovery")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0007"; name = "Discovery"; reference = "https://attack.mitre.org/tactics/TA0007" }; technique = @(@{ id = "T1083"; name = "File and Directory Discovery"; reference = "https://attack.mitre.org/techniques/T1083" }) })
    },

    # =========================================================
    # DEFENSE EVASION - Additional
    # =========================================================
    @{
        name = "[Sysmon] WMIC Shadowcopy Deletion"
        description = "Detects wmic.exe deleting shadow copies, ransomware pre-deployment step."
        risk_score = 99; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1490-wmic-shadow"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "wmic.exe" AND process.command_line: (*shadowcopy* AND (*delete* OR *where*))'
        tags = @("Sysmon","T1490","Ransomware","VSS","Impact")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0040"; name = "Impact"; reference = "https://attack.mitre.org/tactics/TA0040" }; technique = @(@{ id = "T1490"; name = "Inhibit System Recovery"; reference = "https://attack.mitre.org/techniques/T1490" }) })
    },
    @{
        name = "[Sysmon] Base64 Encoded Payload in Command Line"
        description = "Detects suspicious base64 encoded payloads in any process command line."
        risk_score = 73; severity = "high"; enabled = $true
        index = $Index; rule_id = "sysmon-t1027-base64"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.command_line: (*JAB* OR *TVqQ* OR *SUVY* OR *SQBtAHAAbwByAHQA* OR *aQBtAHAAbwByAHQA*)'
        tags = @("Sysmon","T1027","Obfuscation","DefenseEvasion")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0005"; name = "Defense Evasion"; reference = "https://attack.mitre.org/tactics/TA0005" }; technique = @(@{ id = "T1027"; name = "Obfuscated Files or Information"; reference = "https://attack.mitre.org/techniques/T1027" }) })
    },
    @{
        name = "[Sysmon] Process Spawned from Unusual Directory"
        description = "Detects executables launched from unusual writable directories."
        risk_score = 73; severity = "high"; enabled = $true
        index = $Index; rule_id = "sysmon-t1036-unusual-dir"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.executable: (*\\Temp\\* OR *\\ProgramData\\* OR *\\AppData\\Roaming\\* OR *\\AppData\\Local\\Temp\\*) AND process.name: ("*.exe")'
        tags = @("Sysmon","T1036","DefenseEvasion","SuspiciousProcess")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0005"; name = "Defense Evasion"; reference = "https://attack.mitre.org/tactics/TA0005" }; technique = @(@{ id = "T1036"; name = "Masquerading"; reference = "https://attack.mitre.org/techniques/T1036" }) })
    },

    # =========================================================
    # COLLECTION - T1560 Archive / Compress
    # =========================================================
    @{
        name = "[Sysmon] 7zip or WinRAR Archiving Sensitive Files"
        description = "Detects compression tools archiving files from sensitive directories."
        risk_score = 47; severity = "medium"; enabled = $true
        index = $Index; rule_id = "sysmon-t1560-7zip"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: ("7z.exe" OR "7za.exe" OR "rar.exe" OR "winrar.exe") AND process.command_line: (*\\Users\\* OR *\\Documents\\* OR *\\Desktop\\*)'
        tags = @("Sysmon","T1560","Collection","Archive")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0009"; name = "Collection"; reference = "https://attack.mitre.org/tactics/TA0009" }; technique = @(@{ id = "T1560"; name = "Archive Collected Data"; reference = "https://attack.mitre.org/techniques/T1560" }) })
    },

    # =========================================================
    # NETWORK INDICATORS
    # =========================================================
    @{
        name = "[Sysmon] Connection to Raw IP Address (No DNS)"
        description = "Detects processes connecting directly to IP addresses, bypassing DNS, potential C2."
        risk_score = 47; severity = "medium"; enabled = $true
        index = $Index; rule_id = "sysmon-t1071-raw-ip"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "3" AND NOT destination.ip: (10.0.0.0/8 OR 172.16.0.0/12 OR 192.168.0.0/16 OR 127.0.0.1) AND destination.port: (4444 OR 1337 OR 8888 OR 9999 OR 31337)'
        tags = @("Sysmon","T1071","C2","Network","CommonC2Ports")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0011"; name = "Command and Control"; reference = "https://attack.mitre.org/tactics/TA0011" }; technique = @(@{ id = "T1071"; name = "Application Layer Protocol"; reference = "https://attack.mitre.org/techniques/T1071" }) })
    },
    @{
        name = "[Sysmon] Meterpreter Default Port Connection"
        description = "Detects connections to port 4444, the default Metasploit/Meterpreter handler port."
        risk_score = 99; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1071-meterpreter-port"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "3" AND destination.port: 4444'
        tags = @("Sysmon","T1071","C2","Metasploit","Meterpreter")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0011"; name = "Command and Control"; reference = "https://attack.mitre.org/tactics/TA0011" }; technique = @(@{ id = "T1071"; name = "Application Layer Protocol"; reference = "https://attack.mitre.org/techniques/T1071" }) })
    },

    # =========================================================
    # ADDITIONAL LOLBINS
    # =========================================================
    @{
        name = "[Sysmon] Forfiles Command Execution"
        description = "Detects forfiles.exe used to execute commands, a LOLBin technique."
        risk_score = 47; severity = "medium"; enabled = $true
        index = $Index; rule_id = "sysmon-lolbin-forfiles"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "forfiles.exe" AND process.command_line: ("/c" OR "/C")'
        tags = @("Sysmon","T1218","LOLBin","DefenseEvasion")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0005"; name = "Defense Evasion"; reference = "https://attack.mitre.org/tactics/TA0005" }; technique = @(@{ id = "T1218"; name = "System Binary Proxy Execution"; reference = "https://attack.mitre.org/techniques/T1218" }) })
    },
    @{
        name = "[Sysmon] Pcalua LOLBin Execution"
        description = "Detects pcalua.exe used as a LOLBin to execute arbitrary commands."
        risk_score = 73; severity = "high"; enabled = $true
        index = $Index; rule_id = "sysmon-lolbin-pcalua"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "pcalua.exe"'
        tags = @("Sysmon","T1218","LOLBin","DefenseEvasion")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0005"; name = "Defense Evasion"; reference = "https://attack.mitre.org/tactics/TA0005" }; technique = @(@{ id = "T1218"; name = "System Binary Proxy Execution"; reference = "https://attack.mitre.org/techniques/T1218" }) })
    },
    @{
        name = "[Sysmon] SyncAppvPublishingServer LOLBin"
        description = "Detects SyncAppvPublishingServer.exe used to proxy PowerShell execution."
        risk_score = 73; severity = "high"; enabled = $true
        index = $Index; rule_id = "sysmon-lolbin-syncappv"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "SyncAppvPublishingServer.exe"'
        tags = @("Sysmon","T1218","LOLBin","DefenseEvasion")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0005"; name = "Defense Evasion"; reference = "https://attack.mitre.org/tactics/TA0005" }; technique = @(@{ id = "T1218"; name = "System Binary Proxy Execution"; reference = "https://attack.mitre.org/techniques/T1218" }) })
    },

    # =========================================================
    # SURICATA NETWORK RULES (from logs-*)
    # =========================================================
    @{
        name = "[Suricata] ET SCAN Category Alert"
        description = "Detects Suricata ET Open scan category alerts indicating network reconnaissance."
        risk_score = 47; severity = "medium"; enabled = $true
        index = $Index; rule_id = "suricata-et-scan"
        type = "query"; language = "kuery"
        query = 'event.dataset: "suricata.eve" AND event.category: "intrusion_detection" AND rule.category: *SCAN*'
        tags = @("Suricata","Network","Reconnaissance","Scan")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0007"; name = "Discovery"; reference = "https://attack.mitre.org/tactics/TA0007" }; technique = @(@{ id = "T1046"; name = "Network Service Discovery"; reference = "https://attack.mitre.org/techniques/T1046" }) })
    },
    @{
        name = "[Suricata] ET MALWARE Category Alert"
        description = "Detects Suricata ET Open malware category alerts on the network."
        risk_score = 85; severity = "critical"; enabled = $true
        index = $Index; rule_id = "suricata-et-malware"
        type = "query"; language = "kuery"
        query = 'event.dataset: "suricata.eve" AND event.category: "intrusion_detection" AND rule.category: *MALWARE*'
        tags = @("Suricata","Network","Malware","C2")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0011"; name = "Command and Control"; reference = "https://attack.mitre.org/tactics/TA0011" }; technique = @(@{ id = "T1071"; name = "Application Layer Protocol"; reference = "https://attack.mitre.org/techniques/T1071" }) })
    },
    @{
        name = "[Suricata] ET EXPLOIT Category Alert"
        description = "Detects Suricata ET Open exploit category alerts."
        risk_score = 99; severity = "critical"; enabled = $true
        index = $Index; rule_id = "suricata-et-exploit"
        type = "query"; language = "kuery"
        query = 'event.dataset: "suricata.eve" AND event.category: "intrusion_detection" AND rule.category: *EXPLOIT*'
        tags = @("Suricata","Network","Exploit","InitialAccess")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0001"; name = "Initial Access"; reference = "https://attack.mitre.org/tactics/TA0001" }; technique = @(@{ id = "T1190"; name = "Exploit Public-Facing Application"; reference = "https://attack.mitre.org/techniques/T1190" }) })
    },
    @{
        name = "[Suricata] ET TROJAN Category Alert"
        description = "Detects Suricata ET Open trojan category alerts."
        risk_score = 85; severity = "critical"; enabled = $true
        index = $Index; rule_id = "suricata-et-trojan"
        type = "query"; language = "kuery"
        query = 'event.dataset: "suricata.eve" AND event.category: "intrusion_detection" AND rule.category: *TROJAN*'
        tags = @("Suricata","Network","Trojan","C2")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0011"; name = "Command and Control"; reference = "https://attack.mitre.org/tactics/TA0011" }; technique = @(@{ id = "T1071"; name = "Application Layer Protocol"; reference = "https://attack.mitre.org/techniques/T1071" }) })
    },
    @{
        name = "[Suricata] High Severity Alert"
        description = "Detects any Suricata alert with high severity score."
        risk_score = 73; severity = "high"; enabled = $true
        index = $Index; rule_id = "suricata-high-severity"
        type = "query"; language = "kuery"
        query = 'event.dataset: "suricata.eve" AND event.category: "intrusion_detection" AND event.severity: (1 OR 2)'
        tags = @("Suricata","Network","HighSeverity")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0011"; name = "Command and Control"; reference = "https://attack.mitre.org/tactics/TA0011" }; technique = @(@{ id = "T1071"; name = "Application Layer Protocol"; reference = "https://attack.mitre.org/techniques/T1071" }) })
    },

    # =========================================================
    # ZEEK NETWORK RULES
    # =========================================================
    @{
        name = "[Zeek] Long HTTP URI Detected"
        description = "Detects unusually long HTTP URIs in Zeek logs, potential exploit or C2 beaconing."
        risk_score = 47; severity = "medium"; enabled = $true
        index = $Index; rule_id = "zeek-long-uri"
        type = "query"; language = "kuery"
        query = 'event.dataset: "zeek.http" AND url.original.length: >500'
        tags = @("Zeek","Network","HTTP","SuspiciousRequest")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0011"; name = "Command and Control"; reference = "https://attack.mitre.org/tactics/TA0011" }; technique = @(@{ id = "T1071"; name = "Application Layer Protocol"; reference = "https://attack.mitre.org/techniques/T1071" }) })
    },
    @{
        name = "[Zeek] DNS Query for Known Malware Domain Pattern"
        description = "Detects DNS lookups for .onion or .bit TLD which are common in malware C2."
        risk_score = 85; severity = "critical"; enabled = $true
        index = $Index; rule_id = "zeek-dns-malware-tld"
        type = "query"; language = "kuery"
        query = 'event.dataset: "zeek.dns" AND dns.question.name: (*.onion OR *.bit OR *.bazar)'
        tags = @("Zeek","DNS","C2","Malware")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0011"; name = "Command and Control"; reference = "https://attack.mitre.org/tactics/TA0011" }; technique = @(@{ id = "T1071"; name = "Application Layer Protocol"; reference = "https://attack.mitre.org/techniques/T1071" }) })
    },
    @{
        name = "[Zeek] SSL Certificate Expired or Self-Signed"
        description = "Detects SSL connections with self-signed or expired certificates, common in C2 traffic."
        risk_score = 47; severity = "medium"; enabled = $true
        index = $Index; rule_id = "zeek-ssl-selfsigned"
        type = "query"; language = "kuery"
        query = 'event.dataset: "zeek.ssl" AND (tls.server_certificate.issuer: "CN=*" OR tls.established: false)'
        tags = @("Zeek","SSL","TLS","C2","Network")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0011"; name = "Command and Control"; reference = "https://attack.mitre.org/tactics/TA0011" }; technique = @(@{ id = "T1071"; name = "Application Layer Protocol"; reference = "https://attack.mitre.org/techniques/T1071" }) })
    },
    @{
        name = "[Zeek] FTP Data Transfer Detected"
        description = "Detects FTP connections in Zeek logs, uncommon in modern environments, potential data exfil."
        risk_score = 47; severity = "medium"; enabled = $true
        index = $Index; rule_id = "zeek-ftp-detected"
        type = "query"; language = "kuery"
        query = 'event.dataset: "zeek.ftp"'
        tags = @("Zeek","FTP","Exfiltration","Network")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0010"; name = "Exfiltration"; reference = "https://attack.mitre.org/tactics/TA0010" }; technique = @(@{ id = "T1048"; name = "Exfiltration Over Alternative Protocol"; reference = "https://attack.mitre.org/techniques/T1048" }) })
    },

    # =========================================================
    # ADDITIONAL SYSMON EDGE CASES
    # =========================================================
    @{
        name = "[Sysmon] DriverQuery Security Tool Enumeration"
        description = "Detects driverquery.exe used to enumerate installed drivers."
        risk_score = 21; severity = "low"; enabled = $true
        index = $Index; rule_id = "sysmon-t1082-driverquery"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "driverquery.exe"'
        tags = @("Sysmon","T1082","Discovery","Drivers")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0007"; name = "Discovery"; reference = "https://attack.mitre.org/tactics/TA0007" }; technique = @(@{ id = "T1082"; name = "System Information Discovery"; reference = "https://attack.mitre.org/techniques/T1082" }) })
    },
    @{
        name = "[Sysmon] Remote Desktop File Created"
        description = "Detects .rdp file creation which may indicate lateral movement preparation."
        risk_score = 47; severity = "medium"; enabled = $true
        index = $Index; rule_id = "sysmon-t1021-rdp-file"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "11" AND file.extension: "rdp"'
        tags = @("Sysmon","T1021.001","LateralMovement","RDP")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0008"; name = "Lateral Movement"; reference = "https://attack.mitre.org/tactics/TA0008" }; technique = @(@{ id = "T1021"; name = "Remote Services"; reference = "https://attack.mitre.org/techniques/T1021" }) })
    },
    @{
        name = "[Sysmon] Hosts File Modification"
        description = "Detects modification of the Windows hosts file, used for DNS hijacking."
        risk_score = 73; severity = "high"; enabled = $true
        index = $Index; rule_id = "sysmon-t1565-hosts-file"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: ("11" OR "13") AND file.path: *\\Windows\\System32\\drivers\\etc\\hosts*'
        tags = @("Sysmon","T1565","DefenseEvasion","DNSHijack")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0005"; name = "Defense Evasion"; reference = "https://attack.mitre.org/tactics/TA0005" }; technique = @(@{ id = "T1565"; name = "Data Manipulation"; reference = "https://attack.mitre.org/techniques/T1565" }) })
    },
    @{
        name = "[Sysmon] At.exe Scheduled Task (Legacy)"
        description = "Detects at.exe used to schedule tasks, a legacy persistence technique still used by some malware."
        risk_score = 73; severity = "high"; enabled = $true
        index = $Index; rule_id = "sysmon-t1053-at-exe"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "at.exe"'
        tags = @("Sysmon","T1053","Persistence","ScheduledTask")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0003"; name = "Persistence"; reference = "https://attack.mitre.org/tactics/TA0003" }; technique = @(@{ id = "T1053"; name = "Scheduled Task/Job"; reference = "https://attack.mitre.org/techniques/T1053" }) })
    },
    @{
        name = "[Sysmon] Suspicious Child Process of WMI Provider Host"
        description = "Detects child processes of wmiprvse.exe, a common WMI-based lateral movement indicator."
        risk_score = 85; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1047-wmiprvse-child"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.parent.name: "wmiprvse.exe" AND process.name: (cmd.exe OR powershell.exe OR wscript.exe OR cscript.exe)'
        tags = @("Sysmon","T1047","WMI","LateralMovement")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0002"; name = "Execution"; reference = "https://attack.mitre.org/tactics/TA0002" }; technique = @(@{ id = "T1047"; name = "Windows Management Instrumentation"; reference = "https://attack.mitre.org/techniques/T1047" }) })
    },
    @{
        name = "[Sysmon] Attrib Hidden File or Directory"
        description = "Detects attrib.exe used to hide files or directories."
        risk_score = 47; severity = "medium"; enabled = $true
        index = $Index; rule_id = "sysmon-t1564-attrib-hidden"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "attrib.exe" AND process.command_line: (*+h* OR *+s*)'
        tags = @("Sysmon","T1564","HideArtifacts","DefenseEvasion")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0005"; name = "Defense Evasion"; reference = "https://attack.mitre.org/tactics/TA0005" }; technique = @(@{ id = "T1564"; name = "Hide Artifacts"; reference = "https://attack.mitre.org/techniques/T1564" }) })
    },
    @{
        name = "[Sysmon] IEX or Invoke-Expression Obfuscation"
        description = "Detects various obfuscated forms of Invoke-Expression used to evade detection."
        risk_score = 85; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1027-iex-obfuscation"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.command_line: (*i`e`x* OR *i^e^x* OR *invoke-`expression* OR *.invoke(*)'
        tags = @("Sysmon","T1027","Obfuscation","PowerShell","DefenseEvasion")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0005"; name = "Defense Evasion"; reference = "https://attack.mitre.org/tactics/TA0005" }; technique = @(@{ id = "T1027"; name = "Obfuscated Files or Information"; reference = "https://attack.mitre.org/techniques/T1027" }) })
    },
    @{
        name = "[Sysmon] Windows Script Host Execution"
        description = "Detects wscript or cscript executing .js, .vbs, or .hta files from user-writable locations."
        risk_score = 73; severity = "high"; enabled = $true
        index = $Index; rule_id = "sysmon-t1059-wsh"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: ("wscript.exe" OR "cscript.exe") AND process.command_line: (*\\Temp\\* OR *\\Downloads\\* OR *\\AppData\\*)'
        tags = @("Sysmon","T1059","WSH","Execution")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0002"; name = "Execution"; reference = "https://attack.mitre.org/tactics/TA0002" }; technique = @(@{ id = "T1059"; name = "Command and Scripting Interpreter"; reference = "https://attack.mitre.org/techniques/T1059" }) })
    },
    @{
        name = "[Sysmon] Possible Keylogger File Created"
        description = "Detects files with names commonly used by keyloggers written to disk."
        risk_score = 73; severity = "high"; enabled = $true
        index = $Index; rule_id = "sysmon-t1056-keylogger-file"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "11" AND file.name: (*keylog* OR *keystroke* OR *klog*)'
        tags = @("Sysmon","T1056","KeyCapture","Collection")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0009"; name = "Collection"; reference = "https://attack.mitre.org/tactics/TA0009" }; technique = @(@{ id = "T1056"; name = "Input Capture"; reference = "https://attack.mitre.org/techniques/T1056" }) })
    },
    @{
        name = "[Sysmon] Suspicious Named Pipe Creation"
        description = "Detects named pipe creation events associated with common C2 frameworks like Cobalt Strike."
        risk_score = 85; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1055-named-pipe"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: ("17" OR "18") AND winlog.event_data.PipeName: (*MSSE-* OR *postex_* OR *status_* OR *msagent_* OR *mojo* OR *wkssvc* OR *ntsvcs*)'
        tags = @("Sysmon","T1055","CobaltStrike","C2","NamedPipe")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0005"; name = "Defense Evasion"; reference = "https://attack.mitre.org/tactics/TA0005" }; technique = @(@{ id = "T1055"; name = "Process Injection"; reference = "https://attack.mitre.org/techniques/T1055" }) })
    },
    @{
        name = "[Sysmon] PowerShell Accessing Clipboard"
        description = "Detects PowerShell commands accessing clipboard data, potential collection activity."
        risk_score = 47; severity = "medium"; enabled = $true
        index = $Index; rule_id = "sysmon-t1115-clipboard"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "powershell.exe" AND process.command_line: (*Get-Clipboard* OR *Clipboard::GetText* OR *System.Windows.Forms.Clipboard*)'
        tags = @("Sysmon","T1115","Collection","Clipboard")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0009"; name = "Collection"; reference = "https://attack.mitre.org/tactics/TA0009" }; technique = @(@{ id = "T1115"; name = "Clipboard Data"; reference = "https://attack.mitre.org/techniques/T1115" }) })
    },
    @{
        name = "[Sysmon] Regsvc or Regasm Proxy Execution"
        description = "Detects regasm.exe or regsvc.exe used to execute code via COM registration."
        risk_score = 73; severity = "high"; enabled = $true
        index = $Index; rule_id = "sysmon-lolbin-regasm"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: ("regasm.exe" OR "regsvcs.exe")'
        tags = @("Sysmon","T1218","LOLBin","DefenseEvasion")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0005"; name = "Defense Evasion"; reference = "https://attack.mitre.org/tactics/TA0005" }; technique = @(@{ id = "T1218"; name = "System Binary Proxy Execution"; reference = "https://attack.mitre.org/techniques/T1218" }) })
    },
    @{
        name = "[Sysmon] Suspicious Reg.exe Export"
        description = "Detects reg.exe exporting registry hives, potential credential theft preparation."
        risk_score = 73; severity = "high"; enabled = $true
        index = $Index; rule_id = "sysmon-t1012-reg-export"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "reg.exe" AND process.command_line: (*export* OR *save*)'
        tags = @("Sysmon","T1012","Registry","Discovery","CredentialAccess")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0007"; name = "Discovery"; reference = "https://attack.mitre.org/tactics/TA0007" }; technique = @(@{ id = "T1012"; name = "Query Registry"; reference = "https://attack.mitre.org/techniques/T1012" }) })
    },
    @{
        name = "[Sysmon] Netsh Port Forwarding"
        description = "Detects netsh.exe used to configure port forwarding, often used to tunnel traffic."
        risk_score = 73; severity = "high"; enabled = $true
        index = $Index; rule_id = "sysmon-t1090-netsh-portforward"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "netsh.exe" AND process.command_line: (*interface portproxy* OR *v4tov4* OR *listenport*)'
        tags = @("Sysmon","T1090","PortForwarding","LateralMovement")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0011"; name = "Command and Control"; reference = "https://attack.mitre.org/tactics/TA0011" }; technique = @(@{ id = "T1090"; name = "Proxy"; reference = "https://attack.mitre.org/techniques/T1090" }) })
    },
    @{
        name = "[Sysmon] Wevtutil Querying Security Logs"
        description = "Detects wevtutil.exe used to query security event logs, potential pre-attack recon."
        risk_score = 21; severity = "low"; enabled = $true
        index = $Index; rule_id = "sysmon-t1012-wevtutil-query"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "wevtutil.exe" AND process.command_line: (*Security* OR *System* OR *Application*) AND process.command_line: (*qe* OR *query-events*)'
        tags = @("Sysmon","T1012","Discovery","EventLog")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0007"; name = "Discovery"; reference = "https://attack.mitre.org/tactics/TA0007" }; technique = @(@{ id = "T1012"; name = "Query Registry"; reference = "https://attack.mitre.org/techniques/T1012" }) })
    },
    @{
        name = "[Sysmon] PowerShell Accessing LSASS via .NET"
        description = "Detects PowerShell using .NET reflection to access LSASS process memory."
        risk_score = 99; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1003-ps-lsass-net"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "powershell.exe" AND process.command_line: (*OpenProcess* OR *ReadProcessMemory* OR *MiniDumpWriteDump*)'
        tags = @("Sysmon","T1003","CredentialDumping","LSASS","PowerShell")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0006"; name = "Credential Access"; reference = "https://attack.mitre.org/tactics/TA0006" }; technique = @(@{ id = "T1003"; name = "OS Credential Dumping"; reference = "https://attack.mitre.org/techniques/T1003" }) })
    },
    @{
        name = "[Sysmon] Windows Defender Exclusion Added"
        description = "Detects PowerShell adding exclusion paths to Windows Defender."
        risk_score = 85; severity = "critical"; enabled = $true
        index = $Index; rule_id = "sysmon-t1562-defender-exclusion"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: "powershell.exe" AND process.command_line: (*Add-MpPreference* AND *ExclusionPath*)'
        tags = @("Sysmon","T1562","DefenseEvasion","Defender")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0005"; name = "Defense Evasion"; reference = "https://attack.mitre.org/tactics/TA0005" }; technique = @(@{ id = "T1562"; name = "Impair Defenses"; reference = "https://attack.mitre.org/techniques/T1562" }) })
    },
    @{
        name = "[Sysmon] Nmap or Port Scanner Execution"
        description = "Detects nmap or other port scanners launched on Windows."
        risk_score = 73; severity = "high"; enabled = $true
        index = $Index; rule_id = "sysmon-t1046-nmap"
        type = "query"; language = "kuery"
        query = 'event.dataset: "windows.sysmon_operational" AND event.code: "1" AND process.name: ("nmap.exe" OR "masscan.exe" OR "zmap.exe" OR "angry_ip_scanner.exe")'
        tags = @("Sysmon","T1046","Reconnaissance","PortScan")
        threat = @(@{ framework = "MITRE ATT&CK"; tactic = @{ id = "TA0007"; name = "Discovery"; reference = "https://attack.mitre.org/tactics/TA0007" }; technique = @(@{ id = "T1046"; name = "Network Service Discovery"; reference = "https://attack.mitre.org/techniques/T1046" }) })
    }
)

# =========================================================
# Execute
# =========================================================
Write-Host "`n[*] Starting rule creation - $($Rules.Count) rules total`n" -ForegroundColor Cyan

$Success = 0
$Failed  = 0

foreach ($Rule in $Rules) {
    New-DetectionRule -Rule $Rule
    if ($?) { $Success++ } else { $Failed++ }
    Start-Sleep -Milliseconds 200
}

Write-Host "`n[*] Complete. Success: $Success | Failed: $Failed" -ForegroundColor Cyan
Write-Host "[*] Check Kibana > Security > Rules > Detection rules (SIEM)" -ForegroundColor Cyan
