// CoverageMap.tsx
// Shows detection coverage across three layers:
//   1. Elastic/Sysmon rules  — upstream detection engine (100 rules)
//   2. Argus behavioral signals — enrichment profiles (this codebase)
//   3. Cross-layer corroboration — EDR + NDR confirmed (Phase B, planned)
//
// Argus does NOT claim the Elastic rules as its own detections.
// The distinction is intentional and architecturally honest.

// ─── Argus behavioral signal profiles (mirrors behavior_detector.py) ──────────
// Each entry: [technique_id, tactic, description, confidence, behavior_class]
const ARGUS_PROFILES: Array<{
  id: string
  technique: string
  tactic: string
  description: string
  confidence: "low" | "medium" | "high"
  behavior_class: string
}> = [
  // EXECUTION
  { id: "powershell_encoded_exec",   technique: "T1059.001", tactic: "EXECUTION",          description: "PowerShell Encoded Command",         confidence: "high",   behavior_class: "execution" },
  { id: "powershell_download_cradle",technique: "T1059.001", tactic: "EXECUTION",          description: "PowerShell Download Cradle",          confidence: "high",   behavior_class: "execution" },
  { id: "powershell_bypass_policy",  technique: "T1059.001", tactic: "EXECUTION",          description: "PowerShell Policy Bypass",            confidence: "medium", behavior_class: "evasion" },
  { id: "cmd_shell_execution",       technique: "T1059.003", tactic: "EXECUTION",          description: "Windows Command Shell",               confidence: "low",    behavior_class: "execution" },
  { id: "wscript_execution",         technique: "T1059.005", tactic: "EXECUTION",          description: "Windows Script Host",                 confidence: "medium", behavior_class: "execution" },
  { id: "wmic_process_create",       technique: "T1047",     tactic: "EXECUTION",          description: "WMIC Remote Process Creation",        confidence: "high",   behavior_class: "execution" },
  { id: "certutil_download",         technique: "T1105",     tactic: "EXECUTION",          description: "Certutil Download / Decode",          confidence: "high",   behavior_class: "execution" },
  { id: "exe_dropped_temp",          technique: "T1105",     tactic: "EXECUTION",          description: "Executable Dropped in Temp",          confidence: "medium", behavior_class: "execution" },
  // PERSISTENCE
  { id: "schtasks_creation",         technique: "T1053.005", tactic: "PERSISTENCE",        description: "Scheduled Task via Schtasks",         confidence: "high",   behavior_class: "persistence" },
  { id: "at_job_creation",           technique: "T1053.002", tactic: "PERSISTENCE",        description: "Legacy AT Job Creation",              confidence: "high",   behavior_class: "persistence" },
  { id: "sc_service_creation",       technique: "T1543.003", tactic: "PERSISTENCE",        description: "Service Created via SC",              confidence: "high",   behavior_class: "persistence" },
  { id: "net_user_created",          technique: "T1136.001", tactic: "PERSISTENCE",        description: "Local User Account Created",          confidence: "high",   behavior_class: "persistence" },
  { id: "registry_run_key_write",    technique: "T1547.001", tactic: "PERSISTENCE",        description: "Registry Run Key Write (EID 13)",     confidence: "high",   behavior_class: "persistence" },
  { id: "startup_folder_drop",       technique: "T1547.001", tactic: "PERSISTENCE",        description: "File in Startup Folder (EID 11)",     confidence: "high",   behavior_class: "persistence" },
  // DEFENSE EVASION
  { id: "mshta_remote_script",       technique: "T1218.005", tactic: "DEFENSE_EVASION",    description: "MSHTA Remote Script",                 confidence: "high",   behavior_class: "evasion" },
  { id: "regsvr32_lolbin",           technique: "T1218.010", tactic: "DEFENSE_EVASION",    description: "Regsvr32 LOLBin",                     confidence: "high",   behavior_class: "evasion" },
  { id: "rundll32_suspicious",       technique: "T1218.011", tactic: "DEFENSE_EVASION",    description: "Rundll32 Suspicious Exec",            confidence: "high",   behavior_class: "evasion" },
  { id: "base64_in_cmdline",         technique: "T1027",     tactic: "DEFENSE_EVASION",    description: "Base64 Payload in CommandLine",       confidence: "medium", behavior_class: "evasion" },
  { id: "iex_obfuscation",           technique: "T1027",     tactic: "DEFENSE_EVASION",    description: "IEX Obfuscation",                     confidence: "medium", behavior_class: "evasion" },
  { id: "defender_disabled_ps",      technique: "T1562.001", tactic: "DEFENSE_EVASION",    description: "Defender Disabled via PowerShell",    confidence: "high",   behavior_class: "evasion" },
  { id: "attrib_hidden",             technique: "T1564.001", tactic: "DEFENSE_EVASION",    description: "File Hidden via Attrib",              confidence: "medium", behavior_class: "evasion" },
  { id: "msbuild_exec",              technique: "T1127.001", tactic: "DEFENSE_EVASION",    description: "MSBuild Code Execution",              confidence: "high",   behavior_class: "evasion" },
  { id: "installutil_exec",          technique: "T1218.004", tactic: "DEFENSE_EVASION",    description: "InstallUtil Proxy Execution",         confidence: "high",   behavior_class: "evasion" },
  // DISCOVERY
  { id: "whoami_execution",          technique: "T1033",     tactic: "DISCOVERY",          description: "System Owner Discovery",              confidence: "low",    behavior_class: "recon" },
  { id: "systeminfo_execution",      technique: "T1082",     tactic: "DISCOVERY",          description: "System Info Discovery",               confidence: "low",    behavior_class: "recon" },
  { id: "netstat_discovery",         technique: "T1049",     tactic: "DISCOVERY",          description: "Network Connections Discovery",       confidence: "low",    behavior_class: "recon" },
  { id: "ipconfig_discovery",        technique: "T1016",     tactic: "DISCOVERY",          description: "Network Config Discovery",            confidence: "low",    behavior_class: "recon" },
  { id: "net_account_enum",          technique: "T1087.001", tactic: "DISCOVERY",          description: "Local Account Enumeration",           confidence: "low",    behavior_class: "recon" },
  { id: "reg_query",                 technique: "T1012",     tactic: "DISCOVERY",          description: "Registry Query / Export",             confidence: "low",    behavior_class: "recon" },
  { id: "tasklist_discovery",        technique: "T1057",     tactic: "DISCOVERY",          description: "Process Discovery via Tasklist",      confidence: "low",    behavior_class: "recon" },
  { id: "ping_sweep",                technique: "T1018",     tactic: "DISCOVERY",          description: "Remote System Discovery via Ping",    confidence: "low",    behavior_class: "recon" },
  { id: "nltest_domain_trust",       technique: "T1482",     tactic: "DISCOVERY",          description: "Domain Trust Discovery",              confidence: "high",   behavior_class: "recon" },
  { id: "wmic_software_discovery",   technique: "T1518",     tactic: "DISCOVERY",          description: "Software Discovery via WMIC",         confidence: "low",    behavior_class: "recon" },
  // CREDENTIAL ACCESS
  { id: "lsass_process_access",      technique: "T1003.001", tactic: "CREDENTIAL_ACCESS",  description: "LSASS Memory Access (EID 10)",        confidence: "high",   behavior_class: "credential_access" },
  { id: "mimikatz_cmdline",          technique: "T1003.001", tactic: "CREDENTIAL_ACCESS",  description: "Mimikatz Indicators in CommandLine",  confidence: "high",   behavior_class: "credential_access" },
  { id: "sam_hive_access",           technique: "T1003.002", tactic: "CREDENTIAL_ACCESS",  description: "SAM Hive Access",                     confidence: "high",   behavior_class: "credential_access" },
  // LATERAL MOVEMENT
  { id: "psexec_lateral",            technique: "T1021.002", tactic: "LATERAL_MOVEMENT",   description: "PsExec Lateral Movement",             confidence: "high",   behavior_class: "lateral_movement" },
  { id: "rdp_initiated",             technique: "T1021.001", tactic: "LATERAL_MOVEMENT",   description: "RDP Session Initiated",               confidence: "low",    behavior_class: "lateral_movement" },
  // COLLECTION
  { id: "archive_sensitive_files",   technique: "T1560.001", tactic: "COLLECTION",         description: "Archiving via 7zip / WinRAR",         confidence: "low",    behavior_class: "collection" },
  { id: "clipboard_access",          technique: "T1115",     tactic: "COLLECTION",         description: "PowerShell Clipboard Access",         confidence: "medium", behavior_class: "collection" },
  // EXFILTRATION
  { id: "curl_wget_transfer",        technique: "T1048",     tactic: "EXFILTRATION",       description: "Curl / Wget Outbound Transfer",       confidence: "medium", behavior_class: "exfiltration" },
  // IMPACT
  { id: "vss_deletion",              technique: "T1490",     tactic: "IMPACT",             description: "Volume Shadow Copy Deletion",         confidence: "high",   behavior_class: "impact" },
  { id: "bcdedit_recovery",          technique: "T1490",     tactic: "IMPACT",             description: "BCDEdit Disabling Recovery",          confidence: "high",   behavior_class: "impact" },
  { id: "event_log_cleared",         technique: "T1070.001", tactic: "IMPACT",             description: "Event Log Cleared via Wevtutil",      confidence: "high",   behavior_class: "impact" },
]

// ─── Elastic/Sysmon rules — upstream detection engine ─────────────────────────
// These are real rules exported from Kibana. Argus does not own these detections.
// Source: 100 rules exported from Elastic Security (Sysmon + Suricata + Zeek).
const ELASTIC_TECHNIQUES: Record<string, { count: number; description: string }> = {
  "T1059":     { count: 8,  description: "Command and Scripting Interpreter" },
  "T1059.001": { count: 3,  description: "PowerShell" },
  "T1059.003": { count: 1,  description: "Windows Command Shell" },
  "T1053":     { count: 3,  description: "Scheduled Task/Job" },
  "T1053.005": { count: 1,  description: "Scheduled Task" },
  "T1218":     { count: 7,  description: "System Binary Proxy Execution" },
  "T1547":     { count: 2,  description: "Boot or Logon Autostart Execution" },
  "T1547.001": { count: 3,  description: "Registry Run Keys / Startup Folder" },
  "T1543":     { count: 1,  description: "Create or Modify System Process" },
  "T1543.003": { count: 1,  description: "Windows Service" },
  "T1136":     { count: 2,  description: "Create Account" },
  "T1562":     { count: 4,  description: "Impair Defenses" },
  "T1562.001": { count: 1,  description: "Disable or Modify Tools" },
  "T1027":     { count: 2,  description: "Obfuscated Files or Information" },
  "T1036":     { count: 3,  description: "Masquerading" },
  "T1055":     { count: 2,  description: "Process Injection" },
  "T1127":     { count: 1,  description: "Trusted Developer Utilities Proxy Execution" },
  "T1564":     { count: 1,  description: "Hide Artifacts" },
  "T1565":     { count: 1,  description: "Data Manipulation" },
  "T1490":     { count: 3,  description: "Inhibit System Recovery" },
  "T1003":     { count: 4,  description: "OS Credential Dumping" },
  "T1110":     { count: 1,  description: "Brute Force" },
  "T1082":     { count: 2,  description: "System Information Discovery" },
  "T1016":     { count: 3,  description: "System Network Configuration Discovery" },
  "T1049":     { count: 1,  description: "System Network Connections Discovery" },
  "T1033":     { count: 1,  description: "System Owner/User Discovery" },
  "T1057":     { count: 1,  description: "Process Discovery" },
  "T1069":     { count: 1,  description: "Permission Groups Discovery" },
  "T1083":     { count: 1,  description: "File and Directory Discovery" },
  "T1087":     { count: 1,  description: "Account Discovery" },
  "T1012":     { count: 2,  description: "Query Registry" },
  "T1018":     { count: 1,  description: "Remote System Discovery" },
  "T1046":     { count: 2,  description: "Network Service Discovery" },
  "T1482":     { count: 1,  description: "Domain Trust Discovery" },
  "T1518":     { count: 1,  description: "Software Discovery" },
  "T1047":     { count: 2,  description: "Windows Management Instrumentation" },
  "T1105":     { count: 2,  description: "Ingress Tool Transfer" },
  "T1021":     { count: 3,  description: "Remote Services" },
  "T1071":     { count: 8,  description: "Application Layer Protocol" },
  "T1071.001": { count: 2,  description: "Web Protocols" },
  "T1090":     { count: 2,  description: "Proxy" },
  "T1048":     { count: 2,  description: "Exfiltration Over Alternative Protocol" },
  "T1056":     { count: 1,  description: "Input Capture" },
  "T1115":     { count: 1,  description: "Clipboard Data" },
  "T1560":     { count: 1,  description: "Archive Collected Data" },
  "T1566":     { count: 1,  description: "Phishing" },
  "T1190":     { count: 1,  description: "Exploit Public-Facing Application" },
  "T1548":     { count: 2,  description: "Abuse Elevation Control Mechanism" },
}

// ─── Tactic ordering and display ──────────────────────────────────────────────
const TACTIC_ORDER = [
  "INITIAL_ACCESS", "EXECUTION", "PERSISTENCE", "PRIVILEGE_ESCALATION",
  "DEFENSE_EVASION", "CREDENTIAL_ACCESS", "DISCOVERY",
  "LATERAL_MOVEMENT", "COLLECTION", "EXFILTRATION", "IMPACT",
]

const TACTIC_LABEL: Record<string, string> = {
  INITIAL_ACCESS:       "Initial Access",
  EXECUTION:            "Execution",
  PERSISTENCE:          "Persistence",
  PRIVILEGE_ESCALATION: "Privilege Escalation",
  DEFENSE_EVASION:      "Defense Evasion",
  CREDENTIAL_ACCESS:    "Credential Access",
  DISCOVERY:            "Discovery",
  LATERAL_MOVEMENT:     "Lateral Movement",
  COLLECTION:           "Collection",
  EXFILTRATION:         "Exfiltration",
  IMPACT:               "Impact",
}

const TACTIC_COLOR: Record<string, string> = {
  INITIAL_ACCESS:       "rgba(74,143,196,0.12)",
  EXECUTION:            "rgba(229,83,75,0.10)",
  PERSISTENCE:          "rgba(240,140,50,0.10)",
  PRIVILEGE_ESCALATION: "rgba(200,90,200,0.10)",
  DEFENSE_EVASION:      "rgba(123,109,212,0.10)",
  CREDENTIAL_ACCESS:    "rgba(229,83,75,0.14)",
  DISCOVERY:            "rgba(80,160,120,0.10)",
  LATERAL_MOVEMENT:     "rgba(74,143,196,0.14)",
  COLLECTION:           "rgba(200,180,60,0.10)",
  EXFILTRATION:         "rgba(240,140,50,0.14)",
  IMPACT:               "rgba(229,83,75,0.18)",
}

const CONFIDENCE_COLOR: Record<string, string> = {
  high:   "rgba(229,83,75,0.85)",
  medium: "rgba(240,140,50,0.85)",
  low:    "rgba(255,255,255,0.25)",
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function groupByTactic<T extends { tactic: string }>(items: T[]): Record<string, T[]> {
  const out: Record<string, T[]> = {}
  for (const item of items) {
    if (!out[item.tactic]) out[item.tactic] = []
    out[item.tactic].push(item)
  }
  return out
}

function dedupeTechniques(profiles: typeof ARGUS_PROFILES) {
  const seen = new Set<string>()
  return profiles.filter(p => {
    if (seen.has(p.technique)) return false
    seen.add(p.technique)
    return true
  })
}

// ─── Component ────────────────────────────────────────────────────────────────
export default function CoverageMap() {
  const argusUnique    = dedupeTechniques(ARGUS_PROFILES)
  const argusCount     = ARGUS_PROFILES.length
  const techniqueCount = argusUnique.length
  const elasticCount   = 100
  const argusGrouped   = groupByTactic(ARGUS_PROFILES)
  const elasticTids    = new Set(Object.keys(ELASTIC_TECHNIQUES))

  const highCount   = ARGUS_PROFILES.filter(p => p.confidence === "high").length
  const mediumCount = ARGUS_PROFILES.filter(p => p.confidence === "medium").length
  const lowCount    = ARGUS_PROFILES.filter(p => p.confidence === "low").length

  return (
    <div style={{
      flex: 1, overflow: "auto", background: "var(--bg0)",
      padding: "20px 24px", display: "flex", flexDirection: "column", gap: 20,
    }}>

      {/* Header */}
      <div>
        <div style={{ fontSize: 13, fontWeight: 600, color: "var(--t1)", letterSpacing: "0.04em", marginBottom: 4 }}>
          COVERAGE MAP
        </div>
        <div style={{ fontSize: 10, color: "var(--t3)", fontFamily: "var(--mono)" }}>
          Detection coverage across Elastic/Sysmon upstream rules and Argus behavioral signal profiles.
          Argus enriches and correlates — it does not replace the underlying detection engine.
        </div>
      </div>

      {/* Summary stats */}
      <div style={{ display: "flex", gap: 10 }}>
        {[
          { label: "Elastic Rules",          value: elasticCount,   sub: "Sysmon · Suricata · Zeek",    color: "var(--teal)" },
          { label: "Argus Signal Profiles",  value: argusCount,     sub: "EID 1 · 10 · 11 · 13",       color: "var(--amb)"  },
          { label: "ATT&CK Techniques",      value: techniqueCount, sub: "unique IDs, Argus layer",     color: "var(--t2)"   },
          { label: "High Confidence",        value: highCount,      sub: "precise signal profiles",     color: "rgba(229,83,75,0.9)" },
          { label: "Medium Confidence",      value: mediumCount,    sub: "context-dependent signals",   color: "rgba(240,140,50,0.9)" },
          { label: "Low Confidence (Recon)", value: lowCount,       sub: "weak signal, analyst review", color: "rgba(255,255,255,0.3)" },
        ].map(({ label, value, sub, color }) => (
          <div key={label} style={{
            flex: 1, background: "var(--bg1)", border: "1px solid var(--ln2)",
            borderRadius: 4, padding: "10px 14px",
          }}>
            <div style={{ fontSize: 22, fontWeight: 700, color, fontFamily: "var(--mono)", lineHeight: 1 }}>{value}</div>
            <div style={{ fontSize: 10, color: "var(--t2)", marginTop: 4 }}>{label}</div>
            <div style={{ fontSize: 9, color: "var(--t4)", fontFamily: "var(--mono)", marginTop: 2 }}>{sub}</div>
          </div>
        ))}
      </div>

      {/* Architecture explanation */}
      <div style={{
        background: "var(--bg1)", border: "1px solid var(--ln2)", borderRadius: 4,
        padding: "12px 16px", display: "flex", gap: 0,
      }}>
        {[
          { layer: "Layer 1", title: "Elastic Detection Engine", desc: "100 Sysmon, Suricata, and Zeek rules. Source of truth for raw detections. Argus does not own these.", color: "var(--teal)", icon: "◈" },
          { layer: "Layer 2", title: "Argus Behavioral Signals", desc: `${argusCount} profiles across EID 1/10/11/13. Command-line context enrichment. Confidence-weighted. Max 3 per event.`, color: "var(--amb)", icon: "◉" },
          { layer: "Layer 3", title: "Cross-Layer Corroboration", desc: "EDR + NDR signal in same ±15min window. Sysmon behavior + Suricata alert = corroborated case. Phase B.", color: "rgba(123,109,212,0.9)", icon: "◎" },
        ].map(({ layer, title, desc, color, icon }, i) => (
          <div key={layer} style={{
            flex: 1, padding: "0 16px",
            borderLeft: i > 0 ? "1px solid var(--ln2)" : "none",
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
              <span style={{ color, fontSize: 14 }}>{icon}</span>
              <span style={{ fontSize: 9, fontFamily: "var(--mono)", color: "var(--t4)", textTransform: "uppercase", letterSpacing: "0.1em" }}>{layer}</span>
            </div>
            <div style={{ fontSize: 11, fontWeight: 600, color: "var(--t1)", marginBottom: 4 }}>{title}</div>
            <div style={{ fontSize: 10, color: "var(--t3)", lineHeight: 1.5 }}>{desc}</div>
          </div>
        ))}
      </div>

      {/* Tactic grid — Argus profiles grouped by tactic */}
      <div>
        <div style={{ fontSize: 10, color: "var(--t3)", fontFamily: "var(--mono)", marginBottom: 10, textTransform: "uppercase", letterSpacing: "0.08em" }}>
          Argus Behavioral Signals by Tactic
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {TACTIC_ORDER.map(tactic => {
            const profiles = argusGrouped[tactic]
            if (!profiles || profiles.length === 0) return null
            return (
              <div key={tactic} style={{
                background: TACTIC_COLOR[tactic] || "var(--bg1)",
                border: "1px solid var(--ln2)", borderRadius: 4,
                padding: "10px 14px",
              }}>
                <div style={{ fontSize: 10, fontWeight: 600, color: "var(--t2)", marginBottom: 8, fontFamily: "var(--mono)", letterSpacing: "0.06em" }}>
                  {TACTIC_LABEL[tactic] || tactic}
                  <span style={{ color: "var(--t4)", fontWeight: 400, marginLeft: 8 }}>
                    {profiles.length} signal{profiles.length !== 1 ? "s" : ""}
                  </span>
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                  {profiles.map(p => {
                    const elasticCovers = elasticTids.has(p.technique) || elasticTids.has(p.technique.split(".")[0])
                    return (
                      <div key={p.id} style={{
                        background: "var(--bg1)", border: "1px solid var(--ln2)",
                        borderRadius: 3, padding: "5px 9px",
                        display: "flex", flexDirection: "column", gap: 3,
                        minWidth: 170,
                      }}>
                        <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
                          <span style={{
                            fontSize: 9, fontFamily: "var(--mono)", fontWeight: 700,
                            color: "var(--teal)",
                          }}>{p.technique}</span>
                          {/* Confidence dot */}
                          <span style={{
                            width: 5, height: 5, borderRadius: "50%",
                            background: CONFIDENCE_COLOR[p.confidence],
                            flexShrink: 0,
                            title: p.confidence,
                          }} />
                          {/* Elastic coverage indicator */}
                          {elasticCovers && (
                            <span style={{
                              fontSize: 8, fontFamily: "var(--mono)", color: "var(--teal)",
                              background: "rgba(70,190,180,0.08)", border: "1px solid rgba(70,190,180,0.2)",
                              borderRadius: 2, padding: "0 3px",
                            }}>ES</span>
                          )}
                        </div>
                        <div style={{ fontSize: 9, color: "var(--t2)", lineHeight: 1.3 }}>{p.description}</div>
                        <div style={{ fontSize: 8, color: "var(--t4)", fontFamily: "var(--mono)" }}>{p.behavior_class}</div>
                      </div>
                    )
                  })}
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Legend */}
      <div style={{
        background: "var(--bg1)", border: "1px solid var(--ln2)", borderRadius: 4,
        padding: "10px 16px", display: "flex", alignItems: "center", gap: 20,
      }}>
        <span style={{ fontSize: 9, color: "var(--t4)", fontFamily: "var(--mono)", textTransform: "uppercase", letterSpacing: "0.08em" }}>Legend</span>
        {[
          { label: "High confidence signal",   color: CONFIDENCE_COLOR.high },
          { label: "Medium confidence signal",  color: CONFIDENCE_COLOR.medium },
          { label: "Low confidence signal",     color: CONFIDENCE_COLOR.low },
        ].map(({ label, color }) => (
          <div key={label} style={{ display: "flex", alignItems: "center", gap: 5 }}>
            <span style={{ width: 7, height: 7, borderRadius: "50%", background: color, flexShrink: 0, display: "inline-block" }} />
            <span style={{ fontSize: 9, color: "var(--t3)", fontFamily: "var(--mono)" }}>{label}</span>
          </div>
        ))}
        <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
          <span style={{
            fontSize: 8, fontFamily: "var(--mono)", color: "var(--teal)",
            background: "rgba(70,190,180,0.08)", border: "1px solid rgba(70,190,180,0.2)",
            borderRadius: 2, padding: "0 3px",
          }}>ES</span>
          <span style={{ fontSize: 9, color: "var(--t3)", fontFamily: "var(--mono)" }}>Elastic rule also covers this technique</span>
        </div>
      </div>

    </div>
  )
}
