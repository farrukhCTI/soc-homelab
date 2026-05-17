export interface BlastRadius {
  hosts_affected: number
  users_involved: number
  ips_contacted: number
  processes_spawned: number
}

export interface GroupedBy {
  reason: string
  time_window?: string
  shared_host?: string
}

export interface Case {
  case_id: string
  status: string
  highest_severity: string
  risk_score: number
  behavior_count: number
  grouped_by: GroupedBy
  case_summary?: string
  blast_radius: BlastRadius
  tactics_seen: string[]
  created_at?: string
}

export interface Behavior {
  behavior_id: string
  timestamp: string
  host: string
  description: string
  tactic: string
  severity: string
  status: string
  case_id?: string
  process_name?: string
  command_line?: string
  pid?: number
  parent_pid?: number
  parent_process?: string
  user?: string
  mitre_technique?: string
  detection_score?: number
  baseline_deviation?: number
  is_lolbin?: boolean
  raw_event?: Record<string, unknown>
  detection_reasons?: DetectionReason[]
  // Fields from behavior_detector.py (schema locked 2026-05-16)
  confidence?: string
  behavior_class?: string
  fire_reasons?: string[]
  priority_score?: number
  profile?: string
  image?: string
}

export interface DetectionReason {
  reason: string
  weight: number
  category: string
  detail?: string
}

// FIX-14: Action union extended to include closure states used in RightRail and ActionsLog.
// Previously only ESCALATE | BLOCK_IP | NOTE — caused type errors on closure actions.
export interface Action {
  action_id?: string
  behavior_id?: string
  case_id?: string
  action: 'ESCALATE' | 'BLOCK_IP' | 'NOTE' | 'RESOLVED' | 'CONFIRMED_MALICIOUS' | 'FALSE_POSITIVE'
  note?: string
  actor: string
  timestamp: string
}

export interface HuntTemplate {
  id: string
  name: string
  description: string
  params: HuntParam[]
}

export interface HuntParam {
  name: string
  label: string
  type: string
  default?: string | number | boolean
}

export interface ProcessNode {
  pid: number
  process_name: string
  command_line?: string
  parent_pid?: number
  score?: number
  is_lolbin?: boolean
  timestamp?: string
  on_chain?: boolean
  children?: ProcessNode[]
}

// FIX-14: Network context types — previously defined locally in CrossLayerTab.tsx only.
export interface NetworkContext {
  ok: boolean
  has_network_data: boolean
  network_events: NetworkEvent[]
  alerts: SuricataAlert[]
  summary: {
    returned: number
    total_hits: number
    alert_count: number
    network_event_count: number
    unique_ips: string[]
  }
  window: { start: string; end: string }
  error?: string
}

export interface NetworkEvent {
  timestamp: string
  event_type: string
  src_ip?: string
  dest_ip?: string
  src_port?: number
  dest_port?: number
  proto?: string
  url?: string
  hostname?: string
  method?: string
  status?: number
  user_agent?: string
}

export interface SuricataAlert {
  timestamp: string
  event_type?: string
  src_ip?: string
  dest_ip?: string
  src_port?: number
  dest_port?: number
  proto?: string
  signature?: string
  signature_id?: number
  severity?: number
  category?: string
  action?: string
}

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
