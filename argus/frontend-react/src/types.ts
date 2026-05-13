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
}

export interface DetectionReason {
  reason: string
  weight: number
  category: string
  detail?: string
}

export interface Action {
  action_id?: string
  behavior_id?: string
  case_id?: string
  action: 'ESCALATE' | 'BLOCK_IP' | 'NOTE'
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

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
