import type { Case, Behavior, Action, HuntTemplate } from './types'

const BASE = '/api'

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`)
  const data = await res.json()
  if (!data.ok) throw new Error(data.error || data.detail || 'API error')
  return data as T
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  const data = await res.json()
  if (!data.ok) throw new Error(data.error || data.detail || 'API error')
  return data as T
}

// Cases
export const fetchCases = () =>
  get<{ ok: true; cases: Case[] }>('/cases').then(d => d.cases)

export const fetchCaseBehaviors = (caseId: string) =>
  get<{ ok: true; behaviors: Behavior[] }>(`/cases/${caseId}/behaviors`).then(d => d.behaviors)

export const fetchCaseSummary = (caseId: string) =>
  get<{ ok: true; summary: string }>(`/cases/${caseId}/summary`).then(d => d.summary)

// Behaviors
export const fetchBehavior = (behaviorId: string) =>
  get<{ ok: true } & Behavior>(`/behaviors/${behaviorId}`)

export const fetchProcessTree = (behaviorId: string) =>
  get<{ ok: true; nodes: unknown[]; edges: unknown[]; behavior_pid: number }>(`/behaviors/${behaviorId}/process_tree`)

export const fetchBriefing = (behaviorId: string) =>
  get<{ ok: true; briefing?: { summary: string; next_steps: string[]; escalate: boolean }; summary?: string; next_steps?: string[]; escalate?: boolean }>(`/brief/${behaviorId}`)

export const generateBriefing = (behaviorId: string) =>
  post<{ ok: true; summary: string; next_steps: string[]; escalate: boolean }>(`/brief`, { behavior_id: behaviorId })

// Actions
export const fetchActions = () =>
  get<{ ok: true; actions: Action[]; total: number }>('/actions').then(d => d)

// NOTE: route is POST /api/actions (not /api/actions/escalate etc)
export const postEscalate = (behaviorId: string, caseId?: string) =>
  post('/actions', { action: 'ESCALATE', behavior_id: behaviorId, case_id: caseId, actor: 'analyst' })

export const postBlockIP = (behaviorId: string, ip: string, caseId?: string) =>
  post('/actions', { action: 'BLOCK_IP', behavior_id: behaviorId, case_id: caseId, note: ip, actor: 'analyst' })

export const postNote = (behaviorId: string, note: string, caseId?: string) =>
  post('/actions', { action: 'NOTE', behavior_id: behaviorId, case_id: caseId, note, actor: 'analyst' })

// Hunt — route is POST /api/hunt (not /api/hunt/run)
export const fetchHuntTemplates = () =>
  get<{ ok: true; templates: HuntTemplate[] }>('/hunt/templates').then(d => d.templates)

export const runHunt = (templateId: string, params: Record<string, unknown>) =>
  post<{ ok: true; results: unknown[]; query: string; total: number }>('/hunt', { template_id: templateId, params })

export const fetchCopilot = (templateId: string, results: unknown[]) =>
  post<{ ok: true; interpretation: string; pivots: string[] }>('/hunt/copilot', { template_id: templateId, results })
