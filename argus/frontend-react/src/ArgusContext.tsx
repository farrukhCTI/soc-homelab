import { createContext, useContext, useState } from "react"
import type { ReactNode } from "react"
import type { Case, Behavior } from "./types"

export type View = "investigation" | "actions" | "hunt" | "coverage"

export interface HuntPivot {
  templateId: string
  params: Record<string, any>
  label: string           // e.g. "Pivot: 10.0.30.10"
  sourceCase?: string     // originating case ID
  sourceBehavior?: string // originating behavior ID
}

interface ArgusState {
  selectedCase: Case | null
  setSelectedCase: (c: Case | null) => void
  selectedBehavior: Behavior | null
  setSelectedBehavior: (b: Behavior | null) => void
  hoveredNodeId: number | null
  setHoveredNodeId: (id: number | null) => void
  activeRailTab: number
  setActiveRailTab: (n: number) => void
  // Navigation
  activeView: View
  setActiveView: (v: View) => void
  // Hunt pivot — set from CrossLayerTab, consumed by HuntWorkbench
  huntPivot: HuntPivot | null
  setHuntPivot: (p: HuntPivot | null) => void
}

const Ctx = createContext<ArgusState>(null!)

// S-4: Write minimal session state to ES when case is selected.
// Non-fatal — session write failure never blocks investigation.
function persistSession(caseId: string, behaviorId?: string | null) {
  fetch("/api/session", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      case_id:              caseId,
      selected_behavior_id: behaviorId ?? null,
    }),
  }).catch(() => {
    // Non-fatal — session persistence is best-effort
  })
}

export function ArgusProvider({ children }: { children: ReactNode }) {
  const [selectedCase, setSelectedCase] = useState<Case | null>(null)
  const [selectedBehavior, setSelectedBehavior] = useState<Behavior | null>(null)
  const [hoveredNodeId, setHoveredNodeId] = useState<number | null>(null)
  const [activeRailTab, setActiveRailTab] = useState(0)
  const [activeView, setActiveView] = useState<View>("investigation")
  const [huntPivot, setHuntPivot] = useState<HuntPivot | null>(null)

  // S-4: Wrap setSelectedCase to persist session on every case change
  function selectCase(c: Case | null) {
    setSelectedCase(c)
    if (c?.case_id) persistSession(c.case_id, null)
  }

  return (
    <Ctx.Provider value={{
      selectedCase, setSelectedCase: selectCase,
      selectedBehavior, setSelectedBehavior,
      hoveredNodeId, setHoveredNodeId,
      activeRailTab, setActiveRailTab,
      activeView, setActiveView,
      huntPivot, setHuntPivot,
    }}>
      {children}
    </Ctx.Provider>
  )
}

export const useArgus = () => useContext(Ctx)
