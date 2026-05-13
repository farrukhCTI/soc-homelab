import { createContext, useContext, useState, ReactNode } from "react"
import type { Case, Behavior } from "./types"

interface ArgusState {
  selectedCase: Case | null
  setSelectedCase: (c: Case | null) => void
  selectedBehavior: Behavior | null
  setSelectedBehavior: (b: Behavior | null) => void
  hoveredNodeId: number | null
  setHoveredNodeId: (id: number | null) => void
  activeRailTab: number
  setActiveRailTab: (n: number) => void
}

const Ctx = createContext<ArgusState>(null!)

export function ArgusProvider({ children }: { children: ReactNode }) {
  const [selectedCase, setSelectedCase] = useState<Case | null>(null)
  const [selectedBehavior, setSelectedBehavior] = useState<Behavior | null>(null)
  const [hoveredNodeId, setHoveredNodeId] = useState<number | null>(null)
  const [activeRailTab, setActiveRailTab] = useState(0)
  return (
    <Ctx.Provider value={{
      selectedCase, setSelectedCase,
      selectedBehavior, setSelectedBehavior,
      hoveredNodeId, setHoveredNodeId,
      activeRailTab, setActiveRailTab,
    }}>
      {children}
    </Ctx.Provider>
  )
}

export const useArgus = () => useContext(Ctx)
