import { useState } from "react"
import { ArgusProvider } from "./ArgusContext"
import TopBar from "./components/TopBar"
import LeftRail from "./components/LeftRail"
import RightRail from "./components/RightRail"
import Investigation from "./pages/Investigation"
import ActionsLog from "./pages/ActionsLog"
import HuntWorkbench from "./pages/HuntWorkbench"

export type View = "investigation" | "actions" | "hunt"

export default function App() {
  const [view, setView] = useState<View>("investigation")

  return (
    <ArgusProvider>
      <div style={{ height: "100vh", display: "flex", flexDirection: "column", overflow: "hidden", background: "var(--bg0)" }}>
        <TopBar view={view} setView={setView} />
        <div style={{ flex: 1, display: "flex", overflow: "hidden", minHeight: 0 }}>
          <LeftRail />
          {view === "investigation" && <Investigation />}
          {view === "actions"       && <ActionsLog onNavigateToInvestigation={() => setView("investigation")} />}
          {view === "hunt"          && <HuntWorkbench />}
          {view === "investigation" && <RightRail />}
        </div>
      </div>
    </ArgusProvider>
  )
}
