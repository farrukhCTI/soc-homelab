import { ArgusProvider } from "./ArgusContext"
import { useArgus } from "./ArgusContext"
import TopBar from "./components/TopBar"
import LeftRail from "./components/LeftRail"
import RightRail from "./components/RightRail"
import Investigation from "./pages/Investigation"
import ActionsLog from "./pages/ActionsLog"
import HuntWorkbench from "./pages/HuntWorkbench"
import CoverageMap from "./pages/CoverageMap"

// Inner component reads view from context — no prop drilling
function AppInner() {
  const { activeView, setActiveView } = useArgus()
  return (
    <div style={{ height: "100vh", display: "flex", flexDirection: "column", overflow: "hidden", background: "var(--bg0)" }}>
      <TopBar view={activeView} setView={setActiveView} />
      <div style={{ flex: 1, display: "flex", overflow: "hidden", minHeight: 0 }}>
        <LeftRail />
        {activeView === "investigation" && <Investigation />}
        {activeView === "actions"       && <ActionsLog onNavigateToInvestigation={() => setActiveView("investigation")} />}
        {activeView === "hunt"          && <HuntWorkbench />}
        {activeView === "coverage"      && <CoverageMap />}
        {activeView === "investigation" && <RightRail />}
      </div>
    </div>
  )
}

export default function App() {
  return (
    <ArgusProvider>
      <AppInner />
    </ArgusProvider>
  )
}
