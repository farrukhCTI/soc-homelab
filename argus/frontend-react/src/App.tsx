import { useEffect, useState } from "react"
import { ArgusProvider } from "./ArgusContext"
import { useArgus } from "./ArgusContext"
import TopBar from "./components/TopBar"
import LeftRail from "./components/LeftRail"
import RightRail from "./components/RightRail"
import Investigation from "./pages/Investigation"
import ActionsLog from "./pages/ActionsLog"
import HuntWorkbench from "./pages/HuntWorkbench"
import CoverageMap from "./pages/CoverageMap"

// S-4: Resume prompt — shown for up to 4h after last session save
interface ResumeSession {
  case_id: string
  saved_at: string
}

// Inner component reads view from context — no prop drilling
function AppInner() {
  const { activeView, setActiveView } = useArgus()
  const [resumeSession, setResumeSession] = useState<ResumeSession | null>(null)

  // S-4: On mount, check for a recent session to offer resume prompt
  useEffect(() => {
    fetch("/api/session")
      .then(r => r.json())
      .then(data => {
        if (!data.ok || !data.session?.case_id) return
        // Only offer resume if session is < 4 hours old
        const savedAt = new Date(data.session.saved_at).getTime()
        const ageHours = (Date.now() - savedAt) / 3600000
        if (ageHours < 4) {
          setResumeSession({ case_id: data.session.case_id, saved_at: data.session.saved_at })
        }
      })
      .catch(() => {
        // Non-fatal — app loads normally with no resume prompt
      })
  }, [])

  return (
    <div style={{ height: "100vh", display: "flex", flexDirection: "column", overflow: "hidden", background: "var(--bg0)" }}>
      <TopBar view={activeView} setView={setActiveView} />

      {/* S-4: Resume prompt — dismissable amber banner, appears only when recent session found */}
      {resumeSession && (
        <div style={{
          padding: "6px 20px",
          background: "rgba(201,138,58,0.08)",
          borderBottom: "1px solid rgba(201,138,58,0.22)",
          display: "flex", alignItems: "center", gap: 10,
          flexShrink: 0,
        }}>
          <span style={{ fontSize: 10, color: "var(--amb)", fontFamily: "var(--mono)", fontWeight: 600 }}>
            Resume investigation
          </span>
          <span style={{ fontSize: 10, color: "var(--t3)", fontFamily: "var(--mono)" }}>·</span>
          <span style={{ fontSize: 10, color: "var(--t2)", fontFamily: "var(--mono)" }}>
            {resumeSession.case_id}
          </span>
          <span style={{ fontSize: 10, color: "var(--t3)", fontFamily: "var(--mono)" }}>
            · last active {new Date(resumeSession.saved_at).toISOString().slice(11, 16)} UTC
          </span>
          <button
            onClick={() => {
              // LeftRail will handle actual case loading — just navigate to investigation
              setActiveView("investigation")
              setResumeSession(null)
            }}
            style={{
              fontSize: 10, fontFamily: "var(--mono)", padding: "2px 10px",
              borderRadius: 2, cursor: "pointer", fontWeight: 600,
              background: "rgba(201,138,58,0.15)", border: "1px solid rgba(201,138,58,0.35)",
              color: "var(--amb)",
            }}
          >Open</button>
          <button
            onClick={() => setResumeSession(null)}
            style={{
              fontSize: 10, fontFamily: "var(--mono)", padding: "2px 8px",
              borderRadius: 2, cursor: "pointer",
              background: "transparent", border: "1px solid var(--ln2)",
              color: "var(--t3)",
            }}
          >Dismiss</button>
        </div>
      )}

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
