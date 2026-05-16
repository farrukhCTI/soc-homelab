import { useArgus } from "../ArgusContext"

type View = "investigation" | "actions" | "hunt" | "coverage"

interface Props {
  view: View
  setView: (v: View) => void
}

const NAV_TABS: { key: View; label: string }[] = [
  { key: "investigation", label: "Investigation" },
  { key: "actions",       label: "Actions Log" },
  { key: "hunt",          label: "Hunt Workbench" },
  { key: "coverage",      label: "Coverage Map" },
]

export default function TopBar({ view, setView }: Props) {
  const { selectedCase, selectedBehavior, setSelectedCase, setSelectedBehavior } = useArgus()

  return (
    <div style={{
      height: 36, background: "var(--bg1)", borderBottom: "1px solid var(--ln2)",
      display: "flex", alignItems: "center", padding: "0 14px", gap: 0, flexShrink: 0,
    }}>
      <span style={{
        fontFamily: "var(--mono)", fontSize: 11, fontWeight: 700,
        letterSpacing: "0.16em", color: "var(--teal)",
        paddingRight: 14, borderRight: "1px solid var(--ln2)",
      }}>ARGUS</span>

      {/* Health pills */}
      <div style={{
        display: "flex", alignItems: "center", gap: 10,
        padding: "0 14px", borderRight: "1px solid var(--ln2)",
      }}>
        {([["ES","ok"],["Fleet","ok"],["ILM 61h","warn"]] as [string,string][]).map(([label, state]) => (
          <span key={label} style={{ fontSize: 9, fontFamily: "var(--mono)", display: "flex", alignItems: "center", gap: 4, color: "var(--t3)" }}>
            <span style={{
              width: 4, height: 4, borderRadius: "50%",
              background: state === "ok" ? "var(--grn)" : "var(--amb)",
              display: "inline-block",
            }} />
            {label}
          </span>
        ))}
      </div>

      {/* Nav tabs */}
      <div style={{ display: "flex", alignItems: "center", height: "100%" }}>
        {NAV_TABS.map(tab => (
          <div
            key={tab.key}
            onClick={() => setView(tab.key)}
            style={{
              height: "100%", display: "flex", alignItems: "center",
              padding: "0 14px", cursor: "pointer", fontSize: 10,
              color: view === tab.key ? "var(--t1)" : "var(--t3)",
              borderBottom: `1.5px solid ${view === tab.key ? "var(--teal)" : "transparent"}`,
              letterSpacing: "0.02em", transition: "color 0.12s",
            }}
          >{tab.label}</div>
        ))}
      </div>

      {/* Breadcrumb — only on investigation view */}
      {view === "investigation" && (selectedCase || selectedBehavior) && (
        <div style={{ display: "flex", alignItems: "center", gap: 5, padding: "0 14px", borderLeft: "1px solid var(--ln2)" }}>
          <span
            style={{ fontSize: 10, fontFamily: "var(--mono)", color: "var(--t3)", cursor: "pointer", padding: "2px 4px" }}
            onClick={() => { setSelectedCase(null); setSelectedBehavior(null) }}
          >Queue</span>
          {selectedCase && <>
            <span style={{ color: "var(--t4)", fontSize: 10 }}>›</span>
            <span style={{ fontSize: 10, fontFamily: "var(--mono)", color: "var(--t2)", padding: "2px 4px" }}>{selectedCase.case_id}</span>
          </>}
          {selectedBehavior && <>
            <span style={{ color: "var(--t4)", fontSize: 10 }}>›</span>
            <span style={{ fontSize: 10, fontFamily: "var(--mono)", color: "var(--t2)", padding: "2px 4px" }}>
              {selectedBehavior.process_name || selectedBehavior.behavior_id}
            </span>
          </>}
        </div>
      )}

      <div style={{ flex: 1 }} />

      <div style={{
        display: "flex", alignItems: "center", gap: 6,
        background: "var(--bg2)", border: "1px solid var(--ln2)",
        borderRadius: 3, padding: "4px 8px",
      }}>
        <span style={{ fontSize: 13, color: "var(--t3)" }}>⌕</span>
        <input
          placeholder="search..."
          style={{ background: "transparent", border: "none", fontSize: 10, color: "var(--t2)", width: 130, outline: "none", fontFamily: "var(--mono)" }}
        />
      </div>

      <div style={{
        width: 22, height: 22, borderRadius: "50%", background: "var(--teal2)",
        border: "1px solid var(--teal3)", display: "flex", alignItems: "center",
        justifyContent: "center", fontSize: 9, fontWeight: 700, color: "var(--teal)",
        marginLeft: 10,
      }}>FE</div>
    </div>
  )
}
