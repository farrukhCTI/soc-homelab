import { useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { fetchCases } from "../api"
import { useArgus } from "../ArgusContext"
import type { Case } from "../types"

// FIX-06: sparkPath and SPARKS removed. Sparklines were hardcoded to old case IDs
// and fell back to [1,2,3,4,3,2,1] for every new case — fake telemetry.
// Replaced with tactic tag row which uses real data from the case document.

const STATE_COLOR: Record<string, string> = {
  open: "var(--t3)",
  escalated: "var(--red)",
  investigating: "var(--blue)",
}

export default function LeftRail() {
  const { selectedCase, setSelectedCase, setSelectedBehavior } = useArgus()
  const [filter, setFilter] = useState<"ALL" | "HIGH" | "MED">("ALL")
  const { data: cases = [] } = useQuery({
    queryKey: ["cases"],
    queryFn: fetchCases,
    refetchInterval: 30000,
  })

  function select(c: Case) {
    setSelectedCase(c)
    setSelectedBehavior(null)
  }

  const visibleCases = cases.filter((c: Case) => {
    if (filter === "ALL") return true
    if (filter === "HIGH") return c.highest_severity === "HIGH" || c.highest_severity === "CRITICAL"
    if (filter === "MED") return c.highest_severity === "MEDIUM" || c.highest_severity === "MED"
    return true
  })

  return (
    <div style={{
      width: 204, flexShrink: 0, background: "var(--bg1)",
      display: "flex", flexDirection: "column", overflow: "hidden",
      borderRight: "1px solid var(--ln)",
    }}>
      <div style={{ padding: "10px 12px 6px", display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
        <span style={{ fontSize: 11, fontWeight: 600, color: "var(--t2)" }}>Case queue</span>
        <span style={{ fontSize: 9, fontFamily: "var(--mono)", color: "var(--t3)" }}>{visibleCases.length} open</span>
      </div>

      <div style={{ padding: "0 12px 8px", display: "flex", gap: 4, borderBottom: "1px solid var(--ln)" }}>
        {(["HIGH","MED","all"] as const).map(f => {
          const key = f === "all" ? "ALL" : f
          const isActive = filter === key
          return (
            <span key={f} onClick={() => setFilter(key)} style={{
              fontSize: 9, fontFamily: "var(--mono)", padding: "3px 6px", borderRadius: 2, cursor: "pointer",
              color: isActive ? (f === "HIGH" ? "var(--red)" : f === "MED" ? "var(--amb)" : "var(--t2)") : "var(--t3)",
              border: isActive ? (f === "HIGH" ? "1px solid var(--red3)" : f === "MED" ? "1px solid var(--amb3)" : "1px solid var(--ln3)") : "1px solid var(--ln2)",
              background: isActive ? (f === "HIGH" ? "var(--red2)" : f === "MED" ? "var(--amb2)" : "var(--bg3)") : "transparent",
              fontWeight: isActive ? 600 : 400,
            }}>{f}</span>
          )
        })}
      </div>

      <div style={{ flex: 1, overflowY: "auto" }}>
        {visibleCases.map((c) => {
          const isHigh = c.highest_severity === "HIGH" || c.highest_severity === "CRITICAL"
          const col = isHigh ? "var(--red)" : "var(--amb)"
          const sel = selectedCase?.case_id === c.case_id
          const stateCol = STATE_COLOR[c.status?.toLowerCase()] || "var(--t3)"

          // FIX-12: Date prefix on timestamp. created_at comes from the API.
          // Falls back gracefully if field is missing.
          const datePrefix = c.created_at
            ? new Date(c.created_at).toLocaleDateString("en-GB", { day: "2-digit", month: "short" }) + " · "
            : ""

          return (
            <div
              key={c.case_id}
              onClick={() => select(c)}
              style={{
                padding: "9px 12px 8px", cursor: "pointer",
                borderLeft: `2px solid ${sel ? "var(--teal)" : "transparent"}`,
                borderBottom: "1px solid var(--ln)",
                background: sel ? "var(--bg3)" : "transparent",
                transition: "background 0.1s",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 2 }}>
                <span style={{ fontSize: 9, fontFamily: "var(--mono)", color: "var(--t3)" }}>{c.case_id}</span>
                <span style={{ fontSize: 13, fontWeight: 700, fontFamily: "var(--mono)", color: col }}>
                  {(c.risk_score / 1000).toFixed(1)}k
                </span>
              </div>

              {/* FIX-12: Date prefix added before time window */}
              <div style={{ fontSize: 11, color: "var(--t2)", marginBottom: 4, fontWeight: 500 }}>
                {c.behavior_count} behaviors · {datePrefix}{c.grouped_by.time_window || "window"}
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: 5, marginBottom: 5 }}>
                <span style={{
                  fontSize: 8, fontWeight: 700, letterSpacing: "0.05em", padding: "2px 5px", borderRadius: 2,
                  color: isHigh ? "var(--red)" : "var(--amb)",
                  border: isHigh ? "1px solid var(--red3)" : "1px solid var(--amb3)",
                  background: isHigh ? "var(--red2)" : "var(--amb2)",
                }}>{c.highest_severity}</span>
                <span style={{ fontSize: 8, fontFamily: "var(--mono)", color: stateCol }}>
                  {c.status.toUpperCase()}
                </span>
              </div>

              {/* FIX-06: Tactic tag row replaces fake sparklines */}
              <div style={{ display: "flex", gap: 3, flexWrap: "wrap", marginTop: 2 }}>
                {(c.tactics_seen || []).slice(0, 3).map((t: string) => (
                  <span key={t} style={{
                    fontSize: 8, fontFamily: "var(--mono)", color: "var(--t3)",
                    padding: "1px 4px", border: "1px solid var(--ln2)", borderRadius: 2,
                  }}>
                    {t}
                  </span>
                ))}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
