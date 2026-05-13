import { useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { fetchCases } from "../api"
import { useArgus } from "../ArgusContext"
import type { Case } from "../types"

function sparkPath(vals: number[], w: number, h: number) {
  const max = Math.max(...vals)
  const n = vals.length
  const pts = vals.map((v, i) => [i / (n - 1) * w, h - (v / max) * h])
  return "M" + pts.map(p => p[0].toFixed(1) + "," + p[1].toFixed(1)).join("L")
}

const SPARKS: Record<string, number[]> = {
  "CASE-002": [2,5,12,30,55,80,107,95,60,40,20,10],
  "CASE-004": [1,3,8,18,30,45,53,40,25,12],
  "CASE-003": [1,2,10,22,38,50,52,44,30],
  "CASE-005": [1,3,5,8,10,12,11,9,6],
  "CASE-001": [1,2,4,7,11,14,17,15,10],
  "CASE-006": [2,4,7,10,13,16,14,10,6],
  "CASE-007": [1,3,6,9,12,14,12,9],
}

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
        {visibleCases.map((c, i) => {
          const isHigh = c.highest_severity === "HIGH" || c.highest_severity === "CRITICAL"
          const col = isHigh ? "var(--red)" : "var(--amb)"
          const spk = SPARKS[c.case_id] || [1,2,3,4,3,2,1]
          const sel = selectedCase?.case_id === c.case_id
          const stateCol = STATE_COLOR[c.status] || "var(--t3)"

          return (
            <div
              key={c.case_id}
              onClick={() => select(c)}
              style={{
                padding: "9px 12px 6px", cursor: "pointer",
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
              <div style={{ fontSize: 11, color: "var(--t2)", marginBottom: 4, fontWeight: 500 }}>
                {c.behavior_count} behaviors · {c.grouped_by.time_window || "window"}
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
              <div style={{ height: 18, position: "relative" }}>
                <svg viewBox="0 0 180 18" preserveAspectRatio="none" style={{ width: "100%", height: "100%" }}>
                  <path d={sparkPath(spk, 180, 18)} fill="none" stroke={col} strokeWidth="1" opacity="0.45" />
                </svg>
                {i === 0 && (
                  <div style={{
                    position: "absolute", right: 0, top: 6,
                    width: 4, height: 4, borderRadius: "50%", background: "var(--red)",
                    animation: "argus-pulse 1.4s ease-in-out infinite",
                  }} />
                )}
              </div>
            </div>
          )
        })}
      </div>

      <style>{`@keyframes argus-pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }`}</style>
    </div>
  )
}
