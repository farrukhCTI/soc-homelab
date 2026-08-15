import { useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { fetchActions } from "../api"
import { useArgus } from "../ArgusContext"

// T1-3: HUNT_PIVOT added to filter set
type FilterType = "ALL" | "ESCALATE" | "BLOCK_IP" | "NOTE" | "RESOLVED" | "CONFIRMED_MALICIOUS" | "FALSE_POSITIVE" | "HUNT_PIVOT"

const BADGE: Record<string, { color: string; bg: string; border: string }> = {
  ESCALATE:           { color: "var(--red)",  bg: "rgba(229,83,75,0.10)",   border: "rgba(229,83,75,0.30)" },
  BLOCK_IP:           { color: "var(--amb)",  bg: "rgba(201,138,58,0.10)",  border: "rgba(201,138,58,0.28)" },
  NOTE:               { color: "var(--grn)",  bg: "rgba(63,160,106,0.10)",  border: "rgba(63,160,106,0.28)" },
  RESOLVED:           { color: "var(--grn)",  bg: "rgba(63,160,106,0.10)",  border: "rgba(63,160,106,0.28)" },  // T1-7: grn = resolved/benign
  CONFIRMED_MALICIOUS:{ color: "var(--red)",  bg: "rgba(229,83,75,0.10)",   border: "rgba(229,83,75,0.30)" },
  FALSE_POSITIVE:     { color: "var(--grn)",  bg: "rgba(63,160,106,0.10)",  border: "rgba(63,160,106,0.28)" },
  // T1-3: HUNT_PIVOT — blue badge, distinct from all other action types
  HUNT_PIVOT:         { color: "var(--blue)", bg: "rgba(74,143,196,0.10)",  border: "rgba(74,143,196,0.28)" },
}

function fmtTs(iso: string) {
  return new Date(iso).toISOString().replace("T", " ").slice(0, 19) + " UTC"
}

interface Props {
  onNavigateToInvestigation?: () => void
}

export default function ActionsLog({ onNavigateToInvestigation }: Props) {
  const [filter, setFilter] = useState<FilterType>("ALL")
  const [navigating, setNavigating] = useState<string | null>(null)

  // T0-1 + T0-8: need setSelectedCase to resolve case context on navigation
  const { setSelectedBehavior, setSelectedCase } = useArgus()

  const { data, isLoading, error } = useQuery({
    queryKey: ["actions"],
    queryFn: fetchActions,
    refetchInterval: 15000,
  })

  const actions = data?.actions || []
  const total = data?.total || 0
  const filtered = filter === "ALL" ? actions : actions.filter(a => a.action === filter)

  const filters: { key: FilterType; label: string }[] = [
    { key: "ALL",                label: "All" },
    { key: "ESCALATE",           label: "Escalate" },
    { key: "BLOCK_IP",           label: "Block IP" },
    { key: "NOTE",               label: "Note" },
    { key: "RESOLVED",           label: "Resolved" },
    { key: "CONFIRMED_MALICIOUS",label: "Confirmed" },
    { key: "FALSE_POSITIVE",     label: "False Pos" },
    { key: "HUNT_PIVOT",         label: "Hunt Pivot" },  // T1-3
  ]

  // T0-1 + T0-8: GET /api/behaviors/{id} returns {behavior, case} in a single call.
  // behavior.process_name fixes the breadcrumb (T0-8).
  // case doc sets selectedCase so Investigation renders correctly (T0-1).
  async function openBehavior(behaviorId: string) {
    setNavigating(behaviorId)
    try {
      const res = await fetch(`/api/behaviors/${behaviorId}`)
      const json = await res.json()
      if (json.ok && json.behavior) {
        // T0-8: full doc has process_name — TopBar breadcrumb will use it
        setSelectedBehavior(json.behavior)
        // T0-1: case is co-fetched by the route — set it directly, no second request needed
        if (json.case?.case_id) {
          setSelectedCase(json.case)
        }
      } else {
        // Route returned ok:false or unexpected shape — fall back to stub
        setSelectedBehavior({ behavior_id: behaviorId } as any)
      }
    } catch {
      // Network error — at minimum set stub so analyst lands in Investigation view
      setSelectedBehavior({ behavior_id: behaviorId } as any)
    } finally {
      setNavigating(null)
      onNavigateToInvestigation?.()
    }
  }

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden", background: "var(--bg0)" }}>

      <div style={{ padding: "12px 20px 10px", borderBottom: "1px solid var(--ln)", flexShrink: 0 }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 12, marginBottom: 10 }}>
          <span style={{ fontSize: 14, fontWeight: 600, color: "var(--t1)" }}>Actions Log</span>
          <span style={{ fontSize: 10, color: "var(--t2)", fontFamily: "var(--mono)" }}>analyst decision audit trail</span>
          <span style={{ marginLeft: "auto", fontSize: 10, fontFamily: "var(--mono)", color: "var(--t2)", background: "var(--bg3)", border: "1px solid var(--ln2)", padding: "2px 8px", borderRadius: 3 }}>
            {isLoading ? "loading..." : `${total} total`}
          </span>
        </div>
        <div style={{ display: "flex", gap: 6 }}>
          {filters.map(f => {
            const b = BADGE[f.key] || {}
            const isActive = filter === f.key
            return (
              <button key={f.key} onClick={() => setFilter(f.key)} style={{
                fontSize: 10, fontFamily: "var(--mono)", padding: "3px 10px",
                borderRadius: 3, cursor: "pointer", letterSpacing: "0.05em",
                border: `1px solid ${isActive ? (b.border || "var(--teal3)") : "var(--ln2)"}`,
                background: isActive ? (b.bg || "var(--teal2)") : "transparent",
                color: isActive ? (b.color || "var(--teal)") : "var(--t2)",
                fontWeight: isActive ? 600 : 400,
              }}>{f.label}</button>
            )
          })}
        </div>
      </div>

      <div style={{ flex: 1, overflowY: "auto" }}>
        {error && (
          <div style={{ padding: 20, fontSize: 11, color: "var(--red)", fontFamily: "var(--mono)" }}>Failed to load actions</div>
        )}
        {!isLoading && filtered.length === 0 && (
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "60%", gap: 8, color: "var(--t3)" }}>
            <div style={{ fontSize: 28 }}>📋</div>
            <div style={{ fontSize: 12, color: "var(--t2)" }}>No actions recorded</div>
            <div style={{ fontSize: 10, fontFamily: "var(--mono)" }}>
              {filter === "ALL" ? "Use ESCALATE, BLOCK IP or ADD NOTE in the investigation view." : `No ${filter} actions yet.`}
            </div>
          </div>
        )}
        {filtered.length > 0 && (
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr style={{ background: "var(--bg1)", position: "sticky", top: 0, zIndex: 1 }}>
                {["Behavior", "Case", "Action", "Note", "Actor", "Timestamp"].map(h => (
                  <th key={h} style={{
                    textAlign: "left", padding: "7px 14px",
                    fontSize: 10, fontWeight: 700, letterSpacing: "0.08em",
                    textTransform: "uppercase", color: "var(--t2)",
                    borderBottom: "1px solid var(--ln2)",
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((a, i) => {
                const badge = BADGE[a.action] || BADGE.NOTE
                const isNavLoading = navigating === a.behavior_id
                return (
                  <tr key={a.action_id || i} style={{
                    borderBottom: "1px solid var(--ln)",
                    borderLeft: a.action === "ESCALATE" ? "2px solid var(--red)" : "2px solid transparent",
                  }}>
                    <td style={{ padding: "9px 14px" }}>
                      {a.behavior_id ? (
                        <span
                          onClick={() => !isNavLoading && openBehavior(a.behavior_id!)}
                          style={{
                            fontSize: 10, fontFamily: "var(--mono)",
                            color: isNavLoading ? "var(--t4)" : "var(--blue)",
                            cursor: isNavLoading ? "wait" : "pointer",
                            textDecoration: "underline",
                            opacity: isNavLoading ? 0.5 : 1,
                          }}
                          title={isNavLoading ? "Loading..." : "Click to investigate"}
                        >
                          {isNavLoading ? "loading…" : a.behavior_id}
                        </span>
                      ) : (
                        <span style={{ fontSize: 10, color: "var(--t3)", fontFamily: "var(--mono)" }}>—</span>
                      )}
                    </td>
                    <td style={{ padding: "9px 14px", fontSize: 10, fontFamily: "var(--mono)", color: "var(--t2)" }}>
                      {a.case_id || "—"}
                    </td>
                    <td style={{ padding: "9px 14px" }}>
                      <span style={{
                        fontSize: 10, fontWeight: 700, letterSpacing: "0.05em",
                        padding: "2px 7px", borderRadius: 3,
                        color: badge.color, background: badge.bg, border: `1px solid ${badge.border}`,
                      }}>{a.action}</span>
                    </td>
                    <td style={{ padding: "9px 14px", fontSize: 11, color: "var(--t2)", maxWidth: 300 }}>
                      {a.note || <span style={{ color: "var(--t4)" }}>—</span>}
                    </td>
                    <td style={{ padding: "9px 14px", fontSize: 10, fontFamily: "var(--mono)", color: "var(--t2)" }}>
                      {a.actor}
                    </td>
                    <td style={{ padding: "9px 14px", fontSize: 10, fontFamily: "var(--mono)", color: "var(--t2)", whiteSpace: "nowrap" }}>
                      {fmtTs(a.timestamp)}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
