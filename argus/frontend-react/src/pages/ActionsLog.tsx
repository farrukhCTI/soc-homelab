import { useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { fetchActions } from "../api"
import { useArgus } from "../ArgusContext"

type FilterType = "ALL" | "ESCALATE" | "BLOCK_IP" | "NOTE"

const BADGE: Record<string, { color: string; bg: string; border: string }> = {
  ESCALATE: { color: "var(--red)",  bg: "rgba(229,83,75,0.10)",  border: "rgba(229,83,75,0.30)" },
  BLOCK_IP: { color: "var(--amb)",  bg: "rgba(201,138,58,0.10)", border: "rgba(201,138,58,0.28)" },
  NOTE:     { color: "var(--grn)",  bg: "rgba(63,160,106,0.10)", border: "rgba(63,160,106,0.28)" },
}

function fmtTs(iso: string) {
  return new Date(iso).toISOString().replace("T", " ").slice(0, 19) + " UTC"
}

interface Props {
  onNavigateToInvestigation?: () => void
}

export default function ActionsLog({ onNavigateToInvestigation }: Props) {
  const [filter, setFilter] = useState<FilterType>("ALL")
  const { setSelectedBehavior } = useArgus()

  const { data, isLoading, error } = useQuery({
    queryKey: ["actions"],
    queryFn: fetchActions,
    refetchInterval: 15000,
  })

  const actions = data?.actions || []
  const total = data?.total || 0
  const filtered = filter === "ALL" ? actions : actions.filter(a => a.action === filter)

  const filters: { key: FilterType; label: string }[] = [
    { key: "ALL",      label: "All" },
    { key: "ESCALATE", label: "Escalate" },
    { key: "BLOCK_IP", label: "Block IP" },
    { key: "NOTE",     label: "Note" },
  ]

  function openBehavior(behaviorId: string) {
    setSelectedBehavior({ behavior_id: behaviorId } as any)
    onNavigateToInvestigation?.()
  }

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden", background: "var(--bg0)" }}>

      <div style={{ padding: "12px 20px 10px", borderBottom: "1px solid var(--ln)", flexShrink: 0 }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 12, marginBottom: 10 }}>
          <span style={{ fontSize: 14, fontWeight: 600, color: "var(--t1)" }}>Actions Log</span>
          <span style={{ fontSize: 10, color: "var(--t3)", fontFamily: "var(--mono)" }}>analyst decision audit trail</span>
          <span style={{ marginLeft: "auto", fontSize: 9, fontFamily: "var(--mono)", color: "var(--t3)", background: "var(--bg3)", border: "1px solid var(--ln2)", padding: "2px 8px", borderRadius: 3 }}>
            {isLoading ? "loading..." : `${total} total`}
          </span>
        </div>
        <div style={{ display: "flex", gap: 6 }}>
          {filters.map(f => {
            const b = BADGE[f.key] || {}
            const isActive = filter === f.key
            return (
              <button key={f.key} onClick={() => setFilter(f.key)} style={{
                fontSize: 9, fontFamily: "var(--mono)", padding: "3px 10px",
                borderRadius: 3, cursor: "pointer", letterSpacing: "0.05em",
                border: `1px solid ${isActive ? (b.border || "var(--teal3)") : "var(--ln2)"}`,
                background: isActive ? (b.bg || "var(--teal2)") : "transparent",
                color: isActive ? (b.color || "var(--teal)") : "var(--t3)",
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
                    fontSize: 9, fontWeight: 700, letterSpacing: "0.08em",
                    textTransform: "uppercase", color: "var(--t3)",
                    borderBottom: "1px solid var(--ln2)",
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((a, i) => {
                const badge = BADGE[a.action] || BADGE.NOTE
                return (
                  <tr key={a.action_id || i} style={{
                    borderBottom: "1px solid var(--ln)",
                    borderLeft: a.action === "ESCALATE" ? "2px solid var(--red)" : "2px solid transparent",
                  }}>
                    <td style={{ padding: "9px 14px" }}>
                      {a.behavior_id ? (
                        <span
                          onClick={() => openBehavior(a.behavior_id!)}
                          style={{ fontSize: 10, fontFamily: "var(--mono)", color: "var(--blue)", cursor: "pointer", textDecoration: "underline" }}
                          title="Click to investigate"
                        >{a.behavior_id}</span>
                      ) : (
                        <span style={{ fontSize: 10, color: "var(--t4)", fontFamily: "var(--mono)" }}>—</span>
                      )}
                    </td>
                    <td style={{ padding: "9px 14px", fontSize: 10, fontFamily: "var(--mono)", color: "var(--t3)" }}>
                      {a.case_id || "—"}
                    </td>
                    <td style={{ padding: "9px 14px" }}>
                      <span style={{
                        fontSize: 9, fontWeight: 700, letterSpacing: "0.05em",
                        padding: "2px 7px", borderRadius: 3,
                        color: badge.color, background: badge.bg, border: `1px solid ${badge.border}`,
                      }}>{a.action}</span>
                    </td>
                    <td style={{ padding: "9px 14px", fontSize: 11, color: "var(--t2)", maxWidth: 300 }}>
                      {a.note || <span style={{ color: "var(--t4)" }}>—</span>}
                    </td>
                    <td style={{ padding: "9px 14px", fontSize: 10, fontFamily: "var(--mono)", color: "var(--t3)" }}>
                      {a.actor}
                    </td>
                    <td style={{ padding: "9px 14px", fontSize: 10, fontFamily: "var(--mono)", color: "var(--t3)", whiteSpace: "nowrap" }}>
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
