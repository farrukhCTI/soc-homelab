import { useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { useArgus } from "../ArgusContext"
import { fetchCaseBehaviors, fetchProcessTree } from "../api"
import ProcessTree from "../components/ProcessTree"
import CrossLayerTab from "./CrossLayerTab"

const TACTIC_COLOR: Record<string, string> = {
  exec: "#4a8fc4",
  disc: "#7b6dd4",
  pers: "#c47a8a",
  def:  "#c98a3a",
}

const TL_COLORS: Record<string, string> = {
  disc: "#7b6dd4",
  exec: "#4a8fc4",
  pers: "#c47a8a",
}

const TABS = ["Process tree", "Timeline", "Detection logic", "Raw events", "Cross-layer"]

export default function Investigation() {
  const { selectedCase, selectedBehavior } = useArgus()
  const [activeTab, setActiveTab] = useState(0)

  const behaviorsQuery = useQuery({
    queryKey: ["behaviors", selectedCase?.case_id],
    queryFn: () => fetchCaseBehaviors(selectedCase!.case_id),
    enabled: !!selectedCase,
    staleTime: 30000,
  })

  const behaviors_desc = behaviorsQuery.data
    ? [...behaviorsQuery.data].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    : []
  const latestBehavior = behaviors_desc[0]
  const targetBehavior = selectedBehavior?.behavior_id ? selectedBehavior : latestBehavior

  const treeQuery = useQuery({
    queryKey: ["tree", targetBehavior?.behavior_id],
    queryFn: () => fetchProcessTree(targetBehavior!.behavior_id),
    enabled: !!targetBehavior?.behavior_id,
    staleTime: 60000,
  })

  if (!selectedCase) {
    return (
      <div style={{
        flex: 1, display: "flex", alignItems: "center", justifyContent: "center",
        color: "var(--t3)", fontSize: 12, fontFamily: "var(--mono)",
        background: "var(--bg0)",
      }}>
        select a case from the queue
      </div>
    )
  }

  const treeData = treeQuery.data as any
  const tactics = [...new Set(selectedCase.tactics_seen || [])]
  const behaviors = behaviorsQuery.data || []

  const tlEvents = behaviors.slice(0, 16).map((b, i) => ({
    pct: Math.round((i / Math.max(behaviors.length - 1, 1)) * 92) + 3,
    type: (b.tactic || "exec").toLowerCase().slice(0, 4),
    label: new Date(b.timestamp).toISOString().slice(11, 16),
    count: b.detection_score || 10,
  }))

  // Build behavior context object for CrossLayerTab triggering strip
  const behaviorContext = targetBehavior ? {
    behavior_id: targetBehavior.behavior_id,
    description:  targetBehavior.description || "",
    image:        targetBehavior.image,
    command_line: targetBehavior.command_line,
    timestamp:    targetBehavior.timestamp || "",
    tactic:       targetBehavior.tactic,
  } : undefined

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", background: "var(--bg0)", overflow: "hidden" }}>

      {/* Case header */}
      <div style={{
        padding: "9px 14px", background: "var(--bg0)", borderBottom: "1px solid var(--ln)",
        display: "flex", alignItems: "center", gap: 10, flexShrink: 0,
      }}>
        <span style={{
          fontSize: 9, fontWeight: 700, letterSpacing: "0.08em", padding: "3px 7px",
          borderRadius: 2, background: "var(--red2)", color: "var(--red)",
          border: "1px solid var(--red3)", flexShrink: 0,
        }}>
          {selectedCase.highest_severity}
        </span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 15, fontWeight: 600, color: "var(--t1)", letterSpacing: "-0.01em", marginBottom: 2 }}>
            {selectedCase.behavior_count} behaviors · {selectedCase.grouped_by.time_window || "window"}
          </div>
          <div style={{ fontSize: 10, color: "var(--t2)", display: "flex", gap: 6, fontFamily: "var(--mono)" }}>
            <span>{selectedCase.case_id}</span>
            <span style={{ color: "var(--t4)" }}>·</span>
            <span>risk {selectedCase.risk_score.toLocaleString()}</span>
            <span style={{ color: "var(--t4)" }}>·</span>
            <span>{selectedCase.grouped_by.shared_host || "desktop-mm1rem9"}</span>
          </div>
        </div>
        <div style={{ display: "flex", gap: 3, flexShrink: 0 }}>
          {tactics.slice(0, 4).map(t => {
            const key = (t as string).toLowerCase().slice(0, 4)
            const col = TACTIC_COLOR[key] || "var(--t3)"
            return (
              <span key={t as string} style={{
                fontSize: 9, padding: "2px 6px", borderRadius: 2,
                border: `1px solid ${col}44`, background: `${col}14`, color: col,
              }}>{t as string}</span>
            )
          })}
        </div>
      </div>

      {/* Panel tabs */}
      <div style={{
        height: 30, background: "var(--bg0)", borderBottom: "1px solid var(--ln)",
        display: "flex", alignItems: "flex-end", padding: "0 14px", flexShrink: 0,
      }}>
        {TABS.map((tab, i) => (
          <div
            key={tab}
            onClick={() => setActiveTab(i)}
            style={{
              fontSize: 10,
              color: activeTab === i ? "var(--t1)" : i === 4 && activeTab !== 4 ? "#7b6dd488" : "var(--t3)",
              padding: "0 10px", height: 30, display: "flex", alignItems: "center",
              cursor: "pointer",
              borderBottom: `1.5px solid ${activeTab === i ? (i === 4 ? "#7b6dd4" : "var(--teal)") : "transparent"}`,
              letterSpacing: "0.02em",
              transition: "color 0.12s",
            }}
          >{tab}</div>
        ))}
      </div>

      {/* Tab content */}
      {activeTab === 0 && <ProcessTree key={treeData ? "real" : "demo"} treeData={treeData} behaviors={behaviors} />}

      {activeTab === 1 && (
        <div style={{ flex: 1, padding: "16px 20px", overflow: "auto" }}>
          <div style={{ fontSize: 9, fontFamily: "var(--mono)", color: "var(--t3)", letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 12 }}>
            behavior timeline · {behaviors.length} events
          </div>
          {behaviors.slice(0, 30).map((b, i) => {
            const key = (b.tactic || "exec").toLowerCase().slice(0, 4)
            const col = TL_COLORS[key] || "#4a8fc4"
            return (
              <div key={b.behavior_id} style={{
                display: "flex", alignItems: "baseline", gap: 10, marginBottom: 6,
                padding: "5px 8px", borderRadius: 3, borderLeft: `2px solid ${col}44`,
              }}>
                <span style={{ fontSize: 9, fontFamily: "var(--mono)", color: "var(--t3)", flexShrink: 0 }}>
                  {new Date(b.timestamp).toISOString().slice(11, 19)}
                </span>
                <span style={{ fontSize: 9, padding: "1px 5px", borderRadius: 2, background: `${col}14`, color: col, flexShrink: 0 }}>
                  {b.tactic || "UNKNOWN"}
                </span>
                <span style={{ fontSize: 10, color: "var(--t2)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {b.description}
                </span>
              </div>
            )
          })}
        </div>
      )}

      {activeTab === 2 && (
        <div style={{ flex: 1, padding: "16px 20px", overflow: "auto" }}>
          <div style={{ fontSize: 9, fontFamily: "var(--mono)", color: "var(--t3)", letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 12 }}>
            detection logic · {behaviors.length} behaviors
          </div>
          {behaviors.slice(0, 20).map(b => (
            <div key={b.behavior_id} style={{
              marginBottom: 10, padding: "8px 10px", background: "var(--bg2)",
              borderRadius: 3, border: "1px solid var(--ln)",
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                <span style={{ fontSize: 10, fontFamily: "var(--mono)", color: "var(--t1)", fontWeight: 600 }}>
                  {b.process_name || "unknown"}
                </span>
                <span style={{ fontSize: 9, color: "var(--t3)", fontFamily: "var(--mono)" }}>
                  {b.mitre_technique || ""}
                </span>
              </div>
              <div style={{ fontSize: 10, color: "var(--t2)", marginBottom: 4 }}>{b.description}</div>
              {(b.detection_reasons || []).map((r: any, i: number) => (
                <div key={i} style={{ fontSize: 9, color: "var(--t3)", display: "flex", gap: 6, marginTop: 2 }}>
                  <span style={{ color: "var(--teal)" }}>+{r.weight}</span>
                  <span>{r.reason}</span>
                </div>
              ))}
            </div>
          ))}
        </div>
      )}

      {activeTab === 3 && (
        <div style={{ flex: 1, padding: "16px 20px", overflow: "auto" }}>
          <div style={{ fontSize: 9, fontFamily: "var(--mono)", color: "var(--t3)", letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 12 }}>
            raw events
          </div>
          {behaviors.slice(0, 20).map(b => (
            <div key={b.behavior_id} style={{
              marginBottom: 8, padding: "8px 10px", background: "var(--bg2)",
              borderRadius: 3, border: "1px solid var(--ln)", fontFamily: "var(--mono)", fontSize: 9,
            }}>
              <div style={{ color: "var(--teal)", marginBottom: 4 }}>{b.behavior_id}</div>
              <div style={{ color: "var(--t2)", wordBreak: "break-all" }}>
                {b.command_line || b.description || "no command line"}
              </div>
              <div style={{ color: "var(--t3)", marginTop: 3 }}>
                host: {b.host} · pid: {b.pid || "?"} · user: {b.user || "?"}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Cross-layer tab — CL-2 */}
      {activeTab === 4 && (
        <CrossLayerTab
          behaviorId={targetBehavior?.behavior_id || ""}
          behaviorTs={targetBehavior?.timestamp || ""}
          behavior={behaviorContext}
        />
      )}

      {/* Timeline strip — only on process tree tab */}
      {activeTab === 0 && (
        <div style={{
          height: 72, background: "var(--bg1)", borderTop: "1px solid var(--ln)",
          flexShrink: 0, padding: "7px 14px 0",
        }}>
          <div style={{
            fontSize: 9, fontFamily: "var(--mono)", color: "var(--t3)",
            letterSpacing: "0.07em", textTransform: "uppercase", marginBottom: 5,
          }}>
            behavior timeline · {selectedCase.behavior_count} events
          </div>
          <div style={{ position: "relative", height: 36 }}>
            <div style={{ position: "absolute", bottom: 12, left: 0, right: 0, height: 1, background: "var(--ln2)" }} />
            {tlEvents.map((e, i) => {
              const col = TL_COLORS[e.type] || "#4a8fc4"
              const sz = Math.max(4, Math.min(9, Math.round(e.count / 4)))
              return (
                <div
                  key={i}
                  style={{ position: "absolute", bottom: 13, left: `${e.pct}%`, transform: "translateX(-50%)", cursor: "pointer" }}
                  title={`${e.type} · ${e.label}`}
                >
                  <div style={{ width: sz, height: sz, borderRadius: "50%", border: `1px solid ${col}`, background: `${col}22`, margin: "0 auto" }} />
                  <div style={{ width: 1, height: Math.max(4, e.count / 5), background: `${col}44`, margin: "1px auto" }} />
                  <div style={{ fontSize: 8, fontFamily: "var(--mono)", color: "var(--t3)", textAlign: "center", whiteSpace: "nowrap" }}>{e.label}</div>
                </div>
              )
            })}
          </div>
        </div>
      )}

    </div>
  )
}
