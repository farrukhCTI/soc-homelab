import { useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { useArgus } from "../ArgusContext"
import { fetchBriefing, fetchCaseSummary, postEscalate, postNote } from "../api"

const TABS = ["Intel", "Entities", "Actions"]

interface ActionsPanelProps { selectedCase: any }

function ActionsPanel({ selectedCase }: ActionsPanelProps) {
  const [open, setOpen] = useState<string | null>(null)
  const [noteText, setNoteText] = useState("")
  const [ipText, setIpText] = useState("")
  const [status, setStatus] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  async function submit(action: string) {
    setLoading(true)
    setStatus(null)
    try {
      let body: any = { action, case_id: selectedCase.case_id, behavior_id: selectedCase.case_id, actor: "analyst" }
      if (action === "NOTE")     body.note = noteText
      if (action === "BLOCK_IP") body.note = ipText
      const res = await fetch("/api/actions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      })
      const data = await res.json()
      if (!data.ok) throw new Error(data.error || "failed")
      setStatus("ok")
      setOpen(null)
      setNoteText("")
      setIpText("")
    } catch (e: any) {
      setStatus("Error: " + e.message)
    } finally {
      setLoading(false)
    }
  }

  const btn = (label: string, key: string, col: string, bg: string, border: string) => (
    <button onClick={() => setOpen(open === key ? null : key)} style={{
      display: "flex", alignItems: "center", justifyContent: "space-between",
      padding: "7px 8px", borderRadius: 3, cursor: "pointer",
      border: `1px solid ${open === key ? border : "var(--ln2)"}`,
      background: open === key ? bg : "transparent",
      color: open === key ? col : "var(--t2)",
      fontSize: 10, textAlign: "left", width: "100%", marginBottom: 3,
      fontFamily: "inherit", transition: "all 0.1s",
    }}>
      <span>{label}</span>
      <span style={{ fontSize: 9, color: "var(--t4)" }}>{open === key ? "▲" : "▼"}</span>
    </button>
  )

  const inputStyle: React.CSSProperties = {
    width: "100%", background: "var(--bg3)", border: "1px solid var(--ln2)",
    borderRadius: 3, color: "var(--t1)", fontSize: 10, padding: "5px 8px",
    fontFamily: "var(--mono)", outline: "none", marginBottom: 6,
  }

  const submitBtn = (label: string, action: string, col: string) => (
    <button onClick={() => submit(action)} disabled={loading} style={{
      padding: "5px 12px", background: "transparent", border: `1px solid ${col}`,
      borderRadius: 3, color: col, fontSize: 10, cursor: "pointer",
      opacity: loading ? 0.5 : 1, fontFamily: "inherit",
    }}>{loading ? "Submitting..." : label}</button>
  )

  return (
    <div>
      <div style={{ fontSize: 8, fontFamily: "var(--mono)", letterSpacing: "0.08em", color: "var(--t3)", textTransform: "uppercase", marginBottom: 8 }}>Case actions</div>

      {btn("Escalate case", "escalate", "var(--red)", "var(--red2)", "var(--red3)")}
      {open === "escalate" && (
        <div style={{ background: "var(--bg3)", border: "1px solid var(--red3)", borderRadius: 3, padding: "8px 10px", marginBottom: 6, marginTop: -2 }}>
          <div style={{ fontSize: 9, color: "var(--t2)", marginBottom: 8, lineHeight: 1.5 }}>
            Escalate <strong style={{ color: "var(--red)" }}>{selectedCase.case_id}</strong> to Tier 2. This will be logged in the Actions trail.
          </div>
          {submitBtn("Confirm escalate", "ESCALATE", "var(--red)")}
        </div>
      )}

      {btn("Add note", "note", "var(--amb)", "var(--amb2)", "var(--amb3)")}
      {open === "note" && (
        <div style={{ background: "var(--bg3)", border: "1px solid var(--amb3)", borderRadius: 3, padding: "8px 10px", marginBottom: 6, marginTop: -2 }}>
          <textarea
            value={noteText}
            onChange={e => setNoteText(e.target.value)}
            placeholder="Investigation note..."
            rows={3}
            style={{ ...inputStyle, resize: "vertical" }}
          />
          {submitBtn("Save note", "NOTE", "var(--amb)")}
        </div>
      )}

      {btn("Block IP", "blockip", "var(--t2)", "var(--bg4)", "var(--ln3)")}
      {open === "blockip" && (
        <div style={{ background: "var(--bg3)", border: "1px solid var(--ln2)", borderRadius: 3, padding: "8px 10px", marginBottom: 6, marginTop: -2 }}>
          <input
            value={ipText}
            onChange={e => setIpText(e.target.value)}
            placeholder="e.g. 10.0.20.10"
            style={inputStyle}
          />
          {submitBtn("Log block", "BLOCK_IP", "var(--t2)")}
        </div>
      )}

      <button style={{
        display: "flex", alignItems: "center", padding: "7px 8px", borderRadius: 3,
        cursor: "not-allowed", border: "1px solid var(--ln2)", background: "transparent",
        color: "var(--t3)", fontSize: 10, width: "100%", marginBottom: 3, fontFamily: "inherit",
        opacity: 0.5,
      }}>Mark resolved <span style={{ fontSize: 9, marginLeft: "auto", color: "var(--t4)" }}>soon</span></button>

      {status === "ok" && (
        <div style={{ fontSize: 9, color: "var(--grn)", fontFamily: "var(--mono)", marginTop: 6, padding: "4px 8px", background: "var(--grn2)", borderRadius: 3 }}>
          Action logged successfully
        </div>
      )}
      {status && status !== "ok" && (
        <div style={{ fontSize: 9, color: "var(--red)", fontFamily: "var(--mono)", marginTop: 6 }}>{status}</div>
      )}

      <div style={{ display: "flex", alignItems: "center", gap: 5, padding: "6px 8px", background: "var(--bg3)", borderRadius: 3, marginTop: 8 }}>
        <div style={{ width: 4, height: 4, borderRadius: "50%", background: "var(--red)" }} />
        <span style={{ fontSize: 9, fontFamily: "var(--mono)", color: "var(--t3)" }}>
          {selectedCase.status.toUpperCase()} · risk {selectedCase.risk_score.toLocaleString()}
        </span>
      </div>
    </div>
  )
}

function BriefingPanel({ data }: { data: any }) {
  const b = data?.briefing || data
  const steps: string[] = Array.isArray(b?.next_steps) ? b.next_steps : []
  return (
    <>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
        <div>
          <div style={{ fontSize: 20, fontWeight: 700, fontFamily: "var(--mono)", color: b?.escalate ? "var(--red)" : "var(--amb)" }}>
            {b?.escalate ? "HIGH" : "MED"}
          </div>
          <div style={{ fontSize: 9, color: "var(--t3)", lineHeight: 1.4 }}>escalate<br />recommendation</div>
        </div>
      </div>
      <div style={{ fontSize: 11, color: "var(--t1)", fontWeight: 500, lineHeight: 1.5, marginBottom: 7 }}>
        {b?.summary}
      </div>
      <div style={{ fontSize: 8, fontFamily: "var(--mono)", letterSpacing: "0.08em", color: "var(--t3)", textTransform: "uppercase", marginBottom: 5 }}>
        Next steps
      </div>
      {steps.map((step: string, i: number) => (
        <div key={i} style={{ display: "flex", gap: 5, marginBottom: 4 }}>
          <span style={{ fontSize: 9, fontFamily: "var(--mono)", color: "var(--teal)", flexShrink: 0, marginTop: 1 }}>0{i + 1}</span>
          <span style={{ fontSize: 10, color: i === 0 ? "var(--t1)" : "var(--t2)", lineHeight: 1.4 }}>{step}</span>
        </div>
      ))}
    </>
  )
}

export default function RightRail() {
  const { selectedCase, selectedBehavior, activeRailTab, setActiveRailTab } = useArgus()

  const briefQuery = useQuery({
    queryKey: ["brief", selectedBehavior?.behavior_id],
    queryFn: () => fetchBriefing(selectedBehavior!.behavior_id),
    enabled: !!(selectedBehavior?.behavior_id) && selectedBehavior.behavior_id.length > 0 && activeRailTab === 0,
    staleTime: Infinity,
  })

  const summaryQuery = useQuery({
    queryKey: ["summary", selectedCase?.case_id],
    queryFn: () => fetchCaseSummary(selectedCase!.case_id),
    enabled: !!selectedCase && !selectedBehavior && activeRailTab === 0,
    staleTime: Infinity,
  })

  return (
    <div style={{
      width: 218, flexShrink: 0, background: "var(--bg1)",
      display: "flex", flexDirection: "column", overflow: "hidden",
      borderLeft: "1px solid var(--ln)",
    }}>
      <div style={{ display: "flex", borderBottom: "1px solid var(--ln)", flexShrink: 0 }}>
        {TABS.map((t, i) => (
          <div key={t} onClick={() => setActiveRailTab(i)} style={{
            flex: 1, fontSize: 9, fontFamily: "var(--mono)", letterSpacing: "0.06em",
            color: activeRailTab === i ? "var(--teal)" : "var(--t3)",
            textAlign: "center", padding: "7px 0", cursor: "pointer",
            borderBottom: `1.5px solid ${activeRailTab === i ? "var(--teal)" : "transparent"}`,
            textTransform: "uppercase",
          }}>{t}</div>
        ))}
      </div>

      <div style={{ flex: 1, overflowY: "auto", padding: "10px 12px" }}>

        {activeRailTab === 0 && (
          <>
            {selectedBehavior && !selectedBehavior.behavior_id && (
              <div style={{ fontSize: 10, color: "var(--t3)", fontFamily: "var(--mono)", marginTop: 8, lineHeight: 1.6 }}>
                <div style={{ color: "var(--t2)", marginBottom: 4 }}>{selectedBehavior.process_name}</div>
                <div>No behavior record matched this process. This node was observed in the raw Sysmon window but was not flagged by the detection engine.</div>
              </div>
            )}
            {selectedBehavior && selectedBehavior.behavior_id && briefQuery.data ? (
              <BriefingPanel data={briefQuery.data} />
            ) : selectedBehavior && selectedBehavior.behavior_id && briefQuery.isLoading ? (
              <div style={{ fontSize: 10, color: "var(--t3)", marginTop: 10 }}>Loading briefing...</div>
            ) : !selectedBehavior && selectedCase && summaryQuery.data ? (
              <>
                <div style={{ fontSize: 8, fontFamily: "var(--mono)", letterSpacing: "0.08em", color: "var(--t3)", textTransform: "uppercase", marginBottom: 6 }}>
                  Case summary
                </div>
                <div style={{ fontSize: 11, color: "var(--t1)", lineHeight: 1.55, borderLeft: "2px solid var(--teal3)", paddingLeft: 8 }}>
                  {summaryQuery.data}
                </div>
                <div style={{ marginTop: 10, fontSize: 9, fontFamily: "var(--mono)", color: "var(--t3)" }}>
                  Click a process node to get behavior-level AI briefing.
                </div>
              </>
            ) : (
              <div style={{ fontSize: 10, color: "var(--t3)", marginTop: 10 }}>
                {selectedCase ? "Loading..." : "Select a case from the queue to begin."}
              </div>
            )}
          </>
        )}

        {activeRailTab === 1 && selectedCase && (
          <>
            <div style={{ fontSize: 8, fontFamily: "var(--mono)", letterSpacing: "0.08em", color: "var(--t3)", textTransform: "uppercase", marginBottom: 6 }}>
              Entities
            </div>
            {[
              ["◈", selectedCase.case_id, "case"],
              ["◈", `${selectedCase.behavior_count} behaviors`, "count"],
              ["◈", `risk ${selectedCase.risk_score.toLocaleString()}`, "score"],
              ["◈", selectedCase.grouped_by.shared_host || "desktop-mm1rem9", "host"],
            ].map(([icon, val, type]) => (
              <div
                key={String(type)}
                style={{
                  display: "flex", alignItems: "center", gap: 6, padding: "5px 7px",
                  borderRadius: 3, marginBottom: 2, cursor: "pointer",
                  border: "1px solid transparent", transition: "background 0.1s",
                }}
                onMouseEnter={e => { (e.currentTarget as HTMLDivElement).style.background = "var(--bg3)" }}
                onMouseLeave={e => { (e.currentTarget as HTMLDivElement).style.background = "transparent" }}
              >
                <span style={{ fontSize: 11, color: "var(--t3)" }}>{icon}</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 10, fontFamily: "var(--mono)", color: "var(--t2)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{val}</div>
                  <div style={{ fontSize: 8, color: "var(--t3)" }}>{type}</div>
                </div>
                <span style={{ fontSize: 9, color: "var(--t4)" }}>→</span>
              </div>
            ))}
          </>
        )}

        {activeRailTab === 2 && selectedCase && (
          <ActionsPanel selectedCase={selectedCase} />
        )}

        {activeRailTab === 2 && !selectedCase && (
          <div style={{ fontSize: 10, color: "var(--t3)", marginTop: 10 }}>Select a case first.</div>
        )}

        {activeRailTab === 1 && !selectedCase && (
          <div style={{ fontSize: 10, color: "var(--t3)", marginTop: 10 }}>Select a case first.</div>
        )}

      </div>
    </div>
  )
}
