import { useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { fetchHuntTemplates } from "../api"
import type { HuntTemplate } from "../types"

interface HuntResult {
  columns: { name: string; type: string }[]
  rows: any[][]
  query: string
  total: number
}

export default function HuntWorkbench() {
  const [activeId, setActiveId] = useState<string | null>(null)
  const [params, setParams] = useState<Record<string, any>>({})
  const [result, setResult] = useState<HuntResult | null>(null)
  const [running, setRunning] = useState(false)
  const [runError, setRunError] = useState<string | null>(null)
  const [copilot, setCopilot] = useState<Record<string, any> | null>(null)
  const [copilotLoading, setCopilotLoading] = useState(false)

  const { data: templates = [], isLoading } = useQuery({
    queryKey: ["hunt-templates"],
    queryFn: fetchHuntTemplates,
    staleTime: Infinity,
  })

  const activeTemplate = templates.find((t: HuntTemplate) => t.id === activeId)

  function selectTemplate(t: HuntTemplate) {
    setActiveId(t.id)
    setResult(null)
    setCopilot(null)
    setRunError(null)
    const defaults: Record<string, any> = {}
    t.params.forEach(p => { if (p.default !== undefined) defaults[p.name] = p.default })
    setParams(defaults)
  }

  async function runHunt() {
    if (!activeId) return
    setRunning(true)
    setRunError(null)
    setResult(null)
    setCopilot(null)
    try {
      // app.py route is POST /api/hunt with { template_id, params }
      const res = await fetch('/api/hunt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ template_id: activeId, params }),
      })
      const data = await res.json()
      if (!data.ok) throw new Error(data.error || 'Hunt failed')
      setResult({
        columns: data.columns || [],
        rows: data.rows || data.results || [],
        query: data.query || '',
        total: data.total || 0,
      })
    } catch (e: any) {
      setRunError(e.message)
    } finally {
      setRunning(false)
    }
  }

  async function askClaude() {
    if (!result || !activeId) return
    setCopilotLoading(true)
    try {
      const tpl = templates.find((t: HuntTemplate) => t.id === activeId)
      const res = await fetch('/api/hunt/copilot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          template_id:          activeId,
          template_name:        tpl?.name        || activeId,
          template_description: tpl?.description || '',
          query:                result.query      || '',
          columns:              result.columns.map((c: any) => c.name || c),
          total_rows:           result.total,
          preview_rows:         result.rows.slice(0, 20),
          suspicious_row_count: 0,
        }),
      })
      const data = await res.json()
      if (!data.ok) throw new Error(data.error || 'Copilot failed')
      setCopilot(data.copilot)
    } catch (e: any) {
      setCopilot({ summary: `Error: ${e.message}`, findings: [], recommended_actions: [], mitre_tags: [], limitations: [] })
    } finally {
      setCopilotLoading(false)
    }
  }

  return (
    <div style={{ flex: 1, display: "flex", overflow: "hidden", background: "var(--bg0)" }}>

      {/* Sidebar */}
      <div style={{ width: 240, flexShrink: 0, background: "var(--bg1)", borderRight: "1px solid var(--ln)", display: "flex", flexDirection: "column", overflow: "hidden" }}>
        <div style={{ padding: "10px 12px 8px", borderBottom: "1px solid var(--ln)" }}>
          <span style={{ fontSize: 9, fontFamily: "var(--mono)", letterSpacing: "0.08em", color: "var(--t3)", textTransform: "uppercase" }}>Hunt templates</span>
        </div>
        <div style={{ flex: 1, overflowY: "auto" }}>
          {isLoading && <div style={{ padding: 12, fontSize: 10, color: "var(--t3)", fontFamily: "var(--mono)" }}>loading...</div>}
          {templates.map((t: HuntTemplate) => (
            <div key={t.id} onClick={() => selectTemplate(t)} style={{
              padding: "10px 12px", cursor: "pointer",
              borderLeft: `2px solid ${activeId === t.id ? "var(--teal)" : "transparent"}`,
              borderBottom: "1px solid var(--ln)",
              background: activeId === t.id ? "var(--bg3)" : "transparent",
              transition: "background 0.1s",
            }}>
              <div style={{ fontSize: 9, fontFamily: "var(--mono)", color: "var(--teal)", marginBottom: 2 }}>{t.id}</div>
              <div style={{ fontSize: 11, color: "var(--t1)", fontWeight: 500, marginBottom: 3 }}>{t.name}</div>
              <div style={{ fontSize: 10, color: "var(--t3)", lineHeight: 1.4 }}>{t.description}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Main */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        {!activeTemplate ? (
          <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 8, color: "var(--t3)" }}>
            <div style={{ fontSize: 28 }}>🔍</div>
            <div style={{ fontSize: 12, color: "var(--t2)" }}>Select a hunt template</div>
            <div style={{ fontSize: 10, fontFamily: "var(--mono)" }}>Choose from the sidebar to begin hunting</div>
          </div>
        ) : (
          <div style={{ flex: 1, overflowY: "auto", padding: "16px 20px" }}>

            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 14, fontWeight: 600, color: "var(--t1)", marginBottom: 4 }}>{activeTemplate.name}</div>
              <div style={{ fontSize: 11, color: "var(--t2)", lineHeight: 1.5 }}>{activeTemplate.description}</div>
            </div>

            {/* Params */}
            {activeTemplate.params.length > 0 && (
              <div style={{ background: "var(--bg2)", border: "1px solid var(--ln2)", borderRadius: 4, padding: "12px 16px", marginBottom: 14 }}>
                <div style={{ fontSize: 9, fontFamily: "var(--mono)", letterSpacing: "0.08em", color: "var(--t3)", textTransform: "uppercase", marginBottom: 10 }}>Parameters</div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(180px, 1fr))", gap: 12 }}>
                  {activeTemplate.params.map(p => (
                    <div key={p.name} style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                      <label style={{ fontSize: 10, color: "var(--t2)", fontWeight: 600 }}>{p.label}</label>
                      {p.type === "boolean" ? (
                        <input type="checkbox" checked={!!params[p.name]}
                          onChange={e => setParams({ ...params, [p.name]: e.target.checked })}
                          style={{ width: 16, height: 16, cursor: "pointer" }} />
                      ) : (
                        <input
                          type={p.type === "number" ? "number" : "text"}
                          value={params[p.name] ?? ""}
                          onChange={e => setParams({ ...params, [p.name]: p.type === "number" ? Number(e.target.value) : e.target.value })}
                          style={{ background: "var(--bg3)", border: "1px solid var(--ln2)", borderRadius: 3, color: "var(--t1)", fontSize: 11, padding: "5px 8px", fontFamily: "var(--mono)", outline: "none" }}
                        />
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            <button onClick={runHunt} disabled={running} style={{
              padding: "7px 20px", background: "var(--teal)", color: "var(--bg0)",
              border: "none", borderRadius: 3, fontSize: 11, fontWeight: 700,
              cursor: running ? "not-allowed" : "pointer",
              opacity: running ? 0.6 : 1, marginBottom: 16, letterSpacing: "0.04em",
            }}>{running ? "Running..." : "Run Hunt"}</button>

            {runError && (
              <div style={{ fontSize: 11, color: "var(--red)", fontFamily: "var(--mono)", marginBottom: 12 }}>
                Failed: {runError}
              </div>
            )}

            {/* Query */}
            {result?.query && (
              <div style={{ background: "var(--bg2)", border: "1px solid var(--ln)", borderRadius: 4, padding: "10px 14px", marginBottom: 14 }}>
                <div style={{ fontSize: 9, fontFamily: "var(--mono)", letterSpacing: "0.08em", color: "var(--t3)", textTransform: "uppercase", marginBottom: 6 }}>ES|QL Query</div>
                <pre style={{ fontSize: 10, fontFamily: "var(--mono)", color: "var(--t2)", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{result.query}</pre>
              </div>
            )}

            {/* Results */}
            {result && (
              <div style={{ background: "var(--bg1)", border: "1px solid var(--ln2)", borderRadius: 4, overflow: "hidden", marginBottom: 14 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 14px", borderBottom: "1px solid var(--ln)", background: "var(--bg2)" }}>
                  <span style={{ fontSize: 9, fontFamily: "var(--mono)", letterSpacing: "0.08em", color: "var(--t3)", textTransform: "uppercase" }}>Results</span>
                  <span style={{ fontSize: 9, fontFamily: "var(--mono)", color: "var(--t3)", background: "var(--bg3)", padding: "1px 6px", borderRadius: 2 }}>{result.total} rows</span>
                  <button onClick={askClaude} disabled={copilotLoading} style={{
                    marginLeft: "auto", fontSize: 9, fontFamily: "var(--mono)", padding: "3px 10px",
                    border: "1px solid var(--teal3)", background: "var(--teal2)", color: "var(--teal)",
                    borderRadius: 3, cursor: "pointer", opacity: copilotLoading ? 0.6 : 1,
                  }}>{copilotLoading ? "Thinking..." : "✦ Ask Claude"}</button>
                </div>

                {result.rows.length === 0 ? (
                  <div style={{ padding: 20, fontSize: 11, color: "var(--t3)", fontFamily: "var(--mono)", textAlign: "center" }}>
                    No results — try adjusting parameters or expanding the time window
                  </div>
                ) : (
                  <div style={{ overflowX: "auto" }}>
                    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 10, fontFamily: "var(--mono)" }}>
                      {result.columns.length > 0 && (
                        <thead>
                          <tr style={{ background: "var(--bg2)" }}>
                            {result.columns.map((c, i) => (
                              <th key={i} style={{ padding: "6px 12px", textAlign: "left", fontSize: 9, fontWeight: 700, letterSpacing: "0.06em", color: "var(--t3)", borderBottom: "1px solid var(--ln)", whiteSpace: "nowrap", textTransform: "uppercase" }}>
                                {c.name}
                              </th>
                            ))}
                          </tr>
                        </thead>
                      )}
                      <tbody>
                        {result.rows.slice(0, 50).map((row, i) => (
                          <tr key={i} style={{ borderBottom: "1px solid var(--ln)" }}>
                            {row.map((cell, j) => {
                              const s = String(cell ?? "null")
                              const suspicious = ["powershell","cmd","wscript","cscript","mshta","rundll32","certutil","schtasks","regsvr32"].some(x => s.toLowerCase().includes(x))
                              return (
                                <td key={j} style={{ padding: "6px 12px", color: suspicious ? "var(--amb)" : "var(--t2)", maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                                  title={s}>
                                  {s.length > 60 ? s.slice(0, 57) + "..." : s}
                                </td>
                              )
                            })}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {/* Copilot */}
            {copilot && (
              <div style={{ background: "var(--bg2)", border: "1px solid var(--teal3)", borderRadius: 4, padding: "12px 16px", borderLeft: "3px solid var(--teal)" }}>
                <div style={{ fontSize: 9, fontFamily: "var(--mono)", letterSpacing: "0.08em", color: "var(--teal)", textTransform: "uppercase", marginBottom: 8 }}>Claude Co-pilot</div>
                <div style={{ fontSize: 11, color: "var(--t1)", lineHeight: 1.6, marginBottom: 10 }}>{(copilot as any).summary}</div>
                {(copilot as any).findings?.length > 0 && <>
                  <div style={{ fontSize: 9, fontFamily: "var(--mono)", color: "var(--t3)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 6 }}>Findings</div>
                  {(copilot as any).findings.map((f: string, i: number) => (
                    <div key={i} style={{ fontSize: 10, color: "var(--t2)", display: "flex", gap: 6, marginBottom: 3 }}>
                      <span style={{ color: "var(--teal)" }}>·</span><span>{f}</span>
                    </div>
                  ))}
                </>}
                {(copilot as any).recommended_actions?.length > 0 && <>
                  <div style={{ fontSize: 9, fontFamily: "var(--mono)", color: "var(--t3)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 6, marginTop: 8 }}>Recommended actions</div>
                  {(copilot as any).recommended_actions.map((a: string, i: number) => (
                    <div key={i} style={{ fontSize: 10, color: "var(--t2)", display: "flex", gap: 6, marginBottom: 3 }}>
                      <span style={{ color: "var(--amb)" }}>→</span><span>{a}</span>
                    </div>
                  ))}
                </>}
                {(copilot as any).mitre_tags?.length > 0 && (
                  <div style={{ marginTop: 8, display: "flex", gap: 4, flexWrap: "wrap" }}>
                    {(copilot as any).mitre_tags.map((t: string, i: number) => (
                      <span key={i} style={{ fontSize: 9, fontFamily: "var(--mono)", padding: "2px 6px", borderRadius: 2, background: "var(--pur2)", color: "var(--pur)", border: "1px solid var(--pur3)" }}>{t}</span>
                    ))}
                  </div>
                )}
              </div>
            )}

          </div>
        )}
      </div>
    </div>
  )
}
