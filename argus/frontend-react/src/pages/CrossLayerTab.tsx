import { useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { useArgus } from "../ArgusContext"

// ─── API ─────────────────────────────────────────────────────────────────────

async function fetchNetworkContext(behaviorId: string) {
  const r = await fetch(`/api/behaviors/${behaviorId}/network_context`)
  if (!r.ok) throw new Error("network_context fetch failed")
  return r.json()
}

// ─── Types ────────────────────────────────────────────────────────────────────

interface NetworkEvent {
  timestamp: string
  event_type: string
  src_ip: string
  dest_ip: string
  src_port: number
  dest_port: number
  proto: string
  url?: string
  hostname?: string
  method?: string
  status?: number
  user_agent?: string
}

interface AlertEvent {
  timestamp: string
  event_type: string
  src_ip: string
  dest_ip: string
  src_port: number
  dest_port: number
  proto: string
  signature?: string
  signature_id?: number
  severity?: number
  category?: string
  action?: string
}

interface NetworkContextResponse {
  ok: boolean
  has_network_data: boolean
  network_events: NetworkEvent[]
  alerts: AlertEvent[]
  summary: {
    returned: number
    total_hits: number
    alert_count: number
    network_event_count: number
    unique_ips: string[]
  }
  window: { start: string; end: string }
  error?: string
}

export interface BehaviorContext {
  behavior_id: string
  description: string
  image?: string
  command_line?: string
  timestamp: string
  tactic?: string
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmtTs(ts: string): string {
  try { return new Date(ts).toISOString().slice(11, 19) + "Z" }
  catch { return ts }
}

function fmtTsMs(ts: string): string {
  try { return new Date(ts).toISOString().slice(11, 23) + "Z" }
  catch { return ts }
}

function deltaSeconds(a: string, b: string): number {
  return (new Date(b).getTime() - new Date(a).getTime()) / 1000
}

const VICTIM_IP = "10.0.20.10"

const COLOR = {
  teal:    "var(--teal)",
  ndr:     "#7b6dd4",
  alert:   "var(--red)",
  suspect: "#e8903a",
}

function severityColor(sev?: number): string {
  if (!sev) return "var(--t3)"
  if (sev <= 1) return COLOR.alert
  if (sev <= 2) return COLOR.suspect
  return "#c9b03a"
}

function severityLabel(sev?: number): string {
  if (!sev) return "UNKNOWN"
  if (sev <= 1) return "HIGH"
  if (sev <= 2) return "MEDIUM"
  return "LOW"
}

function isOutbound(e: NetworkEvent): boolean {
  return e.src_ip === VICTIM_IP
}

// ─── Pivot entity — clickable investigation affordance ────────────────────────
// Not a hyperlink. An investigation primitive.
// Clicking routes to Hunt Workbench with pre-filled context.

interface PivotEntityProps {
  value: string
  templateId: string
  params: Record<string, any>
  label: string
  sourceCase?: string
  style?: React.CSSProperties
}

function PivotEntity({ value, templateId, params, label, sourceCase, style }: PivotEntityProps) {
  const [hovered, setHovered] = useState(false)
  const { setHuntPivot, setActiveView } = useArgus()

  function handlePivot() {
    setHuntPivot({
      templateId,
      params: { ...params, _pivotLabel: label, _sourceCase: sourceCase },
      label,
      sourceCase,
    })
    setActiveView("hunt")
  }

  return (
    <span
      onClick={handlePivot}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      title={`Pivot to Hunt: ${label}`}
      style={{
        cursor: "crosshair",
        fontFamily: "var(--mono)",
        borderBottom: hovered ? "1px solid var(--teal)" : "1px solid transparent",
        color: hovered ? "var(--teal)" : undefined,
        transition: "color 0.1s, border-color 0.1s",
        ...style,
      }}
    >
      {value}
      {hovered && (
        <span style={{
          fontSize: 7, marginLeft: 4, color: "var(--teal)",
          fontFamily: "var(--mono)", opacity: 0.8,
          verticalAlign: "middle",
        }}>⤷ hunt</span>
      )}
    </span>
  )
}

// ─── Attack chain builder ─────────────────────────────────────────────────────

interface ChainNode {
  id: string
  phase: string
  title: string
  detail: string
  subdetail?: string
  timestamp: string
  color: string
  source: "edr" | "ndr"
  count?: number
  spanMs?: number
}

function buildChain(
  behavior: BehaviorContext,
  networkEvents: NetworkEvent[],
  alerts: AlertEvent[]
): ChainNode[] {
  const nodes: ChainNode[] = []

  // EDR node — the trigger
  const imageName = behavior.image?.split("\\").pop() || "powershell.exe"
  nodes.push({
    id: "edr-behavior",
    phase: behavior.tactic || "EXECUTION",
    title: behavior.description,
    detail: imageName,
    subdetail: behavior.command_line
      ? behavior.command_line.slice(0, 80) + (behavior.command_line.length > 80 ? "…" : "")
      : undefined,
    timestamp: behavior.timestamp,
    color: COLOR.teal,
    source: "edr",
  })

  // Group HTTP retrievals
  const httpEvents = networkEvents.filter(e => e.event_type === "http")
  if (httpEvents.length > 0) {
    const urls = [...new Set(httpEvents.map(e => e.url).filter(Boolean))]
    const firstTs = httpEvents[0].timestamp
    const lastTs = httpEvents[httpEvents.length - 1].timestamp
    const spanMs = new Date(lastTs).getTime() - new Date(firstTs).getTime()
    const outbound = httpEvents.find(e => isOutbound(e))
    const remoteIp = outbound?.dest_ip || networkEvents.find(e => !isOutbound(e))?.src_ip || "unknown"
    const remotePort = outbound?.dest_port || "?"
    const ua = httpEvents[0].user_agent
    const isPowerShell = ua?.toLowerCase().includes("powershell")

    nodes.push({
      id: "ndr-retrieval",
      phase: "PAYLOAD RETRIEVAL",
      title: `GET ${urls[0] || "/payload"}`,
      detail: `${httpEvents.length} successful request${httpEvents.length > 1 ? "s" : ""} · ${remoteIp}:${remotePort}`,
      subdetail: isPowerShell ? `via ${ua?.split("/")[0] || "PowerShell"}` : undefined,
      timestamp: firstTs,
      color: COLOR.ndr,
      source: "ndr",
      count: httpEvents.length,
      spanMs,
    })
  }

  // Suricata alerts
  if (alerts.length > 0) {
    nodes.push({
      id: "ndr-alerts",
      phase: "NETWORK ALERT",
      title: alerts[0].signature || "Suricata signature fired",
      detail: `${alerts.length} alert${alerts.length > 1 ? "s" : ""} · sid:${alerts[0].signature_id}`,
      timestamp: alerts[0].timestamp,
      color: COLOR.alert,
      source: "ndr",
      count: alerts.length,
    })
  }

  return nodes
}

// ─── Analyst assessment (Finding / Implication / Confidence) ─────────────────
// Structured inference. Terse. Operational.

interface Assessment {
  finding: string
  implication: string
  confidence: "High" | "Medium" | "Low"
  confidenceReason: string
}

function buildAssessment(
  networkEvents: NetworkEvent[],
  alerts: AlertEvent[],
  behavior: BehaviorContext
): Assessment {
  const httpEvents = networkEvents.filter(e => e.event_type === "http")
  const uas = [...new Set(networkEvents.map(e => e.user_agent).filter(Boolean))]
  const isPowerShell = uas.some(ua => ua?.toLowerCase().includes("powershell"))
  const outbound = networkEvents.find(e => isOutbound(e))
  const remotePort = outbound?.dest_port
  const suspiciousPort = remotePort === 8080 || remotePort === 4444 || remotePort === 1337

  // Finding — factual, what was observed
  let finding = ""
  if (isPowerShell && httpEvents.length > 1) {
    finding = `${httpEvents.length}× repeated PowerShell-originated HTTP retrievals confirmed.`
  } else if (httpEvents.length > 0) {
    finding = "HTTP payload retrieval confirmed by independent NDR telemetry."
  } else if (alerts.length > 0) {
    finding = `${alerts.length} Suricata network alert${alerts.length > 1 ? "s" : ""} corroborate endpoint behavior.`
  } else {
    finding = "Network activity observed in ±15min window around endpoint behavior."
  }

  // Implication — hedged, what it may mean
  let implication = ""
  if (isPowerShell && suspiciousPort) {
    implication = `Behavior may indicate staged payload delivery or C2 staging over non-standard port ${remotePort}.`
  } else if (isPowerShell) {
    implication = "Scripted HTTP retrieval is consistent with post-exploitation tooling or automated staging."
  } else if (suspiciousPort) {
    implication = `Traffic to port ${remotePort} may indicate non-standard HTTP service or C2 infrastructure.`
  } else {
    implication = "Network activity is consistent with endpoint-initiated retrieval. Additional context required."
  }

  // Confidence — deterministic from evidence quality
  const score = (alerts.length > 0 ? 2 : 0)
    + (httpEvents.length > 1 ? 2 : httpEvents.length > 0 ? 1 : 0)
    + (isPowerShell ? 1 : 0)

  let confidence: "High" | "Medium" | "Low"
  let confidenceReason: string

  if (score >= 3) {
    confidence = "High"
    confidenceReason = alerts.length > 0
      ? "EDR behavior, repeated NDR events, and Suricata alerts — three independent signals."
      : "EDR behavior corroborated by repeated NDR events from independent pipeline."
  } else if (score >= 2) {
    confidence = "Medium"
    confidenceReason = "EDR and NDR corroborate, but single retrieval or partial signal overlap."
  } else {
    confidence = "Low"
    confidenceReason = "Weak corroboration — limited NDR evidence in window."
  }

  return { finding, implication, confidence, confidenceReason }
}


// ─── Dominant banner ──────────────────────────────────────────────────────────

function CorroborationBanner({ data }: { data: NetworkContextResponse }) {
  const hasAlerts = data.alerts.length > 0
  const accentColor = hasAlerts ? COLOR.alert : COLOR.teal
  const bgTint = hasAlerts ? "rgba(180,40,40,0.10)" : "rgba(32,180,110,0.10)"
  const outbound = data.network_events.find(e => isOutbound(e))
  const remoteIp = data.summary.unique_ips[0] || "unknown"
  const remotePort = outbound?.dest_port ?? "?"

  return (
    <div style={{
      padding: "18px 24px",
      background: bgTint,
      borderBottom: `1px solid ${accentColor}44`,
      borderLeft: `5px solid ${accentColor}`,
      flexShrink: 0,
      display: "flex", justifyContent: "space-between", alignItems: "flex-start",
    }}>
      <div>
        <div style={{
          fontSize: 15, fontWeight: 700, color: accentColor,
          letterSpacing: "0.08em", textTransform: "uppercase",
          marginBottom: 7, lineHeight: 1,
        }}>
          Network Corroboration Confirmed
        </div>
        <div style={{ fontSize: 10, color: "var(--t2)", fontFamily: "var(--mono)", lineHeight: 1.8 }}>
          <span style={{ color: "var(--t1)", fontWeight: 600 }}>{data.summary.network_event_count}</span>
          {" network events · "}
          <span style={{ color: hasAlerts ? COLOR.alert : "var(--t2)" }}>{data.summary.alert_count}</span>
          {" Suricata alerts · victim "}
          <span style={{ color: "var(--t1)" }}>{VICTIM_IP}</span>
          <span style={{ color: "var(--t4)", margin: "0 6px" }}>→</span>
          <PivotEntity
            value={`${remoteIp}:${remotePort}`}
            templateId="HT-03"
            params={{ host: "desktop-mm1rem9", hours: 48, exclude_local: false }}
            label={`Outbound connections to ${remoteIp}`}
            style={{ color: "var(--t1)", fontWeight: 600 }}
          />
        </div>
      </div>
      <div style={{ fontSize: 8, fontFamily: "var(--mono)", color: "var(--t4)", textAlign: "right", flexShrink: 0, paddingTop: 3 }}>
        <div>±15 min window</div>
        <div style={{ marginTop: 2 }}>{fmtTs(data.window.start)} → {fmtTs(data.window.end)}</div>
      </div>
    </div>
  )
}

// ─── Attack chain — primary investigation artifact ────────────────────────────

function AttackChain({ nodes }: { nodes: ChainNode[] }) {
  return (
    <div style={{
      padding: "18px 24px 14px",
      borderBottom: "1px solid var(--ln)",
      flexShrink: 0,
      background: "var(--bg0)",
    }}>
      <div style={{
        fontSize: 8, fontFamily: "var(--mono)", color: "var(--t4)",
        letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 14,
      }}>
        Attack Progression
      </div>

      <div style={{ display: "flex", alignItems: "stretch", gap: 0 }}>
        {nodes.map((node, i) => {
          const isLast = i === nodes.length - 1
          const nextNode = nodes[i + 1]
          const deltaS = nextNode ? deltaSeconds(node.timestamp, nextNode.timestamp) : null

          return (
            <div key={node.id} style={{ display: "flex", alignItems: "stretch", flex: i === nodes.length - 1 ? 1 : undefined }}>

              {/* Node block */}
              <div style={{
                padding: node.source === "edr" ? "10px 14px" : "14px 18px",
                background: node.source === "edr" ? `${node.color}06` : `${node.color}10`,
                border: `1px solid ${node.color}33`,
                borderLeft: `3px solid ${node.color}`,
                borderRadius: isLast && i === 0 ? 3 : i === 0 ? "3px 0 0 3px" : isLast ? "0 3px 3px 0" : 0,
                minWidth: node.source === "edr" ? 160 : 240,
                flex: isLast ? 1 : undefined,
                display: "flex", flexDirection: "column", justifyContent: "space-between",
              }}>
                {/* Phase label */}
                <div style={{
                  fontSize: 7, fontFamily: "var(--mono)", color: node.color,
                  letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 6,
                  display: "flex", alignItems: "center", gap: 6,
                }}>
                  <span>{node.source === "edr" ? "EDR" : "NDR"}</span>
                  <span style={{ color: "var(--t4)" }}>·</span>
                  <span>{node.phase}</span>
                </div>

                {/* Title — dominant */}
                <div style={{
                  fontSize: node.source === "edr" ? 11 : 13, fontWeight: 700, color: "var(--t1)",
                  marginBottom: 5, lineHeight: 1.2,
                }}>
                  {node.title}
                </div>

                {/* Detail */}
                <div style={{
                  fontSize: 9, fontFamily: "var(--mono)", color: "var(--t2)",
                  marginBottom: node.subdetail ? 3 : 0,
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                }}>
                  {node.source === "edr" ? (
                    <PivotEntity
                      value={node.detail}
                      templateId="HT-02"
                      params={{ host: "desktop-mm1rem9", hours: 24 }}
                      label={`Encoded PowerShell — ${node.detail}`}
                      style={{ fontSize: 9, color: "var(--t2)" }}
                    />
                  ) : node.detail}
                  {node.count && node.count > 1 && (
                    <span style={{
                      marginLeft: 6, fontSize: 8,
                      background: `${node.color}22`,
                      color: node.color,
                      border: `1px solid ${node.color}44`,
                      borderRadius: 2, padding: "0 4px",
                    }}>×{node.count}</span>
                  )}
                </div>

                {/* Subdetail */}
                {node.subdetail && (
                  <div style={{
                    fontSize: 8, fontFamily: "var(--mono)", color: COLOR.suspect,
                    overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                  }}>
                    {node.subdetail}
                  </div>
                )}

                {/* Timestamp */}
                <div style={{
                  fontSize: 8, fontFamily: "var(--mono)", color: "var(--t4)",
                  marginTop: 8,
                }}>
                  {fmtTs(node.timestamp)}
                  {node.spanMs && node.spanMs > 0 && (
                    <span style={{ color: "var(--t4)", marginLeft: 6 }}>
                      over {(node.spanMs / 1000).toFixed(0)}s
                    </span>
                  )}
                </div>
              </div>

              {/* Connector between nodes */}
              {!isLast && (
                <div style={{
                  display: "flex", flexDirection: "column", alignItems: "center",
                  justifyContent: "center", width: 56, flexShrink: 0,
                  background: "var(--bg0)",
                  borderTop: "1px solid var(--ln)", borderBottom: "1px solid var(--ln)",
                  position: "relative",
                }}>
                  {/* Gradient line */}
                  <div style={{
                    position: "absolute", top: "50%", left: 4, right: 4,
                    height: 1,
                    background: `linear-gradient(90deg, ${node.color}55, ${nodes[i + 1]?.color || "var(--t4)"}55)`,
                    transform: "translateY(-50%)",
                  }} />
                  {/* Arrowhead */}
                  <div style={{
                    position: "absolute", top: "50%", right: 3,
                    transform: "translateY(-50%)",
                    width: 0, height: 0,
                    borderTop: "4px solid transparent",
                    borderBottom: "4px solid transparent",
                    borderLeft: `6px solid ${nodes[i + 1]?.color || "var(--t4)"}66`,
                  }} />
                  {/* Delta pill */}
                  {deltaS !== null && (
                    <div style={{
                      position: "relative", zIndex: 1,
                      background: "var(--bg2)",
                      border: "1px solid var(--ln)",
                      borderRadius: 2, padding: "2px 5px",
                      fontSize: 8, fontFamily: "var(--mono)", color: "var(--t3)",
                    }}>
                      {Math.abs(deltaS) < 60
                        ? `${Math.abs(deltaS).toFixed(0)}s`
                        : `${(Math.abs(deltaS) / 60).toFixed(1)}m`}
                    </div>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ─── Analyst assessment display ─────────────────────────────────────────────

function AnalystAssessment({ assessment }: { assessment: Assessment }) {
  const confColor = assessment.confidence === "High"
    ? "var(--teal)"
    : assessment.confidence === "Medium"
    ? "#c9b03a"
    : "var(--t3)"

  return (
    <div style={{
      padding: "14px 24px",
      background: "var(--bg1)",
      borderBottom: "1px solid var(--ln)",
      flexShrink: 0,
    }}>
      <div style={{
        fontSize: 8, fontFamily: "var(--mono)", color: "var(--t4)",
        letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 12,
      }}>
        Analyst Assessment
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "80px 1fr", gap: "7px 12px", alignItems: "baseline" }}>
        {/* Finding */}
        <div style={{ fontSize: 8, fontFamily: "var(--mono)", color: "var(--t4)", letterSpacing: "0.06em", textTransform: "uppercase" }}>
          Finding
        </div>
        <div style={{ fontSize: 11, color: "var(--t1)", fontWeight: 600, lineHeight: 1.4 }}>
          {assessment.finding}
        </div>

        {/* Implication */}
        <div style={{ fontSize: 8, fontFamily: "var(--mono)", color: "var(--t4)", letterSpacing: "0.06em", textTransform: "uppercase" }}>
          Implication
        </div>
        <div style={{ fontSize: 10, color: "var(--t2)", lineHeight: 1.5 }}>
          {assessment.implication}
        </div>

        {/* Confidence */}
        <div style={{ fontSize: 8, fontFamily: "var(--mono)", color: "var(--t4)", letterSpacing: "0.06em", textTransform: "uppercase" }}>
          Confidence
        </div>
        <div style={{ display: "flex", alignItems: "baseline", gap: 8 }}>
          <span style={{ fontSize: 10, fontFamily: "var(--mono)", color: confColor, fontWeight: 700 }}>
            {assessment.confidence}
          </span>
          <span style={{ fontSize: 9, color: "var(--t3)", lineHeight: 1.5 }}>
            {assessment.confidenceReason}
          </span>
        </div>
      </div>
    </div>
  )
}


// ─── Aggregated event group (replaces repetitive cards) ───────────────────────

function AggregatedEventGroup({
  events,
  alerts,
  expanded,
  onToggle,
}: {
  events: NetworkEvent[]
  alerts: AlertEvent[]
  expanded: boolean
  onToggle: () => void
}) {
  const httpEvents = events.filter(e => e.event_type === "http")
  const urls = [...new Set(events.map(e => e.url).filter(Boolean))]
  const ua = events[0]?.user_agent
  const isPowerShell = ua?.toLowerCase().includes("powershell")
  const outbound = events.find(e => isOutbound(e))
  const remoteIp = outbound?.dest_ip || events.find(e => !isOutbound(e))?.src_ip || "?"
  const remotePort = outbound?.dest_port || "?"
  const firstTs = events[0]?.timestamp
  const lastTs = events[events.length - 1]?.timestamp
  const spanS = firstTs && lastTs ? deltaSeconds(firstTs, lastTs) : 0
  const statuses = [...new Set(events.map(e => e.status).filter(Boolean))]

  return (
    <div style={{ marginBottom: 6 }}>
      {/* Aggregated summary card */}
      <div
        onClick={onToggle}
        style={{
          padding: "10px 14px",
          background: "var(--bg2)",
          border: "1px solid var(--ln)",
          borderLeft: `2px solid ${COLOR.ndr}`,
          borderRadius: expanded ? "2px 2px 0 0" : 2,
          cursor: "pointer",
          userSelect: "none",
        }}
      >
        {/* Title row */}
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 5 }}>
          <span style={{
            fontSize: 7, fontFamily: "var(--mono)", padding: "1px 5px", borderRadius: 2,
            background: `${COLOR.ndr}18`, color: COLOR.ndr, border: `1px solid ${COLOR.ndr}33`,
            textTransform: "uppercase", flexShrink: 0,
          }}>HTTP</span>
          <span style={{
            fontSize: 11, fontFamily: "var(--mono)", color: "var(--t1)", fontWeight: 600,
            flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
          }}>
            {urls[0] || "/payload"}
          </span>
          <span style={{
            fontSize: 10, fontFamily: "var(--mono)", fontWeight: 700,
            color: statuses.includes(200) ? COLOR.teal : COLOR.alert,
          }}>
            {statuses.join(", ") || "?"}
          </span>
        </div>

        {/* Summary row */}
        <div style={{ fontSize: 9, color: "var(--t2)", lineHeight: 1.7 }}>
          <span style={{ color: "var(--t1)", fontWeight: 600 }}>{httpEvents.length}</span>
          {" successful request"}
          {httpEvents.length > 1 ? "s" : ""}
          {spanS > 0 && ` over ${spanS.toFixed(0)}s`}
          {" · "}
          <span style={{ fontFamily: "var(--mono)" }}>{remoteIp}:{remotePort}</span>
        </div>

        {/* UA row — flagged */}
        {isPowerShell && ua && (
          <div style={{
            marginTop: 5, fontSize: 8, fontFamily: "var(--mono)",
            color: COLOR.suspect,
            padding: "2px 6px",
            background: `${COLOR.suspect}0d`,
            border: `1px solid ${COLOR.suspect}22`,
            borderRadius: 2,
            display: "inline-block",
          }}>
            {ua}
          </div>
        )}

        {/* Expand toggle */}
        <div style={{ marginTop: 6, fontSize: 8, fontFamily: "var(--mono)", color: "var(--t4)" }}>
          {/* Richness summary before toggle */}
        {!expanded && firstTs && lastTs && (
          <div style={{ fontSize: 8, fontFamily: "var(--mono)", color: "var(--t4)", marginTop: 4 }}>
            {fmtTs(firstTs)} → {fmtTs(lastTs)}
          </div>
        )}
        <div style={{ marginTop: 5, fontSize: 8, fontFamily: "var(--mono)", color: "var(--t4)" }}>
          {expanded ? "▴ collapse raw telemetry" : `▾ inspect ${events.length} raw events`}
        </div>
        </div>
      </div>

      {/* Expanded raw events */}
      {expanded && (
        <div style={{
          background: "var(--bg1)",
          border: "1px solid var(--ln)", borderTop: "none",
          borderRadius: "0 0 2px 2px",
          overflow: "hidden",
        }}>
          {events.map((e, i) => (
            <div key={i} style={{
              padding: "5px 14px",
              borderBottom: i < events.length - 1 ? "1px solid var(--ln)" : undefined,
              display: "flex", alignItems: "center", gap: 10,
            }}>
              <span style={{
                fontSize: 7, fontFamily: "var(--mono)", padding: "1px 4px", borderRadius: 2,
                background: "var(--bg2)", color: "var(--t4)", border: "1px solid var(--ln)",
                textTransform: "uppercase", flexShrink: 0,
              }}>{e.event_type}</span>
              <span style={{ fontSize: 8, fontFamily: "var(--mono)", color: "var(--t3)", flex: 1 }}>
                {e.src_ip}:{e.src_port} → {e.dest_ip}:{e.dest_port}
              </span>
              <span style={{ fontSize: 8, fontFamily: "var(--mono)", color: "var(--t4)", flexShrink: 0 }}>
                {fmtTsMs(e.timestamp)}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Alert card ───────────────────────────────────────────────────────────────

function AlertCard({ alert }: { alert: AlertEvent }) {
  const col = severityColor(alert.severity)
  return (
    <div style={{
      marginBottom: 5, padding: "7px 14px",
      background: "var(--bg2)", border: "1px solid var(--ln)",
      borderLeft: `2px solid ${col}`, borderRadius: 2,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 3 }}>
        <span style={{
          fontSize: 7, fontFamily: "var(--mono)", padding: "1px 5px", borderRadius: 2,
          background: `${col}18`, color: col, border: `1px solid ${col}33`,
          textTransform: "uppercase", flexShrink: 0,
        }}>{severityLabel(alert.severity)}</span>
        <span style={{ fontSize: 8, fontFamily: "var(--mono)", color: "var(--t3)" }}>sid:{alert.signature_id}</span>
        <span style={{ fontSize: 9, color: "var(--t2)", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {alert.signature}
        </span>
      </div>
      <div style={{ fontSize: 8, fontFamily: "var(--mono)", color: "var(--t4)", display: "flex", gap: 6 }}>
        <span>{alert.src_ip}:{alert.src_port} → {alert.dest_ip}:{alert.dest_port}</span>
        <span style={{ marginLeft: "auto" }}>{fmtTsMs(alert.timestamp)}</span>
      </div>
    </div>
  )
}

// ─── Intel sidebar ────────────────────────────────────────────────────────────

function IntelPanel({ networkEvents, alerts, summary, behavior }: {
  networkEvents: NetworkEvent[]
  alerts: AlertEvent[]
  summary: NetworkContextResponse["summary"]
  behavior?: BehaviorContext
}) {
  const outbound = networkEvents.find(e => isOutbound(e))
  const remoteIps = summary.unique_ips
  const remotePort = outbound?.dest_port
  const proto = outbound?.proto
  const urls = [...new Set(networkEvents.map(e => e.url).filter(Boolean))]
  const uas = [...new Set(networkEvents.map(e => e.user_agent).filter(Boolean))]
  const isPowerShell = uas.some(ua => ua?.toLowerCase().includes("powershell"))
  const statuses = [...new Set(networkEvents.map(e => e.status).filter(Boolean))]

  // Analyst next steps — deterministic
  const pivots: string[] = []
  if (isPowerShell) pivots.push("Inspect powershell.exe parent in process tree")
  pivots.push("Pivot on remote IP — check other hosts contacting same infra")
  if (remotePort === 8080 || remotePort === 4444) pivots.push(`Check firewall for additional port ${remotePort} traffic`)
  if (alerts.length > 0) pivots.push("Review Suricata alert context in Kibana NDR dashboard")
  pivots.push("Check EID 11 file writes in raw events tab")

  const Section = ({ title, accent, children }: { title: string; accent?: string; children: React.ReactNode }) => (
    <div>
      <div style={{
        fontSize: 8, fontFamily: "var(--mono)",
        color: accent || "var(--t4)",
        letterSpacing: "0.1em", textTransform: "uppercase",
        padding: "8px 14px 6px",
        borderBottom: `1px solid ${accent ? accent + "22" : "var(--ln)"}`,
        background: accent ? `${accent}06` : "transparent",
      }}>{title}</div>
      <div style={{ padding: "9px 14px 11px" }}>{children}</div>
    </div>
  )

  const Row = ({ label, value, accent }: { label: string; value: string; accent?: boolean }) => (
    <div style={{ display: "flex", justifyContent: "space-between", gap: 8, marginBottom: 5 }}>
      <span style={{ fontSize: 9, color: "var(--t4)", flexShrink: 0 }}>{label}</span>
      <span style={{
        fontSize: 9, fontFamily: "var(--mono)",
        color: accent ? COLOR.teal : "var(--t2)",
        textAlign: "right", wordBreak: "break-all",
      }}>{value}</span>
    </div>
  )

  return (
    <div style={{
      width: 260, flexShrink: 0,
      borderLeft: "1px solid var(--ln)",
      overflow: "auto",
      background: "var(--bg1)",
    }}>

      <Section title="Next Steps">
        {pivots.slice(0, 4).map((p, i) => (
          <div key={i} style={{ display: "flex", gap: 7, marginBottom: 9, alignItems: "flex-start" }}>
            <span style={{
              color: i === 0 ? "var(--teal)" : "var(--t4)",
              fontSize: 9, flexShrink: 0, fontFamily: "var(--mono)",
              fontWeight: i === 0 ? 700 : 400,
            }}>{i + 1}.</span>
            <span style={{
              fontSize: i === 0 ? 10 : 9,
              color: i === 0 ? "var(--t1)" : "var(--t3)",
              lineHeight: 1.6,
              fontWeight: i === 0 ? 500 : 400,
            }}>{p}</span>
          </div>
        ))}
      </Section>

      <div style={{ borderTop: "1px solid var(--ln)" }} />

      {urls.length > 0 && (
        <>
          <Section title="HTTP Indicators">
            {urls.slice(0, 3).map(url => (
              <div key={url} style={{ display: "flex", justifyContent: "space-between", gap: 8, marginBottom: 5 }}>
                <span style={{ fontSize: 9, color: "var(--t4)", flexShrink: 0 }}>URI</span>
                <PivotEntity
                  value={url!}
                  templateId="HT-03"
                  params={{ host: "desktop-mm1rem9", hours: 48, exclude_local: false }}
                  label={`Outbound connections — ${url}`}
                  style={{ fontSize: 9, color: "var(--t2)" }}
                />
              </div>
            ))}
            {statuses.length > 0 && <Row label="Status" value={statuses.join(", ")} />}
            {uas.slice(0, 1).map((ua, i) => (
              <div key={i}>
                <div style={{ fontSize: 8, color: "var(--t4)", marginBottom: 3 }}>User-Agent</div>
                <div style={{
                  fontSize: 8, fontFamily: "var(--mono)",
                  color: isPowerShell ? COLOR.suspect : "var(--t2)",
                  wordBreak: "break-all", lineHeight: 1.5,
                  padding: isPowerShell ? "3px 6px" : undefined,
                  background: isPowerShell ? `${COLOR.suspect}0d` : undefined,
                  border: isPowerShell ? `1px solid ${COLOR.suspect}33` : undefined,
                  borderRadius: isPowerShell ? 2 : undefined,
                }}>{ua}</div>
              </div>
            ))}
          </Section>
          <div style={{ borderTop: "1px solid var(--ln)" }} />
        </>
      )}

      <Section title="Remote Infrastructure">
        {remoteIps.map(ip => (
          <div key={ip} style={{ display: "flex", justifyContent: "space-between", gap: 8, marginBottom: 5 }}>
            <span style={{ fontSize: 9, color: "var(--t4)", flexShrink: 0 }}>IP</span>
            <PivotEntity
              value={ip}
              templateId="HT-03"
              params={{ host: "desktop-mm1rem9", hours: 48, exclude_local: false }}
              label={`Outbound connections to ${ip}`}
              style={{ fontSize: 9, color: "var(--teal)" }}
            />
          </div>
        ))}
        {remotePort && <Row label="Port" value={String(remotePort)} />}
        {proto && <Row label="Protocol" value={proto} />}
        <Row label="Events" value={String(summary.network_event_count)} />
      </Section>

      {alerts.length > 0 && (
        <>
          <div style={{ borderTop: "1px solid var(--ln)" }} />
          <Section title="Suricata Signatures" accent={COLOR.alert}>
            {alerts.slice(0, 3).map((a, i) => (
              <div key={i} style={{ marginBottom: 10 }}>
                <div style={{ display: "flex", gap: 5, alignItems: "center", marginBottom: 3 }}>
                  <div style={{
                    fontSize: 7, padding: "1px 4px", borderRadius: 2,
                    background: `${severityColor(a.severity)}18`,
                    color: severityColor(a.severity),
                    border: `1px solid ${severityColor(a.severity)}33`,
                    fontFamily: "var(--mono)",
                  }}>{severityLabel(a.severity)}</div>
                  <span style={{ fontSize: 8, fontFamily: "var(--mono)", color: "var(--t4)" }}>sid:{a.signature_id}</span>
                </div>
                <div style={{ fontSize: 8, color: "var(--t2)", lineHeight: 1.5 }}>{a.signature}</div>
              </div>
            ))}
          </Section>
        </>
      )}
    </div>
  )
}

// ─── Empty state ──────────────────────────────────────────────────────────────

function EmptyState({ window: win }: { window: { start: string; end: string } }) {
  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      <div style={{
        padding: "20px 24px",
        background: "var(--bg2)",
        borderBottom: "1px solid var(--ln)",
        borderLeft: "5px solid var(--t4)",
        flexShrink: 0,
      }}>
        <div style={{ fontSize: 15, fontWeight: 700, color: "var(--t2)", letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 8 }}>
          No Network Corroboration
        </div>
        <div style={{ fontSize: 10, fontFamily: "var(--mono)", color: "var(--t3)" }}>
          Suricata queried · window {fmtTs(win.start)} → {fmtTs(win.end)} · 0 events matched
        </div>
      </div>

      <div style={{ flex: 1, padding: "20px 24px", overflow: "auto" }}>
        <div style={{ fontSize: 9, fontFamily: "var(--mono)", color: "var(--t3)", letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 12 }}>
          Investigation Notes
        </div>
        {[
          { label: "Sources checked", value: "Suricata EVE · filebeat-* index" },
          { label: "Query window",    value: `${fmtTs(win.start)} → ${fmtTs(win.end)}` },
          { label: "Filter",          value: "src_ip OR dest_ip = 10.0.20.10" },
        ].map(({ label, value }) => (
          <div key={label} style={{ display: "flex", gap: 12, marginBottom: 7 }}>
            <span style={{ fontSize: 9, color: "var(--t4)", flexShrink: 0, width: 110 }}>{label}</span>
            <span style={{ fontSize: 9, fontFamily: "var(--mono)", color: "var(--t2)" }}>{value}</span>
          </div>
        ))}

        <div style={{ marginTop: 18, marginBottom: 10, fontSize: 9, fontFamily: "var(--mono)", color: "var(--t3)", letterSpacing: "0.08em", textTransform: "uppercase" }}>
          Possible Reasons
        </div>
        {[
          "Behavior was purely local — no outbound network connection generated",
          "Suricata sensor did not see traffic on this segment in this window",
          "Network activity occurred outside the ±15min correlation window",
          "Try selecting a later behavior that may be closer to network activity",
        ].map((r, i) => (
          <div key={i} style={{ display: "flex", gap: 7, marginBottom: 7 }}>
            <span style={{ color: "var(--t4)", fontSize: 9, flexShrink: 0 }}>·</span>
            <span style={{ fontSize: 9, color: "var(--t3)", lineHeight: 1.6 }}>{r}</span>
          </div>
        ))}

        <div style={{ marginTop: 18, marginBottom: 10, fontSize: 9, fontFamily: "var(--mono)", color: "var(--t3)", letterSpacing: "0.08em", textTransform: "uppercase" }}>
          Suggested Pivots
        </div>
        {[
          "Check process tree for child processes with network connections (EID 3)",
          "Review raw events tab for Sysmon network connection events",
          "Open Kibana NDR dashboard and search manually around this timeframe",
        ].map((p, i) => (
          <div key={i} style={{ display: "flex", gap: 7, marginBottom: 7 }}>
            <span style={{ color: COLOR.teal, fontSize: 9, flexShrink: 0 }}>›</span>
            <span style={{ fontSize: 9, color: "var(--t3)", lineHeight: 1.6 }}>{p}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Main export ──────────────────────────────────────────────────────────────

interface CrossLayerTabProps {
  behaviorId: string
  behaviorTs: string
  behavior?: BehaviorContext
}

export default function CrossLayerTab({ behaviorId, behaviorTs, behavior }: CrossLayerTabProps) {
  const [eventsExpanded, setEventsExpanded] = useState(false)

  const { data, isLoading, isError } = useQuery<NetworkContextResponse>({
    queryKey: ["network_context", behaviorId],
    queryFn: () => fetchNetworkContext(behaviorId),
    enabled: !!behaviorId,
    staleTime: 60000,
  })

  if (isLoading) {
    return (
      <div style={{
        flex: 1, display: "flex", alignItems: "center", justifyContent: "center",
        color: "var(--t3)", fontSize: 10, fontFamily: "var(--mono)", background: "var(--bg0)",
      }}>
        querying suricata telemetry…
      </div>
    )
  }

  if (isError || !data?.ok) {
    return (
      <div style={{
        flex: 1, display: "flex", alignItems: "center", justifyContent: "center",
        color: "var(--t3)", fontSize: 10, fontFamily: "var(--mono)", background: "var(--bg0)",
      }}>
        network context unavailable
      </div>
    )
  }

  if (!data.has_network_data) {
    return <EmptyState window={data.window} />
  }

  const chain = behavior
    ? buildChain(behavior, data.network_events, data.alerts)
    : []

  const assessment = behavior
    ? buildAssessment(data.network_events, data.alerts, behavior)
    : null

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden", background: "var(--bg0)" }}>

      {/* 1. Dominant verdict banner */}
      <CorroborationBanner data={data} />

      {/* 2. Attack progression — primary investigation artifact */}
      {chain.length > 0 && <AttackChain nodes={chain} />}

      {/* 3. Analyst assessment — structured inference */}
      {assessment && <AnalystAssessment assessment={assessment} />}

      {/* 4. Evidence + intel */}
      <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>

        <div style={{ flex: 1, overflow: "auto", padding: "10px 14px" }}>

          {data.alerts.length > 0 && (
            <>
              <div style={{
                fontSize: 8, fontFamily: "var(--mono)", color: "var(--t3)",
                letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 6,
              }}>suricata alerts · {data.alerts.length}</div>
              {data.alerts.map((a, i) => <AlertCard key={i} alert={a} />)}
              <div style={{ height: 6 }} />
            </>
          )}

          {data.network_events.length > 0 && (
            <>
              <div style={{
                fontSize: 8, fontFamily: "var(--mono)", color: "var(--t3)",
                letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 6,
              }}>network evidence</div>
              <AggregatedEventGroup
                events={data.network_events}
                alerts={data.alerts}
                expanded={eventsExpanded}
                onToggle={() => setEventsExpanded(v => !v)}
              />
            </>
          )}
        </div>

        <IntelPanel
          networkEvents={data.network_events}
          alerts={data.alerts}
          summary={data.summary}
          behavior={behavior}
        />
      </div>
    </div>
  )
}
