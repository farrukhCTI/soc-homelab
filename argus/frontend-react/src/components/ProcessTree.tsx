import { useRef, useEffect, useCallback } from "react"
import { useArgus } from "../ArgusContext"

// Shape from the actual API response
interface ApiNode {
  id: string
  name?: string
  full_path?: string
  cmd?: string
  ppid?: string
  ts?: string
  score?: number
  on_chain?: boolean
}

interface ApiEdge {
  source: string
  target: string
}

interface ApiTreeData {
  nodes: ApiNode[]
  edges: ApiEdge[]
  behavior_pid?: string
  root?: string
}

// Internal flat node for canvas rendering
interface FlatNode {
  idx: number       // canvas array index
  id: string        // original string id from API
  label: string
  sub: string
  x: number
  y: number
  hot: boolean
  tier: "root" | "red" | "blue" | "disc"
}

interface Edge {
  a: number   // index into flatNodes
  b: number
  hot: boolean
}

const NODE_W = 148
const NODE_H = 32

const TIER_COLOR = {
  root: { fill: "rgba(28,34,48,0.95)", stroke: "rgba(255,255,255,0.09)", text: "rgba(255,255,255,0.30)" },
  red:  { fill: "rgba(229,83,75,0.09)", stroke: "rgba(229,83,75,0.40)", text: "#e5534b" },
  blue: { fill: "rgba(74,143,196,0.09)", stroke: "rgba(74,143,196,0.32)", text: "#4a8fc4" },
  disc: { fill: "rgba(123,109,212,0.08)", stroke: "rgba(123,109,212,0.28)", text: "#7b6dd4" },
}

// High-value process names that get elevated tier
const RED_PROCS = new Set(["powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","regsvr32.exe","rundll32.exe","cmstp.exe","schtasks.exe","reg.exe"])
const DISC_PROCS = new Set(["whoami.exe","ipconfig.exe","netstat.exe","netsh.exe","wmic.exe","systeminfo.exe","hostname.exe","quser.exe","qwinsta.exe","net.exe","nbtstat.exe","arp.exe"])

function getTier(node: ApiNode): "root" | "red" | "blue" | "disc" {
  const name = (node.name || "").toLowerCase()
  if (RED_PROCS.has(name)) return "red"
  if (DISC_PROCS.has(name)) return "disc"
  return "root"
}

function buildGraph(data: ApiTreeData): { flatNodes: FlatNode[]; edges: Edge[] } {
  if (!data.nodes || data.nodes.length === 0) return { flatNodes: demoNodes(), edges: demoEdges() }

  const byId = new Map<string, ApiNode>()
  data.nodes.forEach(n => byId.set(n.id, n))

  // Build parent and children maps from edges (source -> target)
  const childMap = new Map<string, string[]>()
  const parentMap = new Map<string, string>()
  ;(data.edges || []).forEach(e => {
    if (!byId.has(e.source) || !byId.has(e.target)) return
    if (!childMap.has(e.source)) childMap.set(e.source, [])
    childMap.get(e.source)!.push(e.target)
    parentMap.set(e.target, e.source)
  })

  // For each node count how many descendants it has
  const descCount = new Map<string, number>()
  function countDesc(id: string, depth: number): number {
    if (depth > 10) return 0
    const kids = childMap.get(id) || []
    const total = kids.length + kids.reduce((s, c) => s + countDesc(c, depth + 1), 0)
    descCount.set(id, total)
    return total
  }
  data.nodes.forEach(n => { if (!descCount.has(n.id)) countDesc(n.id, 0) })

  // Pick the node with the most descendants as the start
  // (This finds the richest subtree — pwsh.exe/powershell.exe chain)
  let startId = data.nodes[0].id
  let best = -1
  data.nodes.forEach(n => {
    const c = descCount.get(n.id) || 0
    if (c > best) { best = c; startId = n.id }
  })

  const flatNodes: FlatNode[] = []
  const edges: Edge[] = []
  let row = 0
  const visited = new Set<string>()

  function walk(id: string, depth: number, parentIdx: number | null, maxCh: number) {
    if (visited.has(id) || flatNodes.length >= 30) return
    visited.add(id)
    const node = byId.get(id)
    if (!node) return
    const myRow = row++
    const tier = getTier(node)
    const hot = tier === "red" || tier === "disc"
    const myIdx = flatNodes.length
    flatNodes.push({
      idx: myIdx,
      id: node.id,
      label: node.name || "unknown",
      sub: "pid " + node.id + (node.cmd ? " · " + node.cmd.replace(/^["\s]*/g, "").slice(0, 20) : ""),
      x: 20 + depth * 190,
      y: 20 + myRow * 52,
      hot,
      tier,
    })
    if (parentIdx !== null) {
      const parent = flatNodes[parentIdx]
      edges.push({ a: parentIdx, b: myIdx, hot: hot && parent.hot })
    }
    // Sort children: hot ones first
    const kids = (childMap.get(id) || []).slice(0, maxCh)
    kids.sort((a, b) => {
      const na = byId.get(a), nb = byId.get(b)
      const ta = na ? getTier(na) : "root"
      const tb = nb ? getTier(nb) : "root"
      const score = (t: string) => t === "red" ? 2 : t === "disc" ? 1 : 0
      return score(tb) - score(ta)
    })
    kids.forEach(c => walk(c, depth + 1, myIdx, 5))
  }

  walk(startId, 0, null, 6)
  return { flatNodes, edges }
}

function demoNodes(): FlatNode[] {
  return [
    { idx:0, id:"812",  label:"svchost.exe",   sub:"pid 812 · SYSTEM",   x:20,  y:170, hot:false, tier:"root" },
    { idx:1, id:"3204", label:"powershell.exe", sub:"pid 3204 · encoded", x:190, y:100, hot:true,  tier:"red"  },
    { idx:2, id:"3410", label:"cmd.exe",         sub:"pid 3410 · victim",  x:190, y:260, hot:true,  tier:"red"  },
    { idx:3, id:"4012", label:"whoami.exe",      sub:"pid 4012",           x:360, y:50,  hot:false, tier:"disc" },
    { idx:4, id:"4108", label:"schtasks.exe",    sub:"pid 4108 · PERSIST", x:360, y:150, hot:true,  tier:"red"  },
    { idx:5, id:"4220", label:"net.exe",         sub:"pid 4220",           x:360, y:260, hot:false, tier:"disc" },
    { idx:6, id:"5110", label:"ipconfig.exe",    sub:"pid 5110",           x:360, y:340, hot:false, tier:"disc" },
  ]
}
function demoEdges(): Edge[] {
  return [
    { a:0, b:1, hot:true  },
    { a:0, b:2, hot:true  },
    { a:1, b:3, hot:false },
    { a:1, b:4, hot:true  },
    { a:2, b:5, hot:false },
    { a:2, b:6, hot:false },
  ]
}

interface BehaviorRef {
  behavior_id: string
  pid?: number
  process_name?: string
  image?: string
  command_line?: string
  tactic?: string
  description?: string
  severity?: string
  host?: string
}

const LEGEND_ITEMS = [
  { color: "#e5534b",                label: "Execution / Shell" },
  { color: "#7b6dd4",                label: "Discovery" },
  { color: "rgba(255,255,255,0.28)", label: "Other process" },
]

export default function ProcessTree({ treeData, behaviors = [] }: { treeData?: ApiTreeData; behaviors?: BehaviorRef[] }) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const wrapRef = useRef<HTMLDivElement>(null)
  const stateRef = useRef({
    scale: 1, panX: 20, panY: 20,
    dragging: false, lastX: 0, lastY: 0,
    hovered: -1, selected: -1,
  })
  const { setSelectedBehavior, setHoveredNodeId } = useArgus()

  const { flatNodes, edges } = treeData
    ? buildGraph(treeData)
    : { flatNodes: demoNodes(), edges: demoEdges() }

  function wx(x: number) { return x * stateRef.current.scale + stateRef.current.panX }
  function wy(y: number) { return y * stateRef.current.scale + stateRef.current.panY }

  function getPath(nodeIdx: number): Set<number> {
    const path = new Set<number>()
    if (nodeIdx < 0) return path
    path.add(nodeIdx)
    let cur = nodeIdx
    while (true) {
      const e = edges.find(e => e.b === cur)
      if (!e) break
      path.add(e.a)
      cur = e.a
    }
    return path
  }

  function roundRect(ctx: CanvasRenderingContext2D, x: number, y: number, w: number, h: number, r: number) {
    ctx.beginPath()
    ctx.moveTo(x+r,y); ctx.lineTo(x+w-r,y); ctx.arcTo(x+w,y,x+w,y+r,r)
    ctx.lineTo(x+w,y+h-r); ctx.arcTo(x+w,y+h,x+w-r,y+h,r)
    ctx.lineTo(x+r,y+h); ctx.arcTo(x,y+h,x,y+h-r,r)
    ctx.lineTo(x,y+r); ctx.arcTo(x,y,x+r,y,r)
    ctx.closePath(); ctx.fill(); ctx.stroke()
  }

  const draw = useCallback(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext("2d")!
    const s = stateRef.current
    ctx.clearRect(0, 0, canvas.width, canvas.height)

    const hotPath = getPath(s.hovered >= 0 ? s.hovered : s.selected)
    const hasActive = s.hovered >= 0 || s.selected >= 0

    edges.forEach(e => {
      const a = flatNodes[e.a]
      const b = flatNodes[e.b]
      if (!a || !b) return
      const ax = wx(a.x + NODE_W), ay = wy(a.y + NODE_H / 2)
      const bx = wx(b.x),          by = wy(b.y + NODE_H / 2)
      const cx = (ax + bx) / 2
      const inPath = hotPath.has(e.a) && hotPath.has(e.b)
      ctx.beginPath()
      ctx.moveTo(ax, ay)
      ctx.bezierCurveTo(cx, ay, cx, by, bx, by)
      ctx.strokeStyle = inPath
        ? (e.hot ? "rgba(229,83,75,0.55)" : "rgba(61,184,144,0.35)")
        : "rgba(255,255,255,0.05)"
      ctx.lineWidth = inPath ? (e.hot ? 1.5 : 1) : 0.75
      ctx.stroke()
    })

    flatNodes.forEach(n => {
      const x = wx(n.x), y = wy(n.y)
      const w = NODE_W * s.scale
      const h = NODE_H * s.scale
      const tc = TIER_COLOR[n.tier]
      const isSel = n.idx === s.selected
      const isHov = n.idx === s.hovered
      const inPath = hotPath.has(n.idx)
      const alpha = !hasActive ? 1 : inPath ? 1 : 0.28

      ctx.globalAlpha = alpha
      if (n.hot && inPath) {
        ctx.shadowColor = "rgba(229,83,75,0.25)"
        ctx.shadowBlur = 12 * s.scale
      }
      ctx.fillStyle = tc.fill
      ctx.strokeStyle = isSel ? "rgba(61,184,144,0.65)" : tc.stroke
      ctx.lineWidth = isSel || isHov ? 1.5 : 0.75
      roundRect(ctx, x, y, w, h, 3 * s.scale)
      ctx.shadowBlur = 0

      const fs = Math.max(9, 10 * s.scale)
      ctx.fillStyle = inPath ? tc.text : "rgba(255,255,255,0.15)"
      ctx.font = `600 ${fs}px "JetBrains Mono",monospace`
      ctx.textBaseline = "top"
      ctx.fillText((n.label || "unknown").slice(0, 20), x + 8 * s.scale, y + 6 * s.scale)

      const fs2 = Math.max(7, 8.5 * s.scale)
      ctx.font = `${fs2}px "JetBrains Mono",monospace`
      ctx.fillStyle = "rgba(255,255,255,0.18)"
      ctx.fillText((n.sub || "").slice(0, 26), x + 8 * s.scale, y + 18 * s.scale)
      ctx.globalAlpha = 1
    })
  }, [flatNodes, edges])

  function nodeAt(mx: number, my: number): number {
    const s = stateRef.current
    for (let i = flatNodes.length - 1; i >= 0; i--) {
      const n = flatNodes[i]
      const x = wx(n.x), y = wy(n.y)
      const w = NODE_W * s.scale, h = NODE_H * s.scale
      if (mx >= x && mx <= x+w && my >= y && my <= y+h) return n.idx
    }
    return -1
  }

  useEffect(() => {
    const canvas = canvasRef.current
    const wrap = wrapRef.current
    if (!canvas || !wrap) return

    const resize = () => {
      canvas.width = wrap.clientWidth
      canvas.height = wrap.clientHeight
      draw()
    }
    resize()
    const ro = new ResizeObserver(resize)
    ro.observe(wrap)

    const onMove = (e: MouseEvent) => {
      const r = canvas.getBoundingClientRect()
      const mx = e.clientX - r.left, my = e.clientY - r.top
      const s = stateRef.current
      if (s.dragging) {
        s.panX += mx - s.lastX; s.panY += my - s.lastY
        s.lastX = mx; s.lastY = my
        draw(); return
      }
      const id = nodeAt(mx, my)
      if (id !== s.hovered) {
        s.hovered = id
        setHoveredNodeId(id >= 0 ? parseInt(flatNodes[id].id) : null)
        draw()
      }
    }

    const onDown = (e: MouseEvent) => {
      const r = canvas.getBoundingClientRect()
      stateRef.current.dragging = true
      stateRef.current.lastX = e.clientX - r.left
      stateRef.current.lastY = e.clientY - r.top
    }

    const onUp = () => { stateRef.current.dragging = false }

    const onClick = (e: MouseEvent) => {
      const r = canvas.getBoundingClientRect()
      const id = nodeAt(e.clientX - r.left, e.clientY - r.top)
      const s = stateRef.current
      s.selected = id === s.selected ? -1 : id
      if (s.selected >= 0) {
        const n = flatNodes[s.selected]
        const nodePid = parseInt(n.id)
        // Try to match clicked node PID to a real behavior doc
        const matched = behaviors.find(b => {
          const bpid = (b as any).pid || (b as any).process_pid
          return bpid && parseInt(String(bpid)) === nodePid
        }) || behaviors.find(b => {
          // Fallback: match by process name
          const bname = ((b as any).image || b.process_name || "").toLowerCase().split("\\").pop()
          return bname && bname === n.label.toLowerCase()
        })
        if (matched) {
          setSelectedBehavior(matched as any)
        } else {
          // No match — set minimal stub so breadcrumb updates but briefing shows graceful message
          setSelectedBehavior({ behavior_id: "", pid: nodePid, process_name: n.label } as any)
        }
      } else {
        setSelectedBehavior(null)
      }
      draw()
    }

    const onWheel = (e: WheelEvent) => {
      e.preventDefault()
      const r = canvas.getBoundingClientRect()
      const mx = e.clientX - r.left, my = e.clientY - r.top
      const f = e.deltaY < 0 ? 1.12 : 0.89
      const s = stateRef.current
      s.panX = mx - (mx - s.panX) * f
      s.panY = my - (my - s.panY) * f
      s.scale = Math.min(2.5, Math.max(0.3, s.scale * f))
      draw()
    }

    canvas.addEventListener("mousemove", onMove)
    canvas.addEventListener("mousedown", onDown)
    canvas.addEventListener("click", onClick)
    canvas.addEventListener("wheel", onWheel, { passive: false })
    window.addEventListener("mouseup", onUp)

    return () => {
      ro.disconnect()
      canvas.removeEventListener("mousemove", onMove)
      canvas.removeEventListener("mousedown", onDown)
      canvas.removeEventListener("click", onClick)
      canvas.removeEventListener("wheel", onWheel)
      window.removeEventListener("mouseup", onUp)
    }
  }, [draw, flatNodes])

  const zoomTo = (f: number) => {
    const canvas = canvasRef.current
    if (!canvas) return
    const s = stateRef.current
    if (f === 0) { s.scale = 1; s.panX = 20; s.panY = 20 }
    else {
      const W = canvas.width / 2, H = canvas.height / 2
      s.panX = W - (W - s.panX) * f
      s.panY = H - (H - s.panY) * f
      s.scale = Math.min(2.5, Math.max(0.3, s.scale * f))
    }
    draw()
  }

  return (
    <div ref={wrapRef} style={{ flex: 1, position: "relative", overflow: "hidden", cursor: "crosshair" }}>
      <canvas ref={canvasRef} style={{ display: "block", width: "100%", height: "100%" }} />

      {/* Node tier legend */}
      <div style={{ position: "absolute", bottom: 28, left: 14, display: "flex", gap: 12, pointerEvents: "none" }}>
        {LEGEND_ITEMS.map(({ color, label }) => (
          <div key={label} style={{ display: "flex", alignItems: "center", gap: 5 }}>
            <div style={{
              width: 8, height: 8, borderRadius: 1,
              background: color, flexShrink: 0,
            }} />
            <span style={{
              fontSize: 9, fontFamily: "var(--mono)",
              color: "var(--t3)", letterSpacing: "0.04em",
            }}>{label}</span>
          </div>
        ))}
      </div>

      {/* Hint text */}
      <div style={{ position: "absolute", bottom: 8, left: 14, fontSize: 9, fontFamily: "var(--mono)", color: "var(--t3)", pointerEvents: "none" }}>
        hover to trace · click to pin · scroll to zoom · drag to pan
      </div>

      {/* Zoom controls */}
      <div style={{ position: "absolute", bottom: 8, right: 8, display: "flex", gap: 3 }}>
        {(["+", "-", "o"] as string[]).map((lbl, i) => {
          const factors = [1.2, 0.83, 0]
          return (
            <div key={lbl} onClick={() => zoomTo(factors[i])} style={{
              width: 22, height: 22, background: "var(--bg2)", border: "1px solid var(--ln2)",
              borderRadius: 2, display: "flex", alignItems: "center", justifyContent: "center",
              cursor: "pointer", fontSize: 13, color: "var(--t2)", userSelect: "none",
            }}>{lbl}</div>
          )
        })}
      </div>
    </div>
  )
}
