"use client";

import { useEffect } from "react";
import ReactFlow, {
  Node,
  Edge,
  Background,
  BackgroundVariant,
  Controls,
  useNodesState,
  useEdgesState,
  Position,
} from "reactflow";
import "reactflow/dist/style.css";
import { SessionSnapshot } from "@/lib/types";

interface Props {
  snapshot: SessionSnapshot | null;
  sessionId: string;
  sessionName: string;
}

// ── Palette ────────────────────────────────────────────────────────────────────
const P = {
  owner:          { bg: "#0f2240", border: "#4f8ef7", text: "#7db5ff" },
  human_on:       { bg: "#111f38", border: "#2d5fa6", text: "#4f8ef7" },
  human_off:      { bg: "#141414", border: "#2e2e2e", text: "#555"    },
  agent_running:  { bg: "#0b2318", border: "#3ecf8e", text: "#3ecf8e" },
  agent_waiting:  { bg: "#201700", border: "#f5a623", text: "#f5a623" },
  agent_blocked:  { bg: "#200d0d", border: "#f56565", text: "#f56565" },
  agent_idle:     { bg: "#141414", border: "#2e2e2e", text: "#555"    },
  approval:       { bg: "#221200", border: "#f5a623", text: "#f5a623" },
  session:        { bg: "#141414", border: "#444",    text: "#e2e2e2" },
};

function agentPalette(status?: string) {
  if (status === "running") return P.agent_running;
  if (status === "waiting") return P.agent_waiting;
  if (status === "blocked" || status === "error") return P.agent_blocked;
  return P.agent_idle;
}

function nodeStyle(c: { bg: string; border: string; text: string }, extra?: object) {
  return {
    background: c.bg,
    border: `1px solid ${c.border}`,
    color: c.text,
    borderRadius: 10,
    padding: "10px 16px",
    fontSize: 11,
    fontFamily: "Inter, sans-serif",
    textAlign: "center" as const,
    whiteSpace: "pre-line" as const,
    minWidth: 110,
    ...extra,
  };
}

function buildGraph(snapshot: SessionSnapshot | null, sessionId: string, sessionName: string) {
  const nodes: Node[] = [];
  const edges: Edge[] = [];

  if (!snapshot) {
    nodes.push({
      id: "empty",
      position: { x: 200, y: 150 },
      data: { label: "Waiting for session data…" },
      style: nodeStyle(P.session),
    });
    return { nodes, edges };
  }

  const humans = snapshot.members.filter(m => m.role !== "agent");
  const agents = snapshot.members.filter(m => m.role === "agent");
  const approvals = snapshot.pending_approvals;

  const H_SPACING = 100;
  const centerY = Math.max(humans.length, agents.length, 1) * H_SPACING / 2;

  // Session node
  nodes.push({
    id: "session",
    position: { x: 320, y: centerY - 30 },
    data: { label: `${sessionName || sessionId.slice(0, 8)}\n${snapshot.status}` },
    style: nodeStyle(P.session, { fontWeight: 600, fontSize: 12, minWidth: 140 }),
    sourcePosition: Position.Right,
    targetPosition: Position.Left,
  });

  // Human nodes
  humans.forEach((h, i) => {
    const isOwner = h.actor_id === snapshot.owner;
    const c = isOwner ? P.owner : h.attached ? P.human_on : P.human_off;
    const y = i * H_SPACING;
    nodes.push({
      id: `h-${h.actor_id}`,
      position: { x: 60, y },
      data: { label: `${h.name || h.actor_id}\n${isOwner ? "owner" : h.role}${!h.attached ? "\naway" : ""}` },
      style: nodeStyle(c),
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
    });
    edges.push({
      id: `eh-${h.actor_id}`,
      source: `h-${h.actor_id}`,
      target: "session",
      animated: h.attached && isOwner,
      style: {
        stroke: isOwner ? "#4f8ef7" : h.attached ? "#2d5fa6" : "#2e2e2e",
        strokeWidth: isOwner ? 2 : 1,
        strokeDasharray: h.attached ? undefined : "4 3",
      },
      label: isOwner ? "owner" : undefined,
      labelStyle: { fontSize: 9, fill: "#4f8ef7" },
      labelBgStyle: { fill: "#0d0d0d", fillOpacity: 0.85 },
    });
  });

  // Agent nodes
  agents.forEach((a, i) => {
    const c = agentPalette(a.status);
    const statusLabel = a.status ?? "idle";
    const y = i * H_SPACING;
    nodes.push({
      id: `a-${a.actor_id}`,
      position: { x: 580, y },
      data: { label: `${a.name || a.actor_id}\n${statusLabel}` },
      style: nodeStyle(c),
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
    });
    edges.push({
      id: `ea-${a.actor_id}`,
      source: "session",
      target: `a-${a.actor_id}`,
      animated: a.status === "running",
      style: {
        stroke: c.border,
        strokeWidth: 1,
        strokeDasharray: a.status === "idle" ? "4 3" : undefined,
      },
    });
  });

  // Approval nodes
  approvals.forEach((ap, i) => {
    const y = i * 110;
    nodes.push({
      id: `ap-${ap.approval_id}`,
      position: { x: 840, y },
      data: { label: `${ap.tool}\n${ap.state.toLowerCase()}` },
      style: nodeStyle(P.approval, { minWidth: 140 }),
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
    });
    const srcAgent = agents.find(a => a.actor_id === ap.requested_by);
    edges.push({
      id: `eap-${ap.approval_id}`,
      source: srcAgent ? `a-${ap.requested_by}` : "session",
      target: `ap-${ap.approval_id}`,
      animated: true,
      style: { stroke: "#f5a623", strokeWidth: 1.5 },
      label: "requesting",
      labelStyle: { fontSize: 9, fill: "#f5a623" },
      labelBgStyle: { fill: "#0d0d0d", fillOpacity: 0.85 },
    });
  });

  return { nodes, edges };
}

export default function SessionGraph({ snapshot, sessionId, sessionName }: Props) {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  useEffect(() => {
    const { nodes: n, edges: e } = buildGraph(snapshot, sessionId, sessionName);
    setNodes(n);
    setEdges(e);
  }, [snapshot, sessionId, sessionName]);

  return (
    <div className="flex-1" style={{ background: "#0d0d0d" }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        fitView
        fitViewOptions={{ padding: 0.25 }}
        proOptions={{ hideAttribution: true }}
        style={{ background: "#0d0d0d" }}
      >
        <Background
          color="#1e1e1e"
          gap={24}
          variant={BackgroundVariant.Dots}
        />
        <Controls
          style={{
            background: "#141414",
            border: "1px solid #2e2e2e",
            borderRadius: 8,
          }}
        />
      </ReactFlow>
    </div>
  );
}
