"use client";

import React, { useCallback, useEffect, useMemo } from "react";
import ReactFlow, {
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  addEdge,
  useEdgesState,
  useNodesState,
  type Connection,
  type Edge,
  type Node,
  type NodeTypes,
  MarkerType,
  Position,
  Handle,
} from "reactflow";
import "reactflow/dist/style.css";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface RawNode {
  id: string;
  file?: string;
  line?: number;
  complexity?: number;
  [key: string]: unknown;
}

interface RawLink {
  source: string;
  target: string;
  [key: string]: unknown;
}

interface CallGraphJson {
  nodes?: RawNode[];
  links?: RawLink[];
  [key: string]: unknown;
}

interface ASTVisualizerProps {
  callGraphJson: CallGraphJson;
}

// ---------------------------------------------------------------------------
// Complexity → colour mapping
// ---------------------------------------------------------------------------

function complexityColor(complexity: number): string {
  if (complexity <= 2) return "#34d399"; // emerald — simple
  if (complexity <= 5) return "#60a5fa"; // blue — moderate
  if (complexity <= 8) return "#f59e0b"; // amber — complex
  return "#f87171";                       // red — very complex
}

// ---------------------------------------------------------------------------
// Custom AST node component
// ---------------------------------------------------------------------------

interface ASTNodeData {
  label: string;
  file: string;
  line: number;
  complexity: number;
}

function ASTNode({ data, selected }: { data: ASTNodeData; selected: boolean }) {
  const color = complexityColor(data.complexity);
  return (
    <div
      className="rounded-lg border px-3 py-2 text-left min-w-[160px] max-w-[240px] backdrop-blur-sm transition-shadow"
      style={{
        backgroundColor: "#0f172a",
        borderColor: selected ? color : `${color}55`,
        boxShadow: selected ? `0 0 0 2px ${color}` : `0 0 12px ${color}22`,
      }}
    >
      <Handle
        type="target"
        position={Position.Top}
        style={{ background: color, width: 8, height: 8 }}
      />
      <p className="text-xs font-bold truncate" style={{ color }}>
        {data.label}
      </p>
      <p className="mt-0.5 text-[10px] text-slate-500 truncate font-mono">
        {data.file}:{data.line}
      </p>
      <div className="mt-1.5 flex items-center gap-1">
        <span className="text-[9px] uppercase font-semibold text-slate-600">Complexity</span>
        <span
          className="text-[10px] font-bold tabular-nums px-1 rounded"
          style={{ backgroundColor: `${color}22`, color }}
        >
          {data.complexity}
        </span>
      </div>
      <Handle
        type="source"
        position={Position.Bottom}
        style={{ background: color, width: 8, height: 8 }}
      />
    </div>
  );
}

const NODE_TYPES: NodeTypes = { astNode: ASTNode };

// ---------------------------------------------------------------------------
// Layout — simple top-down layered positioning
// ---------------------------------------------------------------------------

function computeLayout(
  rawNodes: RawNode[],
  rawLinks: RawLink[]
): { nodes: Node[]; edges: Edge[] } {
  // Build adjacency for BFS-based level assignment
  const inDegree: Map<string, number> = new Map();
  const adjList: Map<string, string[]> = new Map();

  for (const n of rawNodes) {
    inDegree.set(n.id, 0);
    adjList.set(n.id, []);
  }
  for (const link of rawLinks) {
    inDegree.set(link.target, (inDegree.get(link.target) ?? 0) + 1);
    adjList.get(link.source)?.push(link.target);
  }

  // BFS level assignment
  const levels: Map<string, number> = new Map();
  const queue: string[] = [];
  for (const [id, deg] of Array.from(inDegree.entries())) {
    if (deg === 0) queue.push(id);
  }
  while (queue.length > 0) {
    const id = queue.shift()!;
    const lvl = levels.get(id) ?? 0;
    for (const child of adjList.get(id) ?? []) {
      const childLvl = Math.max(levels.get(child) ?? 0, lvl + 1);
      levels.set(child, childLvl);
      queue.push(child);
    }
  }

  // Group by level for x-positioning
  const levelGroups: Map<number, string[]> = new Map();
  for (const n of rawNodes) {
    const lvl = levels.get(n.id) ?? 0;
    if (!levelGroups.has(lvl)) levelGroups.set(lvl, []);
    levelGroups.get(lvl)!.push(n.id);
  }

  const X_GAP = 220;
  const Y_GAP = 120;
  const nodePositions: Map<string, { x: number; y: number }> = new Map();

  for (const [level, ids] of Array.from(levelGroups.entries())) {
    const totalWidth = (ids.length - 1) * X_GAP;
    ids.forEach((id: string, i: number) => {
      nodePositions.set(id, {
        x: -totalWidth / 2 + i * X_GAP,
        y: level * Y_GAP,
      });
    });
  }

  const nodes: Node[] = rawNodes.map((n) => ({
    id: n.id,
    type: "astNode",
    position: nodePositions.get(n.id) ?? { x: 0, y: 0 },
    data: {
      label: n.id.split("::").pop() ?? n.id,
      file: (n.file as string) ?? "<unknown>",
      line: (n.line as number) ?? 0,
      complexity: (n.complexity as number) ?? 1,
    },
  }));

  const edges: Edge[] = rawLinks.map((link, i) => ({
    id: `e-${i}`,
    source: link.source,
    target: link.target,
    animated: true,
    style: { stroke: "#475569", strokeWidth: 1.5 },
    markerEnd: { type: MarkerType.ArrowClosed, color: "#475569" },
  }));

  return { nodes, edges };
}

// ---------------------------------------------------------------------------
// ASTVisualizer component
// ---------------------------------------------------------------------------

export default function ASTVisualizer({ callGraphJson }: ASTVisualizerProps) {
  const rawNodes: RawNode[] = (callGraphJson?.nodes as RawNode[]) ?? [];
  const rawLinks: RawLink[] = (callGraphJson?.links as RawLink[]) ?? [];

  const { nodes: initNodes, edges: initEdges } = useMemo(
    () => computeLayout(rawNodes, rawLinks),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [JSON.stringify(rawNodes), JSON.stringify(rawLinks)]
  );

  const [nodes, setNodes, onNodesChange] = useNodesState(initNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initEdges);

  useEffect(() => {
    setNodes(initNodes);
    setEdges(initEdges);
  }, [initNodes, initEdges, setNodes, setEdges]);

  const onConnect = useCallback(
    (params: Connection) => setEdges((eds) => addEdge(params, eds)),
    [setEdges]
  );

  if (rawNodes.length === 0) {
    return (
      <div className="flex h-full items-center justify-center">
        <p className="text-sm text-slate-600 font-mono">No graph data. Run an analysis first.</p>
      </div>
    );
  }

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      onConnect={onConnect}
      nodeTypes={NODE_TYPES}
      fitView
      fitViewOptions={{ padding: 0.25 }}
      attributionPosition="bottom-right"
      style={{ background: "#0a0f1e" }}
    >
      <Background
        variant={BackgroundVariant.Dots}
        color="#1e293b"
        gap={20}
        size={1}
      />
      <Controls
        style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8 }}
        showInteractive={false}
      />
      <MiniMap
        style={{ background: "#080d1a", border: "1px solid #1e293b" }}
        nodeColor={(n) => complexityColor((n.data as ASTNodeData).complexity)}
        maskColor="#080d1a99"
      />
    </ReactFlow>
  );
}
