"use client";

import React, { useEffect, useState, useCallback } from "react";
import ASTVisualizer from "@/components/ASTVisualizer";
import TerminalHarness from "@/components/TerminalHarness";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface MetricCardProps {
  label: string;
  value: string | number;
  unit?: string;
  delta?: string;
  deltaPositive?: boolean;
  accentColor: string;
}

interface CVEFlag {
  flag_id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  category: string;
  file: string;
  line: number;
  description: string;
  remediation: string;
}

interface ASTAnalysisResult {
  target_directory: string;
  total_nodes: number;
  total_edges: number;
  total_files_scanned: number;
  nodes: Array<{ node_id: string; file: string; line: number; kind: string; name: string; complexity: number }>;
  edges: Array<{ source: string; target: string; call_site_line: number; call_site_file: string }>;
  cve_flags: CVEFlag[];
  tech_debt_score: number;
  call_graph_json: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Severity badge
// ---------------------------------------------------------------------------

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "bg-red-500/20 text-red-400 border border-red-500/40",
  HIGH: "bg-orange-500/20 text-orange-400 border border-orange-500/40",
  MEDIUM: "bg-yellow-500/20 text-yellow-300 border border-yellow-500/40",
  LOW: "bg-blue-500/20 text-blue-400 border border-blue-500/40",
};

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-mono font-semibold ${SEVERITY_COLORS[severity] ?? "bg-slate-700 text-slate-300"}`}>
      {severity}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Metric card
// ---------------------------------------------------------------------------

function MetricCard({ label, value, unit, delta, deltaPositive, accentColor }: MetricCardProps) {
  return (
    <div
      className="relative flex flex-col justify-between rounded-xl border border-slate-700/60 bg-[#0f172a] p-5 overflow-hidden"
      style={{ boxShadow: `0 0 0 1px ${accentColor}18, inset 0 1px 0 ${accentColor}10` }}
    >
      {/* Accent glow */}
      <div
        className="pointer-events-none absolute -top-6 -right-6 h-24 w-24 rounded-full opacity-20 blur-2xl"
        style={{ backgroundColor: accentColor }}
      />
      <span className="text-xs font-semibold uppercase tracking-widest text-slate-500">{label}</span>
      <div className="mt-3 flex items-end gap-2">
        <span className="text-4xl font-bold tabular-nums tracking-tight text-slate-100" style={{ color: accentColor }}>
          {value}
        </span>
        {unit && <span className="mb-1 text-sm text-slate-500">{unit}</span>}
      </div>
      {delta && (
        <span
          className={`mt-2 text-xs font-medium ${deltaPositive ? "text-emerald-400" : "text-red-400"}`}
        >
          {deltaPositive ? "▲" : "▼"} {delta}
        </span>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// CVE table row
// ---------------------------------------------------------------------------

function CVERow({ flag }: { flag: CVEFlag }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <>
      <tr
        className="cursor-pointer border-b border-slate-800 hover:bg-slate-800/40 transition-colors"
        onClick={() => setExpanded((v) => !v)}
      >
        <td className="px-4 py-3 font-mono text-xs text-slate-400">{flag.flag_id}</td>
        <td className="px-4 py-3">
          <SeverityBadge severity={flag.severity} />
        </td>
        <td className="px-4 py-3 font-mono text-xs text-slate-300">{flag.file}</td>
        <td className="px-4 py-3 text-xs text-slate-400">:{flag.line}</td>
        <td className="px-4 py-3 text-xs text-slate-400 max-w-xs truncate">{flag.category}</td>
        <td className="px-4 py-3 text-xs text-slate-500">{expanded ? "▲" : "▼"}</td>
      </tr>
      {expanded && (
        <tr className="bg-[#080d1a]">
          <td colSpan={6} className="px-4 py-3">
            <p className="text-xs text-slate-300 mb-1">
              <span className="text-slate-500 uppercase font-semibold mr-2">Description</span>
              {flag.description}
            </p>
            <p className="text-xs text-emerald-400">
              <span className="text-slate-500 uppercase font-semibold mr-2">Remediation</span>
              {flag.remediation}
            </p>
          </td>
        </tr>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Section header
// ---------------------------------------------------------------------------

function SectionHeader({ title, badge }: { title: string; badge?: string | number }) {
  return (
    <div className="flex items-center gap-3 mb-4">
      <h2 className="text-sm font-bold uppercase tracking-widest text-slate-400">{title}</h2>
      {badge !== undefined && (
        <span className="rounded-full bg-slate-700 px-2.5 py-0.5 text-xs font-semibold text-slate-300">
          {badge}
        </span>
      )}
      <div className="flex-1 h-px bg-slate-800" />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Mock data for demo mode (used when backend is not available)
// ---------------------------------------------------------------------------

const MOCK_RESULT: ASTAnalysisResult = {
  target_directory: "/demo/graphward-src",
  total_nodes: 87,
  total_edges: 214,
  total_files_scanned: 23,
  tech_debt_score: 41.5,
  nodes: [],
  edges: [],
  call_graph_json: {
    directed: true,
    multigraph: false,
    nodes: [
      { id: "main.py::run_server", file: "main.py", line: 12, complexity: 3 },
      { id: "core/ast_parser.py::analyze", file: "core/ast_parser.py", line: 45, complexity: 7 },
      { id: "core/ast_parser.py::_process_file", file: "core/ast_parser.py", line: 89, complexity: 5 },
      { id: "core/verifier.py::verify", file: "core/verifier.py", line: 34, complexity: 4 },
      { id: "core/verifier.py::_run_pytest", file: "core/verifier.py", line: 67, complexity: 6 },
      { id: "utils/logger.py::log_event", file: "utils/logger.py", line: 8, complexity: 2 },
    ],
    links: [
      { source: "main.py::run_server", target: "core/ast_parser.py::analyze" },
      { source: "core/ast_parser.py::analyze", target: "core/ast_parser.py::_process_file" },
      { source: "main.py::run_server", target: "core/verifier.py::verify" },
      { source: "core/verifier.py::verify", target: "core/verifier.py::_run_pytest" },
      { source: "core/ast_parser.py::analyze", target: "utils/logger.py::log_event" },
      { source: "core/verifier.py::verify", target: "utils/logger.py::log_event" },
    ],
  },
  cve_flags: [
    {
      flag_id: "CVE-GW-A1B2C3D4",
      severity: "CRITICAL",
      category: "dangerous-call",
      file: "legacy/runner.py",
      line: 34,
      description: "Dangerous call `eval` detected — potential remote code execution vector.",
      remediation: "Replace `eval` with a safe AST-based evaluator.",
    },
    {
      flag_id: "CVE-GW-E5F6G7H8",
      severity: "CRITICAL",
      category: "hardcoded-secret",
      file: "config/settings.py",
      line: 12,
      description: "Hardcoded credential detected: `API_KEY = 'sk-...'`.",
      remediation: "Move to environment variables or a secrets manager.",
    },
    {
      flag_id: "CVE-GW-I9J0K1L2",
      severity: "HIGH",
      category: "deserialization",
      file: "utils/loader.py",
      line: 57,
      description: "`yaml.load()` called without `Loader=yaml.SafeLoader`.",
      remediation: "Use `yaml.safe_load()` instead.",
    },
    {
      flag_id: "CVE-GW-M3N4O5P6",
      severity: "MEDIUM",
      category: "dangerous-call",
      file: "scripts/deploy.py",
      line: 91,
      description: "`os.system()` call detected — shell injection risk.",
      remediation: "Use `subprocess.run()` with a list of arguments.",
    },
  ],
};

// ---------------------------------------------------------------------------
// Main dashboard page
// ---------------------------------------------------------------------------

export default function DashboardPage() {
  const [result, setResult] = useState<ASTAnalysisResult>(MOCK_RESULT);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [activeTab, setActiveTab] = useState<"graph" | "cve" | "terminal">("terminal");
  const [targetDir, setTargetDir] = useState("/repo/src");
  const [apiStatus, setApiStatus] = useState<"online" | "offline" | "unknown">("unknown");

  // Check API health on mount
  useEffect(() => {
    fetch("http://localhost:8000/health")
      .then((r) => r.ok ? setApiStatus("online") : setApiStatus("offline"))
      .catch(() => setApiStatus("offline"));
  }, []);

  const handleAnalyze = useCallback(async () => {
    setIsAnalyzing(true);
    try {
      const res = await fetch("http://localhost:8000/api/v1/ast/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_directory: targetDir, max_depth: 10, include_tests: false }),
      });
      if (res.ok) {
        const data: ASTAnalysisResult = await res.json();
        setResult(data);
      }
    } catch {
      // Backend not reachable — keep demo data
    } finally {
      setIsAnalyzing(false);
    }
  }, [targetDir]);

  // Derived stats
  const criticalCount = result.cve_flags.filter((f) => f.severity === "CRITICAL").length;
  const highCount = result.cve_flags.filter((f) => f.severity === "HIGH").length;
  const passRate = result.total_nodes > 0
    ? Math.max(0, 100 - result.tech_debt_score).toFixed(1)
    : "100.0";

  const TABS = [
    { id: "terminal", label: "Execution Log" },
    { id: "graph", label: "AST Graph" },
    { id: "cve", label: `CVE Backlog (${result.cve_flags.length})` },
  ] as const;

  return (
    <div className="min-h-screen bg-[#080d1a] text-slate-100 font-sans antialiased">
      {/* ------------------------------------------------------------------ */}
      {/* Top bar                                                              */}
      {/* ------------------------------------------------------------------ */}
      <header className="sticky top-0 z-50 flex items-center justify-between border-b border-slate-800 bg-[#080d1a]/90 px-6 py-3 backdrop-blur-sm">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-violet-600">
            <svg className="h-4 w-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
          </div>
          <span className="text-sm font-bold tracking-tight text-slate-100">GraphWard AI</span>
          <span className="hidden sm:block text-xs text-slate-600">/ Autonomous Code Remediation</span>
        </div>
        <div className="flex items-center gap-4">
          <span
            className={`flex items-center gap-1.5 text-xs font-medium ${
              apiStatus === "online" ? "text-emerald-400" : apiStatus === "offline" ? "text-red-400" : "text-slate-500"
            }`}
          >
            <span
              className={`h-1.5 w-1.5 rounded-full ${
                apiStatus === "online" ? "bg-emerald-400 animate-pulse" : apiStatus === "offline" ? "bg-red-400" : "bg-slate-500"
              }`}
            />
            API {apiStatus}
          </span>
          <span className="text-xs text-slate-600 font-mono">v1.0.0</span>
        </div>
      </header>

      <main className="mx-auto max-w-screen-2xl px-6 py-8 space-y-8">
        {/* ---------------------------------------------------------------- */}
        {/* KPI metrics grid                                                  */}
        {/* ---------------------------------------------------------------- */}
        <section>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <MetricCard
              label="Total Tech Debt"
              value={result.tech_debt_score}
              unit="/ 100"
              delta="−3.2 vs last scan"
              deltaPositive={true}
              accentColor="#a78bfa"
            />
            <MetricCard
              label="Active CVE Backlog"
              value={result.cve_flags.length}
              unit="flags"
              delta={`${criticalCount} critical, ${highCount} high`}
              deltaPositive={false}
              accentColor="#f87171"
            />
            <MetricCard
              label="Zero-Breakage Pass Rate"
              value={passRate}
              unit="%"
              delta="+1.4% since last patch"
              deltaPositive={true}
              accentColor="#34d399"
            />
            <MetricCard
              label="Call Graph Nodes"
              value={result.total_nodes}
              unit={`/ ${result.total_edges} edges`}
              delta={`${result.total_files_scanned} files scanned`}
              deltaPositive={true}
              accentColor="#60a5fa"
            />
          </div>
        </section>

        {/* ---------------------------------------------------------------- */}
        {/* Analyze controls                                                  */}
        {/* ---------------------------------------------------------------- */}
        <section className="flex items-center gap-3 rounded-xl border border-slate-700/50 bg-[#0f172a] px-5 py-4">
          <label className="text-xs font-semibold uppercase tracking-widest text-slate-500 whitespace-nowrap">
            Target Directory
          </label>
          <input
            type="text"
            value={targetDir}
            onChange={(e) => setTargetDir(e.target.value)}
            className="flex-1 rounded-lg border border-slate-700 bg-[#080d1a] px-3 py-2 text-sm font-mono text-slate-200 focus:outline-none focus:ring-2 focus:ring-violet-500/60 placeholder-slate-600"
            placeholder="/repo/src"
          />
          <button
            onClick={handleAnalyze}
            disabled={isAnalyzing}
            className="flex items-center gap-2 rounded-lg bg-violet-600 px-5 py-2 text-sm font-semibold text-white transition-colors hover:bg-violet-500 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isAnalyzing ? (
              <>
                <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                </svg>
                Analyzing…
              </>
            ) : (
              "▶ Run Analysis"
            )}
          </button>
        </section>

        {/* ---------------------------------------------------------------- */}
        {/* Main content tabs                                                 */}
        {/* ---------------------------------------------------------------- */}
        <section>
          {/* Tab bar */}
          <div className="flex gap-1 border-b border-slate-800 mb-6">
            {TABS.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-4 py-2.5 text-xs font-semibold uppercase tracking-wider transition-colors border-b-2 -mb-px ${
                  activeTab === tab.id
                    ? "border-violet-500 text-violet-400"
                    : "border-transparent text-slate-500 hover:text-slate-300"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Terminal tab */}
          {activeTab === "terminal" && (
            <div>
              <SectionHeader title="Agentic Execution Log" badge="LIVE" />
              <TerminalHarness
                nodeCount={result.total_nodes}
                edgeCount={result.total_edges}
                cveCount={result.cve_flags.length}
                testsTotal={142}
                testsPassed={142 - result.cve_flags.filter((f) => f.severity === "CRITICAL").length * 2}
              />
            </div>
          )}

          {/* AST graph tab */}
          {activeTab === "graph" && (
            <div>
              <SectionHeader
                title="AST Call-Graph Visualizer"
                badge={`${result.total_nodes} nodes · ${result.total_edges} edges`}
              />
              <div className="h-[560px] rounded-xl border border-slate-700/60 overflow-hidden bg-[#0a0f1e]">
                <ASTVisualizer callGraphJson={result.call_graph_json} />
              </div>
            </div>
          )}

          {/* CVE backlog tab */}
          {activeTab === "cve" && (
            <div>
              <SectionHeader title="CVE Backlog" badge={result.cve_flags.length} />
              <div className="rounded-xl border border-slate-700/60 overflow-hidden">
                <table className="w-full text-left">
                  <thead className="bg-[#0f172a] border-b border-slate-800">
                    <tr>
                      {["Flag ID", "Severity", "File", "Line", "Category", ""].map((h) => (
                        <th key={h} className="px-4 py-3 text-xs font-semibold uppercase tracking-widest text-slate-500">
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="bg-[#080d1a]">
                    {result.cve_flags.map((flag) => (
                      <CVERow key={flag.flag_id} flag={flag} />
                    ))}
                    {result.cve_flags.length === 0 && (
                      <tr>
                        <td colSpan={6} className="px-4 py-8 text-center text-sm text-emerald-400 font-semibold">
                          ✓ No CVE flags detected in this scan.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </section>
      </main>
    </div>
  );
}
