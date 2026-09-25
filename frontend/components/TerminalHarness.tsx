"use client";

import React, { useEffect, useRef, useState, useCallback } from "react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type LogLevel = "INFO" | "SUCCESS" | "WARN" | "ERROR" | "STEP" | "SYSTEM";

interface LogEntry {
  id: number;
  timestamp: string;
  level: LogLevel;
  message: string;
}

interface TerminalHarnessProps {
  nodeCount?: number;
  edgeCount?: number;
  cveCount?: number;
  testsTotal?: number;
  testsPassed?: number;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function ts(): string {
  return new Date().toISOString().replace("T", " ").slice(0, -1);
}

const LEVEL_STYLES: Record<LogLevel, string> = {
  STEP:    "text-violet-400  font-bold",
  SUCCESS: "text-emerald-400 font-semibold",
  ERROR:   "text-red-400     font-semibold",
  WARN:    "text-yellow-400",
  INFO:    "text-slate-400",
  SYSTEM:  "text-sky-400     font-mono",
};

const LEVEL_BADGE: Record<LogLevel, string> = {
  STEP:    "bg-violet-500/20  text-violet-300  border-violet-500/30",
  SUCCESS: "bg-emerald-500/20 text-emerald-300 border-emerald-500/30",
  ERROR:   "bg-red-500/20     text-red-300     border-red-500/30",
  WARN:    "bg-yellow-500/20  text-yellow-300  border-yellow-500/30",
  INFO:    "bg-slate-700/50   text-slate-400   border-slate-700",
  SYSTEM:  "bg-sky-500/20     text-sky-300     border-sky-500/30",
};

// ---------------------------------------------------------------------------
// Sequence generator
// ---------------------------------------------------------------------------

function buildSequence(
  nodeCount: number,
  edgeCount: number,
  cveCount: number,
  testsTotal: number,
  testsPassed: number
): Array<{ level: LogLevel; message: string; delayMs: number }> {
  type Entry = { level: LogLevel; message: string; delayMs: number };
  const testsFailed = testsTotal - testsPassed;

  return [
    { level: "SYSTEM", message: "GraphWard Autonomous Remediation Engine v1.0.0", delayMs: 0 },
    { level: "SYSTEM", message: "Session ID: GW-" + Math.random().toString(36).slice(2, 10).toUpperCase(), delayMs: 300 },
    { level: "STEP",   message: "[STEP 1/7] Ingesting repository…", delayMs: 600 },
    { level: "INFO",   message: "  Scanning Python source tree with max_depth=10", delayMs: 900 },
    { level: "INFO",   message: `  → Discovered ${Math.ceil(nodeCount / 4)} files, ${nodeCount} symbols`, delayMs: 1200 },
    { level: "SUCCESS",message: `  ✓ Repository ingested (${nodeCount} nodes)`, delayMs: 1500 },

    { level: "STEP",   message: "[STEP 2/7] Building AST call graph…", delayMs: 2000 },
    { level: "INFO",   message: "  Initialising NetworkX DiGraph", delayMs: 2300 },
    { level: "INFO",   message: `  Parsing function definitions and call sites…`, delayMs: 2600 },
    { level: "INFO",   message: `  Computing McCabe cyclomatic complexity…`, delayMs: 2900 },
    { level: "SUCCESS",message: `  ✓ Call graph built — ${nodeCount} nodes, ${edgeCount} directed edges`, delayMs: 3200 },

    { level: "STEP",   message: "[STEP 3/7] Running CVE anti-pattern detection…", delayMs: 3800 },
    { level: "INFO",   message: "  Checking 18 dangerous-call patterns…", delayMs: 4100 },
    { level: "INFO",   message: "  Scanning for hardcoded secrets (regex × 3 patterns)…", delayMs: 4400 },
    ...(cveCount > 0
      ? [
          { level: "WARN" as LogLevel,  message: `  ⚠ ${cveCount} CVE flag(s) raised — review required`, delayMs: 4700 },
          { level: "WARN" as LogLevel,  message: `  ⚠ Highest severity: CRITICAL — immediate remediation advised`, delayMs: 5000 },
        ]
      : [
          { level: "SUCCESS" as LogLevel, message: "  ✓ No CVE anti-patterns detected", delayMs: 4700 },
        ]),

    { level: "STEP",   message: "[STEP 4/7] Generating remediation patch diff…", delayMs: 5600 },
    { level: "INFO",   message: "  Invoking LLM-guided patch synthesis…", delayMs: 5900 },
    { level: "INFO",   message: "  Validating AST structural integrity post-patch…", delayMs: 6200 },
    { level: "SUCCESS",message: "  ✓ Patch diff generated (unified format, p1)", delayMs: 6500 },

    { level: "STEP",   message: "[STEP 5/7] Applying patch to sandbox…", delayMs: 7100 },
    { level: "INFO",   message: "  Copying working tree to /tmp/graphward-sandbox-XXXXXX…", delayMs: 7400 },
    { level: "INFO",   message: "  Executing: patch --batch --forward -p1 -i remediation.patch", delayMs: 7700 },
    { level: "SUCCESS",message: "  ✓ Patch applied cleanly — 0 rejects", delayMs: 8000 },

    { level: "STEP",   message: "[STEP 6/7] Executing pytest regression suite…", delayMs: 8600 },
    { level: "INFO",   message: `  Command: python -m pytest tests/ --tb=long -q --color=no`, delayMs: 8900 },
    { level: "INFO",   message: `  Collecting ${testsTotal} test items…`, delayMs: 9200 },
    { level: "INFO",   message: "  Running…", delayMs: 9500 },
    ...Array.from({ length: Math.min(6, Math.ceil(testsTotal / 25)) }, (_, i) => ({
      level: "INFO" as LogLevel,
      message: `  [${".".repeat(i + 1).padEnd(6, " ")}] ${Math.min((i + 1) * 25, testsTotal)} / ${testsTotal} tests`,
      delayMs: 9800 + i * 400,
    })),
    ...(testsFailed === 0
      ? [{ level: "SUCCESS" as LogLevel, message: `  ✓ ${testsTotal}/${testsTotal} tests passed — zero regressions`, delayMs: 12200 }]
      : [{ level: "ERROR" as LogLevel,   message: `  ✗ ${testsFailed} test(s) FAILED — regression detected`, delayMs: 12200 }]),

    { level: "STEP",   message: "[STEP 7/7] Generating remediation report…", delayMs: 13000 },
    { level: "INFO",   message: "  Serialising ASTAnalysisResult to JSON…", delayMs: 13300 },
    { level: "INFO",   message: "  Writing structured regression log…", delayMs: 13600 },
    {
      level: (testsFailed === 0 ? "SUCCESS" : "WARN") as LogLevel,
      message: testsFailed === 0
        ? `[SUCCESS] Remediation complete — ${testsTotal}/${testsTotal} tests passed ✓`
        : `[PARTIAL] Remediation requires manual review — ${testsFailed} regressions`,
      delayMs: 14000,
    } satisfies Entry,
    { level: "SYSTEM", message: "─────────────────────────────────────────────", delayMs: 14300 },
    { level: "SYSTEM", message: `Elapsed: ${(14.3 + Math.random() * 2).toFixed(2)}s`, delayMs: 14600 },
    { level: "SYSTEM", message: "Session closed.", delayMs: 14900 },
  ];
}

// ---------------------------------------------------------------------------
// TerminalHarness component
// ---------------------------------------------------------------------------

export default function TerminalHarness({
  nodeCount = 87,
  edgeCount = 214,
  cveCount = 4,
  testsTotal = 142,
  testsPassed = 138,
}: TerminalHarnessProps) {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [running, setRunning] = useState(false);
  const [completed, setCompleted] = useState(false);
  const [cursor, setCursor] = useState(true);
  const bottomRef = useRef<HTMLDivElement>(null);
  const timeoutsRef = useRef<ReturnType<typeof setTimeout>[]>([]);
  const runIdRef = useRef(0);

  // Blinking cursor
  useEffect(() => {
    const id = setInterval(() => setCursor((v) => !v), 530);
    return () => clearInterval(id);
  }, []);

  // Auto-scroll
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  const clearTimeouts = useCallback(() => {
    for (const t of timeoutsRef.current) clearTimeout(t);
    timeoutsRef.current = [];
  }, []);

  const runSequence = useCallback(() => {
    clearTimeouts();
    runIdRef.current += 1;
    const runId = runIdRef.current;
    setLogs([]);
    setCompleted(false);
    setRunning(true);

    const sequence = buildSequence(nodeCount, edgeCount, cveCount, testsTotal, testsPassed);

    sequence.forEach((entry, index) => {
      const id = setTimeout(() => {
        setLogs((prev) => [
          ...prev,
          {
            id: runId * 1000 + index,
            timestamp: ts(),
            level: entry.level,
            message: entry.message,
          },
        ]);
      }, entry.delayMs);
      timeoutsRef.current.push(id);
    });

    const finalDelay = Math.max(...sequence.map((e) => e.delayMs)) + 200;
    const doneId = setTimeout(() => {
      setRunning(false);
      setCompleted(true);
    }, finalDelay);
    timeoutsRef.current.push(doneId);
  }, [nodeCount, edgeCount, cveCount, testsTotal, testsPassed, clearTimeouts]);

  // Auto-run on mount and when props change
  useEffect(() => {
    runSequence();
    return clearTimeouts;
  }, [runSequence, clearTimeouts]);

  const handleRerun = () => {
    runSequence();
  };

  const testsFailed = testsTotal - testsPassed;

  return (
    <div className="flex flex-col rounded-xl border border-slate-700/60 overflow-hidden bg-[#080d1a]">
      {/* Terminal title bar */}
      <div className="flex items-center justify-between border-b border-slate-800 bg-[#0f172a] px-4 py-2.5">
        <div className="flex items-center gap-2">
          <div className="flex gap-1.5">
            <span className="h-3 w-3 rounded-full bg-red-500/70" />
            <span className="h-3 w-3 rounded-full bg-yellow-500/70" />
            <span className="h-3 w-3 rounded-full bg-emerald-500/70" />
          </div>
          <span className="ml-2 text-xs font-mono text-slate-500">
            graphward-agent — bash
          </span>
        </div>
        <div className="flex items-center gap-3">
          {running && (
            <span className="flex items-center gap-1.5 text-xs text-violet-400 font-medium">
              <span className="h-1.5 w-1.5 rounded-full bg-violet-400 animate-pulse" />
              Running
            </span>
          )}
          {completed && (
            <span className={`text-xs font-semibold ${testsFailed === 0 ? "text-emerald-400" : "text-yellow-400"}`}>
              {testsFailed === 0 ? "✓ Passed" : `⚠ ${testsFailed} failed`}
            </span>
          )}
          <button
            onClick={handleRerun}
            disabled={running}
            className="rounded px-2.5 py-1 text-xs font-semibold border border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-500 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            ↺ Rerun
          </button>
        </div>
      </div>

      {/* Log output area */}
      <div className="h-[420px] overflow-y-auto px-4 py-3 font-mono text-xs leading-relaxed scrollbar-thin scrollbar-thumb-slate-700 scrollbar-track-transparent">
        {logs.map((entry) => (
          <div key={entry.id} className="flex items-start gap-3 mb-0.5">
            <span className="shrink-0 text-slate-700 text-[10px] pt-px tabular-nums">
              {entry.timestamp.slice(11, 23)}
            </span>
            <span
              className={`shrink-0 rounded border px-1.5 py-px text-[9px] font-bold uppercase ${LEVEL_BADGE[entry.level]}`}
            >
              {entry.level}
            </span>
            <span className={`${LEVEL_STYLES[entry.level]} break-all`}>
              {entry.message}
            </span>
          </div>
        ))}

        {/* Blinking cursor at bottom */}
        {running && (
          <div className="flex items-center gap-3 mt-1">
            <span className="text-slate-700 text-[10px] tabular-nums">{ts().slice(11, 23)}</span>
            <span className="text-slate-500">
              {cursor ? "█" : " "}
            </span>
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      {/* Status bar */}
      <div className="flex items-center justify-between border-t border-slate-800 bg-[#0f172a] px-4 py-2">
        <div className="flex items-center gap-4">
          <span className="text-[10px] text-slate-600 font-mono">
            {logs.length} lines
          </span>
          <span className="text-[10px] text-slate-600 font-mono">
            {nodeCount} nodes · {cveCount} CVE flags
          </span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-[10px] text-slate-600 font-mono">
            {testsPassed}/{testsTotal} tests
          </span>
          <span
            className={`h-1.5 w-1.5 rounded-full ${
              completed
                ? testsFailed === 0
                  ? "bg-emerald-400"
                  : "bg-yellow-400"
                : running
                ? "bg-violet-400 animate-pulse"
                : "bg-slate-600"
            }`}
          />
        </div>
      </div>
    </div>
  );
}
