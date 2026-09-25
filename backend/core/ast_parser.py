"""
GraphWard AI — AST Parser & Call-Graph Builder
Parses a Python source directory, builds a NetworkX call graph, and flags CVE anti-patterns.
"""

from __future__ import annotations

import ast
import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import networkx as nx
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# CVE Anti-Pattern Registry
# ---------------------------------------------------------------------------

# Each entry: (pattern_id, human label, AST check type, detail)
_DANGEROUS_CALLS: frozenset[str] = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "__import__",
        "execfile",
        "input",          # Python 2 style raw exec
        "subprocess.call",
        "subprocess.Popen",
        "os.system",
        "os.popen",
        "pickle.loads",
        "pickle.load",
        "marshal.loads",
        "yaml.load",      # without Loader=SafeLoader
        "jsonpickle.decode",
        "shelve.open",
    }
)

_HARDCODED_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'(?i)(password|passwd|secret|token|api_key|apikey|auth_token)\s*=\s*["\'][^"\']{4,}["\']'),
    re.compile(r'(?i)(aws_access_key_id|aws_secret_access_key)\s*=\s*["\'][A-Za-z0-9/+=]{16,}["\']'),
    re.compile(r'-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----'),
]

# ---------------------------------------------------------------------------
# Pydantic output models (also used as FastAPI response_model)
# ---------------------------------------------------------------------------

class NodeDetail(BaseModel):
    node_id: str
    file: str
    line: int
    col: int
    kind: str  # "function" | "class" | "module"
    name: str
    complexity: int = Field(description="McCabe cyclomatic complexity estimate")


class EdgeDetail(BaseModel):
    source: str
    target: str
    call_site_line: int
    call_site_file: str


class CVEFlag(BaseModel):
    flag_id: str
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    category: str
    file: str
    line: int
    col: int
    description: str
    remediation: str


class ASTAnalysisResult(BaseModel):
    target_directory: str
    total_nodes: int
    total_edges: int
    total_files_scanned: int
    nodes: list[NodeDetail]
    edges: list[EdgeDetail]
    cve_flags: list[CVEFlag]
    tech_debt_score: float = Field(description="Composite debt score 0–100")
    call_graph_json: dict[str, Any] = Field(
        description="NetworkX node-link data for frontend rendering"
    )


# ---------------------------------------------------------------------------
# Internal dataclasses
# ---------------------------------------------------------------------------

@dataclass
class _FunctionRecord:
    qualified_name: str
    file: str
    line: int
    col: int
    complexity: int


@dataclass
class _CallRecord:
    caller: str
    callee: str
    line: int
    file: str


# ---------------------------------------------------------------------------
# Complexity visitor
# ---------------------------------------------------------------------------

class _ComplexityVisitor(ast.NodeVisitor):
    """Estimates McCabe cyclomatic complexity for a single function body."""

    _BRANCH_NODES = (
        ast.If, ast.For, ast.While, ast.ExceptHandler,
        ast.With, ast.Assert, ast.comprehension,
    )

    def __init__(self) -> None:
        self.complexity: int = 1

    def visit_If(self, node: ast.If) -> None:  # noqa: N802
        self.complexity += 1
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:  # noqa: N802
        self.complexity += 1
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:  # noqa: N802
        self.complexity += 1
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:  # noqa: N802
        self.complexity += 1
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:  # noqa: N802
        self.complexity += len(node.values) - 1
        self.generic_visit(node)

    def visit_comprehension(self, node: ast.comprehension) -> None:  # noqa: N802
        self.complexity += 1
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:  # noqa: N802
        self.complexity += 1
        self.generic_visit(node)


def _measure_complexity(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    v = _ComplexityVisitor()
    v.visit(func_node)
    return v.complexity


# ---------------------------------------------------------------------------
# Call-collector visitor
# ---------------------------------------------------------------------------

class _CallCollector(ast.NodeVisitor):
    """Collects all function/method calls within a scope."""

    def __init__(self, file: str) -> None:
        self._file = file
        self.calls: list[_CallRecord] = []
        self._current_scope: str = "<module>"

    def _scope_push(self, name: str) -> str:
        prev = self._current_scope
        self._current_scope = name
        return prev

    def _resolve_call_name(self, node: ast.Call) -> str:
        func = node.func
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                return f"{func.value.id}.{func.attr}"
            return func.attr
        if isinstance(func, ast.Name):
            return func.id
        return "<unknown>"

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        prev = self._scope_push(node.name)
        self.generic_visit(node)
        self._current_scope = prev

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        prev = self._scope_push(node.name)
        self.generic_visit(node)
        self._current_scope = prev

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        callee = self._resolve_call_name(node)
        self.calls.append(
            _CallRecord(
                caller=self._current_scope,
                callee=callee,
                line=node.lineno,
                file=self._file,
            )
        )
        self.generic_visit(node)


# ---------------------------------------------------------------------------
# CVE anti-pattern detection visitor
# ---------------------------------------------------------------------------

class _CVEVisitor(ast.NodeVisitor):
    """Detects dangerous call patterns and hardcoded secrets."""

    def __init__(self, file: str, source_lines: list[str]) -> None:
        self._file = file
        self._source_lines = source_lines
        self.flags: list[CVEFlag] = []

    def _make_id(self, category: str, line: int) -> str:
        raw = f"{self._file}:{line}:{category}"
        return "CVE-GW-" + hashlib.sha1(raw.encode()).hexdigest()[:8].upper()

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        func = node.func
        call_name = ""
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                call_name = f"{func.value.id}.{func.attr}"
            else:
                call_name = func.attr
        elif isinstance(func, ast.Name):
            call_name = func.id

        if call_name in _DANGEROUS_CALLS:
            severity = (
                "CRITICAL"
                if call_name in {"eval", "exec", "pickle.loads", "pickle.load", "marshal.loads"}
                else "HIGH"
            )
            self.flags.append(
                CVEFlag(
                    flag_id=self._make_id(call_name, node.lineno),
                    severity=severity,
                    category="dangerous-call",
                    file=self._file,
                    line=node.lineno,
                    col=node.col_offset,
                    description=f"Dangerous call `{call_name}` detected — potential remote code execution or data exfiltration vector.",
                    remediation=f"Replace `{call_name}` with a safe alternative. Audit all inputs before use.",
                )
            )

        # yaml.load without SafeLoader
        if call_name == "yaml.load":
            has_safe_loader = any(
                (isinstance(kw.value, ast.Attribute) and kw.value.attr == "SafeLoader")
                or (isinstance(kw.value, ast.Name) and kw.value.id == "SafeLoader")
                for kw in node.keywords
            )
            if not has_safe_loader and len(node.args) < 2:
                self.flags.append(
                    CVEFlag(
                        flag_id=self._make_id("yaml.load-unsafe", node.lineno),
                        severity="HIGH",
                        category="deserialization",
                        file=self._file,
                        line=node.lineno,
                        col=node.col_offset,
                        description="`yaml.load()` called without `Loader=yaml.SafeLoader` — arbitrary code execution risk.",
                        remediation="Use `yaml.safe_load()` or pass `Loader=yaml.SafeLoader`.",
                    )
                )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        # Detect hardcoded secrets in assignments
        if node.lineno <= len(self._source_lines):
            line_text = self._source_lines[node.lineno - 1]
            for pattern in _HARDCODED_SECRET_PATTERNS:
                if pattern.search(line_text):
                    self.flags.append(
                        CVEFlag(
                            flag_id=self._make_id("hardcoded-secret", node.lineno),
                            severity="CRITICAL",
                            category="hardcoded-secret",
                            file=self._file,
                            line=node.lineno,
                            col=node.col_offset,
                            description="Hardcoded credential or secret detected in source code.",
                            remediation="Move secrets to environment variables or a secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager).",
                        )
                    )
                    break
        self.generic_visit(node)


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

class ASTParser:
    """
    Walks a Python source directory, builds a NetworkX directed call graph,
    and aggregates CVE flags into an ASTAnalysisResult.
    """

    def __init__(self, max_depth: int = 10, include_tests: bool = False) -> None:
        self._max_depth = max_depth
        self._include_tests = include_tests

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def analyze(self, target_directory: str) -> ASTAnalysisResult:
        root = Path(target_directory).resolve()
        if not root.exists():
            raise FileNotFoundError(target_directory)

        graph = nx.DiGraph()
        all_cve_flags: list[CVEFlag] = []
        files_scanned = 0
        function_registry: dict[str, _FunctionRecord] = {}

        for py_file in self._iter_python_files(root):
            if not self._include_tests and self._is_test_file(py_file):
                continue
            try:
                records, calls, cve_flags = self._process_file(py_file, root)
                files_scanned += 1
                for rec in records:
                    function_registry[rec.qualified_name] = rec
                    graph.add_node(
                        rec.qualified_name,
                        file=rec.file,
                        line=rec.line,
                        col=rec.col,
                        complexity=rec.complexity,
                    )
                for call in calls:
                    if graph.has_node(call.caller) or graph.has_node(call.callee):
                        if not graph.has_node(call.caller):
                            graph.add_node(call.caller, file=call.file, line=0, col=0, complexity=1)
                        if not graph.has_node(call.callee):
                            graph.add_node(call.callee, file="<external>", line=0, col=0, complexity=0)
                        graph.add_edge(
                            call.caller,
                            call.callee,
                            line=call.line,
                            file=call.file,
                        )
                all_cve_flags.extend(cve_flags)
            except SyntaxError:
                # Unparseable files are skipped; the caller may log the skip
                continue

        # Prune graph to max_depth from entry points (nodes with in-degree 0)
        pruned = self._prune_to_depth(graph)

        nodes = self._build_node_details(pruned, function_registry)
        edges = self._build_edge_details(pruned)
        tech_debt = self._compute_tech_debt(nodes, all_cve_flags)

        return ASTAnalysisResult(
            target_directory=str(root),
            total_nodes=pruned.number_of_nodes(),
            total_edges=pruned.number_of_edges(),
            total_files_scanned=files_scanned,
            nodes=nodes,
            edges=edges,
            cve_flags=all_cve_flags,
            tech_debt_score=tech_debt,
            call_graph_json=nx.node_link_data(pruned),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _iter_python_files(self, root: Path):
        for dirpath, dirnames, filenames in os.walk(root):
            # Skip common non-source directories
            dirnames[:] = [
                d for d in dirnames
                if d not in {".git", "__pycache__", ".venv", "venv", "node_modules", ".mypy_cache"}
            ]
            for fname in filenames:
                if fname.endswith(".py"):
                    yield Path(dirpath) / fname

    @staticmethod
    def _is_test_file(path: Path) -> bool:
        return path.name.startswith("test_") or path.name.endswith("_test.py") or "tests" in path.parts

    def _process_file(
        self, path: Path, root: Path
    ) -> tuple[list[_FunctionRecord], list[_CallRecord], list[CVEFlag]]:
        source = path.read_text(encoding="utf-8", errors="replace")
        source_lines = source.splitlines()
        tree = ast.parse(source, filename=str(path))

        rel_path = str(path.relative_to(root))
        records: list[_FunctionRecord] = []

        # Collect function/class definitions
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                complexity = _measure_complexity(node)
                records.append(
                    _FunctionRecord(
                        qualified_name=f"{rel_path}::{node.name}",
                        file=rel_path,
                        line=node.lineno,
                        col=node.col_offset,
                        complexity=complexity,
                    )
                )

        # Collect call graph edges
        call_collector = _CallCollector(rel_path)
        call_collector.visit(tree)
        # Qualify caller names
        qualified_calls: list[_CallRecord] = []
        for call in call_collector.calls:
            caller_qname = f"{rel_path}::{call.caller}"
            qualified_calls.append(
                _CallRecord(
                    caller=caller_qname,
                    callee=call.callee,
                    line=call.line,
                    file=rel_path,
                )
            )

        # CVE detection
        cve_visitor = _CVEVisitor(rel_path, source_lines)
        cve_visitor.visit(tree)

        return records, qualified_calls, cve_visitor.flags

    def _prune_to_depth(self, graph: nx.DiGraph) -> nx.DiGraph:
        if graph.number_of_nodes() == 0:
            return graph
        entry_points = [n for n, d in graph.in_degree() if d == 0]
        if not entry_points:
            return graph
        reachable: set[str] = set()
        for ep in entry_points:
            for node in nx.dfs_preorder_nodes(graph, ep, depth_limit=self._max_depth):
                reachable.add(node)
        return graph.subgraph(reachable).copy()

    @staticmethod
    def _build_node_details(
        graph: nx.DiGraph,
        registry: dict[str, _FunctionRecord],
    ) -> list[NodeDetail]:
        details: list[NodeDetail] = []
        for node_id, data in graph.nodes(data=True):
            rec = registry.get(node_id)
            details.append(
                NodeDetail(
                    node_id=node_id,
                    file=data.get("file", "<unknown>"),
                    line=data.get("line", 0),
                    col=data.get("col", 0),
                    kind="function" if "::" in node_id else "module",
                    name=node_id.split("::")[-1],
                    complexity=data.get("complexity", 1),
                )
            )
        return details

    @staticmethod
    def _build_edge_details(graph: nx.DiGraph) -> list[EdgeDetail]:
        edges: list[EdgeDetail] = []
        for src, tgt, data in graph.edges(data=True):
            edges.append(
                EdgeDetail(
                    source=src,
                    target=tgt,
                    call_site_line=data.get("line", 0),
                    call_site_file=data.get("file", "<unknown>"),
                )
            )
        return edges

    @staticmethod
    def _compute_tech_debt(nodes: list[NodeDetail], cve_flags: list[CVEFlag]) -> float:
        """
        Composite score 0–100.
        40% from CVE severity counts, 60% from average cyclomatic complexity.
        """
        severity_weights = {"CRITICAL": 10.0, "HIGH": 5.0, "MEDIUM": 2.0, "LOW": 0.5}
        cve_score = min(
            40.0,
            sum(severity_weights.get(f.severity, 1.0) for f in cve_flags),
        )
        if nodes:
            avg_complexity = sum(n.complexity for n in nodes) / len(nodes)
            # Normalise: complexity 1 = 0 debt, complexity 10+ = 60 debt
            complexity_score = min(60.0, (avg_complexity - 1.0) * 60.0 / 9.0)
        else:
            complexity_score = 0.0
        return round(cve_score + complexity_score, 2)
