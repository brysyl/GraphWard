"""
Unit tests for ASTParser — file traversal, graph construction, BFS pruning,
LRU cache, parallel processing, and the full analyze() pipeline.
"""
from __future__ import annotations

import ast
import os
import textwrap
import time
from pathlib import Path

import networkx as nx
import pytest

from core.ast_parser import (
    ASTParser,
    ASTAnalysisResult,
    _cached_parse,
    _process_file_worker,
    _FileResult,
    _SKIP_DIRS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_py(directory: Path, name: str, content: str) -> Path:
    p = directory / name
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# _iter_python_files
# ---------------------------------------------------------------------------


class TestIterPythonFiles:
    def test_finds_py_files(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("", encoding="utf-8")
        (tmp_path / "b.txt").write_text("", encoding="utf-8")
        parser = ASTParser()
        found = list(parser._iter_python_files(tmp_path))
        names = {f.name for f in found}
        assert "a.py" in names
        assert "b.txt" not in names

    def test_recurses_into_subdirs(self, tmp_path: Path) -> None:
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "c.py").write_text("", encoding="utf-8")
        parser = ASTParser()
        found = list(parser._iter_python_files(tmp_path))
        assert any(f.name == "c.py" for f in found)

    def test_skips_excluded_directories(self, tmp_path: Path) -> None:
        for skip_dir in ("venv", "__pycache__", ".git", "node_modules"):
            d = tmp_path / skip_dir
            d.mkdir()
            (d / "hidden.py").write_text("", encoding="utf-8")
        (tmp_path / "visible.py").write_text("", encoding="utf-8")
        parser = ASTParser()
        found = list(parser._iter_python_files(tmp_path))
        assert all(f.name != "hidden.py" for f in found)
        assert any(f.name == "visible.py" for f in found)

    def test_all_skip_dirs_excluded(self, tmp_path: Path) -> None:
        """Every directory in _SKIP_DIRS is actually excluded."""
        for skip_dir in _SKIP_DIRS:
            d = tmp_path / skip_dir
            d.mkdir()
            (d / "file.py").write_text("x = 1", encoding="utf-8")
        parser = ASTParser()
        found = list(parser._iter_python_files(tmp_path))
        assert found == []


# ---------------------------------------------------------------------------
# _is_test_file
# ---------------------------------------------------------------------------


class TestIsTestFile:
    @pytest.mark.parametrize("name,expected", [
        ("test_foo.py", True),
        ("foo_test.py", True),
        ("conftest.py", False),
        ("app.py", False),
    ])
    def test_name_patterns(self, name: str, expected: bool) -> None:
        assert ASTParser._is_test_file(Path(name)) is expected

    def test_path_in_tests_dir(self) -> None:
        assert ASTParser._is_test_file(Path("project/tests/test_x.py")) is True

    def test_path_not_in_tests_dir(self) -> None:
        assert ASTParser._is_test_file(Path("project/src/utils.py")) is False


# ---------------------------------------------------------------------------
# _prune_to_depth (BFS)
# ---------------------------------------------------------------------------


class TestPruneToDepth:
    def _make_chain(self, n: int) -> nx.DiGraph:
        """Create a linear chain 0→1→2→...→(n-1)."""
        G = nx.DiGraph()
        for i in range(n):
            G.add_node(str(i))
        for i in range(n - 1):
            G.add_edge(str(i), str(i + 1))
        return G

    def test_empty_graph_returns_empty(self) -> None:
        parser = ASTParser(max_depth=5)
        result = parser._prune_to_depth(nx.DiGraph())
        assert result.number_of_nodes() == 0

    def test_depth_0_retains_only_entry_points(self) -> None:
        parser = ASTParser(max_depth=0)
        G = self._make_chain(3)
        pruned = parser._prune_to_depth(G)
        # depth=0 → BFS seeds entry points but never expands
        assert "0" in pruned.nodes

    def test_depth_1_retains_entry_and_one_hop(self) -> None:
        parser = ASTParser(max_depth=1)
        G = self._make_chain(4)  # 0→1→2→3
        pruned = parser._prune_to_depth(G)
        assert "0" in pruned.nodes
        assert "1" in pruned.nodes
        assert "2" not in pruned.nodes
        assert "3" not in pruned.nodes

    def test_depth_larger_than_graph(self) -> None:
        parser = ASTParser(max_depth=100)
        G = self._make_chain(5)
        pruned = parser._prune_to_depth(G)
        assert pruned.number_of_nodes() == 5

    def test_multi_source_bfs(self) -> None:
        # Two separate chains; both entry-points are seeded simultaneously
        G = nx.DiGraph()
        G.add_edges_from([("A", "B"), ("B", "C"), ("X", "Y"), ("Y", "Z")])
        parser = ASTParser(max_depth=1)
        pruned = parser._prune_to_depth(G)
        assert "A" in pruned
        assert "B" in pruned
        assert "C" not in pruned
        assert "X" in pruned
        assert "Y" in pruned
        assert "Z" not in pruned

    def test_no_entry_points_returns_full_graph(self) -> None:
        # Cycle: every node has in-degree > 0
        G = nx.DiGraph()
        G.add_edges_from([("A", "B"), ("B", "A")])
        parser = ASTParser(max_depth=5)
        pruned = parser._prune_to_depth(G)
        assert pruned.number_of_nodes() == 2

    def test_returned_graph_is_copy(self) -> None:
        G = self._make_chain(3)
        parser = ASTParser(max_depth=10)
        pruned = parser._prune_to_depth(G)
        # Modifying original shouldn't affect pruned
        G.add_node("extra")
        assert "extra" not in pruned.nodes


# ---------------------------------------------------------------------------
# _cached_parse LRU cache
# ---------------------------------------------------------------------------


class TestCachedParse:
    def test_parse_returns_tree_and_lines(self, tmp_path: Path) -> None:
        f = tmp_path / "x.py"
        f.write_text("x = 1\n", encoding="utf-8")
        _cached_parse.cache_clear()
        stat = os.stat(str(f))
        tree, lines = _cached_parse(str(f), stat.st_mtime_ns, stat.st_size)
        assert isinstance(tree, ast.Module)
        assert "x = 1" in lines

    def test_cache_hit_on_repeated_call(self, tmp_path: Path) -> None:
        f = tmp_path / "y.py"
        f.write_text("y = 2\n", encoding="utf-8")
        _cached_parse.cache_clear()
        stat = os.stat(str(f))
        _cached_parse(str(f), stat.st_mtime_ns, stat.st_size)
        _cached_parse(str(f), stat.st_mtime_ns, stat.st_size)
        info = _cached_parse.cache_info()
        assert info.hits >= 1

    def test_cache_miss_after_content_change(self, tmp_path: Path) -> None:
        f = tmp_path / "z.py"
        f.write_text("z = 3\n", encoding="utf-8")
        _cached_parse.cache_clear()
        stat = os.stat(str(f))
        _cached_parse(str(f), stat.st_mtime_ns, stat.st_size)

        # Write different content (changes size)
        f.write_text("z = 3\nw = 4\n", encoding="utf-8")
        stat2 = os.stat(str(f))
        _cached_parse(str(f), stat2.st_mtime_ns, stat2.st_size)
        info = _cached_parse.cache_info()
        assert info.misses == 2

    def test_syntax_error_not_cached(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.py"
        f.write_text("def broken(:\n", encoding="utf-8")
        _cached_parse.cache_clear()
        stat = os.stat(str(f))
        with pytest.raises(SyntaxError):
            _cached_parse(str(f), stat.st_mtime_ns, stat.st_size)


# ---------------------------------------------------------------------------
# _process_file_worker
# ---------------------------------------------------------------------------


class TestProcessFileWorker:
    def test_clean_file_returns_file_result(self, tmp_path: Path) -> None:
        f = _make_py(tmp_path, "clean.py", "def foo(): pass\n")
        result = _process_file_worker((str(f), "clean.py"))
        assert result is not None
        assert isinstance(result, _FileResult)
        assert any(r.qualified_name == "clean.py::foo" for r in result.records)

    def test_syntax_error_returns_none(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.py"
        f.write_text("def broken(:\n", encoding="utf-8")
        result = _process_file_worker((str(f), "bad.py"))
        assert result is None

    def test_missing_file_returns_none(self, tmp_path: Path) -> None:
        result = _process_file_worker((str(tmp_path / "nonexistent.py"), "x.py"))
        assert result is None

    def test_calls_qualified_with_rel_path(self, tmp_path: Path) -> None:
        src = "def caller():\n    callee()\n"
        f = _make_py(tmp_path, "mod.py", src)
        result = _process_file_worker((str(f), "pkg/mod.py"))
        assert result is not None
        callers = [c.caller for c in result.calls]
        assert "pkg/mod.py::caller" in callers


# ---------------------------------------------------------------------------
# ASTParser.analyze — full pipeline
# ---------------------------------------------------------------------------


class TestASTParserAnalyze:
    def test_raises_for_missing_directory(self, tmp_path: Path) -> None:
        parser = ASTParser()
        with pytest.raises(FileNotFoundError):
            parser.analyze(str(tmp_path / "nonexistent"))

    def test_empty_directory_returns_empty_result(self, tmp_path: Path) -> None:
        result = ASTParser().analyze(str(tmp_path))
        assert isinstance(result, ASTAnalysisResult)
        assert result.total_files_scanned == 0
        assert result.total_nodes == 0
        assert result.cve_flags == []

    def test_clean_files_scanned(self, tmp_src: Path) -> None:
        result = ASTParser(workers=1).analyze(str(tmp_src))
        assert result.total_files_scanned == 2
        assert result.total_nodes >= 2

    def test_syntax_error_files_skipped(self, tmp_src_mixed: Path) -> None:
        result = ASTParser(workers=1).analyze(str(tmp_src_mixed))
        # broken.py has SyntaxError → should be skipped, not crash
        assert result.total_files_scanned == 2  # clean.py + evil.py

    def test_cve_flags_from_dangerous_source(self, tmp_src_dangerous: Path) -> None:
        result = ASTParser(workers=1).analyze(str(tmp_src_dangerous))
        assert len(result.cve_flags) >= 3  # eval + pickle.loads + yaml.load + os.system

    def test_cve_flags_from_secret_source(self, tmp_src_secrets: Path) -> None:
        result = ASTParser(workers=1).analyze(str(tmp_src_secrets))
        secret_flags = [f for f in result.cve_flags if f.category == "hardcoded-secret"]
        assert len(secret_flags) >= 1

    def test_include_tests_false_excludes_test_files(self, tmp_path: Path) -> None:
        (tmp_path / "test_foo.py").write_text("def test_bar(): pass\n", encoding="utf-8")
        (tmp_path / "app.py").write_text("def run(): pass\n", encoding="utf-8")
        result = ASTParser(include_tests=False, workers=1).analyze(str(tmp_path))
        node_ids = [n.node_id for n in result.nodes]
        assert not any("test_bar" in nid for nid in node_ids)

    def test_include_tests_true_includes_test_files(self, tmp_path: Path) -> None:
        (tmp_path / "test_foo.py").write_text("def test_bar(): pass\n", encoding="utf-8")
        result = ASTParser(include_tests=True, workers=1).analyze(str(tmp_path))
        node_ids = [n.node_id for n in result.nodes]
        assert any("test_bar" in nid for nid in node_ids)

    def test_result_target_directory_is_absolute(self, tmp_src: Path) -> None:
        result = ASTParser(workers=1).analyze(str(tmp_src))
        assert Path(result.target_directory).is_absolute()

    def test_tech_debt_between_0_and_100(self, tmp_src: Path) -> None:
        result = ASTParser(workers=1).analyze(str(tmp_src))
        assert 0.0 <= result.tech_debt_score <= 100.0

    def test_call_graph_json_has_nodes_and_links(self, tmp_src: Path) -> None:
        result = ASTParser(workers=1).analyze(str(tmp_src))
        cg = result.call_graph_json
        assert "nodes" in cg
        assert "links" in cg

    def test_node_details_have_correct_kind(self, tmp_src: Path) -> None:
        result = ASTParser(workers=1).analyze(str(tmp_src))
        for node in result.nodes:
            assert node.kind in ("function", "module", "class")

    def test_max_depth_limits_graph_nodes(self, tmp_path: Path) -> None:
        # Build a chain of 6 functions calling each other
        src = textwrap.dedent("""\
            def f0(): f1()
            def f1(): f2()
            def f2(): f3()
            def f3(): f4()
            def f4(): f5()
            def f5(): pass
        """)
        (tmp_path / "chain.py").write_text(src, encoding="utf-8")
        result_shallow = ASTParser(max_depth=2, workers=1).analyze(str(tmp_path))
        result_deep = ASTParser(max_depth=10, workers=1).analyze(str(tmp_path))
        assert result_shallow.total_nodes <= result_deep.total_nodes


# ---------------------------------------------------------------------------
# Tech-debt score
# ---------------------------------------------------------------------------


class TestTechDebtScore:
    def test_no_nodes_no_cve_score_zero(self) -> None:
        score = ASTParser._compute_tech_debt([], [])
        assert score == 0.0

    def test_cve_critical_adds_10(self) -> None:
        from core.ast_parser import CVEFlag, NodeDetail
        flag = CVEFlag(
            flag_id="X",
            severity="CRITICAL",
            category="dangerous-call",
            file="f.py",
            line=1,
            col=0,
            description="d",
            remediation="r",
        )
        score = ASTParser._compute_tech_debt([], [flag])
        assert score == 10.0

    def test_score_capped_at_100(self) -> None:
        from core.ast_parser import CVEFlag, NodeDetail
        flags = [
            CVEFlag(
                flag_id=f"X{i}",
                severity="CRITICAL",
                category="dangerous-call",
                file="f.py",
                line=i,
                col=0,
                description="d",
                remediation="r",
            )
            for i in range(20)  # 20 × 10 = 200 → capped at 40 for CVE portion
        ]
        nodes = [
            NodeDetail(
                node_id=f"f.py::fn{i}",
                file="f.py",
                line=i,
                col=0,
                kind="function",
                name=f"fn{i}",
                complexity=15,  # very high → complexity_score capped at 60
            )
            for i in range(5)
        ]
        score = ASTParser._compute_tech_debt(nodes, flags)
        assert score <= 100.0
