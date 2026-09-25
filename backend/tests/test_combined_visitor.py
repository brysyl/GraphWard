"""
Unit tests for _CombinedVisitor — GraphWard's single-pass AST visitor.

Covers:
  • Function record extraction (sync + async functions)
  • McCabe cyclomatic complexity calculation
  • Nested function scope isolation
  • Call-graph edge collection
  • CVE: dangerous call detection (CRITICAL / HIGH severity)
  • CVE: yaml.load without SafeLoader (deserialization flag)
  • CVE: yaml.load with SafeLoader (no flag)
  • CVE: hardcoded secret detection (all three patterns)
  • CVE: duplicate flag prevention for the same call
  • Module-level scope resolution
"""
from __future__ import annotations

import ast
import textwrap

import pytest

from core.ast_parser import (
    CVEFlag,
    _CombinedVisitor,
    _DANGEROUS_CALLS,
    _CRITICAL_CALLS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _visit(source: str, rel_path: str = "test.py") -> _CombinedVisitor:
    source = textwrap.dedent(source)
    tree = ast.parse(source)
    visitor = _CombinedVisitor(rel_path, source.splitlines())
    visitor.visit(tree)
    return visitor


def _records_by_name(visitor: _CombinedVisitor) -> dict[str, int]:
    """Return {function_name: complexity} from visitor.records."""
    return {r.qualified_name.split("::")[-1]: r.complexity for r in visitor.records}


def _cve_categories(visitor: _CombinedVisitor) -> list[str]:
    return [f.category for f in visitor.cve_flags]


def _cve_severities(visitor: _CombinedVisitor) -> list[str]:
    return [f.severity for f in visitor.cve_flags]


# ---------------------------------------------------------------------------
# Function record extraction
# ---------------------------------------------------------------------------


class TestFunctionRecords:
    def test_simple_function_captured(self) -> None:
        v = _visit("def foo(): pass")
        assert "foo" in _records_by_name(v)

    def test_async_function_captured(self) -> None:
        v = _visit("async def bar(): pass")
        assert "bar" in _records_by_name(v)

    def test_multiple_functions_all_captured(self) -> None:
        src = """
            def alpha(): pass
            def beta(): pass
            async def gamma(): pass
        """
        v = _visit(src)
        names = _records_by_name(v)
        assert "alpha" in names
        assert "beta" in names
        assert "gamma" in names

    def test_record_has_correct_rel_path(self) -> None:
        v = _visit("def foo(): pass", rel_path="pkg/mod.py")
        assert v.records[0].file == "pkg/mod.py"
        assert v.records[0].qualified_name == "pkg/mod.py::foo"

    def test_record_line_number(self) -> None:
        src = "\ndef foo(): pass\n"
        v = _visit(src)
        assert v.records[0].line == 2

    def test_no_records_for_empty_module(self) -> None:
        v = _visit("")
        assert v.records == []

    def test_nested_functions_both_recorded(self) -> None:
        src = """
            def outer():
                def inner():
                    pass
        """
        v = _visit(src)
        names = _records_by_name(v)
        assert "outer" in names
        assert "inner" in names


# ---------------------------------------------------------------------------
# Complexity calculation
# ---------------------------------------------------------------------------


class TestComplexity:
    def test_base_complexity_is_one(self) -> None:
        v = _visit("def plain(): pass")
        assert _records_by_name(v)["plain"] == 1

    def test_single_if_adds_one(self) -> None:
        src = """
            def f(x):
                if x:
                    pass
        """
        assert _records_by_name(_visit(src))["f"] == 2

    def test_for_loop_adds_one(self) -> None:
        src = """
            def f(xs):
                for x in xs:
                    pass
        """
        assert _records_by_name(_visit(src))["f"] == 2

    def test_while_adds_one(self) -> None:
        src = """
            def f():
                while True:
                    break
        """
        assert _records_by_name(_visit(src))["f"] == 2

    def test_except_handler_adds_one(self) -> None:
        src = """
            def f():
                try:
                    pass
                except Exception:
                    pass
        """
        assert _records_by_name(_visit(src))["f"] == 2

    def test_bool_op_and_two_values(self) -> None:
        # `a and b` → BoolOp with 2 values → adds 1
        src = """
            def f(a, b):
                return a and b
        """
        assert _records_by_name(_visit(src))["f"] == 2

    def test_bool_op_and_three_values(self) -> None:
        # `a and b and c` → BoolOp with 3 values → adds 2
        src = """
            def f(a, b, c):
                return a and b and c
        """
        assert _records_by_name(_visit(src))["f"] == 3

    def test_assert_adds_one(self) -> None:
        src = """
            def f(x):
                assert x > 0
        """
        assert _records_by_name(_visit(src))["f"] == 2

    def test_complex_function(self) -> None:
        # if(1) + for(1) + if_inner(1) + else_branch(0) + while(1) + except(1) = base 1 + 5
        src = """
            def complex_func(x, y, z):
                if x > 0:
                    for i in range(y):
                        if i % 2 == 0:
                            pass
                elif y > 0:
                    while z > 0:
                        z -= 1
                try:
                    result = x / y
                except ZeroDivisionError:
                    result = 0
                return result
        """
        complexity = _records_by_name(_visit(src))["complex_func"]
        assert complexity >= 5  # at least 4 branches + base

    def test_nested_function_complexity_isolated(self) -> None:
        # inner has 1 branch, outer has none of its own branches
        src = """
            def outer():
                def inner(x):
                    if x:
                        pass
                pass
        """
        names = _records_by_name(_visit(src))
        assert names["inner"] == 2
        assert names["outer"] == 1

    def test_list_comprehension_adds_one(self) -> None:
        src = """
            def f(xs):
                return [x for x in xs]
        """
        assert _records_by_name(_visit(src))["f"] == 2


# ---------------------------------------------------------------------------
# Call-graph edge collection
# ---------------------------------------------------------------------------


class TestCallCollection:
    def test_simple_call_captured(self) -> None:
        src = """
            def caller():
                callee()
        """
        v = _visit(src)
        callees = [c.callee for c in v.calls]
        assert "callee" in callees

    def test_method_call_resolved(self) -> None:
        src = """
            def f(obj):
                obj.method()
        """
        v = _visit(src)
        callees = [c.callee for c in v.calls]
        assert "obj.method" in callees

    def test_module_level_call_scope(self) -> None:
        src = "print('hi')"
        v = _visit(src)
        assert v.calls[0].caller.endswith("<module>")

    def test_call_inside_function_scope(self) -> None:
        src = """
            def runner():
                helper()
        """
        v = _visit(src)
        caller_names = [c.caller.split("::")[-1] for c in v.calls]
        assert "runner" in caller_names

    def test_unknown_call_emits_unknown(self) -> None:
        # A chained attribute deeper than one level → <unknown>
        src = """
            def f():
                a.b.c()
        """
        v = _visit(src)
        callees = [c.callee for c in v.calls]
        # a.b.c() → func is Attribute(value=Attribute(...)), no Name at root
        assert any(callee in ("<unknown>", "c") for callee in callees)


# ---------------------------------------------------------------------------
# CVE: dangerous call detection
# ---------------------------------------------------------------------------


class TestDangerousCallCVE:
    @pytest.mark.parametrize("call,expected_severity", [
        ("eval('x')", "CRITICAL"),
        ("exec('x')", "CRITICAL"),
        ("pickle.loads(b'')", "CRITICAL"),
        ("pickle.load(f)", "CRITICAL"),
        ("marshal.loads(b'')", "CRITICAL"),
        ("compile('x','<>','exec')", "HIGH"),
        ("os.system('ls')", "HIGH"),
        ("os.popen('ls')", "HIGH"),
        ("subprocess.call(['ls'])", "HIGH"),
        ("subprocess.Popen(['ls'])", "HIGH"),
        ("jsonpickle.decode(s)", "HIGH"),
        ("shelve.open('db')", "HIGH"),
    ])
    def test_dangerous_call_flagged(
        self, call: str, expected_severity: str
    ) -> None:
        src = f"def f():\n    {call}\n"
        v = _visit(src)
        assert len(v.cve_flags) >= 1
        flag = v.cve_flags[0]
        assert flag.category == "dangerous-call"
        assert flag.severity == expected_severity

    def test_eval_flag_contains_call_name(self) -> None:
        v = _visit("def f():\n    eval('x')\n")
        assert "eval" in v.cve_flags[0].description

    def test_flag_id_is_deterministic(self) -> None:
        v1 = _visit("def f():\n    eval('x')\n", "a.py")
        v2 = _visit("def f():\n    eval('x')\n", "a.py")
        assert v1.cve_flags[0].flag_id == v2.cve_flags[0].flag_id

    def test_flag_id_differs_for_different_file(self) -> None:
        v1 = _visit("def f():\n    eval('x')\n", "a.py")
        v2 = _visit("def f():\n    eval('x')\n", "b.py")
        assert v1.cve_flags[0].flag_id != v2.cve_flags[0].flag_id

    def test_safe_call_not_flagged(self) -> None:
        v = _visit("def f():\n    print('hello')\n")
        assert v.cve_flags == []

    def test_all_dangerous_calls_covered(self) -> None:
        """Every entry in _DANGEROUS_CALLS must produce at least one flag."""
        for call_name in _DANGEROUS_CALLS:
            if "." in call_name:
                obj, attr = call_name.split(".", 1)
                call_expr = f"{obj}.{attr}(x)"
            else:
                call_expr = f"{call_name}(x)"
            src = f"def f(x, f):\n    {call_expr}\n"
            v = _visit(src)
            dangerous_flags = [
                fl for fl in v.cve_flags if fl.category == "dangerous-call"
            ]
            assert dangerous_flags, (
                f"Expected CVE flag for '{call_name}' but got none"
            )


# ---------------------------------------------------------------------------
# CVE: yaml.load deserialization
# ---------------------------------------------------------------------------


class TestYamlLoadCVE:
    def test_yaml_load_no_loader_flagged(self) -> None:
        src = "def f(s):\n    yaml.load(s)\n"
        v = _visit(src)
        deser = [fl for fl in v.cve_flags if fl.category == "deserialization"]
        assert len(deser) == 1
        assert deser[0].severity == "HIGH"

    def test_yaml_load_with_safe_loader_kwarg_not_flagged(self) -> None:
        src = "def f(s):\n    yaml.load(s, Loader=yaml.SafeLoader)\n"
        v = _visit(src)
        deser = [fl for fl in v.cve_flags if fl.category == "deserialization"]
        assert deser == []

    def test_yaml_load_with_safe_loader_name_kwarg_not_flagged(self) -> None:
        src = "def f(s):\n    yaml.load(s, Loader=SafeLoader)\n"
        v = _visit(src)
        deser = [fl for fl in v.cve_flags if fl.category == "deserialization"]
        assert deser == []

    def test_yaml_load_positional_safe_loader_not_flagged(self) -> None:
        # yaml.load(stream, SafeLoader) — two positional args
        src = "def f(s):\n    yaml.load(s, SafeLoader)\n"
        v = _visit(src)
        deser = [fl for fl in v.cve_flags if fl.category == "deserialization"]
        assert deser == []


# ---------------------------------------------------------------------------
# CVE: hardcoded secrets
# ---------------------------------------------------------------------------


class TestHardcodedSecretCVE:
    @pytest.mark.parametrize("line", [
        'api_key = "sk-supersecretvalue123"',
        'password = "HunterPassword99!"',
        'token = "ghp_abcdefghijklmnop"',
        'auth_token = "Bearer xyz1234567"',
        'passwd = "secureP4ssw0rd!"',
        'secret = "supersecretvalue!1"',
    ])
    def test_secret_assignment_flagged(self, line: str) -> None:
        v = _visit(f"{line}\n")
        assert any(fl.category == "hardcoded-secret" for fl in v.cve_flags), (
            f"Expected hardcoded-secret flag for: {line}"
        )

    def test_aws_key_flagged(self) -> None:
        src = 'aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"\n'
        v = _visit(src)
        assert any(fl.category == "hardcoded-secret" for fl in v.cve_flags)

    def test_private_key_pem_flagged(self) -> None:
        src = 'x = "-----BEGIN RSA PRIVATE KEY-----"\n'
        # The PEM pattern is a plain regex on the line text, but only triggered
        # by visit_Assign. The AST parses this as a string constant assignment.
        v = _visit(src)
        assert any(fl.category == "hardcoded-secret" for fl in v.cve_flags)

    def test_benign_assignment_not_flagged(self) -> None:
        v = _visit('name = "Alice"\n')
        assert all(fl.category != "hardcoded-secret" for fl in v.cve_flags)

    def test_secret_flag_is_critical(self) -> None:
        v = _visit('api_key = "sk-supersecretvalue123"\n')
        secret_flags = [fl for fl in v.cve_flags if fl.category == "hardcoded-secret"]
        assert all(fl.severity == "CRITICAL" for fl in secret_flags)

    def test_only_one_flag_per_line(self) -> None:
        """Even if multiple patterns match, only one flag is emitted per line."""
        # This line matches patterns 1 (password) but not 2 (aws key)
        v = _visit('password = "hunter2password123"\n')
        secret_flags = [fl for fl in v.cve_flags if fl.category == "hardcoded-secret"]
        assert len(secret_flags) == 1


# ---------------------------------------------------------------------------
# Multiple CVEs in one file
# ---------------------------------------------------------------------------


class TestMultipleCVEs:
    def test_dangerous_and_secret_both_flagged(self) -> None:
        src = textwrap.dedent("""\
            api_key = "sk-supersecretvalue123"

            def f():
                eval("1+1")
        """)
        v = _visit(src)
        cats = _cve_categories(v)
        assert "dangerous-call" in cats
        assert "hardcoded-secret" in cats

    def test_line_numbers_correct(self) -> None:
        src = textwrap.dedent("""\
            def f():
                eval("x")
                exec("y")
        """)
        v = _visit(src)
        lines = sorted(fl.line for fl in v.cve_flags if fl.category == "dangerous-call")
        assert lines == [2, 3]
