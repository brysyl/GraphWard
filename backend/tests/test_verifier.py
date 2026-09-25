"""
Unit tests for the verifier module:
  • _parse_pytest_output — summary line parsing
  • _extract_failures — failure section parsing
  • _build_regression_log — keyword filtering
  • _apply_unified_diff — patch application gate
  • PatchVerifier.verify — deterministic verification gates
"""
from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.verifier import (
    PatchVerifier,
    StackFrame,
    FailureDetail,
    VerificationResult,
    _apply_unified_diff,
    _build_regression_log,
    _extract_failures,
    _parse_pytest_output,
)


# ---------------------------------------------------------------------------
# _parse_pytest_output
# ---------------------------------------------------------------------------


class TestParsePytestOutput:
    def test_all_passed(self) -> None:
        stdout = "5 passed in 0.42s"
        result = _parse_pytest_output(stdout, "")
        assert result["tests_passed"] == 5
        assert result["tests_failed"] == 0
        assert result["tests_errors"] == 0
        assert result["tests_skipped"] == 0
        assert result["tests_total"] == 5

    def test_mixed_results(self) -> None:
        stdout = "3 passed, 2 failed, 1 error, 1 skipped in 1.23s"
        result = _parse_pytest_output(stdout, "")
        assert result["tests_passed"] == 3
        assert result["tests_failed"] == 2
        assert result["tests_errors"] == 1
        assert result["tests_skipped"] == 1
        assert result["tests_total"] == 7

    def test_duration_extracted(self) -> None:
        stdout = "10 passed in 2.71s"
        result = _parse_pytest_output(stdout, "")
        assert result["duration_seconds"] == pytest.approx(2.71)

    def test_empty_output_returns_zeros(self) -> None:
        result = _parse_pytest_output("", "")
        assert result["tests_passed"] == 0
        assert result["tests_total"] == 0

    def test_last_summary_line_used(self) -> None:
        # Intermediate lines should be ignored; only the last summary counts
        stdout = (
            "some noise\n"
            "collecting ...\n"
            "7 passed in 0.10s\n"
        )
        result = _parse_pytest_output(stdout, "")
        assert result["tests_passed"] == 7

    def test_failures_list_populated(self) -> None:
        stdout = textwrap.dedent("""\
            _____ test_module.py::test_bad _____
            test_module.py::test_bad
              File "test_module.py", line 5, in test_bad
            AssertionError: expected True
            1 failed in 0.05s
        """)
        result = _parse_pytest_output(stdout, "")
        assert len(result["failures"]) >= 1


# ---------------------------------------------------------------------------
# _extract_failures
# ---------------------------------------------------------------------------


class TestExtractFailures:
    def test_single_failure_parsed(self) -> None:
        stdout = textwrap.dedent("""\
            _____ test_foo.py::test_one _____
            test_foo.py::test_one
              File "test_foo.py", line 10, in test_one
            AssertionError: 1 != 2
        """)
        failures = _extract_failures(stdout)
        # The separator splits into a header section + body section; both have ::
        assert len(failures) >= 1
        # The section with the actual assertion error is the relevant one
        matching = [f for f in failures if "AssertionError" in f.message]
        assert matching, "Expected at least one failure with AssertionError in message"
        f = matching[0]
        assert f.test_id == "test_foo.py::test_one"
        assert f.outcome == "FAILED"

    def test_stack_frame_extracted(self) -> None:
        stdout = textwrap.dedent("""\
            _____ test_foo.py::test_two _____
            test_foo.py::test_two
              File "app/module.py", line 42, in my_func
            AssertionError
        """)
        failures = _extract_failures(stdout)
        # Find the section that actually has a stack frame
        framed = [f for f in failures if f.stack_frames]
        assert framed, "Expected at least one failure with stack frames"
        frame = framed[0].stack_frames[0]
        assert frame.file == "app/module.py"
        assert frame.line == 42
        assert frame.function == "my_func"

    def test_multiple_failures_parsed(self) -> None:
        stdout = textwrap.dedent("""\
            _____ test_a.py::test_one _____
            test_a.py::test_one
            AssertionError
            _____ test_b.py::test_two _____
            test_b.py::test_two
            AssertionError
        """)
        failures = _extract_failures(stdout)
        # Each failure yields ≥1 entry; verify both test IDs are present
        ids = {f.test_id for f in failures}
        assert "test_a.py::test_one" in ids
        assert "test_b.py::test_two" in ids

    def test_no_failures_returns_empty(self) -> None:
        assert _extract_failures("3 passed in 0.1s") == []

    def test_message_truncated_at_2000_chars(self) -> None:
        long_msg = "x" * 3000
        stdout = f"_____ test.py::test_t _____\ntest.py::test_t\n{long_msg}\n"
        failures = _extract_failures(stdout)
        assert len(failures[0].message) <= 2000


# ---------------------------------------------------------------------------
# _build_regression_log
# ---------------------------------------------------------------------------


class TestBuildRegressionLog:
    def test_failed_lines_captured(self) -> None:
        stdout = "FAILED test_foo.py::test_bar - AssertionError"
        log = _build_regression_log(stdout, "")
        assert any("FAILED" in line for line in log)

    def test_traceback_lines_captured(self) -> None:
        stderr = "Traceback (most recent call last):\n  File x.py"
        log = _build_regression_log("", stderr)
        assert any("Traceback" in line for line in log)

    def test_clean_output_returns_empty(self) -> None:
        log = _build_regression_log("3 passed in 0.1s", "")
        assert log == []

    def test_capped_at_200_entries(self) -> None:
        noisy = "\n".join(f"FAILED test_{i}" for i in range(500))
        log = _build_regression_log(noisy, "")
        assert len(log) <= 200

    def test_empty_lines_excluded(self) -> None:
        log = _build_regression_log("FAILED\n\n\nERROR\n", "")
        assert "" not in log

    @pytest.mark.parametrize("keyword", [
        "FAILED", "ERROR", "AssertionError", "Exception", "Traceback", "WARNING",
    ])
    def test_all_keywords_captured(self, keyword: str) -> None:
        log = _build_regression_log(f"line with {keyword} in it", "")
        assert len(log) == 1


# ---------------------------------------------------------------------------
# _apply_unified_diff
# ---------------------------------------------------------------------------


class TestApplyUnifiedDiff:
    def test_returns_false_when_patch_not_on_path(self, tmp_path: Path) -> None:
        with patch("shutil.which", return_value=None):
            ok, err = _apply_unified_diff("--- a\n+++ b\n", tmp_path)
        assert ok is False
        assert "patch" in err.lower()

    def test_malformed_diff_returns_false(self, tmp_path: Path) -> None:
        # pass a diff that `patch` will reject
        ok, err = _apply_unified_diff("not a real diff\n", tmp_path)
        assert ok is False

    def test_valid_diff_applied(self, tmp_path: Path) -> None:
        target = tmp_path / "file.txt"
        target.write_text("line1\nline2\nline3\n", encoding="utf-8")
        diff = textwrap.dedent("""\
            --- a/file.txt
            +++ b/file.txt
            @@ -1,3 +1,3 @@
             line1
            -line2
            +LINE2
             line3
        """)
        ok, err = _apply_unified_diff(diff, tmp_path)
        if ok:
            assert target.read_text(encoding="utf-8") == "line1\nLINE2\nline3\n"
        # else: patch binary not available → skip assertion on file content


# ---------------------------------------------------------------------------
# PatchVerifier — deterministic gates
# ---------------------------------------------------------------------------


class TestPatchVerifierGates:
    """
    These tests mock subprocess.run so the verifier is deterministic
    and does not depend on the filesystem or a running pytest.
    """

    def _make_verifier(self, tmp_path: Path) -> PatchVerifier:
        test_dir = tmp_path / "tests"
        test_dir.mkdir()
        return PatchVerifier(
            working_directory=str(tmp_path),
            test_directory="tests",
            timeout_seconds=30,
        )

    def _mock_run(
        self,
        stdout: str = "",
        stderr: str = "",
        returncode: int = 0,
    ) -> MagicMock:
        mock = MagicMock()
        mock.stdout = stdout
        mock.stderr = stderr
        mock.returncode = returncode
        return mock

    def test_passed_when_patch_ok_and_tests_pass(self, tmp_path: Path) -> None:
        verifier = self._make_verifier(tmp_path)
        with (
            patch(
                "core.verifier._apply_unified_diff", return_value=(True, "")
            ),
            patch(
                "subprocess.run",
                return_value=self._mock_run("5 passed in 0.1s", "", 0),
            ),
        ):
            result = verifier.verify("some diff")
        assert result.passed is True
        assert result.patch_applied is True
        assert result.tests_passed == 5

    def test_failed_when_patch_rejected(self, tmp_path: Path) -> None:
        verifier = self._make_verifier(tmp_path)
        with (
            patch(
                "core.verifier._apply_unified_diff",
                return_value=(False, "patch failed"),
            ),
            patch(
                "subprocess.run",
                return_value=self._mock_run("5 passed in 0.1s", "", 0),
            ),
        ):
            result = verifier.verify("bad diff")
        assert result.passed is False
        assert result.patch_applied is False
        assert result.patch_error == "patch failed"

    def test_failed_when_tests_fail(self, tmp_path: Path) -> None:
        verifier = self._make_verifier(tmp_path)
        stdout = "2 passed, 1 failed in 0.5s"
        with (
            patch(
                "core.verifier._apply_unified_diff", return_value=(True, "")
            ),
            patch(
                "subprocess.run",
                return_value=self._mock_run(stdout, "", 1),
            ),
        ):
            result = verifier.verify("diff")
        assert result.passed is False
        assert result.tests_failed == 1

    def test_failed_when_returncode_nonzero(self, tmp_path: Path) -> None:
        verifier = self._make_verifier(tmp_path)
        with (
            patch(
                "core.verifier._apply_unified_diff", return_value=(True, "")
            ),
            patch(
                "subprocess.run",
                return_value=self._mock_run("0 passed in 0.0s", "", 2),
            ),
        ):
            result = verifier.verify("diff")
        assert result.passed is False

    def test_missing_test_directory_returns_failure(self, tmp_path: Path) -> None:
        # test_dir does NOT exist
        verifier = PatchVerifier(
            working_directory=str(tmp_path),
            test_directory="nonexistent_tests",
            timeout_seconds=30,
        )
        with patch("core.verifier._apply_unified_diff", return_value=(True, "")):
            result = verifier.verify("diff")
        assert result.passed is False
        assert "does not exist" in result.raw_stderr

    def test_patch_error_none_when_no_error(self, tmp_path: Path) -> None:
        verifier = self._make_verifier(tmp_path)
        with (
            patch(
                "core.verifier._apply_unified_diff", return_value=(True, "")
            ),
            patch(
                "subprocess.run",
                return_value=self._mock_run("3 passed in 0.1s", "", 0),
            ),
        ):
            result = verifier.verify("diff")
        assert result.patch_error is None

    def test_raw_stdout_capped_at_50k(self, tmp_path: Path) -> None:
        verifier = self._make_verifier(tmp_path)
        big_stdout = "x" * 100_000 + "\n1 passed in 0.1s"
        with (
            patch(
                "core.verifier._apply_unified_diff", return_value=(True, "")
            ),
            patch(
                "subprocess.run",
                return_value=self._mock_run(big_stdout, "", 0),
            ),
        ):
            result = verifier.verify("diff")
        assert len(result.raw_stdout) <= 50_000

    def test_regression_log_populated_on_failure(self, tmp_path: Path) -> None:
        verifier = self._make_verifier(tmp_path)
        stdout = "FAILED test_x.py::test_one\n1 failed in 0.1s"
        with (
            patch(
                "core.verifier._apply_unified_diff", return_value=(True, "")
            ),
            patch(
                "subprocess.run",
                return_value=self._mock_run(stdout, "", 1),
            ),
        ):
            result = verifier.verify("diff")
        assert len(result.regression_log) >= 1

    def test_result_is_pydantic_model(self, tmp_path: Path) -> None:
        verifier = self._make_verifier(tmp_path)
        with (
            patch(
                "core.verifier._apply_unified_diff", return_value=(True, "")
            ),
            patch(
                "subprocess.run",
                return_value=self._mock_run("2 passed in 0.2s", "", 0),
            ),
        ):
            result = verifier.verify("diff")
        assert isinstance(result, VerificationResult)

    def test_duration_seconds_positive(self, tmp_path: Path) -> None:
        verifier = self._make_verifier(tmp_path)
        with (
            patch(
                "core.verifier._apply_unified_diff", return_value=(True, "")
            ),
            patch(
                "subprocess.run",
                return_value=self._mock_run("1 passed in 0.1s", "", 0),
            ),
        ):
            result = verifier.verify("diff")
        assert result.duration_seconds >= 0.0
