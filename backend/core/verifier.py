"""
GraphWard AI — Closed-Loop Patch Verifier
Applies a unified diff patch, executes pytest in a sandboxed subprocess,
and captures a structured verification report with stderr stack traces.
"""

from __future__ import annotations

import io
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

logger = logging.getLogger("graphward.verifier")


# ---------------------------------------------------------------------------
# Pydantic output models
# ---------------------------------------------------------------------------

class StackFrame(BaseModel):
    file: str
    line: int
    function: str
    code: Optional[str] = None


class TestFailure(BaseModel):
    test_id: str
    outcome: str  # "FAILED" | "ERROR"
    message: str
    stack_frames: list[StackFrame]
    duration_ms: float


class VerificationResult(BaseModel):
    passed: bool
    tests_total: int
    tests_passed: int
    tests_failed: int
    tests_errors: int
    tests_skipped: int
    duration_seconds: float
    patch_applied: bool
    patch_error: Optional[str] = None
    failures: list[TestFailure]
    raw_stdout: str
    raw_stderr: str
    regression_log: list[str] = Field(
        description="Chronological list of regression-relevant log lines"
    )


# ---------------------------------------------------------------------------
# Patch application
# ---------------------------------------------------------------------------

_HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def _apply_unified_diff(diff: str, working_dir: Path) -> tuple[bool, str]:
    """
    Applies a unified diff to the working directory using the system `patch` command.
    Returns (success, error_message).
    """
    patch_bin = shutil.which("patch")
    if patch_bin is None:
        return False, "`patch` binary not found on PATH."

    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".patch",
        dir=working_dir,
        delete=False,
        encoding="utf-8",
    ) as tmp:
        tmp.write(diff)
        patch_file = tmp.name

    try:
        result = subprocess.run(
            [patch_bin, "--batch", "--forward", "-p1", "-i", patch_file],
            capture_output=True,
            text=True,
            cwd=str(working_dir),
            timeout=30,
        )
        if result.returncode != 0:
            return False, result.stderr.strip() or result.stdout.strip()
        return True, ""
    except subprocess.TimeoutExpired:
        return False, "patch application timed out (>30s)"
    finally:
        try:
            os.unlink(patch_file)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Pytest output parser
# ---------------------------------------------------------------------------

_TRACEBACK_FILE_LINE = re.compile(r'^\s*File "(.+?)", line (\d+), in (.+)$')
_FAILED_TESTS_SECTION = re.compile(r"^FAILED (.+?)(?:\s+-\s+(.+))?$", re.MULTILINE)
_PASSED_RE = re.compile(r"(\d+) passed")
_FAILED_RE = re.compile(r"(\d+) failed")
_ERROR_RE = re.compile(r"(\d+) error")
_SKIPPED_RE = re.compile(r"(\d+) skipped")
_DURATION_RE = re.compile(r"in ([\d.]+)s")


def _parse_pytest_output(stdout: str, stderr: str) -> dict:
    """
    Parses pytest terminal output into structured counts and failure details.
    """
    summary_line = ""
    for line in reversed(stdout.splitlines()):
        if "passed" in line or "failed" in line or "error" in line:
            summary_line = line
            break

    def _extract(pattern: re.Pattern[str], text: str, default: int = 0) -> int:
        m = pattern.search(text)
        return int(m.group(1)) if m else default

    tests_passed = _extract(_PASSED_RE, summary_line)
    tests_failed = _extract(_FAILED_RE, summary_line)
    tests_errors = _extract(_ERROR_RE, summary_line)
    tests_skipped = _extract(_SKIPPED_RE, summary_line)
    total = tests_passed + tests_failed + tests_errors + tests_skipped

    duration_m = _DURATION_RE.search(summary_line)
    duration_seconds = float(duration_m.group(1)) if duration_m else 0.0

    failures = _extract_failures(stdout)

    return {
        "tests_passed": tests_passed,
        "tests_failed": tests_failed,
        "tests_errors": tests_errors,
        "tests_skipped": tests_skipped,
        "tests_total": total,
        "duration_seconds": duration_seconds,
        "failures": failures,
    }


def _extract_failures(stdout: str) -> list[TestFailure]:
    """
    Parses the FAILURES section of pytest's verbose output.
    """
    failures: list[TestFailure] = []
    # Split on short test separators
    sections = re.split(r"_{5,}", stdout)

    for section in sections:
        lines = section.strip().splitlines()
        if not lines:
            continue
        header = lines[0].strip()
        # A failure section header looks like: "test_module.py::test_name"
        if "::" not in header:
            continue
        test_id = header
        frames: list[StackFrame] = []
        message_lines: list[str] = []
        in_traceback = False

        for raw in lines[1:]:
            fm = _TRACEBACK_FILE_LINE.match(raw)
            if fm:
                in_traceback = True
                frames.append(
                    StackFrame(
                        file=fm.group(1),
                        line=int(fm.group(2)),
                        function=fm.group(3),
                    )
                )
            elif in_traceback and raw.strip().startswith(("AssertionError", "Error", "Exception")):
                message_lines.append(raw.strip())
            elif not in_traceback:
                message_lines.append(raw.strip())

        failures.append(
            TestFailure(
                test_id=test_id,
                outcome="FAILED",
                message="\n".join(filter(None, message_lines))[:2000],
                stack_frames=frames,
                duration_ms=0.0,
            )
        )

    return failures


# ---------------------------------------------------------------------------
# Regression log extractor
# ---------------------------------------------------------------------------

def _build_regression_log(stdout: str, stderr: str) -> list[str]:
    """Extracts lines relevant to regression analysis from combined output."""
    combined = stdout + "\n" + stderr
    relevant: list[str] = []
    keywords = ("FAILED", "ERROR", "AssertionError", "Exception", "Traceback", "WARNING")
    for line in combined.splitlines():
        stripped = line.strip()
        if stripped and any(kw in stripped for kw in keywords):
            relevant.append(stripped)
    return relevant[:200]  # Cap at 200 entries


# ---------------------------------------------------------------------------
# Main verifier
# ---------------------------------------------------------------------------

class PatchVerifier:
    """
    Applies a unified diff patch to a working directory, runs pytest in a
    sandboxed subprocess with a hard timeout, and returns a VerificationResult.
    """

    def __init__(
        self,
        working_directory: str = ".",
        test_directory: str = "tests",
        timeout_seconds: int = 120,
    ) -> None:
        self._work_dir = Path(working_directory).resolve()
        self._test_dir = test_directory
        self._timeout = timeout_seconds

    def verify(self, patch_diff: str) -> VerificationResult:
        start_ts = time.perf_counter()

        # Step 1: Apply patch
        patch_applied, patch_error = _apply_unified_diff(patch_diff, self._work_dir)
        if not patch_applied:
            logger.warning("Patch application failed: %s", patch_error)

        # Step 2: Run pytest in a sandboxed subprocess
        stdout, stderr, returncode = self._run_pytest()

        elapsed = time.perf_counter() - start_ts

        # Step 3: Parse output
        parsed = _parse_pytest_output(stdout, stderr)
        regression_log = _build_regression_log(stdout, stderr)

        passed = (
            patch_applied
            and returncode == 0
            and parsed["tests_failed"] == 0
            and parsed["tests_errors"] == 0
        )

        return VerificationResult(
            passed=passed,
            tests_total=parsed["tests_total"],
            tests_passed=parsed["tests_passed"],
            tests_failed=parsed["tests_failed"],
            tests_errors=parsed["tests_errors"],
            tests_skipped=parsed["tests_skipped"],
            duration_seconds=round(elapsed, 3),
            patch_applied=patch_applied,
            patch_error=patch_error if patch_error else None,
            failures=parsed["failures"],
            raw_stdout=stdout[:50_000],   # Cap payload
            raw_stderr=stderr[:10_000],
            regression_log=regression_log,
        )

    def _run_pytest(self) -> tuple[str, str, int]:
        """
        Executes pytest in a subprocess with:
        - clean environment (no inherited PYTHONDONTWRITEBYTECODE pollution)
        - hard timeout
        - stdout/stderr capture
        """
        test_path = self._work_dir / self._test_dir
        if not test_path.exists():
            return (
                "",
                f"Test directory '{test_path}' does not exist.",
                1,
            )

        env = {
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1",
            # Isolate from any active virtual env customisations that might break tests
            "PYTEST_ADDOPTS": "",
        }

        cmd: list[str] = [
            sys.executable,
            "-m",
            "pytest",
            str(test_path),
            "--tb=long",
            "--no-header",
            "-q",
            "--color=no",
            f"--timeout={self._timeout}",
        ]

        logger.info("Executing: %s", " ".join(cmd))

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=str(self._work_dir),
                env=env,
                timeout=self._timeout + 10,  # extra buffer for process setup
            )
            return proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired as exc:
            stdout = (exc.stdout or b"").decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = (exc.stderr or b"").decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            return stdout, stderr + f"\n[TIMEOUT] Exceeded {self._timeout}s limit.", 124
        except Exception as exc:
            return "", f"[RUNNER ERROR] {exc}", 1
