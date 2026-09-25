"""
FastAPI integration tests — /health, /api/v1/ast/analyze, /api/v1/remediate/verify.

Uses httpx.AsyncClient with ASGITransport (no real network).
The analysis endpoint is called against real temp source trees so the full
parser pipeline executes end-to-end.
"""
from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
import pytest_asyncio
from httpx import AsyncClient

from core.verifier import VerificationResult


pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    async def test_returns_200(self, async_client: AsyncClient) -> None:
        resp = await async_client.get("/health")
        assert resp.status_code == 200

    async def test_body_contains_ok(self, async_client: AsyncClient) -> None:
        resp = await async_client.get("/health")
        body = resp.json()
        assert body["status"] == "ok"
        assert body["service"] == "graphward-control-room"

    async def test_process_time_header_present(
        self, async_client: AsyncClient
    ) -> None:
        resp = await async_client.get("/health")
        assert "x-process-time" in resp.headers


# ---------------------------------------------------------------------------
# /api/v1/ast/analyze — happy path
# ---------------------------------------------------------------------------


class TestAnalyzeEndpoint:
    async def test_analyze_clean_src_returns_200(
        self, async_client: AsyncClient, tmp_src: Path
    ) -> None:
        resp = await async_client.post(
            "/api/v1/ast/analyze",
            json={"target_directory": str(tmp_src), "workers": 1},
        )
        assert resp.status_code == 200

    async def test_analyze_response_schema(
        self, async_client: AsyncClient, tmp_src: Path
    ) -> None:
        resp = await async_client.post(
            "/api/v1/ast/analyze",
            json={"target_directory": str(tmp_src), "workers": 1},
        )
        body = resp.json()
        for key in (
            "target_directory",
            "total_nodes",
            "total_edges",
            "total_files_scanned",
            "nodes",
            "edges",
            "cve_flags",
            "tech_debt_score",
            "call_graph_json",
        ):
            assert key in body, f"Missing key: {key}"

    async def test_analyze_counts_are_non_negative(
        self, async_client: AsyncClient, tmp_src: Path
    ) -> None:
        body = (
            await async_client.post(
                "/api/v1/ast/analyze",
                json={"target_directory": str(tmp_src), "workers": 1},
            )
        ).json()
        assert body["total_nodes"] >= 0
        assert body["total_edges"] >= 0
        assert body["total_files_scanned"] >= 0

    async def test_analyze_detects_cve_flags(
        self, async_client: AsyncClient, tmp_src_dangerous: Path
    ) -> None:
        body = (
            await async_client.post(
                "/api/v1/ast/analyze",
                json={"target_directory": str(tmp_src_dangerous), "workers": 1},
            )
        ).json()
        assert len(body["cve_flags"]) >= 3

    async def test_analyze_cve_flag_schema(
        self, async_client: AsyncClient, tmp_src_dangerous: Path
    ) -> None:
        body = (
            await async_client.post(
                "/api/v1/ast/analyze",
                json={"target_directory": str(tmp_src_dangerous), "workers": 1},
            )
        ).json()
        flag = body["cve_flags"][0]
        for key in ("flag_id", "severity", "category", "file", "line", "description"):
            assert key in flag

    async def test_analyze_max_depth_accepted(
        self, async_client: AsyncClient, tmp_src: Path
    ) -> None:
        resp = await async_client.post(
            "/api/v1/ast/analyze",
            json={
                "target_directory": str(tmp_src),
                "max_depth": 3,
                "include_tests": False,
                "workers": 1,
            },
        )
        assert resp.status_code == 200

    async def test_analyze_include_tests_true(
        self, async_client: AsyncClient, tmp_path: Path
    ) -> None:
        (tmp_path / "test_foo.py").write_text(
            "def test_bar(): pass\n", encoding="utf-8"
        )
        resp = await async_client.post(
            "/api/v1/ast/analyze",
            json={
                "target_directory": str(tmp_path),
                "include_tests": True,
                "workers": 1,
            },
        )
        body = resp.json()
        node_ids = [n["node_id"] for n in body["nodes"]]
        assert any("test_bar" in nid for nid in node_ids)

    async def test_analyze_workers_field_accepted(
        self, async_client: AsyncClient, tmp_src: Path
    ) -> None:
        resp = await async_client.post(
            "/api/v1/ast/analyze",
            json={"target_directory": str(tmp_src), "workers": 2},
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# /api/v1/ast/analyze — error paths
# ---------------------------------------------------------------------------


class TestAnalyzeEndpointErrors:
    async def test_missing_directory_returns_404(
        self, async_client: AsyncClient, tmp_path: Path
    ) -> None:
        resp = await async_client.post(
            "/api/v1/ast/analyze",
            json={"target_directory": str(tmp_path / "nonexistent"), "workers": 1},
        )
        assert resp.status_code == 404

    async def test_missing_target_directory_field_returns_422(
        self, async_client: AsyncClient
    ) -> None:
        resp = await async_client.post("/api/v1/ast/analyze", json={})
        assert resp.status_code == 422

    async def test_max_depth_out_of_range_returns_422(
        self, async_client: AsyncClient, tmp_src: Path
    ) -> None:
        resp = await async_client.post(
            "/api/v1/ast/analyze",
            json={"target_directory": str(tmp_src), "max_depth": 0},
        )
        assert resp.status_code == 422

    async def test_workers_out_of_range_returns_422(
        self, async_client: AsyncClient, tmp_src: Path
    ) -> None:
        resp = await async_client.post(
            "/api/v1/ast/analyze",
            json={"target_directory": str(tmp_src), "workers": 0},
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# /api/v1/remediate/verify — happy path
# ---------------------------------------------------------------------------


def _mock_verification(passed: bool = True) -> VerificationResult:
    return VerificationResult(
        passed=passed,
        tests_total=5,
        tests_passed=5 if passed else 4,
        tests_failed=0 if passed else 1,
        tests_errors=0,
        tests_skipped=0,
        duration_seconds=0.1,
        patch_applied=True,
        patch_error=None,
        failures=[],
        raw_stdout="5 passed in 0.1s",
        raw_stderr="",
        regression_log=[],
    )


class TestVerifyEndpoint:
    async def test_verify_returns_200(
        self, async_client: AsyncClient, tmp_path: Path
    ) -> None:
        with patch("main.PatchVerifier") as mock_cls:
            mock_cls.return_value.verify.return_value = _mock_verification()
            resp = await async_client.post(
                "/api/v1/remediate/verify",
                json={
                    "patch_diff": "--- a\n+++ b\n",
                    "working_directory": str(tmp_path),
                    "test_directory": "tests",
                    "timeout_seconds": 30,
                },
            )
        assert resp.status_code == 200

    async def test_verify_response_schema(
        self, async_client: AsyncClient, tmp_path: Path
    ) -> None:
        with patch("main.PatchVerifier") as mock_cls:
            mock_cls.return_value.verify.return_value = _mock_verification()
            body = (
                await async_client.post(
                    "/api/v1/remediate/verify",
                    json={
                        "patch_diff": "--- a\n+++ b\n",
                        "working_directory": str(tmp_path),
                    },
                )
            ).json()
        for key in (
            "passed",
            "tests_total",
            "tests_passed",
            "tests_failed",
            "patch_applied",
            "failures",
            "raw_stdout",
            "regression_log",
        ):
            assert key in body

    async def test_verify_passed_true_in_response(
        self, async_client: AsyncClient, tmp_path: Path
    ) -> None:
        with patch("main.PatchVerifier") as mock_cls:
            mock_cls.return_value.verify.return_value = _mock_verification(passed=True)
            body = (
                await async_client.post(
                    "/api/v1/remediate/verify",
                    json={"patch_diff": "diff", "working_directory": str(tmp_path)},
                )
            ).json()
        assert body["passed"] is True

    async def test_verify_failed_false_in_response(
        self, async_client: AsyncClient, tmp_path: Path
    ) -> None:
        with patch("main.PatchVerifier") as mock_cls:
            mock_cls.return_value.verify.return_value = _mock_verification(passed=False)
            body = (
                await async_client.post(
                    "/api/v1/remediate/verify",
                    json={"patch_diff": "diff", "working_directory": str(tmp_path)},
                )
            ).json()
        assert body["passed"] is False


# ---------------------------------------------------------------------------
# /api/v1/remediate/verify — error paths
# ---------------------------------------------------------------------------


class TestVerifyEndpointErrors:
    async def test_missing_patch_diff_returns_422(
        self, async_client: AsyncClient
    ) -> None:
        resp = await async_client.post("/api/v1/remediate/verify", json={})
        assert resp.status_code == 422

    async def test_timeout_below_minimum_returns_422(
        self, async_client: AsyncClient
    ) -> None:
        resp = await async_client.post(
            "/api/v1/remediate/verify",
            json={"patch_diff": "diff", "timeout_seconds": 5},
        )
        assert resp.status_code == 422

    async def test_timeout_above_maximum_returns_422(
        self, async_client: AsyncClient
    ) -> None:
        resp = await async_client.post(
            "/api/v1/remediate/verify",
            json={"patch_diff": "diff", "timeout_seconds": 700},
        )
        assert resp.status_code == 422

    async def test_internal_error_returns_500(
        self, async_client: AsyncClient, tmp_path: Path
    ) -> None:
        with patch("main.PatchVerifier") as mock_cls:
            mock_cls.return_value.verify.side_effect = RuntimeError("boom")
            resp = await async_client.post(
                "/api/v1/remediate/verify",
                json={"patch_diff": "diff", "working_directory": str(tmp_path)},
            )
        assert resp.status_code == 500
