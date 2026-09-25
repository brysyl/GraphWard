"""
GraphWard AI — Control Room API
Exposes AST analysis and patch verification endpoints.
"""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

import uvicorn
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from core.ast_parser import ASTParser, ASTAnalysisResult
from core.verifier import PatchVerifier, VerificationResult

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("graphward.api")


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("GraphWard Control Room starting up…")
    yield
    logger.info("GraphWard Control Room shutting down.")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="GraphWard AI",
    description="Autonomous code remediation platform — Control Room API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://graphward.ai"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------
class AnalyzeRequest(BaseModel):
    target_directory: str = Field(
        ...,
        description="Absolute or relative path to the Python source directory to analyse.",
        examples=["/repo/src"],
    )
    max_depth: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum recursion depth for call-graph traversal.",
    )
    include_tests: bool = Field(
        default=False,
        description="Whether to include test files in the AST scan.",
    )


class VerifyRequest(BaseModel):
    patch_diff: str = Field(
        ...,
        description="Unified diff string representing the AST-derived patch to apply.",
    )
    test_directory: str = Field(
        default="tests",
        description="Path to the pytest test suite to run after patching.",
    )
    timeout_seconds: int = Field(
        default=120,
        ge=10,
        le=600,
        description="Hard timeout for the sandboxed test run.",
    )
    working_directory: str = Field(
        default=".",
        description="Root directory in which the patch and tests reside.",
    )


# ---------------------------------------------------------------------------
# Middleware — request timing
# ---------------------------------------------------------------------------
@app.middleware("http")
async def add_process_time_header(request: Request, call_next: Any) -> Any:
    start = time.perf_counter()
    response = await call_next(request)
    elapsed = time.perf_counter() - start
    response.headers["X-Process-Time"] = f"{elapsed:.4f}s"
    return response


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/health", tags=["ops"], summary="Liveness probe")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "graphward-control-room"}


# ---------------------------------------------------------------------------
# API v1 — AST Analysis
# ---------------------------------------------------------------------------
@app.post(
    "/api/v1/ast/analyze",
    response_model=ASTAnalysisResult,
    status_code=status.HTTP_200_OK,
    tags=["ast"],
    summary="Parse a source directory and return an annotated AST call graph with CVE flags",
)
async def analyze_ast(payload: AnalyzeRequest) -> ASTAnalysisResult:
    logger.info("AST analysis requested for '%s'", payload.target_directory)
    try:
        parser = ASTParser(
            max_depth=payload.max_depth,
            include_tests=payload.include_tests,
        )
        result = parser.analyze(payload.target_directory)
        logger.info(
            "AST analysis complete — %d nodes, %d CVE flags",
            result.total_nodes,
            len(result.cve_flags),
        )
        return result
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target directory not found: {exc}",
        ) from exc
    except Exception as exc:
        logger.exception("AST analysis failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc


# ---------------------------------------------------------------------------
# API v1 — Patch Verification
# ---------------------------------------------------------------------------
@app.post(
    "/api/v1/remediate/verify",
    response_model=VerificationResult,
    status_code=status.HTTP_200_OK,
    tags=["remediation"],
    summary="Apply a patch diff, run the test suite in a sandbox, and return a verification report",
)
async def verify_patch(payload: VerifyRequest) -> VerificationResult:
    logger.info("Patch verification requested in '%s'", payload.working_directory)
    try:
        verifier = PatchVerifier(
            working_directory=payload.working_directory,
            test_directory=payload.test_directory,
            timeout_seconds=payload.timeout_seconds,
        )
        result = verifier.verify(payload.patch_diff)
        logger.info(
            "Verification complete — passed=%s tests=%d/%d",
            result.passed,
            result.tests_passed,
            result.tests_total,
        )
        return result
    except Exception as exc:
        logger.exception("Patch verification failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
