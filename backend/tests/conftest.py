"""
Shared pytest fixtures for the GraphWard backend test suite.
"""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

# ---------------------------------------------------------------------------
# sys.path bootstrap — ensure the backend package root is importable
# ---------------------------------------------------------------------------
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from main import app  # noqa: E402


# ---------------------------------------------------------------------------
# Source-file fixture helpers
# ---------------------------------------------------------------------------

CLEAN_SOURCE = textwrap.dedent("""\
    def greet(name: str) -> str:
        return f"Hello, {name}"

    async def fetch(url: str) -> str:
        return url
""")

COMPLEX_SOURCE = textwrap.dedent("""\
    def complex_func(x, y, z):
        if x > 0:
            for i in range(y):
                if i % 2 == 0:
                    pass
                else:
                    pass
        elif y > 0:
            while z > 0:
                z -= 1
        try:
            result = x / y
        except ZeroDivisionError:
            result = 0
        return result
""")

DANGEROUS_SOURCE = textwrap.dedent("""\
    import pickle
    import yaml
    import os

    def run_evil():
        data = eval("1 + 1")
        obj = pickle.loads(b"gASV...")
        yaml.load("key: value")
        os.system("ls")
""")

SECRET_SOURCE = textwrap.dedent("""\
    api_key = "sk-supersecret1234567890"
    password = "hunter2password"

    def use_creds():
        pass
""")

SYNTAX_ERROR_SOURCE = "def broken(\n    # unclosed paren\n"


# ---------------------------------------------------------------------------
# Filesystem fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_src(tmp_path: Path) -> Path:
    """A temp directory containing a clean Python source tree."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "greet.py").write_text(CLEAN_SOURCE, encoding="utf-8")
    (src / "complex.py").write_text(COMPLEX_SOURCE, encoding="utf-8")
    return src


@pytest.fixture()
def tmp_src_dangerous(tmp_path: Path) -> Path:
    """Temp source directory with dangerous-call patterns."""
    src = tmp_path / "dangerous"
    src.mkdir()
    (src / "evil.py").write_text(DANGEROUS_SOURCE, encoding="utf-8")
    return src


@pytest.fixture()
def tmp_src_secrets(tmp_path: Path) -> Path:
    """Temp source directory with hardcoded secrets."""
    src = tmp_path / "secrets"
    src.mkdir()
    (src / "config.py").write_text(SECRET_SOURCE, encoding="utf-8")
    return src


@pytest.fixture()
def tmp_src_mixed(tmp_path: Path) -> Path:
    """Temp source dir with clean, dangerous, and broken files."""
    src = tmp_path / "mixed"
    src.mkdir()
    (src / "clean.py").write_text(CLEAN_SOURCE, encoding="utf-8")
    (src / "evil.py").write_text(DANGEROUS_SOURCE, encoding="utf-8")
    (src / "broken.py").write_text(SYNTAX_ERROR_SOURCE, encoding="utf-8")
    return src


# ---------------------------------------------------------------------------
# HTTP client fixture (FastAPI integration)
# ---------------------------------------------------------------------------


@pytest.fixture()
async def async_client() -> AsyncClient:  # type: ignore[override]
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield client
