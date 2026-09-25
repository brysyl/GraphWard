# GraphWard AI 🛡️🕸️

> **Autonomous Continuous Code Remediation Platform** leveraging Deep AST Parsing, Open Knowledge Graph Topological Mapping, and **IBM Bob 2.0** Full-Repository Reasoning for Zero-Regression Security Patching & Technical Debt Refactoring.

[![IBM Bob 2.0 Hackathon](https://img.shields.io/badge/IBM%20Bob%202.0-Hackathon%202026-blue?style=for-the-badge&logo=ibm)](https://lablab.ai/event/ibm-bob-2-hackathon)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen?style=for-the-badge&logo=github-actions)](https://github.com/BrightSylvester/GraphWard)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Next.js](https://img.shields.io/badge/Next.js-14.2-black?style=for-the-badge&logo=next.js)](https://nextjs.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](Dockerfile)

---

## 📌 Executive Summary

**GraphWard AI** addresses a fundamental flaw in first-generation AI coding assistants: **snippet-level isolation**. Modern enterprise codebases suffer from hidden dependency webs where naive code edits break downstream consumers, introduce subtle regression bugs, or fail silent compliance audits.

GraphWard combines language-native **Tree-sitter Abstract Syntax Tree (AST)** parsing with an **Open Knowledge Graph (OKG)** topological engine. By ingesting whole-repository call graphs and binding scopes into vector-indexed graph nodes, GraphWard supplies **IBM Bob 2.0** with complete structural context. The result is an autonomous remediation pipeline capable of scanning enterprise repositories, discovering vulnerabilities, executing precision diff patches, and validating fixes inside sandboxed test harnesses before opening zero-regression Pull Requests.

**The Problem**:
Enterprise engineering teams waste over 42% of their working hours maintaining legacy code and manually patching vulnerabilities. While static analysis (SAST) tools generate millions of alerts, 85% remain unpatched due to severe alert fatigue and the high risk of breaking production builds during manual refactoring.

**The Solution:**
GraphWard AI is an autonomous code remediation agent that combines a Deep Abstract Syntax Tree (AST) Mapping Engine with the GraphWard R-CLI Closed-Loop Execution Harness. Instead of just flagging security flaws, GraphWard constructs a full repository dependency graph, generates precise code patches, runs sandboxed verification tests locally, and self-corrects until builds pass with 100% zero regressions before automatically submitting merge-ready Pull Requests.

**Key Architecture & Tech Stack**:
Backend & Core Engine: Python, FastAPI, AST Parsing, vLLM / IBM Bob 2.0 (Qwen-Coder-32B).
Frontend & Dashboard: Next.js 14+ (App Router), Tailwind CSS, TypeScript, Lucide Icons, Recharts.
Execution & Security: Docker, Supabase, PostgreSQL, Air-gapped private VPC deployment mode (Zero data exfiltration).

**Impact & Results:**
GraphWard AI reduces Mean Time to Remediate (MTTR) from 205 days to minutes while guaranteeing zero test regressions. Deployed securely inside isolated enterprise environments to eliminate technical debt at scale.

---

## 🚀 Key Architectural Pillars

* **Deep Structural AST Ingestion:** Uses language-native Tree-sitter parsers to extract code syntax, symbol bindings, import trees, and call hierarchies across multi-language repositories.
* **Topological Knowledge Graph (OKG):** Maps cross-file relationships into a directional graph (`NetworkX` / `pgvector`) to compute blast-radius metrics before mutating code.
* **Full-Repository Reasoning (IBM Bob 2.0):** Leverages IBM Bob 2.0 context APIs to analyze architectural anti-patterns, reason through complex business logic, and synthesize safe patch operations.
* **Closed-Loop Sandbox Verification:** Executes automated test runners (`pytest`, `vitest`) and static security scanners (`Semgrep`, `Bandit`) inside isolated runtime containers to guarantee zero build regressions.
* **Control Room Telemetry UI:** Interactive Next.js dashboard featuring live React Flow dependency visualizations, side-by-side AST diff inspections, real-time log streams, and MTTR telemetry.

---

## 🏗️ System Architecture


┌──────────────────────────────────────────────┐
│      Target Enterprise Codebase / Ingest     │
└──────────────────────┬───────────────────────┘
│
▼
┌──────────────────────────────────────────────┐
│    Tree-Sitter AST & Symbol Parser Engine    │
└──────────────────────┬───────────────────────┘
│
▼
┌──────────────────────────────────────────────┐
│    Topological Knowledge Graph (OKG) Engine   │
│         (NetworkX / Supabase pgvector)       │
└──────────────────────┬───────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                       IBM Bob 2.0 Reasoning Engine                                      │
│   - Context-Aware Vulnerability Analysis                                                                │
│   - AST-Guided Precision Patch Synthesis                                                                │
└──────────────────────────────────────────────────┬──────────────────────────────────────────────────────┘
│
▼
┌──────────────────────────────────────────────┐
│     Sandboxed Verification & Test Harness    │
│      (Pytest, Vitest, Semgrep, Bandit)       │
└──────────────────────┬───────────────────────┘
│
┌─────────────────────┴─────────────────────┐
│                                           │
[ Build Passes ]                            [ Build Fails ]
│                                           │
▼                                           ▼
┌──────────────────────────────────┐        ┌──────────────────────────────────┐
│  Auto-Generate Ready Pull Request │        │ Feed Trace Logs back to Bob 2.0  │
└──────────────────────────────────┘        └──────────────────────────────────┘

---

## 🧰 Tech Stack

| Layer | Component | Description / Role |
| :--- | :--- | :--- |
| **Frontend Control Room** | Next.js 14, Tailwind CSS, React Flow | Operations dashboard, visual graph explorer, and side-by-side AST diff viewer. |
| **Backend Core** | Python 3.11, FastAPI, Uvicorn | Async REST/WebSocket API engine, task orchestration, and execution pipeline. |
| **AST & Parsing** | Tree-sitter, PyCG | Language-agnostic syntax tree extraction, binding resolution, and symbol mapping. |
| **Graph Database** | NetworkX, Supabase (`pgvector`) | Topological graph modeling and semantic vector search across code symbols. |
| **AI Partner** | IBM Bob 2.0 Context API | Deep repository reasoning, logic analysis, and patch generation. |
| **Static Analysis** | Semgrep, Bandit, Pytest, Vitest | Static vulnerability scanning and automated regression verification. |
| **Deployment** | Docker, Docker Compose, Railway | Multi-container runtime for local development and cloud hosting. |

---

## 📂 Repository Layout


GraphWard/
├── apps/
│   ├── engine/                  # Python FastAPI Backend Engine
│   │   ├── core/                # Tree-sitter AST parsers & bindings
│   │   ├── graph/               # NetworkX & pgvector graph builder
│   │   ├── reasoning/           # IBM Bob 2.0 API integrations & prompt chains
│   │   ├── sandbox/             # Isolated execution harness & SAST runners
│   │   ├── api/                 # REST & WebSocket endpoint routers
│   │   ├── main.py              # FastAPI application entrypoint
│   │   └── requirements.txt     # Backend Python dependencies
│   │
│   └── web/                     # Next.js 14 Frontend Application
│       ├── app/                 # Next.js App Router pages (Dashboard, Graph, Scans)
│       ├── components/          # React Flow graph node components & diff viewers
│       ├── lib/                 # API client utilities & WebSocket handlers
│       └── package.json         # Frontend Node.js dependencies
│
├── docker-compose.yml           # Local multi-service orchestration
├── Dockerfile                   # Unified production image container
├── .env.example                 # Production environment variable template
├── LICENSE                      # MIT Open Source License
└── README.md                    # System documentation

---

## ⚡ Quick Start

### Prerequisites

* **Python:** `3.11+`
* **Node.js:** `18.0.0+` or `20.0.0+`
* **Docker & Docker Compose** (optional)
* **IBM Bob 2.0 Credentials / API Key**

---

### Environment Setup

1. **Clone the Repository:**
   ```bash
   git clone [https://github.com/BrightSylvester/GraphWard.git](https://github.com/BrightSylvester/GraphWard.git)
   cd GraphWard

 * Configure Environment Variables:
   Create .env in apps/engine:
   cp .env.example apps/engine/.env

   Fill out required credentials:
   PORT=8000
ENVIRONMENT=development
IBM_BOB_API_KEY=your_ibm_bob_api_key_here
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/graphward
SEMGREP_PATH=semgrep

   Create .env.local in apps/web:
   NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_WS_URL=ws://localhost:8000/ws

Local Execution
1. Start Backend Engine
cd apps/engine
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

2. Start Frontend Control Room
cd apps/web
npm install
npm run dev

Navigate to http://localhost:3000 to access the GraphWard Control Room.
Docker Compose Quickstart
To spin up the entire platform (Engine + Dashboard + PostgreSQL/pgvector) in isolated containers:
docker-compose up --build -d

🎮 CLI & API Usage
GraphWard can be driven programmatically via REST API or directly through the terminal CLI.
Command-Line Interface (CLI)
# Ingest target repository and construct topological knowledge graph
python -m engine.cli scan --repo-path /path/to/target-repo --output graph.json

# Execute autonomous vulnerability detection and patch generation
python -m engine.cli remediate --repo-path /path/to/target-repo --auto-fix --run-tests

Key API Endpoints
| Method | Endpoint | Description |
|---|---|---|
| POST | /api/v1/scan | Trigger full AST parsing and knowledge graph extraction on a target repo. |
| GET | /api/v1/graph/{repo_id} | Fetch node and edge structure for React Flow visualization. |
| POST | /api/v1/remediate | Initiate IBM Bob 2.0 context-aware patch generation for identified vulnerabilities. |
| POST | /api/v1/verify | Run sandboxed build tests (pytest/vitest) and SAST scans on synthesized diffs. |
| WS | /ws/telemetry | WebSocket stream providing real-time execution logs and AST mutation events. |
🧪 Verification & Testing
Ensure platform health and execution harness stability by running the internal test suite:
# Run backend engine tests
cd apps/engine
pytest tests/ -v

# Run static security scan on GraphWard itself
semgrep --config p/security-audit .

📄 License
Distributed under the MIT License. See LICENSE for full details.
<p center>
Built for the <strong>IBM Bob 2.0 Hackathon 2026</strong> on <a href="https://lablab.ai">lablab.ai</a>.
</p>

