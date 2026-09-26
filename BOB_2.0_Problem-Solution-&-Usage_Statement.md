
# 🎯 Problem & Solution Statement

> **Project Title:** GraphWard AI  
> **Tagline:** Autonomous Topological Code Remediation & AST Control Room  
> **Submission Deliverable:** *Word Count: 340 words — Max Limit: 500 words*

---

## Problem Statement

Modern enterprise software engineering suffers from severe security triage friction and cascade breakage during code remediation. As codebases scale, structural technical debt and indirect dependency vulnerabilities (OWASP Top 10, CVEs, type-contract mismatches) compound rapidly. Traditional Static Application Security Testing (SAST) linters operate on isolated file snippets without true topological awareness. Consequently, developers spend hours manually tracing call graphs across hundreds of modules to assess whether a vulnerability is reachable or if applying a quick fix will trigger downstream cascade failures. Current AI coding assistants exacerbate this by generating localized patches in a vacuum—frequently introducing regression bugs, breaking API contracts, or failing to verify AST-level dependencies. The core bottleneck is the absence of an integrated, epistemic control plane that combines deterministic structural parsing with agentic, context-aware remediation.

## Solution Statement

GraphWard AI addresses this challenge by functioning as an autonomous code remediation control room powered by Abstract Syntax Tree (AST) parsing, Open Knowledge Graph (OKG) topological mapping, and real-time visual orchestration.

GraphWard AI transforms raw source code into a dynamic, queryable knowledge graph:

* **Deterministic AST Parsing & Mapping:** GraphWard ingests multi-language repositories, extracting functions, imports, class hierarchies, and execution paths to construct a high-fidelity topological map of the entire codebase.
* **Impact & Vulnerability Surface Analysis:** Rather than raising isolated text alerts, GraphWard calculates reachability paths and vulnerability radius scores across the AST topology, immediately highlighting critical security gaps and structural bottlenecks.
* **Cascade-Aware Patching:** Using AI agent orchestration, GraphWard generates precision remediation patches. Before applying fixes, it evaluates downstream call chains to guarantee that modifications do not break external dependencies or contract types.
* **Interactive Command Center:** Built with FastAPI and a responsive Next.js/React Flow frontend, developers visually inspect node dependencies, run automated test harnesses, preview terminal diffs, and execute verified fixes in real time.

GraphWard AI bridges the gap between static analysis and autonomous engineering—reducing security triage from hours to seconds and giving developers absolute confidence in automated code repair.


---

---


# 🤖 IBM Bob 2.0 Usage Statement

> **Submission Deliverable** - *Word Count: 340 words — Max Limit: 500 words*

---

## Engineering GraphWard AI with IBM Bob 2.0 Agentic Orchestration

IBM Bob 2.0 served as the central AI development partner, system architect, and execution engine throughout the creation of **GraphWard AI**. By leveraging Bob 2.0’s full repository context, multi-file Agent Mode, and subagent parallel task processing, we designed, implemented, and validated an enterprise-grade full-stack application within 48 hours.

### Full Repository Context & Architectural Alignment
Navigating a dual-workspace repository containing both a FastAPI/Python backend (`/backend`) and a Next.js 14/TypeScript frontend (`/frontend`) requires deep contextual awareness. Bob 2.0 analyzed the end-to-end repository structure, allowing us to enforce strict API contracts and shared data models across both environments. When designing our AST parsing pipeline and React Flow graph state schemas, Bob 2.0 mapped backend Pydantic models directly to TypeScript interfaces without manual translation errors.

### Agent Mode & Autonomous Bug Remediation
Bob 2.0’s Agent Mode was pivotal in implementing complex features and resolving environment-specific test suite regressions. During frontend testing with Jest, Bob 2.0 identified an unhandled JSDOM browser API limitation (`scrollIntoView` undefined in headless DOM testing), modified `jest.setup.ts`, injected the global stub mock, and rerun `npm test` until all component unit tests passed cleanly. In the backend, Bob 2.0 refactored Uvicorn process lifecycle bindings, configured multi-interface host networking (`0.0.0.0:8000`), and generated OpenAPI route signatures for health and telemetry checks.

### Subagent Parallel Execution & Workflow Acceleration
By dispatching concurrent subagent tasks, Bob 2.0 executed parallel workflows:

* **Subagent A:** Architected AST parsing routines and network graph construction algorithms using Python's `ast` module.
* **Subagent B:** Constructed custom node rendered components and control room UI states in Next.js.
* **Subagent C:** Configured Docker build steps, Jest harness setups, and deployment configs.

Without Bob 2.0’s deep codebase reasoning, implementing deterministic AST parsing alongside an interactive graph visualization UI would have taken weeks. Bob 2.0 reduced our manual dev effort by over 80%, demonstrating how AI partners drive complex software engineering tasks from concept to verified execution.


---
