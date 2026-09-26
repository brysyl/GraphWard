import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="GraphWard AI")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- API ENDPOINTS (Define BEFORE static mounting) ---

@app.api_route("/api/health", methods=["GET", "HEAD"])
def api_health_check():
    return {
        "status": "online",
        "engine": "IBM Bob 2.0 / Qwen-Coder-32B",
        "service": "GraphWard AI Backend",
        "vpc": "Air-Gapped Private VPC",
    }

@app.get("/api/metrics")
def get_metrics():
    return {
        "technical_debt_baseline_usd": 2410000,
        "technical_debt_remediated_usd": 1820000,
        "active_cve_backlog": 14,
        "mttr_reduction_days": 191,
        "zero_breakage_pass_rate_pct": 100.0,
        "active_ast_nodes": 2104,
    }

# --- STATIC FRONTEND MOUNTING ---

# Mount Next.js static build export at root
frontend_build_path = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../frontend/out")
)

if os.path.exists(frontend_build_path):
    app.mount("/", StaticFiles(directory=frontend_build_path, html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
