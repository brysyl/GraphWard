import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

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

@app.get("/api/health")
def health_check():
    return {
        "status": "online",
        "engine": "IBM Bob 2.0 / Qwen-Coder-32B",
        "service": "GraphWard AI Backend",
        "vpc": "Air-Gapped Private VPC"
    }

@app.get("/api/metrics")
def get_metrics():
    return {
        "technical_debt_baseline_usd": 2410000,
        "technical_debt_remediated_usd": 1820000,
        "active_cve_backlog": 14,
        "mttr_reduction_days": 191,
        "zero_breakage_pass_rate_pct": 100.0,
        "active_ast_nodes": 2104
    }

# --- STATIC FRONTEND MOUNTING ---

# Path to Next.js exported static build
FRONTEND_OUT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../frontend/out"))

if os.path.exists(FRONTEND_OUT_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_OUT_DIR, html=True), name="static")
else:
    @app.get("/")
    def read_root():
        return {"status": "backend online", "message": "Frontend build directory not found"}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
# Render deployment trigger stamp
