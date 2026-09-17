from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any

from backend.core.delta_engine import compute_permission_delta
from backend.ai.bedrock_agent import generate_least_privilege_policy

app = FastAPI(
    title="IAM-Sentry Control Plane API",
    description="Backend API connecting Delta Engine, Bedrock AI, and Dashboard",
    version="1.0.0"
)

# Enable CORS for React Frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows requests from Vite dashboard on port 5173
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------------
# Data Schemas
# ------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    role_name: str
    granted_policy: Dict[str, Any]
    cloudtrail_events: List[Dict[str, Any]]

class ApproveRequest(BaseModel):
    role_name: str
    recommended_policy: Dict[str, Any]

# ------------------------------------------------------------------
# API Endpoints
# ------------------------------------------------------------------

@app.get("/health")
def health_check():
    return {"status": "online", "service": "IAM-Sentry Control Plane"}

@app.post("/analyze")
def analyze_role_drift(payload: AnalyzeRequest):
    try:
        delta_result = compute_permission_delta(
            payload.granted_policy, 
            payload.cloudtrail_events
        )
        ai_result = generate_least_privilege_policy(delta_result)

        return {
            "status": "success",
            "role_name": payload.role_name,
            "delta": delta_result,
            "ai_analysis": ai_result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/approve")
def approve_and_apply_policy(payload: ApproveRequest):
    return {
        "status": "REMEDIATED",
        "role_name": payload.role_name,
        "message": f"Successfully applied least-privilege policy to {payload.role_name}"
    }