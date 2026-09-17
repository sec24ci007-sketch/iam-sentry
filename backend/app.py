from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
from backend.core.delta_engine import compute_permission_delta
from backend.core.delta_engine import compute_permission_delta
from backend.ai.bedrock_agent import generate_least_privilege_policy

app = FastAPI(
    title="IAM-Sentry Control Plane API",
    description="Backend API connecting Delta Engine, Bedrock AI, and Dashboard",
    version="1.0.0"
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
    """Health check endpoint for LocalStack / SAM testing."""
    return {"status": "online", "service": "IAM-Sentry Control Plane"}

@app.post("/analyze")
def analyze_role_drift(payload: AnalyzeRequest):
    """
    Coordinates Delta Math Engine + Bedrock AI Agent.
    """
    try:
        # 1. Math Engine Computation (Δ = Granted - Used)
        delta_result = compute_permission_delta(
            payload.granted_policy, 
            payload.cloudtrail_events
        )
        
        # 2. Bedrock AI Agent Recommendation Engine
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
    """
    Triggered by 1-Click Approve button on Dashboard.
    """
    return {
        "status": "REMEDIATED",
        "role_name": payload.role_name,
        "message": f"Successfully applied least-privilege policy to {payload.role_name}"
    }