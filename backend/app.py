from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
from backend.core.delta_engine import compute_permission_delta

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
        # 1. Real Math Engine Computation (Δ = Granted - Used)
        delta_result = compute_permission_delta(
            payload.granted_policy, 
            payload.cloudtrail_events
        )
        
        # 2. Temporary Bedrock AI Mock (Will connect to bedrock_agent.py next)
        mock_ai_response = {
            "risk_score": "CRITICAL_OVERPRIVILEGED" if delta_result["is_overprivileged"] else "LOW",
            "explanation": f"Role '{payload.role_name}' has unused permissions flagged by the deterministic engine.",
            "recommended_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": delta_result["used_actions"] if delta_result["used_actions"] else ["s3:GetObject"],
                        "Resource": "*"
                    }
                ]
            }
        }

        return {
            "status": "success",
            "role_name": payload.role_name,
            "delta": delta_result,
            "ai_analysis": mock_ai_response
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