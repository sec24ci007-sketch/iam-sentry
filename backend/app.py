from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any

app = FastAPI(
    title="IAM-Sentry Control Plane API",
    description="Backend API connecting Delta Engine, Bedrock AI, and Dashboard",
    version="1.0.0"
)

# ------------------------------------------------------------------
# Data Schemas (The Shared Contract Between All Teammates)
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
    Called by Dashboard / Seeding script.
    Coordinates Delta Math Engine + Bedrock AI Agent.
    """
    try:
        # 1. Teammate 1's Hook: Run Deterministic Math Engine
        # delta_result = compute_delta(payload.granted_policy, payload.cloudtrail_events)
        
        # Temporary Mock Data until Teammate 1 connects delta_engine.py
        mock_delta = {
            "total_granted_count": 45,
            "total_used_count": 3,
            "unused_actions": ["s3:DeleteBucket", "dynamodb:*", "sqs:*"],
            "is_overprivileged": True
        }

        # 2. Teammate 2's Hook: Run Amazon Bedrock Risk Scoring & Policy Generator
        # bedrock_result = generate_least_privilege_policy(mock_delta)
        
        # Temporary Mock Data until Teammate 2 connects bedrock_agent.py
        mock_ai_response = {
            "risk_score": "CRITICAL_OVERPRIVILEGED",
            "explanation": "Role is granted full admin access (*), but only called 3 S3 read actions in the last 7 days.",
            "recommended_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:ListBucket"],
                        "Resource": "*"
                    }
                ]
            }
        }

        return {
            "status": "success",
            "role_name": payload.role_name,
            "delta": mock_delta,
            "ai_analysis": mock_ai_response
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/approve")
def approve_and_apply_policy(payload: ApproveRequest):
    """
    Triggered by 1-Click Approve button on Dashboard.
    Applies minimal JSON policy to target AWS IAM role.
    """
    # Teammate 3 hooks this up to update DynamoDB state & trigger AWS IAM apply
    return {
        "status": "REMEDIATED",
        "role_name": payload.role_name,
        "message": f"Successfully applied least-privilege policy to {payload.role_name}"
    }