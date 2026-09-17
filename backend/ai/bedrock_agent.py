import json
import boto3
from typing import Dict, Any

def generate_least_privilege_policy(delta_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calls Amazon Bedrock to calculate risk scores and format clean least-privilege IAM policies.
    Includes a local fallback if running offline without AWS credentials.
    """
    used_actions = delta_data.get("used_actions", [])
    unused_actions = delta_data.get("unused_actions", [])
    is_overprivileged = delta_data.get("is_overprivileged", False)

    # 1. Fallback / Mock behavior if running without live Bedrock API access during local dev
    if not is_overprivileged:
        return {
            "risk_score": "LOW",
            "explanation": "Role permissions tightly align with CloudTrail usage history.",
            "recommended_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": used_actions if used_actions else ["s3:GetObject"],
                        "Resource": "*"
                    }
                ]
            }
        }

    # Construct clean default actions from CloudTrail if available
    safe_actions = used_actions if used_actions else ["s3:GetObject", "s3:ListBucket"]

    prompt_payload = f"""
    You are an AWS IAM Security Expert. Analyze this permission drift data:
    - Actions Used in CloudTrail: {used_actions}
    - Actions Granted but Unused: {unused_actions}

    Provide output in strict JSON format with keys:
    "risk_score" ("CRITICAL_OVERPRIVILEGED", "HIGH", "MEDIUM", "LOW"),
    "explanation" (1 concise sentence describing the risk),
    "recommended_policy" (Valid AWS IAM JSON policy restricting access ONLY to used actions).
    """

    try:
        # Initialize AWS Bedrock Runtime Client
        bedrock = boto3.client(service_name="bedrock-runtime", region_name="us-east-1")
        
        body = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 500,
            "messages": [
                {"role": "user", "content": prompt_payload}
            ]
        })

        response = bedrock.invoke_model(
            modelId="anthropic.claude-3-haiku-20240307-v1:0",
            body=body
        )
        
        response_body = json.loads(response.get("body").read())
        ai_text = response_body["content"][0]["text"]
        return json.loads(ai_text)

    except Exception:
        # Graceful fallback for local development without live AWS Bedrock keys
        return {
            "risk_score": "CRITICAL_OVERPRIVILEGED",
            "explanation": f"Role is granted {len(unused_actions)} unused actions (including wildcards). Restricted to active CloudTrail events.",
            "recommended_policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "IAM-SentryAutoRemediated",
                        "Effect": "Allow",
                        "Action": safe_actions,
                        "Resource": "*"
                    }
                ]
            }
        }