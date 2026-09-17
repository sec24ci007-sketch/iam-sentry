import json
import requests

# Local FastAPI endpoint URL
API_URL = "http://127.0.0.1:8000/analyze"

# Over-privileged IAM Policy (Granted)
MOCK_GRANTED_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "OverPrivilegedAccess",
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteBucket",
                "dynamodb:*",
                "sqs:*"
            ],
            "Resource": "*"
        }
    ]
}

# Active CloudTrail Events (Only S3 read/write was actually used)
MOCK_CLOUDTRAIL_LOGS = [
    {"eventSource": "s3.amazonaws.com", "eventName": "GetObject"},
    {"eventSource": "s3.amazonaws.com", "eventName": "GetObject"},
    {"eventSource": "s3.amazonaws.com", "eventName": "PutObject"}
]

def run_simulation():
    """Seeds test IAM policy and CloudTrail logs to test the complete pipeline."""
    payload = {
        "role_name": "Production-DataProcessor-Role",
        "granted_policy": MOCK_GRANTED_POLICY,
        "cloudtrail_events": MOCK_CLOUDTRAIL_LOGS
    }

    print("🚀 Sending simulation payload to IAM-Sentry Control Plane...")
    try:
        response = requests.post(API_URL, json=payload)
        if response.status_code == 200:
            print("✅ Analysis Complete! Engine Output:\n")
            print(json.dumps(response.json(), indent=2))
        else:
            print(f"❌ API Error {response.status_code}: {response.text}")
    except Exception as e:
        print(f"❌ Could not connect to API at {API_URL}. Is Uvicorn running?\nError: {e}")

if __name__ == "__main__":
    run_simulation()