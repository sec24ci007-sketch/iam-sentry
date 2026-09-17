import React, { useState } from 'react';
import { Shield, AlertTriangle, CheckCircle, Activity } from 'lucide-react';

export default function App() {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState(null);

  const mockPayload = {
    role_name: "Production-DataProcessor-Role",
    granted_policy: {
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "OverPrivilegedAccess",
          Effect: "Allow",
          Action: [
            "s3:GetObject",
            "s3:PutObject",
            "s3:DeleteBucket",
            "dynamodb:*",
            "sqs:*"
          ],
          Resource: "*"
        }
      ]
    },
    cloudtrail_events: [
      { eventSource: "s3.amazonaws.com", eventName: "GetObject" },
      { eventSource: "s3.amazonaws.com", eventName: "PutObject" }
    ]
  };

  const handleAnalyze = async () => {
    setLoading(true);
    try {
      const res = await fetch('http://127.0.0.1:8000/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(mockPayload)
      });
      const result = await res.json();
      setData(result);
    } catch (err) {
      alert("Error connecting to FastAPI backend. Make sure Uvicorn is running on port 8000!");
    } finally {
      setLoading(false);
    }
  };

  const handleApprove = async () => {
    if (!data) return;
    try {
      const res = await fetch('http://127.0.0.1:8000/approve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          role_name: data.role_name,
          recommended_policy: data.ai_analysis.recommended_policy
        })
      });
      const result = await res.json();
      alert(`Remediation Complete! Status: ${result.status}`);
    } catch (err) {
      alert("Error approving policy.");
    }
  };

  return (
    <div style={{ padding: '2rem', fontFamily: 'sans-serif', backgroundColor: '#0f172a', color: '#f8fafc', minHeight: '100vh' }}>
      <header style={{ display: 'flex', alignItems: 'center', gap: '1rem', borderBottom: '1px solid #334155', paddingBottom: '1rem' }}>
        <Shield size={36} color="#38bdf8" />
        <div>
          <h1 style={{ margin: 0, fontSize: '1.5rem' }}>IAM-Sentry Remediation Dashboard</h1>
          <p style={{ margin: 0, color: '#94a3b8', fontSize: '0.875rem' }}>Automated IAM Permission Drift & AI Least-Privilege Generator</p>
        </div>
      </header>

      <main style={{ marginTop: '2rem' }}>
        <button 
          onClick={handleAnalyze} 
          disabled={loading}
          style={{ padding: '0.75rem 1.5rem', backgroundColor: '#0284c7', color: 'white', border: 'none', borderRadius: '0.375rem', cursor: 'pointer', fontWeight: 'bold' }}
        >
          {loading ? "Analyzing Permission Drift..." : "Run Role Scan Simulation"}
        </button>

        {data && (
          <div style={{ marginTop: '2rem', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
            {/* Left Card: Deterministic Engine Output */}
            <div style={{ backgroundColor: '#1e293b', padding: '1.5rem', borderRadius: '0.5rem', border: '1px solid #334155' }}>
              <h2 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#f43f5e' }}>
                <Activity /> Deterministic Math Engine
              </h2>
              <p><strong>Role Target:</strong> {data.role_name}</p>
              <p><strong>Granted Permissions:</strong> {data.delta.total_granted_count}</p>
              <p><strong>Used Permissions (CloudTrail):</strong> {data.delta.total_used_count}</p>
              <p style={{ color: '#fbbf24' }}><strong>Unused Actions Detected:</strong></p>
              <ul>
                {data.delta.unused_actions.map((act, i) => <li key={i}>{act}</li>)}
              </ul>
            </div>

            {/* Right Card: Bedrock AI Reasoning */}
            <div style={{ backgroundColor: '#1e293b', padding: '1.5rem', borderRadius: '0.5rem', border: '1px solid #334155' }}>
              <h2 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#38bdf8' }}>
                <AlertTriangle color="#f59e0b" /> Bedrock AI Remediation
              </h2>
              <p><strong>Risk Score:</strong> <span style={{ color: '#ef4444', fontWeight: 'bold' }}>{data.ai_analysis.risk_score}</span></p>
              <p><strong>Explanation:</strong> {data.ai_analysis.explanation}</p>
              <p><strong>Recommended Least-Privilege Policy:</strong></p>
              <pre style={{ backgroundColor: '#090d16', padding: '1rem', borderRadius: '0.25rem', overflowX: 'auto', fontSize: '0.8rem', color: '#4ade80' }}>
                {JSON.stringify(data.ai_analysis.recommended_policy, null, 2)}
              </pre>

              <button 
                onClick={handleApprove}
                style={{ width: '100%', padding: '0.75rem', backgroundColor: '#22c55e', color: 'white', border: 'none', borderRadius: '0.375rem', cursor: 'pointer', fontWeight: 'bold', marginTop: '1rem', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}
              >
                <CheckCircle size={18} /> Approve & Apply Remediation Policy
              </button>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}