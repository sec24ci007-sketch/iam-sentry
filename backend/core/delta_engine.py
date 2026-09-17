from typing import List, Dict, Any, Set

def parse_policy_actions(granted_policy: Dict[str, Any]) -> Set[str]:
    """Extracts all explicit actions allowed in an IAM JSON Policy."""
    actions = set()
    statements = granted_policy.get("Statement", [])
    
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect") == "Allow":
            stmt_actions = stmt.get("Action", [])
            if isinstance(stmt_actions, str):
                actions.add(stmt_actions)
            elif isinstance(stmt_actions, list):
                actions.update(stmt_actions)
                
    return actions


def parse_cloudtrail_actions(cloudtrail_events: List[Dict[str, Any]]) -> Set[str]:
    """Extracts unique API actions called in CloudTrail logs (e.g., 's3:GetObject')."""
    used_actions = set()
    for event in cloudtrail_events:
        service_source = event.get("eventSource", "").split(".")[0] # e.g. "s3.amazonaws.com" -> "s3"
        event_name = event.get("eventName", "") # e.g. "GetObject"
        if service_source and event_name:
            used_actions.add(f"{service_source}:{event_name}")
    return used_actions


def compute_permission_delta(granted_policy: Dict[str, Any], cloudtrail_events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Core Deterministic Formula: Delta = Granted - Used
    Calculates exact over-privileged action drift.
    """
    granted_actions = parse_policy_actions(granted_policy)
    used_actions = parse_cloudtrail_actions(cloudtrail_events)

    # Expand full wildcards (*) for basic calculation flagging
    is_admin = "*" in granted_actions or "*:*" in granted_actions

    if is_admin:
        # If full admin, unused actions are all uncalled AWS services
        unused_actions = ["* (Full Admin Access Granted)"]
        overprivileged = True
    else:
        # Exact Math Set Difference: Δ = Granted - Used
        unused_actions = list(granted_actions - used_actions)
        overprivileged = len(unused_actions) > 0

    return {
        "granted_actions": list(granted_actions),
        "used_actions": list(used_actions),
        "unused_actions": unused_actions,
        "is_overprivileged": overprivileged,
        "total_granted_count": len(granted_actions) if not is_admin else 999,
        "total_used_count": len(used_actions)
    }