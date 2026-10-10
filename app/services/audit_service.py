from ..extensions import db
from ..models import AuthenticationEvent, DecisionEvent, SecurityAlert, utcnow


def record_decision(correlation, user_id, event_type, check_name, result, explanation, policy, next_action):
    event = DecisionEvent(
        correlation_id=correlation,
        user_id=user_id,
        event_type=event_type,
        check_name=check_name,
        result=result,
        explanation=explanation[:500],
        policy=policy,
        next_action=next_action,
    )
    db.session.add(event)
    return event


def record_auth_event(
    *, user_id, method, outcome, correlation, decision, risk_score=0,
    device_id=None, ip_address=None, alert_severity=None,
):
    event = AuthenticationEvent(
        user_id=user_id,
        method=method,
        outcome=outcome,
        correlation_id=correlation,
        decision=decision[:500],
        risk_score=risk_score,
        device_id=device_id,
        ip_address=ip_address,
    )
    db.session.add(event)
    db.session.flush()
    if alert_severity:
        db.session.add(SecurityAlert(
            event_id=event.id,
            user_id=user_id,
            severity=alert_severity,
            description=decision[:300],
        ))
    return event


def resolve_alert(alert):
    alert.resolved_at = utcnow()