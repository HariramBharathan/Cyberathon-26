import base64
import io
import re
import uuid
from datetime import timedelta

import qrcode
from flask import Blueprint, current_app, g, jsonify, request
from sqlalchemy import func, update

from ..extensions import db, limiter
from ..models import (
    AuthenticationEvent,
    DecisionEvent,
    OTPChallenge,
    QRLoginRequest,
    SecurityAlert,
    SessionRecord,
    TrustedDevice,
    User,
    as_utc,
    utc_iso,
    utcnow,
)
from ..risk_engine import RiskPolicy, evaluate_risk
from ..services import audit_service
from ..services.device_service import (
    enroll_current_device,
    is_current_device_cookie,
    rename_device,
    revoke_device,
    set_device_cookie,
)
from ..services.otp_service import OTPError, OTPThrottle, consume_challenge, create_challenge
from ..services.security import (
    browser_summary,
    correlation_id,
    normalized_email,
    normalized_phone,
    new_token,
    secure_equal,
    token_hash,
)
from ..services.session_service import (
    DEVICE_COOKIE,
    PENDING_COOKIE,
    SESSION_COOKIE,
    api_login_required,
    clear_session_cookie,
    issue_session,
    set_session_cookie,
)

api = Blueprint("api", __name__)


def success(data=None, status=200):
    return jsonify({"ok": True, "data": data or {}}), status


def failure(code, message, status=400, details=None):
    error = {"code": code, "message": message}
    if details:
        error["details"] = details
    return jsonify({"ok": False, "error": error}), status


def body_json():
    return request.get_json(silent=True) or {}


def safe_user(user):
    return {
        "id": user.id,
        "full_name": user.full_name,
        "email": user.email,
        "phone": user.phone,
        "email_verified": user.email_verified,
        "phone_verified": user.phone_verified,
        "status": user.status,
        "created_at": utc_iso(user.created_at),
    }


def policy_from_config():
    return RiskPolicy(
        low_max=current_app.config["RISK_LOW_MAX"],
        medium_max=current_app.config["RISK_MEDIUM_MAX"],
    )


def recent_failures(user_id):
    cutoff = utcnow() - timedelta(minutes=15)
    return AuthenticationEvent.query.filter(
        AuthenticationEvent.user_id == user_id,
        AuthenticationEvent.outcome.in_(("failed", "denied", "rejected")),
        AuthenticationEvent.created_at >= cutoff,
    ).count()


def timeline(correlation, user_id, event_type, check_name, result, explanation, policy, next_action):
    return audit_service.record_decision(
        correlation, user_id, event_type, check_name, result,
        explanation, policy, next_action,
    )


def log_auth(user_id, method, outcome, correlation, decision, risk_score=0,
             device_id=None, severity=None):
    return audit_service.record_auth_event(
        user_id=user_id,
        method=method,
        outcome=outcome,
        correlation=correlation,
        decision=decision,
        risk_score=risk_score,
        device_id=device_id,
        ip_address=request.remote_addr,
        alert_severity=severity,
    )


def auth_response(user, method, correlation, decision, device=None):
    raw_token, _record = issue_session(user, device)
    db.session.commit()
    from flask import session
    session.clear()
    response, status = success({
        "authenticated": True,
        "user": safe_user(user),
        "next": "/app",
        "correlation_id": correlation,
        "decision": decision,
    })
    set_session_cookie(response, raw_token)
    if g.get("revoked_device_cookie"):
        response.delete_cookie(DEVICE_COOKIE, path="/", httponly=True, samesite="Lax")
    return response, status


@api.post("/register")
@limiter.limit("5 per hour")
def register():
    payload = body_json()
    name = str(payload.get("full_name", "")).strip()
    email = normalized_email(str(payload.get("email", "")))
    phone = normalized_phone(str(payload.get("phone", ""))) if payload.get("phone") else None
    if not 2 <= len(name) <= 120:
        return failure("invalid_name", "Enter a name between 2 and 120 characters.")
    if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        return failure("invalid_email", "Enter a valid email address.")
    if phone and not re.fullmatch(r"\+?[0-9]{7,15}", phone):
        return failure("invalid_phone", "Enter a valid phone number with country code.")
    if User.query.filter_by(email=email).first() or (phone and User.query.filter_by(phone=phone).first()):
        return failure("registration_unavailable", "An account could not be created with those details.", 409)
    user = User(full_name=name, email=email, phone=phone, status="pending")
    db.session.add(user)
    try:
        db.session.flush()
        challenge = create_challenge(user, "verify_email", "email")
        db.session.commit()
    except OTPThrottle as error:
        db.session.rollback()
        return failure("rate_limited", str(error), 429)
    except (OTPError, RuntimeError):
        db.session.rollback()
        current_app.logger.exception("Registration verification delivery failed")
        return failure("delivery_unavailable", "Verification could not be sent. Try again later.", 503)
    message = (
        "Development mode: check the terminal running Flask for your verification code. "
        "The account is not active until verified."
        if current_app.config["DEVELOPMENT"] and not current_app.config.get("MAIL_SERVER")
        else "Check your email for a verification code. The account is not active until verified."
    )
    return success({
        "message": message,
        "challenge_id": challenge.id,
        "expires_in": current_app.config["OTP_TTL_SECONDS"],
    }, 201)


@api.post("/otp/request")
@limiter.limit("6 per minute; 20 per hour")
def otp_request():
    payload = body_json()
    purpose = str(payload.get("purpose", "login"))
    destination_type = str(payload.get("method", "email"))
    value = str(payload.get("destination", "")).strip()
    if purpose not in {"login", "verify_phone"} or destination_type not in {"email", "phone"}:
        return failure("invalid_request", "Choose a supported verification method.")
    normalized = normalized_email(value) if destination_type == "email" else normalized_phone(value)
    user = User.query.filter_by(**{"email" if destination_type == "email" else "phone": normalized}).first()
    if not user or user.status != "active":
        return success({"message": "If the account is eligible, a code has been sent."})
    if purpose == "login" and destination_type == "phone" and not user.phone_verified:
        return success({"message": "If the account is eligible, a code has been sent."})
    if purpose == "verify_phone" and (not g.user or user.id != g.user.id):
        return failure("authentication_required", "Sign in to verify this phone number.", 401)
    if destination_type == "email" and not user.email_verified and purpose == "login":
        return success({"message": "If the account is eligible, a code has been sent."})
    try:
        challenge = create_challenge(user, purpose, destination_type)
        db.session.commit()
    except OTPThrottle as error:
        db.session.rollback()
        return failure("rate_limited", str(error), 429)
    except (OTPError, RuntimeError):
        db.session.rollback()
        current_app.logger.exception("OTP delivery failed")
        return failure("delivery_unavailable", "The code could not be sent. Try again later.", 503)
    return success({
        "message": "A verification code was sent using the selected delivery method.",
        "challenge_id": challenge.id,
        "expires_in": current_app.config["OTP_TTL_SECONDS"],
    }, 201)


@api.post("/otp/verify")
@limiter.limit("12 per minute")
def otp_verify():
    payload = body_json()
    challenge = db.session.get(OTPChallenge, str(payload.get("challenge_id", "")))
    result = consume_challenge(challenge, str(payload.get("code", "")).strip())
    if result != "verified":
        if challenge and result in {"incorrect", "attempts_exceeded", "expired"}:
            correlation = challenge.correlation_id
            timeline(correlation, challenge.user_id, "otp_check", "one_time_code", result,
                     f"The OTP challenge was {result.replace('_', ' ')}.", "otp_v1", "request_new_code")
            log_auth(challenge.user_id, challenge.destination_type + "_otp", "failed",
                     correlation, f"OTP verification {result.replace('_', ' ')}.", severity="medium")
            db.session.commit()
        public = "The code is invalid or has expired. Request a new code and try again."
        return failure("code_not_accepted", public, 400)

    user = db.session.get(User, challenge.user_id)
    if not user or user.status == "deleted":
        db.session.rollback()
        return failure("code_not_accepted", "The code is invalid or has expired.", 400)
    if challenge.purpose == "verify_email":
        user.email_verified = True
        user.status = "active"
        timeline(challenge.correlation_id, user.id, "verification", "email_ownership", "passed",
                 "Email ownership was verified using a single-use code.", "registration_v1", "account_activated")
        log_auth(user.id, "email_verification", "success", challenge.correlation_id,
                 "Email ownership verified; account activated.")
        return auth_response(user, "email_verification", challenge.correlation_id, "allow")
    if challenge.purpose == "verify_phone":
        user.phone_verified = True
        timeline(challenge.correlation_id, user.id, "verification", "phone_ownership", "passed",
                 "Phone ownership was verified using a single-use code.", "registration_v1", "phone_otp_enabled")
        db.session.commit()
        return success({"verified": True, "message": "Phone verified for phone-code sign-in."})
    if challenge.purpose not in {"login", "step_up"} or user.status != "active":
        db.session.rollback()
        return failure("code_not_accepted", "The code is invalid or has expired.", 400)

    trusted = g.login_device if g.login_device and g.login_device.user_id == user.id else None
    correlation = challenge.correlation_id
    count = recent_failures(user.id)
    decision = evaluate_risk(
        trusted_device=bool(trusted),
        recent_failures=count,
        device_revoked=bool(g.revoked_device_cookie),
        policy=policy_from_config(),
    )
    timeline(correlation, user.id, "otp_check", "one_time_code", "passed",
             "The single-use OTP matched and was consumed atomically.", "otp_v1", "evaluate_risk")
    timeline(correlation, user.id, "device_check", "trusted_device", "trusted" if trusted else "unknown",
             "A current trusted device token was verified." if trusted else "This browser has no active trusted-device credential.",
             "device_trust_v1", "evaluate_risk")
    timeline(correlation, user.id, "risk_evaluation", "liae_risk_score", decision.band,
             decision.explanation, decision.policy, decision.action)
    if decision.action in {"deny", "reject"}:
        log_auth(user.id, challenge.destination_type + "_otp", "denied", correlation,
                 decision.explanation, decision.score, trusted.id if trusted else None, "high")
        db.session.commit()
        return failure("access_denied", "This sign-in was blocked by security policy.", 403,
                       {"correlation_id": correlation, "risk_score": decision.score})

    if challenge.purpose == "login" and decision.action == "require_additional_verification":
        try:
            step_up = create_challenge(
                user, "step_up", challenge.destination_type,
                correlation_id=correlation, parent_id=challenge.id,
            )
            log_auth(user.id, challenge.destination_type + "_otp", "challenge", correlation,
                     decision.explanation, decision.score, trusted.id if trusted else None)
            db.session.commit()
        except (OTPError, RuntimeError) as error:
            db.session.rollback()
            current_app.logger.exception("Step-up delivery failed")
            return failure("verification_unavailable", "Additional verification could not be sent.", 503)
        return success({
            "authenticated": False,
            "step_up_required": True,
            "challenge_id": step_up.id,
            "message": "This device needs an additional verification code before sign-in.",
            "risk_score": decision.score,
            "decision": decision.action,
            "correlation_id": correlation,
        })

    if challenge.purpose == "step_up" and decision.action == "require_additional_verification":
        timeline(correlation, user.id, "step_up", "additional_otp", "passed",
                 "Additional verification succeeded for the elevated-risk sign-in.", "liae_v1", "create_session")
    log_auth(user.id, challenge.destination_type + "_otp", "success", correlation,
             decision.explanation, decision.score, trusted.id if trusted else None)
    timeline(correlation, user.id, "session", "revocable_session", "created",
             "A new database-backed session was created after required checks passed.", "session_v1", "allow")
    return auth_response(user, challenge.destination_type + "_otp", correlation, decision.action, trusted)


@api.post("/qr")
@limiter.limit("10 per minute")
def create_qr_request():
    raw_binding = request.cookies.get(PENDING_COOKIE) or new_token(32)
    request_id = str(uuid.uuid4())
    raw_token = new_token(40)
    now = utcnow()
    qr_request = QRLoginRequest(
        id=request_id,
        request_token_hash=token_hash(raw_token),
        desktop_binding_hash=token_hash(raw_binding),
        browser_summary=browser_summary(),
        ip_address=request.remote_addr,
        expires_at=now + timedelta(seconds=current_app.config["QR_TTL_SECONDS"]),
    )
    db.session.add(qr_request)
    timeline(request_id, None, "request_created", "desktop_session_binding", "created",
             "A short-lived QR request was bound to this desktop browser session.", "liae_qr_v1", "await_mobile_approval")
    db.session.commit()
    approval_url = f"{request.host_url.rstrip('/')}/approve/{request_id}#{raw_token}"
    image = qrcode.make(approval_url)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    response, status = success({
        "request_id": request_id,
        "qr_image": "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode("ascii"),
        "expires_at": utc_iso(qr_request.expires_at),
        "expires_in": current_app.config["QR_TTL_SECONDS"],
    }, 201)
    response.set_cookie(PENDING_COOKIE, raw_binding, httponly=True,
                        secure=not current_app.config["DEVELOPMENT"], samesite="Lax", path="/")
    return response, status


@api.get("/qr/<request_id>")
@limiter.limit("120 per minute")
def qr_status(request_id):
    qr_request = db.session.get(QRLoginRequest, request_id)
    binding = request.cookies.get(PENDING_COOKIE)
    if not qr_request or not binding or not secure_equal(qr_request.desktop_binding_hash, token_hash(binding)):
        return failure("request_not_found", "This login request is unavailable.", 404)
    now = utcnow()
    if qr_request.state in {"pending", "approved"} and as_utc(qr_request.expires_at) <= now:
        previous = qr_request.state
        result = db.session.execute(
            update(QRLoginRequest.__table__)
            .where(QRLoginRequest.id == request_id, QRLoginRequest.state == previous,
                   QRLoginRequest.consumed_at.is_(None), QRLoginRequest.expires_at <= now)
            .values(state="expired", denial_reason="expired")
        )
        if result.rowcount:
            timeline(request_id, qr_request.user_id, "request_expired", "qr_expiry", "rejected",
                     "The QR request expired before the desktop session was established.",
                     "liae_qr_v1", "restart_authentication")
            log_auth(qr_request.user_id, "qr", "expired", request_id,
                     "The QR request expired before desktop session creation.", severity="medium")
            db.session.commit()
        return success({"state": "expired"})
    if qr_request.state == "approved" and qr_request.consumed_at is None:
        result = db.session.execute(
            update(QRLoginRequest.__table__)
            .where(QRLoginRequest.id == request_id, QRLoginRequest.state == "approved",
                   QRLoginRequest.consumed_at.is_(None), QRLoginRequest.expires_at > now,
                   QRLoginRequest.desktop_binding_hash == token_hash(binding))
            .values(consumed_at=now, state="consumed")
        )
        if result.rowcount == 1:
            db.session.flush()
            user = db.session.get(User, qr_request.user_id)
            if not user or user.status != "active":
                db.session.rollback()
                return failure("request_not_found", "This login request is unavailable.", 404)
            correlation = request_id
            log_auth(user.id, "qr", "success", correlation,
                     "Registered mobile approval validated; desktop session binding matched and request was consumed.",
                     30, None)
            timeline(correlation, user.id, "session", "desktop_session_binding", "validated",
                     "Only the initiating desktop session received a new independent session.",
                     "liae_qr_v1", "allow")
            raw_session, _record = issue_session(user)
            db.session.commit()
            from flask import session
            session.clear()
            response, status = success({
                "state": "approved",
                "authenticated": True,
                "user": safe_user(user),
                "next": "/app",
                "correlation_id": correlation,
            })
            set_session_cookie(response, raw_session)
            return response, status
        db.session.rollback()
        qr_request = db.session.get(QRLoginRequest, request_id)
    return success({"state": qr_request.state})


@api.post("/qr/<request_id>/review")
@api_login_required
@limiter.limit("30 per minute")
def review_qr(request_id):
    qr_request = db.session.get(QRLoginRequest, request_id)
    payload = body_json()
    raw_token = str(payload.get("token", ""))
    device = g.get("current_device")
    if not device or device.user_id != g.user.id or device.revoked_at or as_utc(device.expires_at) <= utcnow():
        return failure("registered_device_required", "Sign in on an active trusted device to review this request.", 403)
    if not is_current_device_cookie(device):
        return failure("registered_device_required", "This session is not bound to its registered device.", 403)
    if not qr_request or qr_request.state != "pending" or as_utc(qr_request.expires_at) <= utcnow():
        return failure("request_not_pending", "This QR request is expired or no longer pending.", 409)
    if not raw_token or not secure_equal(qr_request.request_token_hash, token_hash(raw_token)):
        return failure("request_not_pending", "This QR request is unavailable.", 404)
    return success({
        "request_id": qr_request.id,
        "browser": qr_request.browser_summary,
        "created_at": utc_iso(qr_request.created_at),
        "expires_at": utc_iso(qr_request.expires_at),
        "ip_address": qr_request.ip_address,
    })


def qr_transition(request_id, approve):
    qr_request = db.session.get(QRLoginRequest, request_id)
    payload = body_json()
    raw_token = str(payload.get("token", ""))
    device = g.get("current_device")
    if not g.get("user"):
        return failure("authentication_required", "Sign in on this registered device to continue.", 401)
    if not device or device.user_id != g.user.id or device.revoked_at or as_utc(device.expires_at) <= utcnow():
        return failure("registered_device_required", "Approve QR login from a trusted, active device.", 403)
    if not is_current_device_cookie(device):
        return failure("registered_device_required", "This session is not bound to its registered device.", 403)
    if not qr_request or qr_request.state != "pending" or as_utc(qr_request.expires_at) <= utcnow():
        return failure("request_not_pending", "This QR request is expired or no longer pending.", 409)
    if not raw_token or not secure_equal(qr_request.request_token_hash, token_hash(raw_token)):
        timeline(request_id, g.user.id, "approval_rejected", "request_token_binding", "failed",
                 "The scanned token did not match this pending request.", "liae_qr_v1", "deny")
        log_auth(g.user.id, "qr", "rejected", request_id,
                 "QR approval token did not match the pending request.", severity="high")
        db.session.commit()
        return failure("request_not_pending", "This QR request is unavailable.", 409)

    decision = evaluate_risk(
        trusted_device=False,
        recent_failures=recent_failures(g.user.id),
        qr_valid=True,
        device_revoked=False,
        policy=policy_from_config(),
    )
    if decision.action == "deny":
        result = db.session.execute(
            update(QRLoginRequest.__table__).where(
                QRLoginRequest.id == request_id, QRLoginRequest.state == "pending",
                QRLoginRequest.expires_at > utcnow(),
            ).values(state="denied", denial_reason="high_risk", user_id=g.user.id)
        )
        if result.rowcount:
            timeline(request_id, g.user.id, "risk_evaluation", "liae_risk_score", "high",
                     decision.explanation, decision.policy, "deny")
            log_auth(g.user.id, "qr", "denied", request_id, decision.explanation, decision.score,
                     device.id, "high")
            db.session.commit()
        else:
            db.session.rollback()
        return failure("approval_denied", "Security policy denied this login request.", 403)

    if approve:
        new_state = "approved"
        values = {
            "state": new_state,
            "user_id": g.user.id,
            "approving_device_id": device.id,
            "approved_at": utcnow(),
        }
    else:
        new_state = "denied"
        values = {"state": new_state, "user_id": g.user.id, "denial_reason": "user_denied"}
    result = db.session.execute(
        update(QRLoginRequest.__table__)
        .where(
            QRLoginRequest.id == request_id,
            QRLoginRequest.state == "pending",
            QRLoginRequest.expires_at > utcnow(),
            QRLoginRequest.request_token_hash == token_hash(raw_token),
        )
        .values(**values)
    )
    if result.rowcount != 1:
        db.session.rollback()
        return failure("request_not_pending", "This QR request is expired or was already handled.", 409)

    timeline(request_id, g.user.id, "device_check", "approving_device", "trusted",
             "The approver is signed in on an active registered device.", "device_trust_v1", "validate_request")
    timeline(request_id, g.user.id, "qr_binding", "transaction_binding", "valid",
             "The scanned token matches this exact unexpired desktop request.", "liae_qr_v1", "record_user_decision")
    timeline(request_id, g.user.id, "risk_evaluation", "liae_risk_score", decision.band,
             decision.explanation, decision.policy,
             "await_desktop_session" if approve else "deny")
    if approve:
        timeline(request_id, g.user.id, "mobile_approval", "explicit_user_consent", "approved",
                 "The authenticated user explicitly approved this desktop request; this step satisfies the medium-risk verification requirement.",
                 "liae_qr_v1", "await_desktop_poll")
        log_auth(g.user.id, "qr", "approved", request_id,
                 "Explicit registered-mobile approval accepted; the initiating desktop must still consume the request.",
                 decision.score, device.id)
    else:
        timeline(request_id, g.user.id, "mobile_denial", "explicit_user_consent", "denied",
                 "The authenticated user denied this desktop request.", "liae_qr_v1", "deny")
        log_auth(g.user.id, "qr", "denied", request_id, "The user denied the desktop login request.",
                 decision.score, device.id, "medium")
    DecisionEvent.query.filter_by(correlation_id=request_id, user_id=None).update({"user_id": g.user.id})
    db.session.commit()
    return success({"state": new_state, "message": "The desktop will receive the decision after validating its session binding."})


@api.post("/qr/<request_id>/approve")
@limiter.limit("12 per minute")
def approve_qr(request_id):
    return qr_transition(request_id, True)


@api.post("/qr/<request_id>/deny")
@limiter.limit("12 per minute")
def deny_qr(request_id):
    return qr_transition(request_id, False)


@api.get("/me")
@api_login_required
def get_me():
    return success({"user": safe_user(g.user), "development": current_app.config["DEVELOPMENT"]})


@api.post("/logout")
@api_login_required
def logout():
    g.session_record.revoked_at = utcnow()
    db.session.commit()
    from flask import session
    session.clear()
    response, status = success({"message": "Signed out."})
    clear_session_cookie(response)
    return response, status


@api.post("/logout-all")
@api_login_required
def logout_all():
    SessionRecord.query.filter_by(user_id=g.user.id, revoked_at=None).update({"revoked_at": utcnow()})
    db.session.commit()
    from flask import session
    session.clear()
    response, status = success({"message": "All sessions were revoked."})
    clear_session_cookie(response)
    return response, status


@api.get("/dashboard/summary")
@api_login_required
def dashboard_summary():
    days = request.args.get("days", "30")
    days = int(days) if days in {"7", "30", "90"} else 30
    start = utcnow() - timedelta(days=days)
    events = AuthenticationEvent.query.filter(
        AuthenticationEvent.user_id == g.user.id,
        AuthenticationEvent.created_at >= start,
    )
    total = events.count()
    outcomes = dict(db.session.query(AuthenticationEvent.outcome, func.count(AuthenticationEvent.id))
                    .filter(AuthenticationEvent.user_id == g.user.id,
                            AuthenticationEvent.created_at >= start)
                    .group_by(AuthenticationEvent.outcome).all())
    methods = dict(db.session.query(AuthenticationEvent.method, func.count(AuthenticationEvent.id))
                   .filter(AuthenticationEvent.user_id == g.user.id,
                           AuthenticationEvent.created_at >= start,
                           AuthenticationEvent.outcome == "success")
                   .group_by(AuthenticationEvent.method).all())
    recent = AuthenticationEvent.query.filter_by(user_id=g.user.id).order_by(
        AuthenticationEvent.created_at.desc()).limit(8).all()
    devices = TrustedDevice.query.filter_by(user_id=g.user.id, revoked_at=None).filter(
        TrustedDevice.expires_at > utcnow()).count()
    alerts = SecurityAlert.query.filter_by(user_id=g.user.id, resolved_at=None).count()
    return success({
        "days": days,
        "total_attempts": total,
        "successful": outcomes.get("success", 0),
        "failed": sum(value for key, value in outcomes.items() if key in {"failed", "denied", "rejected", "expired"}),
        "active_trusted_devices": devices,
        "open_alerts": alerts,
        "method_distribution": methods,
        "recent_events": [serialize_auth_event(event) for event in recent],
    })


def serialize_auth_event(event):
    device = db.session.get(TrustedDevice, event.device_id) if event.device_id else None
    return {
        "id": event.id,
        "timestamp": utc_iso(event.created_at),
        "method": event.method,
        "outcome": event.outcome,
        "device": device.device_name if device else "Unregistered browser",
        "risk_score": event.risk_score,
        "decision": event.decision,
        "ip_address": event.ip_address,
        "correlation_id": event.correlation_id,
    }


@api.get("/history")
@api_login_required
def history():
    page = max(1, min(request.args.get("page", 1, type=int), 10000))
    per_page = 15
    query = AuthenticationEvent.query.filter_by(user_id=g.user.id)
    method = request.args.get("method", "")
    outcome = request.args.get("outcome", "")
    term = request.args.get("q", "").strip()[:80]
    if method in {"email_otp", "phone_otp", "qr", "email_verification"}:
        query = query.filter_by(method=method)
    if outcome in {"success", "failed", "challenge", "denied", "rejected", "expired", "approved"}:
        query = query.filter_by(outcome=outcome)
    if term:
        query = query.filter(AuthenticationEvent.decision.ilike(f"%{term}%"))
    total = query.count()
    rows = query.order_by(AuthenticationEvent.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
    return success({"items": [serialize_auth_event(event) for event in rows],
                    "page": page, "per_page": per_page, "total": total,
                    "pages": (total + per_page - 1) // per_page})


@api.get("/devices")
@api_login_required
def list_devices():
    rows = TrustedDevice.query.filter_by(user_id=g.user.id).order_by(TrustedDevice.created_at.desc()).all()
    return success({"items": [{
        "id": row.id,
        "name": row.device_name,
        "browser": row.browser_summary,
        "created_at": utc_iso(row.created_at),
        "last_used_at": utc_iso(row.last_used_at) if row.last_used_at else None,
        "expires_at": utc_iso(row.expires_at),
        "revoked_at": utc_iso(row.revoked_at) if row.revoked_at else None,
        "current": bool(g.current_device and row.id == g.current_device.id),
        "active": not row.revoked_at and as_utc(row.expires_at) > utcnow(),
    } for row in rows]})


@api.post("/devices")
@api_login_required
@limiter.limit("5 per hour")
def create_device():
    payload = body_json()
    try:
        device, raw_token = enroll_current_device(str(payload.get("name", "")))
        correlation = correlation_id()
        log_auth(g.user.id, "device_management", "success", correlation,
                 "A trusted device was enrolled after recent authentication.", 0, device.id)
        timeline(correlation, g.user.id, "device_enrolled", "device_token", "created",
                 "An opaque device token was generated and only its hash was stored.",
                 "device_trust_v1", "trusted")
        db.session.commit()
    except ValueError as error:
        db.session.rollback()
        return failure("device_enrollment_rejected", str(error), 400)
    response, status = success({"device_id": device.id, "message": "This browser is now a trusted device."}, 201)
    set_device_cookie(response, raw_token)
    return response, status


@api.patch("/devices/<int:device_id>")
@api_login_required
def update_device(device_id):
    device = TrustedDevice.query.filter_by(id=device_id, user_id=g.user.id).first_or_404()
    payload = body_json()
    try:
        rename_device(device, str(payload.get("name", "")))
        db.session.commit()
    except ValueError as error:
        db.session.rollback()
        return failure("invalid_device_name", str(error))
    return success({"message": "Device name updated."})


@api.delete("/devices/<int:device_id>")
@api_login_required
def delete_device(device_id):
    device = TrustedDevice.query.filter_by(id=device_id, user_id=g.user.id).first_or_404()
    correlation = correlation_id()
    current = is_current_device_cookie(device)
    revoke_device(device)
    log_auth(g.user.id, "device_management", "success", correlation,
             f"Trusted device {device.device_name} was revoked.", 0, device.id,
             "medium")
    timeline(correlation, g.user.id, "device_revoked", "token_status", "revoked",
             "The device token and sessions attached to it were revoked server-side.",
             "device_trust_v1", "reject_future_use")
    db.session.commit()
    response, status = success({"message": "Device revoked."})
    if current:
        response.delete_cookie(DEVICE_COOKIE, path="/", httponly=True, samesite="Lax")
        clear_session_cookie(response)
    return response, status


@api.post("/devices/revoke-others")
@api_login_required
def revoke_other_devices():
    now = utcnow()
    rows = TrustedDevice.query.filter(
        TrustedDevice.user_id == g.user.id,
        TrustedDevice.revoked_at.is_(None),
        TrustedDevice.id != (g.current_device.id if g.current_device else -1),
    ).all()
    for device in rows:
        revoke_device(device)
    correlation = correlation_id()
    log_auth(g.user.id, "device_management", "success", correlation,
             f"Revoked {len(rows)} other trusted device(s).", 0,
             g.current_device.id if g.current_device else None, "medium" if rows else None)
    timeline(correlation, g.user.id, "devices_revoked", "trusted_device_tokens", "revoked",
             f"{len(rows)} other device token(s) were revoked.", "device_trust_v1", "reject_future_use")
    db.session.commit()
    return success({"revoked": len(rows)})


@api.get("/alerts")
@api_login_required
def alerts():
    query = SecurityAlert.query.filter_by(user_id=g.user.id)
    severity = request.args.get("severity", "")
    status = request.args.get("status", "open")
    if severity in {"low", "medium", "high", "critical"}:
        query = query.filter_by(severity=severity)
    if status == "open":
        query = query.filter(SecurityAlert.resolved_at.is_(None))
    elif status == "resolved":
        query = query.filter(SecurityAlert.resolved_at.is_not(None))
    rows = query.order_by(SecurityAlert.created_at.desc()).limit(100).all()
    return success({"items": [{
        "id": row.id, "severity": row.severity, "description": row.description,
        "created_at": utc_iso(row.created_at),
        "resolved_at": utc_iso(row.resolved_at) if row.resolved_at else None,
    } for row in rows]})


@api.post("/alerts/<int:alert_id>/resolve")
@api_login_required
def resolve_security_alert(alert_id):
    alert = SecurityAlert.query.filter_by(id=alert_id, user_id=g.user.id).first_or_404()
    audit_service.resolve_alert(alert)
    db.session.commit()
    return success({"message": "Alert resolved."})


@api.get("/timeline/<correlation>")
@api_login_required
def decision_timeline(correlation):
    events = DecisionEvent.query.filter_by(correlation_id=correlation, user_id=g.user.id).order_by(
        DecisionEvent.created_at.asc(), DecisionEvent.id.asc()).all()
    auth_event = AuthenticationEvent.query.filter_by(correlation_id=correlation, user_id=g.user.id).first()
    if not events and not auth_event:
        return failure("not_found", "That decision timeline was not found.", 404)
    return success({"correlation_id": correlation, "items": [{
        "timestamp": utc_iso(event.created_at),
        "event_type": event.event_type,
        "check": event.check_name,
        "result": event.result,
        "explanation": event.explanation,
        "policy": event.policy,
        "next_action": event.next_action,
    } for event in events]})


@api.get("/settings")
@api_login_required
def settings():
    sessions = SessionRecord.query.filter_by(user_id=g.user.id, revoked_at=None).filter(
        SessionRecord.expires_at > utcnow()).order_by(SessionRecord.created_at.desc()).all()
    return success({
        "user": safe_user(g.user),
        "sessions": [{
            "id": row.id,
            "created_at": utc_iso(row.created_at),
            "expires_at": utc_iso(row.expires_at),
            "current": bool(g.session_record and row.id == g.session_record.id),
            "device": db.session.get(TrustedDevice, row.device_id).device_name if row.device_id and db.session.get(TrustedDevice, row.device_id) else "Unregistered browser",
        } for row in sessions],
    })


@api.patch("/settings")
@api_login_required
def update_settings():
    payload = body_json()
    name = str(payload.get("full_name", g.user.full_name)).strip()
    if not 2 <= len(name) <= 120:
        return failure("invalid_name", "Enter a name between 2 and 120 characters.")
    g.user.full_name = name
    db.session.commit()
    return success({"user": safe_user(g.user)})


@api.post("/settings/phone")
@api_login_required
@limiter.limit("5 per hour")
def set_phone_number():
    payload = body_json()
    phone = normalized_phone(str(payload.get("phone", "")))
    if not re.fullmatch(r"\+?[0-9]{7,15}", phone):
        return failure("invalid_phone", "Enter a valid phone number with country code.")
    existing = User.query.filter(User.phone == phone, User.id != g.user.id).first()
    if existing:
        return failure("phone_unavailable", "This phone number cannot be used for this account.", 409)
    changed = phone != g.user.phone
    g.user.phone = phone
    if changed:
        g.user.phone_verified = False
    try:
        challenge = create_challenge(g.user, "verify_phone", "phone")
        db.session.commit()
    except OTPThrottle as error:
        db.session.rollback()
        return failure("rate_limited", str(error), 429)
    except (OTPError, RuntimeError):
        db.session.rollback()
        current_app.logger.exception("Phone verification delivery failed")
        return failure("delivery_unavailable", "The verification code could not be sent.", 503)
    return success({
        "challenge_id": challenge.id,
        "message": "A verification code was sent using the configured phone delivery adapter.",
        "expires_in": current_app.config["OTP_TTL_SECONDS"],
    }, 201)


@api.delete("/account")
@api_login_required
def delete_account():
    payload = body_json()
    if payload.get("confirm") != g.user.email:
        return failure("confirmation_required", "Enter your account email to confirm deletion.", 400)
    user_id = g.user.id
    g.user.full_name = "Deleted account"
    g.user.email = f"deleted+{uuid.uuid4().hex}@invalid.local"
    g.user.phone = None
    g.user.email_verified = False
    g.user.phone_verified = False
    g.user.status = "deleted"
    SessionRecord.query.filter_by(user_id=user_id, revoked_at=None).update({"revoked_at": utcnow()})
    TrustedDevice.query.filter_by(user_id=user_id, revoked_at=None).update({"revoked_at": utcnow()})
    db.session.commit()
    from flask import session
    session.clear()
    response, status = success({"message": "Account access revoked and identifying details anonymized."})
    clear_session_cookie(response)
    response.delete_cookie(DEVICE_COOKIE, path="/", httponly=True, samesite="Lax")
    return response, status