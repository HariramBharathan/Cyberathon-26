from datetime import datetime, timezone

from .extensions import db


def utcnow():
    return datetime.now(timezone.utc)


def as_utc(value):
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def utc_iso(value):
    return as_utc(value).isoformat()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(254), nullable=False, unique=True, index=True)
    phone = db.Column(db.String(32), unique=True, index=True)
    email_verified = db.Column(db.Boolean, nullable=False, default=False)
    phone_verified = db.Column(db.Boolean, nullable=False, default=False)
    status = db.Column(db.String(20), nullable=False, default="pending")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)


class OTPChallenge(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False, index=True)
    purpose = db.Column(db.String(24), nullable=False)
    destination_type = db.Column(db.String(12), nullable=False)
    destination = db.Column(db.String(254), nullable=False)
    otp_hash = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    consumed_at = db.Column(db.DateTime(timezone=True))
    parent_challenge_id = db.Column(db.String(36), db.ForeignKey("otp_challenge.id"))
    correlation_id = db.Column(db.String(36), nullable=False, index=True)


class TrustedDevice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = db.Column(db.String(64), nullable=False, unique=True, index=True)
    device_name = db.Column(db.String(80), nullable=False)
    browser_summary = db.Column(db.String(160), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    last_used_at = db.Column(db.DateTime(timezone=True))
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    revoked_at = db.Column(db.DateTime(timezone=True))


class QRLoginRequest(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), index=True)
    request_token_hash = db.Column(db.String(64), nullable=False)
    desktop_binding_hash = db.Column(db.String(64), nullable=False)
    browser_summary = db.Column(db.String(160), nullable=False)
    ip_address = db.Column(db.String(64))
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    state = db.Column(db.String(16), nullable=False, default="pending", index=True)
    approved_at = db.Column(db.DateTime(timezone=True))
    approving_device_id = db.Column(db.Integer, db.ForeignKey("trusted_device.id", ondelete="SET NULL"))
    consumed_at = db.Column(db.DateTime(timezone=True))
    denial_reason = db.Column(db.String(80))


class AuthenticationEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), index=True)
    method = db.Column(db.String(24), nullable=False)
    outcome = db.Column(db.String(24), nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    device_id = db.Column(db.Integer, db.ForeignKey("trusted_device.id", ondelete="SET NULL"))
    risk_score = db.Column(db.Integer, nullable=False, default=0)
    decision = db.Column(db.String(500), nullable=False)
    correlation_id = db.Column(db.String(36), nullable=False, index=True)
    ip_address = db.Column(db.String(64))


class SecurityAlert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey("authentication_event.id", ondelete="SET NULL"), index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), index=True)
    severity = db.Column(db.String(12), nullable=False, index=True)
    description = db.Column(db.String(300), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    resolved_at = db.Column(db.DateTime(timezone=True))


class DecisionEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    correlation_id = db.Column(db.String(36), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), index=True)
    event_type = db.Column(db.String(40), nullable=False)
    check_name = db.Column(db.String(80), nullable=False)
    result = db.Column(db.String(24), nullable=False)
    explanation = db.Column(db.String(500), nullable=False)
    policy = db.Column(db.String(80), nullable=False)
    next_action = db.Column(db.String(80), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)


class SessionRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String(64), nullable=False, unique=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False, index=True)
    device_id = db.Column(db.Integer, db.ForeignKey("trusted_device.id", ondelete="SET NULL"))
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    revoked_at = db.Column(db.DateTime(timezone=True))