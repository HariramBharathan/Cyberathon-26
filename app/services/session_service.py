from datetime import timedelta, timezone
from functools import wraps

from flask import current_app, g, jsonify, request

from ..extensions import db
from ..models import SessionRecord, TrustedDevice, User, utcnow
from .security import cookie_options, new_token, token_hash

SESSION_COOKIE = "sentinelpass_session"
DEVICE_COOKIE = "sentinelpass_device"
PENDING_COOKIE = "sentinelpass_pending"


def load_request_identity():
    g.user = None
    g.session_record = None
    g.current_device = None
    g.login_device = None
    g.revoked_device_cookie = False
    raw_session = request.cookies.get(SESSION_COOKIE)
    if raw_session:
        record = SessionRecord.query.filter_by(token_hash=token_hash(raw_session)).first()
        record_expiry = _aware(record.expires_at) if record else None
        if record and not record.revoked_at and record_expiry > utcnow():
            if record.device_id:
                device = db.session.get(TrustedDevice, record.device_id)
                if not device or device.revoked_at or _aware(device.expires_at) <= utcnow():
                    record.revoked_at = utcnow()
                    db.session.commit()
                else:
                    g.current_device = device
                    device.last_used_at = utcnow()
            if not record.revoked_at:
                user = db.session.get(User, record.user_id)
                if user and user.status == "active":
                    g.user = user
                    g.session_record = record
    raw_device = request.cookies.get(DEVICE_COOKIE)
    if raw_device:
        device = TrustedDevice.query.filter_by(token_hash=token_hash(raw_device)).first()
        if device and (not g.user or device.user_id == g.user.id):
            if device.revoked_at:
                g.revoked_device_cookie = True
            elif _aware(device.expires_at) > utcnow():
                g.login_device = device


def _aware(value):
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def issue_session(user, device=None):
    raw_token = new_token(40)
    now = utcnow()
    record = SessionRecord(
        token_hash=token_hash(raw_token),
        user_id=user.id,
        device_id=device.id if device else None,
        expires_at=now + timedelta(seconds=current_app.config["SESSION_TTL_SECONDS"]),
    )
    db.session.add(record)
    db.session.flush()
    return raw_token, record


def set_session_cookie(response, raw_token):
    response.set_cookie(
        SESSION_COOKIE,
        raw_token,
        max_age=current_app.config["SESSION_TTL_SECONDS"],
        **cookie_options(),
    )
    return response


def clear_session_cookie(response):
    response.delete_cookie(SESSION_COOKIE, **cookie_options())
    return response


def api_login_required(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        if not g.get("user"):
            return jsonify({"ok": False, "error": {"code": "authentication_required", "message": "Sign in to continue."}}), 401
        return function(*args, **kwargs)
    return wrapped


def page_login_required(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        if not g.get("user"):
            from flask import redirect, url_for
            return redirect(url_for("web.login", next=request.full_path.rstrip("?")))
        return function(*args, **kwargs)
    return wrapped