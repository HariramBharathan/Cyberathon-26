from datetime import timedelta

from flask import current_app, g, request

from ..extensions import db
from ..models import SessionRecord, TrustedDevice, as_utc, utcnow
from .security import browser_summary, new_token, token_hash
from .session_service import DEVICE_COOKIE


def enroll_current_device(name):
    if not g.user or not g.session_record:
        raise ValueError("Sign in before registering a trusted device.")
    if (utcnow() - as_utc(g.session_record.created_at)).total_seconds() > 600:
        raise ValueError("Recent authentication is required to register a device.")
    if not name or len(name.strip()) > 80:
        raise ValueError("Choose a device name of 1 to 80 characters.")
    raw_token = new_token(40)
    device = TrustedDevice(
        user_id=g.user.id,
        token_hash=token_hash(raw_token),
        device_name=name.strip(),
        browser_summary=browser_summary(),
        expires_at=utcnow() + timedelta(days=current_app.config["TRUSTED_DEVICE_DAYS"]),
    )
    db.session.add(device)
    db.session.flush()
    g.session_record.device_id = device.id
    device.last_used_at = utcnow()
    return device, raw_token


def set_device_cookie(response, raw_token):
    response.set_cookie(
        DEVICE_COOKIE,
        raw_token,
        max_age=current_app.config["TRUSTED_DEVICE_DAYS"] * 86400,
        httponly=True,
        secure=not current_app.config["DEVELOPMENT"],
        samesite="Lax",
        path="/",
    )
    return response


def revoke_device(device):
    now = utcnow()
    device.revoked_at = now
    SessionRecord.query.filter_by(device_id=device.id, revoked_at=None).update({"revoked_at": now})
    is_current = g.get("current_device") and g.current_device.id == device.id
    db.session.flush()
    return is_current


def rename_device(device, name):
    if not name or len(name.strip()) > 80:
        raise ValueError("Choose a device name of 1 to 80 characters.")
    device.device_name = name.strip()


def is_current_device_cookie(device):
    raw = request.cookies.get(DEVICE_COOKIE)
    return bool(raw and token_hash(raw) == device.token_hash)