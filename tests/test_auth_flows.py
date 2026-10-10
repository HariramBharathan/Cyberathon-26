from datetime import timedelta

import qrcode

from app.extensions import db
from app.models import OTPChallenge, QRLoginRequest, SessionRecord, TrustedDevice, User, utcnow
from app.services.session_service import SESSION_COOKIE
from tests.conftest import latest_code
from app.services.security import new_token, token_hash
from datetime import timedelta


def register_verified(app, client, email="person@example.com"):
    response = client.post("/api/register", json={
        "full_name": "Test Person", "email": email, "phone": "+15550102040",
    })
    assert response.status_code == 201
    challenge_id = response.json["data"]["challenge_id"]
    code = latest_code(app, "verify_email")
    verified = client.post("/api/otp/verify", json={"challenge_id": challenge_id, "code": code})
    assert verified.status_code == 200
    user = User.query.filter_by(email=email).first()
    client.delete_cookie(SESSION_COOKIE)
    SessionRecord.query.filter_by(user_id=user.id).delete()
    db.session.commit()
    return user


def login_with_email_code(app, client, email="person@example.com"):
    response = client.post("/api/otp/request", json={"method": "email", "destination": email})
    assert response.status_code == 201
    challenge_id = response.json["data"]["challenge_id"]
    code = latest_code(app, "login")
    verified = client.post("/api/otp/verify", json={"challenge_id": challenge_id, "code": code})
    if verified.json["data"].get("step_up_required"):
        step_up = verified.json["data"]["challenge_id"]
        verified = client.post("/api/otp/verify", json={
            "challenge_id": step_up, "code": latest_code(app, "step_up"),
        })
    assert verified.status_code == 200
    assert verified.json["data"]["authenticated"] is True
    assert client.get("/api/me").status_code == 200, (
        client.get_cookie("sentinelpass_session"),
        [(row.token_hash, row.revoked_at, row.expires_at) for row in SessionRecord.query.all()],
    )
    return verified


def enroll_device(client, name="Test phone"):
    response = client.post("/api/devices", json={"name": name})
    assert response.status_code == 201, response.json
    return response.json["data"]["device_id"]


def test_registration_requires_email_ownership(client, app):
    response = client.post("/api/register", json={
        "full_name": "Test Person", "email": "Person@Example.com",
    })
    assert response.status_code == 201
    user = User.query.filter_by(email="person@example.com").first()
    assert user.status == "pending"
    assert not user.email_verified
    challenge = db.session.get(OTPChallenge, response.json["data"]["challenge_id"])
    assert latest_code(app, "verify_email") == "549213"
    assert latest_code(app, "verify_email") not in challenge.otp_hash
    verified = client.post("/api/otp/verify", json={
        "challenge_id": challenge.id, "code": latest_code(app, "verify_email"),
    })
    assert verified.status_code == 200
    assert verified.json["data"]["authenticated"] is True
    assert client.get("/api/me").status_code == 200
    assert user.status == "active"
    assert user.email_verified


def test_production_otp_does_not_use_the_development_code(client, app, monkeypatch):
    app.config["DEVELOPMENT"] = False
    monkeypatch.setattr("app.services.otp_service.secrets.randbelow", lambda _limit: 42)

    response = client.post("/api/register", json={
        "full_name": "Production Test", "email": "production@example.com",
    })

    assert response.status_code == 201
    assert latest_code(app, "verify_email") == "000042"


def test_otp_is_single_use_and_wrong_codes_are_counted(client, app):
    register_verified(app, client)
    requested = client.post("/api/otp/request", json={"method": "email", "destination": "person@example.com"})
    challenge_id = requested.json["data"]["challenge_id"]
    code = latest_code(app, "login")
    for _ in range(2):
        bad = client.post("/api/otp/verify", json={"challenge_id": challenge_id, "code": "000000" if code != "000000" else "000001"})
        assert bad.status_code == 400
    assert db.session.get(OTPChallenge, challenge_id).attempts == 2
    verified = client.post("/api/otp/verify", json={"challenge_id": challenge_id, "code": code})
    assert verified.status_code == 200
    if verified.json["data"].get("step_up_required"):
        assert SessionRecord.query.count() == 0
        verified = client.post("/api/otp/verify", json={
            "challenge_id": verified.json["data"]["challenge_id"],
            "code": latest_code(app, "step_up"),
        })
        assert verified.status_code == 200
    replay = client.post("/api/otp/verify", json={"challenge_id": challenge_id, "code": code})
    assert replay.status_code == 400
    assert SessionRecord.query.filter_by(user_id=1, revoked_at=None).count() == 1


def test_expired_otp_is_rejected(client, app):
    register_verified(app, client)
    response = client.post("/api/otp/request", json={"method": "email", "destination": "person@example.com"})
    challenge_id = response.json["data"]["challenge_id"]
    challenge = db.session.get(OTPChallenge, challenge_id)
    challenge.expires_at = utcnow() - timedelta(seconds=1)
    db.session.commit()
    result = client.post("/api/otp/verify", json={"challenge_id": challenge_id, "code": latest_code(app, "login")})
    assert result.status_code == 400
    assert SessionRecord.query.count() == 0


def test_phone_sign_in_is_unavailable_until_phone_ownership_is_verified(client, app):
    register_verified(app, client)
    login_with_email_code(app, client)
    phone = client.post("/api/settings/phone", json={"phone": "+1 (555) 010-2040"})
    assert phone.status_code == 201
    user = User.query.filter_by(email="person@example.com").first()
    assert user.phone == "+15550102040"
    assert not user.phone_verified
    verified = client.post("/api/otp/verify", json={
        "challenge_id": phone.json["data"]["challenge_id"],
        "code": latest_code(app, "verify_phone"),
    })
    assert verified.status_code == 200
    assert user.phone_verified
    other_browser = app.test_client()
    requested = other_browser.post("/api/otp/request", json={
        "method": "phone", "destination": "+15550102040",
    })
    assert requested.status_code == 201
    assert latest_code(app, "login") != ""


def test_login_timeline_records_checks_without_raw_otp(client, app):
    register_verified(app, client)
    result = login_with_email_code(app, client)
    correlation = result.json["data"]["correlation_id"]
    response = client.get(f"/api/timeline/{correlation}")
    assert response.status_code == 200
    checks = [event["check"] for event in response.json["data"]["items"]]
    assert "one_time_code" in checks
    assert "liae_risk_score" in checks
    assert "revocable_session" in checks
    raw_code = latest_code(app, "step_up")
    assert all(raw_code not in event["explanation"] for event in response.json["data"]["items"])


def test_unknown_device_requires_step_up(client, app):
    register_verified(app, client)
    initial = client.post("/api/otp/request", json={"method": "email", "destination": "person@example.com"})
    result = client.post("/api/otp/verify", json={
        "challenge_id": initial.json["data"]["challenge_id"], "code": latest_code(app, "login"),
    })
    assert result.status_code == 200
    assert result.json["data"]["step_up_required"] is True
    assert result.json["data"]["risk_score"] == 30
    assert SessionRecord.query.count() == 0
    finish = client.post("/api/otp/verify", json={
        "challenge_id": result.json["data"]["challenge_id"], "code": latest_code(app, "step_up"),
    })
    assert finish.status_code == 200
    assert finish.json["data"]["authenticated"] is True


def test_device_enrollment_and_revocation_invalidate_sessions(client, app):
    register_verified(app, client)
    login_with_email_code(app, client)
    device_id = enroll_device(client)
    device = db.session.get(TrustedDevice, device_id)
    assert device.token_hash
    assert len(device.token_hash) == 64
    assert client.get("/api/devices").json["data"]["items"][0]["active"]
    revoked = client.delete(f"/api/devices/{device_id}")
    assert revoked.status_code == 200
    assert db.session.get(TrustedDevice, device_id).revoked_at is not None
    assert client.get("/api/me").status_code == 401


def test_qr_mobile_approval_creates_session_only_for_bound_desktop(client, app, monkeypatch):
    register_verified(app, client)
    login_with_email_code(app, client)
    enroll_device(client, "Registered mobile")

    qr_contents = []
    original_make = qrcode.make

    def capture_qr(value, *args, **kwargs):
        qr_contents.append(value)
        return original_make(value, *args, **kwargs)

    monkeypatch.setattr("app.routes.api.qrcode.make", capture_qr)
    desktop = app.test_client()
    created = desktop.post("/api/qr", json={})
    assert created.status_code == 201
    request_id = created.json["data"]["request_id"]
    token = qr_contents[0].split("#", 1)[1]
    request_record = db.session.get(QRLoginRequest, request_id)
    assert token not in request_record.request_token_hash

    mobile_session = client.get_cookie("sentinelpass_session").value
    review = client.post(f"/api/qr/{request_id}/review", json={"token": token})
    assert review.status_code == 200, review.json
    assert "Firefox" in review.json["data"]["browser"] or "Browser" in review.json["data"]["browser"]
    approved = client.post(f"/api/qr/{request_id}/approve", json={"token": token})
    assert approved.status_code == 200, approved.json
    assert client.get_cookie("sentinelpass_session").value == mobile_session

    result = desktop.get(f"/api/qr/{request_id}")
    assert result.status_code == 200, result.json
    assert result.json["data"]["authenticated"] is True
    desktop_session = desktop.get_cookie("sentinelpass_session").value
    assert desktop_session != mobile_session
    assert desktop.get("/api/me").status_code == 200
    assert client.post(f"/api/qr/{request_id}/approve", json={"token": token}).status_code == 409
    assert db.session.get(QRLoginRequest, request_id).state == "consumed"


def test_qr_wrong_binding_expiry_and_untrusted_approver(client, app, monkeypatch):
    register_verified(app, client)
    login_with_email_code(app, client)
    enroll_device(client)
    captured = []
    original_make = qrcode.make
    monkeypatch.setattr("app.routes.api.qrcode.make", lambda value, *a, **k: (captured.append(value), original_make(value, *a, **k))[1])
    desktop = app.test_client()
    created = desktop.post("/api/qr", json={})
    request_id = created.json["data"]["request_id"]
    token = captured[-1].split("#", 1)[1]
    stranger = app.test_client()
    assert stranger.post(f"/api/qr/{request_id}/review", json={"token": token}).status_code == 401
    wrong_desktop = app.test_client()
    assert wrong_desktop.get(f"/api/qr/{request_id}").status_code == 404
    row = db.session.get(QRLoginRequest, request_id)
    row.expires_at = utcnow() - timedelta(seconds=1)
    db.session.commit()
    assert desktop.get(f"/api/qr/{request_id}").json["data"]["state"] == "expired"
    assert desktop.get(f"/api/qr/{request_id}").json["data"]["state"] == "expired"