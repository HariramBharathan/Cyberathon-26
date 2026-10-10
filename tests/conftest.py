import pytest

from app import create_app
from app.extensions import db


@pytest.fixture
def app(tmp_path, monkeypatch):
    database = tmp_path / "sentinelpass-test.db"
    application = create_app({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database}",
        "SECRET_KEY": "test-key-that-is-long-enough-for-local-tests",
        "RATELIMIT_ENABLED": False,
        "DEVELOPMENT": True,
        "OTP_TTL_SECONDS": 300,
        "OTP_MAX_ATTEMPTS": 5,
        "QR_TTL_SECONDS": 120,
        "SESSION_TTL_SECONDS": 3600,
        "TRUSTED_DEVICE_DAYS": 30,
    })
    application.extensions["sentinelpass_deliveries"] = []

    def capture_email(destination, code, purpose):
        application.extensions["sentinelpass_deliveries"].append(("email", destination, code, purpose))

    def capture_sms(destination, code, purpose="login"):
        application.extensions["sentinelpass_deliveries"].append(("phone", destination, code, purpose))

    monkeypatch.setattr("app.services.otp_service.send_email", capture_email)
    monkeypatch.setattr("app.services.otp_service.send_sms", capture_sms)
    with application.app_context():
        db.create_all()
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture(autouse=True)
def application_context(app):
    with app.app_context():
        yield


def latest_code(app, purpose=None):
    deliveries = app.extensions["sentinelpass_deliveries"]
    for _method, _destination, code, delivered_purpose in reversed(deliveries):
        if purpose is None or purpose == delivered_purpose:
            return code
    raise AssertionError("No matching verification code was delivered.")