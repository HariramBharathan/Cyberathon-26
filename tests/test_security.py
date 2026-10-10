from concurrent.futures import ThreadPoolExecutor
import uuid

from sqlalchemy import update

from app import create_app
from app.extensions import db
from app.models import AuthenticationEvent, QRLoginRequest, SessionRecord, User, utcnow
from datetime import timedelta
from app.services.security import new_token, token_hash


def test_create_app_initializes_missing_database_schema(tmp_path):
    database = tmp_path / "fresh-schema.db"
    app = create_app({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database}",
        "SECRET_KEY": "test-key-that-is-long-enough-for-local-tests",
        "RATELIMIT_ENABLED": False,
        "DEVELOPMENT": True,
    })
    with app.app_context():
        assert db.inspect(db.engine).has_table("user")
        assert db.inspect(db.engine).has_table("otp_challenge")


def test_csrf_is_enforced_for_state_changes(tmp_path):
    app = create_app({
        "TESTING": True,
        "WTF_CSRF_ENABLED": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'csrf.db'}",
        "SECRET_KEY": "csrf-test-key-long-enough-for-test-suite",
        "RATELIMIT_ENABLED": False,
        "DEVELOPMENT": True,
    })
    with app.app_context():
        db.create_all()
    response = app.test_client().post("/api/otp/request", json={"method": "email", "destination": "nobody@example.com"})
    assert response.status_code == 400
    assert response.json["error"]["code"] == "csrf_failed"
    with app.app_context():
        db.drop_all()


def test_private_routes_require_authentication(client):
    assert client.get("/api/dashboard/summary").status_code == 401
    assert client.get("/api/history").status_code == 401
    assert client.get("/api/devices").status_code == 401
    assert client.get("/api/alerts").status_code == 401


def test_dashboard_and_history_are_isolated_by_user(client, app):
    with app.app_context():
        first = User(full_name="First Person", email="first@example.com", email_verified=True, status="active")
        second = User(full_name="Second Person", email="second@example.com", email_verified=True, status="active")
        db.session.add_all([first, second])
        db.session.commit()
        db.session.add(AuthenticationEvent(
            user_id=second.id, method="email_otp", outcome="success", risk_score=0,
            decision="private event", correlation_id="private-correlation",
        ))
        first_token = new_token()
        second_token = new_token()
        db.session.add_all([
            SessionRecord(token_hash=token_hash(first_token), user_id=first.id,
                          expires_at=utcnow() + timedelta(hours=1)),
            SessionRecord(token_hash=token_hash(second_token), user_id=second.id,
                          expires_at=utcnow() + timedelta(hours=1)),
        ])
        db.session.commit()
    client.set_cookie("sentinelpass_session", first_token)
    summary = client.get("/api/dashboard/summary")
    assert summary.status_code == 200
    assert summary.json["data"]["total_attempts"] == 0
    assert client.get("/api/history").json["data"]["total"] == 0
    response = client.get("/api/timeline/private-correlation")
    assert response.status_code == 404


def test_production_configuration_rejects_unsafe_defaults(monkeypatch):
    from app.config import ProductionConfig

    monkeypatch.setenv("SECRET_KEY", "short")
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "memory://")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///prod.db")
    try:
        ProductionConfig.validate()
    except RuntimeError as error:
        assert "SECRET_KEY" in str(error)
    else:
        raise AssertionError("Unsafe production configuration was accepted")


def test_qr_compare_and_swap_allows_only_one_concurrent_transition(app):
    request_id = str(uuid.uuid4())
    with app.app_context():
        db.session.add(QRLoginRequest(
            id=request_id,
            request_token_hash="a" * 64,
            desktop_binding_hash="b" * 64,
            browser_summary="Test browser",
            expires_at=utcnow() + timedelta(minutes=2),
        ))
        db.session.commit()

    def approve_once():
        with app.app_context():
            result = db.session.execute(
                update(QRLoginRequest.__table__)
                .where(QRLoginRequest.id == request_id, QRLoginRequest.state == "pending")
                .values(state="approved")
            )
            db.session.commit()
            return result.rowcount

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(lambda _index: approve_once(), range(2)))
    assert sorted(outcomes) == [0, 1]