import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "local-development-key-change-before-deploying")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{BASE_DIR / 'instance' / 'sentinelpass.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}
    WTF_CSRF_TIME_LIMIT = 3600
    SESSION_COOKIE_NAME = "sentinelpass_flask_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_HTTPONLY = True
    PERMANENT_SESSION_LIFETIME = 60 * 60 * 8
    TRUSTED_DEVICE_DAYS = int(os.environ.get("TRUSTED_DEVICE_DAYS", "30"))
    OTP_TTL_SECONDS = int(os.environ.get("OTP_TTL_SECONDS", "300"))
    OTP_MAX_ATTEMPTS = int(os.environ.get("OTP_MAX_ATTEMPTS", "5"))
    DEMO_OTP = os.environ.get("DEMO_OTP", "549213")
    QR_TTL_SECONDS = int(os.environ.get("QR_TTL_SECONDS", "120"))
    SESSION_TTL_SECONDS = int(os.environ.get("SESSION_TTL_SECONDS", "28800"))
    RISK_LOW_MAX = int(os.environ.get("RISK_LOW_MAX", "24"))
    RISK_MEDIUM_MAX = int(os.environ.get("RISK_MEDIUM_MAX", "49"))
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_DEFAULT = "200 per day; 50 per hour"
    MAIL_SERVER = os.environ.get("MAIL_SERVER")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", "587"))
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
    MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "true").lower() == "true"
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER", "SentinelPass <no-reply@localhost>")
    SMS_PROVIDER = os.environ.get("SMS_PROVIDER", "demo").lower()
    SMS_WEBHOOK_URL = os.environ.get("SMS_WEBHOOK_URL")
    SMS_WEBHOOK_TOKEN = os.environ.get("SMS_WEBHOOK_TOKEN")
    APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://127.0.0.1:5000")
    DEVELOPMENT = os.environ.get("SENTINELPASS_ENV", "development").lower() != "production"


class ProductionConfig(Config):
    DEVELOPMENT = False
    SESSION_COOKIE_SECURE = True
    WTF_CSRF_SSL_STRICT = True

    @classmethod
    def validate(cls):
        secret = os.environ.get("SECRET_KEY", "")
        storage = os.environ.get("RATELIMIT_STORAGE_URI", "")
        if len(secret) < 32:
            raise RuntimeError("Production requires a SECRET_KEY of at least 32 characters.")
        if not storage or storage.startswith("memory://"):
            raise RuntimeError("Production requires shared rate-limit storage, such as Redis.")
        if not os.environ.get("DATABASE_URL"):
            raise RuntimeError("Production requires an explicit DATABASE_URL.")