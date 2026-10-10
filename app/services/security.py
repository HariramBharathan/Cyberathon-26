import hashlib
import hmac
import secrets
import uuid

from flask import current_app, request


def new_token(byte_count=32):
    return secrets.token_urlsafe(byte_count)


def token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def otp_hash(challenge_id, code):
    return hmac.new(
        current_app.config["SECRET_KEY"].encode("utf-8"),
        f"{challenge_id}:{code}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def secure_equal(left, right):
    return hmac.compare_digest(left, right)


def correlation_id():
    return str(uuid.uuid4())


def browser_summary():
    agent = request.user_agent
    browser = agent.browser or "Browser"
    version = agent.version.split(".")[0] if agent.version else ""
    platform = agent.platform or "Unknown platform"
    return f"{browser} {version} on {platform}"[:160]


def normalized_email(value):
    return value.strip().casefold()


def normalized_phone(value):
    return "".join(character for character in value if character.isdigit() or character == "+")


def cookie_options():
    return {
        "httponly": True,
        "secure": not current_app.config["DEVELOPMENT"],
        "samesite": "Lax",
        "path": "/",
    }