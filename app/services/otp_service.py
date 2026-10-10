import secrets
import uuid
from datetime import timedelta

from flask import current_app
from sqlalchemy import update

from ..extensions import db
from ..models import OTPChallenge, User, utcnow
from .delivery import send_email, send_sms
from .security import otp_hash, secure_equal


class OTPError(Exception):
    pass


class OTPThrottle(OTPError):
    pass


def create_challenge(user, purpose, destination_type, correlation_id=None, parent_id=None):
    now = utcnow()
    recent = OTPChallenge.query.filter(
        OTPChallenge.user_id == user.id,
        OTPChallenge.purpose == purpose,
        OTPChallenge.consumed_at.is_(None),
        OTPChallenge.created_at >= now - timedelta(minutes=1),
    ).count()
    hourly = OTPChallenge.query.filter(
        OTPChallenge.user_id == user.id,
        OTPChallenge.purpose == purpose,
        OTPChallenge.consumed_at.is_(None),
        OTPChallenge.created_at >= now - timedelta(hours=1),
    ).count()
    if recent or hourly >= 5:
        raise OTPThrottle("Please wait before requesting another code.")

    destination = user.email if destination_type == "email" else user.phone
    if not destination:
        raise OTPError("That verification method is not available for this account.")
    if destination_type == "phone" and not user.phone_verified and purpose == "login":
        raise OTPError("Verify the phone number before using phone sign-in.")

    challenge_id = str(uuid.uuid4())
    code = current_app.config["DEMO_OTP"] if current_app.config["DEVELOPMENT"] else f"{secrets.randbelow(1_000_000):06d}"
    challenge = OTPChallenge(
        id=challenge_id,
        user_id=user.id,
        purpose=purpose,
        destination_type=destination_type,
        destination=destination,
        otp_hash=otp_hash(challenge_id, code),
        expires_at=now + timedelta(seconds=current_app.config["OTP_TTL_SECONDS"]),
        parent_challenge_id=parent_id,
        correlation_id=correlation_id or challenge_id,
    )
    db.session.add(challenge)
    db.session.flush()
    if destination_type == "email":
        send_email(destination, code, purpose)
    else:
        send_sms(destination, code, purpose)
    return challenge


def consume_challenge(challenge, code):
    if not challenge or not code or len(code) != 6 or not code.isdigit():
        return "invalid"
    now = utcnow()
    expires_at = challenge.expires_at
    if expires_at.tzinfo is None:
        from datetime import timezone
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if challenge.consumed_at:
        return "used"
    if expires_at <= now:
        return "expired"
    if challenge.attempts >= current_app.config["OTP_MAX_ATTEMPTS"]:
        return "attempts_exceeded"

    expected_hash = otp_hash(challenge.id, code)
    if not secure_equal(challenge.otp_hash, expected_hash):
        result = db.session.execute(
            update(OTPChallenge.__table__)
            .where(
                OTPChallenge.id == challenge.id,
                OTPChallenge.consumed_at.is_(None),
                OTPChallenge.attempts < current_app.config["OTP_MAX_ATTEMPTS"],
            )
            .values(attempts=OTPChallenge.attempts + 1),
            execution_options={"synchronize_session": False},
        )
        db.session.commit()
        return "attempts_exceeded" if not result.rowcount else "incorrect"

    result = db.session.execute(
        update(OTPChallenge.__table__)
        .where(
            OTPChallenge.id == challenge.id,
            OTPChallenge.consumed_at.is_(None),
            OTPChallenge.expires_at > now,
            OTPChallenge.attempts < current_app.config["OTP_MAX_ATTEMPTS"],
            OTPChallenge.otp_hash == expected_hash,
        )
        .values(consumed_at=now),
        execution_options={"synchronize_session": False},
    )
    db.session.commit()
    return "verified" if result.rowcount == 1 else "used"