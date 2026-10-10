# SentinelPass

**Every login has a reason. Every decision has an explanation.**

SentinelPass is a passwordless authentication prototype that combines verified email/phone OTP, explicit trusted-device enrollment, transaction-bound desktop QR approval, and a deterministic, explainable Login Intent Assurance Engine (LIAE). It demonstrates an integrated workflow; it does not claim that OTP, QR, device trust, or risk scoring are individually novel.

## What It Does

- Account registration stays pending until the user proves control of the email address.
- Email and verified-phone OTPs are six digits, hashed, single-use, expiring, attempt-limited, and atomically consumed.
- A new browser must complete additional verification before receiving a session.
- Trusted devices are enrolled explicitly after recent authentication. Random device tokens are hashed in the database and can be expired or revoked.
- Desktop QR requests use a high-entropy token hash, a pending desktop-session binding, a two-minute expiry, and atomic one-time state transitions. Mobile approval requires an authenticated session bound to a registered device. Only the initiating desktop receives a separate revocable session after polling and consuming the approval.
- LIAE scores contextual signals, explains its policy/action, records a decision timeline, and never lets a low score override mandatory checks.
- Dashboard, history, alerts, device management, settings, and timelines use user-scoped SQLite data.
- No password field or password verifier is implemented.

## Architecture

Flask serves HTML templates and JSON API endpoints. Business logic lives in `app/services/`; SQLAlchemy records users, OTP challenges, trusted devices, QR intents, authentication events, security alerts, decision timeline events, and revocable sessions. SQLite stores local development data under `instance/`. Opaque authentication session and device tokens are sent only as `HttpOnly`, `SameSite=Lax` cookies; only SHA-256 hashes are stored. Flask-WTF CSRF protects state-changing requests. Flask-Limiter applies endpoint and global limits.

See [ARCHITECTURE.md](ARCHITECTURE.md), [API.md](API.md), and [SECURITY.md](SECURITY.md) for implementation detail and boundaries.

## Stack

Python 3.11+, Flask, Flask-SQLAlchemy, Flask-WTF, Flask-Limiter, PyOTP (available for future TOTP extension; current email/SMS codes are random OTPs), `secrets`, `hashlib`, `hmac`, `qrcode[pil]`, python-dotenv, SQLite, HTML/CSS, and vanilla JavaScript. Tests use pytest and Flask's test client.

## Install And Run

### Windows PowerShell

```powershell
cd "D:\Personal\Cyber Hackathon"
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python -m flask --app run.py init-db
python -m flask --app run.py create-demo-user
python run.py
```

Open `http://127.0.0.1:5000`. For a phone on the same network, find the development computer's LAN address, run with ` $env:HOST="0.0.0.0" `, and open `http://<computer-lan-ip>:5000` on both devices. Permit local Python through the private-network firewall if Windows asks. Do not expose the development server to the public internet.

### Linux / macOS

```sh
cd "/path/to/Cyber Hackathon"
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
cp .env.example .env
flask --app run.py init-db
flask --app run.py create-demo-user
python run.py
```

The CLI commands are safe to repeat. `create-demo-user` creates no password or reusable token; it creates a verified local account named `demo@sentinelpass.local`. Demo codes are visible only in the development server console.

## Providers

With no SMTP host configured, email codes are printed with the label `[SENTINELPASS LOCAL EMAIL - NOT SENT]` to the local server console. Development uses the fixed demo code `549213` by default (`DEMO_OTP` can override it); production always generates random codes. This adapter never sends an email and is development-only. Configure `MAIL_SERVER`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_USE_TLS`, and `MAIL_DEFAULT_SENDER` for SMTP delivery.

`SMS_PROVIDER=demo` is a development-only adapter that prints `[SENTINELPASS SMS DEMO - NOT SENT]`; no SMS is sent. To connect a provider, set `SMS_PROVIDER=webhook`, `SMS_WEBHOOK_URL` to an HTTPS JSON endpoint, and `SMS_WEBHOOK_TOKEN` to its bearer credential. The endpoint receives `{ "to": "...", "message": "..." }`. Validate the selected provider's delivery/security guarantees before production use.

## Database And Tests

Initialize the database with `python -m flask --app run.py init-db` or `python scripts/initialize_database.py`. The default database path is `instance/sentinelpass.db`; override it with `DATABASE_URL`.

Run tests:

```powershell
python -m pytest -q
```

Tests create isolated temporary SQLite databases and mock OTP delivery. They cover registration proof, OTP expiry/attempts/single use, step-up verification, trusted-device revocation, transaction-bound QR approval, desktop binding, expiry/replay, CSRF, auth gates, user-scoped data, and risk policy. `tests/test_auth_flows.py` captures adapter codes inside tests only; public routes never return codes.

## Five-Minute Demonstration

See [DEMO.md](DEMO.md) for a complete script. In brief: register a test identity, enter the local demo code from the server console, and the account is verified and signed in automatically. Inspect the actual risk decision. Then enroll the signed-in mobile browser from **Trusted devices**. On a separate desktop browser choose **Authenticate → QR login**, scan the QR on the registered mobile browser, explicitly approve, and watch the desktop create its independent session. Revoke the phone device, then demonstrate that it can no longer approve requests. Open the authentication event's timeline to show checks recorded by the backend.

## LIAE Policy

Default documented weights: unknown device +30; at least three failed/rejected attempts in 15 minutes +25; unusual context +15; browser change +10. Default bands: 0–24 low (continue after required checks), 25–49 medium (additional verification), 50+ high (deny). A newly unknown browser therefore receives a second OTP. Explicit authenticated approval on a registered mobile device is the additional verification for QR intent. An invalid/expired/consumed QR, invalid OTP, or revoked approving device is a mandatory rejection independent of score. IP-address changes alone carry no penalty. See [ARCHITECTURE.md](ARCHITECTURE.md#risk-policy) for rule details.

## Limitations And Production Readiness

This is a hackathon prototype, not a production identity provider. Development delivery prints codes to a local console; demo SMS is not a real message. The webhook adapter is generic, not a certified provider integration. SQLite is intended for local demonstration, not a multi-worker production deployment. Rate limiting defaults to in-memory storage outside production; production startup rejects that default. Set a strong random secret, shared Redis-compatible limiter storage, a managed database, HTTPS, trusted reverse-proxy configuration, log/retention policies, provider credentials, monitoring, backup, dependency review, migration tooling, and independent security review before deployment. Risk weights are demonstration policy values, not empirically calibrated or an AI model. IP addresses are stored in authentication history and must be handled under an explicit privacy policy.