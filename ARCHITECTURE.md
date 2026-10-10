# Architecture

## Request Flow

`run.py` creates the Flask application. `app/__init__.py` loads config, extensions, SQLite foreign keys, blueprints, secure response headers, CLI commands, and request identity. `app/routes/web.py` renders server templates. `app/routes/api.py` validates API inputs and permissions, delegates challenge/device work to services, records audit events, and returns the common `{ "ok": true, "data": ... }` or `{ "ok": false, "error": ... }` envelope.

`app/models.py` defines SQLAlchemy entities and UTC helpers. `app/services/otp_service.py` owns OTP generation, delivery handoff, cooldown, hash verification, attempt accounting, expiry and atomic consumption. `device_service.py` owns trusted-device enrollment and revocation. `session_service.py` resolves and issues revocable database sessions. `audit_service.py` records event and timeline rows. `delivery.py` isolates SMTP and SMS provider adapters. `risk_engine.py` is the deterministic LIAE rules module. Templates and static assets contain the responsive server-rendered shell and vanilla JavaScript UI.

## Data Entities

- `User`: normalized unique email, optional unique phone, verification and account status.
- `OTPChallenge`: purpose-bound keyed OTP hash, destination, expiry, attempts, consumption, correlation ID.
- `TrustedDevice`: unique device-token hash, name/browser summary, timestamps, revocation.
- `QRLoginRequest`: QR token hash, desktop cookie-binding hash, request context, state, expiry and optional approver.
- `SessionRecord`: unique opaque session-token hash, user/device, expiry, revocation.
- `AuthenticationEvent`: outcome, method, risk summary, correlation ID and IP address.
- `SecurityAlert`: user-scoped signal tied to an optional event.
- `DecisionEvent`: ordered, user-scoped check/result/explanation/policy/action history.

Foreign keys, unique credential hashes, indexes on ownership/time/state fields, SQLite foreign-key enforcement, and conditional database updates protect common integrity boundaries. Date values are created as UTC. SQLite may return naive Python datetimes, which are interpreted as UTC before in-process comparison.

## Login Intent Assurance Engine

### Risk Policy

`evaluate_risk` in `app/risk_engine.py` considers verified trust state and available failure/context/browser signals. Default weights: unknown device +30, at least 3 recent failures +25, unusual context +15, browser change +10. Thresholds are configurable via `.env`: low through 24, medium through 49, high at 50+. Low continues only after required checks. Medium requires an additional verification step. High denies. These values are examples for controlled demonstration, not calibrated threat intelligence.

Mandatory invalid OTP, invalid/expired/consumed QR, and revoked approver conditions return `reject` independently of the score. No IP-change penalty is implemented. For QR approval, authenticated explicit consent from an active trusted device is the additional verification. Decisions and checks are written as `DecisionEvent` rows, and outcomes as `AuthenticationEvent` rows.

### Email OTP Login

1. Request endpoint normalizes lookup and returns a generic response for unknown/unverified accounts.
2. Service creates a six-digit code from `secrets`, stores an HMAC-SHA256 hash bound to challenge ID, and invokes the email adapter.
3. Verification checks purpose/user/status/expiry/attempt budget and constant-time hash equality.
4. A conditional database update consumes the challenge exactly once.
5. LIAE evaluates trusted-device and recent-failure signals. An unknown browser gets an independent step-up challenge; failure does not create a session.
6. After checks, an opaque session token is returned in a distinct secure cookie; its hash/expiry/user/device association is persisted.

### QR Desktop Login

1. Desktop receives an `HttpOnly` pending-browser binding cookie and a QR token of high entropy. The QR carries `request_id#token`; only its SHA-256 token hash and browser-binding hash are stored.
2. The desktop polls using its request ID and cookie binding.
3. The mobile scans the QR; the fragment stays client-side until the authenticated approval page submits it. The service requires an active session and matching trusted-device cookie for the same user.
4. Review and approval verify that the token belongs to the exact pending, unexpired request. An atomic pending-to-approved/denied update prevents a second decision.
5. Desktop polling checks its own pending cookie, expiry, approved state, and unconsumed status, then atomically consumes approval and creates a new desktop session. It never copies the mobile session.

## Frontend

The landing, registration, sign-in, dashboard, and QR review screens are HTML templates. `static/js/app.js` calls only implemented API routes using `fetch`, JSON, same-origin cookies, and a CSRF token. Authenticated console pages load live, user-scoped data. Security decision timelines are rendered from backend decision records, never animation fixtures. CSS uses a restrained charcoal/navy surface, teal accent, slate typography, responsive sidebar/tables, and reduced-motion support.

## Deployment Boundary

Local SQLite, Flask's built-in server, in-memory rate-limit storage, and console delivery adapters are for a single-machine demo. Production must configure a persistent database, HTTPS, a WSGI server, shared limiter backend, strong secret, provider credentials, privacy/retention policies, monitoring, backups, migrations, and reviewed reverse-proxy/trusted-host behavior. Production configuration validation intentionally blocks unsafe defaults.