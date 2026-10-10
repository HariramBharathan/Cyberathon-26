# Security Notes

## Implemented Controls

- CSRF protection applies to unsafe requests, including JSON APIs.
- Auth sessions and trusted-device credentials use high-entropy random bearer values in `HttpOnly`, `SameSite=Lax` cookies; only SHA-256 hashes are persisted. The auth session is a server-side database record, so logout, logout-all, device revocation, expiry, and account deletion invalidate copies server-side.
- Authentication rotates by issuing a new opaque token only after verification. Flask's CSRF/session cookie has a separate name from the revocable auth cookie.
- OTP records bind a challenge to its user, purpose, destination, hash, expiry, attempt count, and consumption state. Verification uses HMAC-SHA256 with constant-time comparison and a conditional single-use SQL update.
- QR records bind a hash of a high-entropy fragment token to the exact pending desktop cookie binding, expiry, state, device, and approver. Conditional SQL state transitions prevent replay and duplicate approval. Desktop consumption separately checks the initiating browser binding and issues a distinct session.
- Ownership filters scope history, device records, alerts, settings, and timelines by authenticated user.
- Unknown accounts receive a generic OTP-request response. Error handlers do not return stack traces. Sensitive API/authenticated pages set `Cache-Control: no-store`.
- Security headers include `X-Content-Type-Options`, `X-Frame-Options`, and `Referrer-Policy`. State-changing endpoints are rate limited.
- Production startup rejects short/missing secrets, implicit databases, and in-memory rate-limit storage. Production auth/device cookies are `Secure`.

## Local Demo Warning

The local email adapter prints OTPs to the development server console and is disabled in production. The demo SMS adapter explicitly reports that it sent nothing, is disabled in production, and must not be described as real SMS. Never publish the development server or its console output. Do not reuse demo data or secrets in production.

## QR Token Handling

The QR URL contains a random bearer token in the URL fragment. Browsers do not transmit fragments in HTTP requests or referrer headers. The approval page reads the fragment and submits it in a CSRF-protected JSON request after the mobile browser has authenticated and the device token is validated. The server stores only the token hash. The client removes the fragment after its explicit decision. A user who obtains the live QR image can attempt the request, which is why the mobile page displays the requesting browser/context and requires explicit approval.

## Policy And Residual Risks

LIAE is deterministic and inspectable, not machine learning. Weights and thresholds are illustrative prototype values. Its rules do not replace authentication, authorization, mandatory checks, or operator judgment. IP changes alone are not penalized. The prototype stores IP addresses for audit history; define retention, access, and deletion policy for the deployment jurisdiction.

The generic HTTPS SMS webhook adapter is not a provider certification. SMTP TLS behavior depends on deployment configuration. The Flask development server is not production WSGI infrastructure. There is no migration framework, distributed lock service, email change verification workflow, notification-preference storage, federated identity, account recovery, device attestation, or independent penetration test. The SQLite compare-and-swap logic is tested locally; production database transaction behavior still requires deployment-specific verification. Configure HTTPS, secure proxy handling, a production WSGI server, shared rate limiting, monitoring, key rotation, backups, migration/retention jobs, and external review before real users rely on the service.