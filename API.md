# API Reference

All JSON endpoints use `{ "ok": true, "data": ... }` on success and `{ "ok": false, "error": { "code", "message" } }` on failure. State-changing requests require the `X-CSRFToken` header matching the rendered `csrf-token` meta tag. Authentication uses the HttpOnly `sentinelpass_session` cookie. User-owned endpoints are scoped to the authenticated user.

## Public Identity And OTP

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/register` | Create pending account; requires `full_name`, `email`, optional `phone`; starts email proof. |
| `POST` | `/api/otp/request` | Request OTP with `method`, `destination`, optional `purpose`. Unknown/ineligible login targets receive a generic response. |
| `POST` | `/api/otp/verify` | Verify `{ "challenge_id", "code" }`; may return `step_up_required`, verification completion, or an authenticated session. |

## QR

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/qr` | Create short-lived bound desktop request and QR image data URI. Sets the pending desktop-binding cookie. |
| `GET` | `/api/qr/{request_id}` | Poll from the initiating browser; only this browser can consume approval and receive its session. |
| `POST` | `/api/qr/{request_id}/review` | Authenticated trusted-device review; JSON `{ "token" }`; returns browser context and expiry. |
| `POST` | `/api/qr/{request_id}/approve` | Explicit mobile approval with `{ "token" }`. |
| `POST` | `/api/qr/{request_id}/deny` | Explicit mobile denial with `{ "token" }`. |

## Authenticated Resources

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/me` | Current account. |
| `GET` | `/api/dashboard/summary?days=7\|30\|90` | User-scoped activity counts and recent events. |
| `GET` | `/api/history?page=1&method=&outcome=&q=` | Server-filtered, paginated event history. |
| `GET` | `/api/devices` | Owned device records, current state, timestamps. |
| `POST` | `/api/devices` | Enroll current browser after recent auth: `{ "name" }`; sets device cookie. |
| `PATCH` | `/api/devices/{id}` | Rename owned device: `{ "name" }`. |
| `DELETE` | `/api/devices/{id}` | Revoke owned device and its sessions. |
| `POST` | `/api/devices/revoke-others` | Revoke all other active device credentials. |
| `GET` | `/api/alerts?severity=&status=` | List user-scoped alerts. |
| `POST` | `/api/alerts/{id}/resolve` | Resolve owned alert. |
| `GET` | `/api/timeline/{correlation_id}` | Read actual backend decision events for an owned authentication correlation. |
| `GET` | `/api/settings` | Account verification state and active sessions. |
| `PATCH` | `/api/settings` | Update full name. |
| `POST` | `/api/settings/phone` | Set phone and start ownership challenge. |
| `POST` | `/api/logout` | Revoke current database session. |
| `POST` | `/api/logout-all` | Revoke all account sessions. |
| `DELETE` | `/api/account` | Confirm with `{ "confirm": "account@email" }`, anonymize account identifiers and revoke access. |

The local adapter code is not returned by OTP request endpoints. HTTP status reflects authentication, validation, rate-limit, conflict, and policy outcomes. Public errors avoid account enumeration.