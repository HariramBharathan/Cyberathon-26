# Five-Minute SentinelPass Demo

## Prepare

1. Initialize and start the app using the commands in `README.md`.
2. For the demo user, keep the server console visible. For a clean user-owned timeline, register a unique test email instead of using the CLI account.
3. To use a physical phone, run with `HOST=0.0.0.0` (PowerShell: `$env:HOST="0.0.0.0"`), open the computer's LAN address on the phone, and keep both on the same trusted network. Local firewall permission may be required.

## Script

1. **Verify identity.** Open `/register`; enter a test name/email. Read the clearly labeled local email code in the server console, enter it, and confirm the account activates only after successful verification.
2. **Show unknown-device step-up.** Sign in with email OTP. The first browser is unknown, so LIAE requests a second code. Read and enter the separate step-up code; only then does the app create the session. Open Login History and inspect the score/explanation.
3. **Enroll the phone browser.** On the phone, sign in to the same test account. Complete the unknown-device step-up. Open **Trusted devices → Register this browser** and name it. Enrollment is an explicit action, not an IP inference.
4. **Approve a desktop request.** On another desktop browser, open **Authenticate**, then **QR login**. Scan the QR from the registered phone browser. Review browser context and expiry; explicitly approve. The desktop polls and receives a distinct session only after server-side token, status, expiry, and binding checks pass.
5. **Inspect the real timeline.** Open the resulting event in Login History and select **Timeline**. Show the recorded OTP/device/risk/approval/binding/session checks and policy outcome.
6. **Demonstrate rejection/revocation.** Reuse the scanned approval after the state is consumed, or wait for the two-minute request to expire; the backend refuses it. Revoke the phone device from the desktop. Its old session/token can no longer authorize device-bound approval.

## Notes

- Development email/SMS codes print only to the local server console. The phone demo adapter explicitly says that no SMS was sent.
- QR tokens are in the URL fragment and are never displayed by the UI. Scan the currently displayed QR; do not use an old screenshot.
- The QR approval page requires the same account's authenticated session on a currently trusted device.
- A new request creates real rows and decision events. No frontend-only status or fake telemetry is used.