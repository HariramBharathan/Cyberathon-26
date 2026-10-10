import json
import smtplib
import urllib.request
from email.message import EmailMessage

from flask import current_app


class DemoSMSAdapter:
    """Local-only adapter; it prints a labeled code and sends no real SMS."""

    def send(self, destination, code, purpose=None):
        masked = f"***{destination[-4:]}" if len(destination) > 4 else "***"
        purpose_label = f" ({purpose})" if purpose else ""
        print(f"[SENTINELPASS SMS DEMO - NOT SENT] {masked}{purpose_label}: code {code}")


class WebhookSMSAdapter:
    """Adapter for an operator-configured HTTPS SMS gateway endpoint."""

    def send(self, destination, code, purpose=None):
        endpoint = current_app.config.get("SMS_WEBHOOK_URL", "")
        token = current_app.config.get("SMS_WEBHOOK_TOKEN", "")
        if not endpoint.startswith("https://") or not token:
            raise RuntimeError("SMS webhook requires an HTTPS URL and token.")
        body = json.dumps({
            "to": destination,
            "message": f"Your SentinelPass code is {code}.",
            "purpose": purpose or "login",
        }).encode()
        request = urllib.request.Request(
            endpoint,
            data=body,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=8) as response:
            if response.status >= 300:
                raise RuntimeError("The SMS provider rejected the delivery request.")


def send_email(destination, code, purpose):
    server = current_app.config.get("MAIL_SERVER")
    if not server:
        if not current_app.config["DEVELOPMENT"]:
            raise RuntimeError("Email delivery is not configured.")
        print(f"[SENTINELPASS LOCAL EMAIL - NOT SENT] {destination} ({purpose}): code {code}", flush=True)
        return
    message = EmailMessage()
    message["Subject"] = "Your SentinelPass verification code"
    message["From"] = current_app.config["MAIL_DEFAULT_SENDER"]
    message["To"] = destination
    message.set_content(
        f"Your SentinelPass code is {code}. It expires in five minutes. "
        "If you did not request it, you can ignore this message."
    )
    with smtplib.SMTP(server, current_app.config["MAIL_PORT"], timeout=10) as smtp:
        if current_app.config["MAIL_USE_TLS"]:
            smtp.starttls()
        username = current_app.config.get("MAIL_USERNAME")
        if username:
            smtp.login(username, current_app.config.get("MAIL_PASSWORD", ""))
        smtp.send_message(message)


def send_sms(destination, code, purpose="login"):
    provider = current_app.config.get("SMS_PROVIDER", "demo")
    if provider == "demo":
        if not current_app.config["DEVELOPMENT"]:
            raise RuntimeError("Demo SMS delivery is disabled in production.")
        DemoSMSAdapter().send(destination, code, purpose)
    elif provider == "webhook":
        WebhookSMSAdapter().send(destination, code, purpose)
    else:
        raise RuntimeError("The configured SMS provider is not supported.")