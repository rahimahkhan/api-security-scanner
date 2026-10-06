"""Outgoing email for the dashboard (password-reset OTP codes).

Two sending paths, picked automatically:

1. SendGrid HTTPS API (preferred on Render): set SENDGRID_API_KEY.
   Render blocks outbound SMTP entirely, so direct SMTP can never work
   there — the HTTPS API is the way. Free tier (100 emails/day) plus
   "Single Sender Verification" for the from-address is enough; no
   custom domain needed.
2. Plain SMTP fallback (works on any host where SMTP isn't blocked):
    SMTP_HOST=smtp.gmail.com        (default)
    SMTP_PORT=587                   (default)
    SMTP_USERNAME=you@gmail.com
    SMTP_PASSWORD=<16-char app password, no spaces>
    SMTP_FROM=you@gmail.com         (defaults to SMTP_USERNAME)

If neither is configured, sending is disabled and the forgot-password
page says so honestly instead of failing silently.
"""
import json as jsonlib
import os
import smtplib
import urllib.request
import urllib.error
from email.mime.text import MIMEText
from typing import Tuple

from config.logging_config import logger


def is_email_configured() -> bool:
    return bool(os.environ.get("SENDGRID_API_KEY")) or \
        bool(os.environ.get("SMTP_USERNAME") and os.environ.get("SMTP_PASSWORD"))


def _sendgrid_from() -> str:
    return (os.environ.get("SENDGRID_FROM_EMAIL")
            or os.environ.get("SMTP_FROM")
            or os.environ.get("SMTP_USERNAME", ""))


def _send(to_email: str, subject: str, body: str) -> Tuple[bool, str]:
    """Low-level send. Returns (ok, reason)."""
    if os.environ.get("SENDGRID_API_KEY"):
        return _send_via_sendgrid(to_email, subject, body)
    return _send_via_smtp(to_email, subject, body)


def _send_via_sendgrid(to_email: str, subject: str, body: str) -> Tuple[bool, str]:
    """Send through the SendGrid v3 HTTPS API (works where SMTP is blocked)."""
    api_key = os.environ["SENDGRID_API_KEY"]
    from_addr = _sendgrid_from()
    payload = {
        "personalizations": [{"to": [{"email": to_email}]}],
        "from": {"email": from_addr},
        "subject": subject,
        "content": [{"type": "text/plain", "value": body}],
    }
    req = urllib.request.Request(
        "https://api.sendgrid.com/v3/mail/send",
        data=jsonlib.dumps(payload).encode("utf-8"),
        headers={"Authorization": "Bearer " + api_key,
                 "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            if resp.status in (200, 201, 202):
                logger.info(f"Email '{subject}' sent to {to_email} via SendGrid")
                return True, "sent"
            logger.warning(f"SendGrid send to {to_email} failed: HTTP {resp.status}")
            return False, f"sendgrid_{resp.status}"
    except urllib.error.HTTPError as e:
        # Never log the response body — it can echo auth details.
        logger.warning(f"SendGrid send to {to_email} failed: HTTP {e.code}")
        return False, f"sendgrid_{e.code}"
    except Exception as e:  # network failure — report, don't crash
        logger.warning(f"SendGrid send to {to_email} failed: {e}")
        return False, "send_failed"


def _send_via_smtp(to_email: str, subject: str, body: str) -> Tuple[bool, str]:
    if not (os.environ.get("SMTP_USERNAME") and os.environ.get("SMTP_PASSWORD")):
        return False, "email_not_configured"
    host = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    port = int(os.environ.get("SMTP_PORT", "587"))
    username = os.environ["SMTP_USERNAME"]
    password = os.environ["SMTP_PASSWORD"]
    from_addr = os.environ.get("SMTP_FROM", username)

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_email
    try:
        with smtplib.SMTP(host, port, timeout=30) as smtp:
            smtp.starttls()
            smtp.login(username, password)
            smtp.sendmail(from_addr, [to_email], msg.as_string())
        logger.info(f"Email '{subject}' sent to {to_email}")
        return True, "sent"
    except Exception as e:  # network/auth failure — report, don't crash
        logger.warning(f"Failed to send '{subject}' to {to_email}: {e}")
        return False, "send_failed"


def send_otp_email(to_email: str, otp: str) -> Tuple[bool, str]:
    """Send a 6-digit password-reset OTP. Returns (ok, reason)."""
    body = (
        "You asked to reset your Xploiter password.\n\n"
        f"Your one-time code is:  {otp}\n\n"
        "Enter it on the site within 15 minutes. It works only once.\n\n"
        "If you didn't ask for this, just ignore this email — "
        "your password stays unchanged."
    )
    return _send(to_email, "Xploiter password-reset code", body)
