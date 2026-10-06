"""Outgoing email for the dashboard (password-reset OTP codes).

Uses plain SMTP from environment variables so it works on any host with
zero new dependencies. The standard setup is a Gmail App Password:

    SMTP_HOST=smtp.gmail.com        (default)
    SMTP_PORT=587                   (default)
    SMTP_USERNAME=you@gmail.com
    SMTP_PASSWORD=<16-char app password, no spaces>
    SMTP_FROM=you@gmail.com         (defaults to SMTP_USERNAME)

If SMTP_USERNAME/SMTP_PASSWORD are not set, sending is disabled and the
forgot-password page says so honestly instead of failing silently.
"""
import os
import smtplib
from email.mime.text import MIMEText
from typing import Tuple

from config.logging_config import logger


def is_email_configured() -> bool:
    return bool(os.environ.get("SMTP_USERNAME") and os.environ.get("SMTP_PASSWORD"))


def _send(to_email: str, subject: str, body: str) -> Tuple[bool, str]:
    """Low-level send. Returns (ok, reason)."""
    if not is_email_configured():
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
