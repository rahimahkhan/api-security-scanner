"""Signup/login input policy: password strength and email allow-list.

Kept in one place so the signup form, the password-reset form, and the
tests all enforce the same rules.
"""
import re
from typing import Optional

# Only these email domains are accepted on the manual signup form.
# (Google OAuth is exempt — Google already verified those addresses.)
ALLOWED_EMAIL_DOMAINS = {"gmail.com", "email.com"}

# Local parts that are obviously not a real person's address.
JUNK_LOCAL_PARTS = {
    "xyz", "abc", "test", "asdf", "qwerty", "123", "1234", "abcd",
    "abc123", "xyz123", "aaa", "xxx", "temp", "tmp",
}

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# At least 8 chars, one capital letter, one number, one special character.
MIN_PASSWORD_LENGTH = 8


def password_strength_error(password: str) -> Optional[str]:
    """Return None when the password meets policy, else a human-readable reason."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return "Password must include at least one capital letter (A–Z)."
    if not re.search(r"[0-9]", password):
        return "Password must include at least one number (0–9)."
    if not re.search(r"[^A-Za-z0-9]", password):
        return "Password must include at least one special character (e.g. !@#$%)."
    return None


def validate_signup_email(email: str) -> Optional[str]:
    """Return None when the email is acceptable, else a human-readable reason.

    Empty email is allowed (the field is optional); callers check that first.
    """
    email = (email or "").strip()
    if not email:
        return None
    if not EMAIL_RE.match(email):
        return "That doesn't look like a valid email address."
    local, _, domain = email.partition("@")
    if domain.lower() not in ALLOWED_EMAIL_DOMAINS:
        return "Please use a @gmail.com or @email.com address."
    if len(local) < 4:
        return "That email looks too short to be real — please use your actual email address."
    if local.lower() in JUNK_LOCAL_PARTS:
        return "Please use your real email address."
    return None
