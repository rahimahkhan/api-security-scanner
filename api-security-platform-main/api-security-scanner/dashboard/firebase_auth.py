"""Firebase Authentication integration for the dashboard.

Identity lives in Firebase (email/password + Google sign-in via the Firebase
JS SDK in the browser). This backend verifies Firebase ID tokens with the
Admin SDK and keeps one local ``User`` row per Firebase user (keyed by
``firebase_uid``) so scan history stays per-user isolated.

Configuration (all from environment, never committed):
    FIREBASE_API_KEY, FIREBASE_AUTH_DOMAIN, FIREBASE_PROJECT_ID,
    FIREBASE_APP_ID            -- public web config, injected into templates
    FIREBASE_SERVICE_ACCOUNT_JSON -- private key JSON for the Admin SDK
"""
import json
import os

_admin_app = None


def firebase_web_config() -> dict:
    """Public Firebase web config for the JS SDK (safe to embed in pages)."""
    return {
        "apiKey": os.environ.get("FIREBASE_API_KEY", ""),
        "authDomain": os.environ.get("FIREBASE_AUTH_DOMAIN", ""),
        "projectId": os.environ.get("FIREBASE_PROJECT_ID", ""),
        "appId": os.environ.get("FIREBASE_APP_ID", ""),
    }


def firebase_configured() -> bool:
    """True once the web config env vars are set."""
    return all(firebase_web_config().values())


def _admin_app():
    """Lazily initialise the Firebase Admin SDK (singleton)."""
    global _admin_app
    if _admin_app is not None:
        return _admin_app
    key_json = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON", "").strip()
    if not key_json:
        raise RuntimeError("FIREBASE_SERVICE_ACCOUNT_JSON is not set")
    import firebase_admin
    from firebase_admin import credentials
    try:
        service_account = json.loads(key_json)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON: {e}")
    _admin_app = firebase_admin.initialize_app(
        credentials.Certificate(service_account))
    return _admin_app


def verify_firebase_token(id_token: str) -> dict:
    """Verify a Firebase ID token. Returns the decoded claims.

    Raises on invalid/expired/revoked tokens — callers turn that into 401.
    """
    _admin_app()
    from firebase_admin import auth as fb_auth
    return fb_auth.verify_id_token(id_token)


def reset_admin_app_cache() -> None:
    """Test helper: drop the cached Admin app so each test re-initialises."""
    global _admin_app
    _admin_app = None
