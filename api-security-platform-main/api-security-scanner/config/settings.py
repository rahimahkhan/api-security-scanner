import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Core Directories & Safe Fallbacks
MODELS_DIR = os.path.join(BASE_DIR, "models")
# NOTE: scan outputs go here, NOT into the reports/ Python package directory.
# Pointing REPORTS_DIR at the package dir would mix generated artifacts with
# source code (and risk them being committed or packaged accidentally).
REPORTS_DIR = os.path.join(BASE_DIR, "scan_reports")
PAYLOADS_DIR = os.path.join(BASE_DIR, "payloads")
DATASETS_DIR = str(BASE_DIR / "datasets")

# Model File Paths
# NOTE: Layer 3 (detection/deep_learning.py) loads these with torch.load() on a
# state_dict, so they must be the .pt files written by training/train_lstm.py
# and training/train_autoencoder.py (see models/model_manifest.json).
ISOLATION_FOREST_PATH = os.path.join(MODELS_DIR, "isolation_forest.pkl")
TABULAR_RANKER_PATH = os.path.join(MODELS_DIR, "tabular_ranker.pkl")
LSTM_MODEL_PATH = os.path.join(MODELS_DIR, "lstm_model.pt")
AUTOENCODER_PATH = os.path.join(MODELS_DIR, "autoencoder.pt")

# Application & Scanner Limits
MAX_ENDPOINTS = int(os.getenv("MAX_ENDPOINTS", 20))
SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", 30))

# Flask & Dashboard Settings
FLASK_PORT = int(os.getenv("PORT", os.getenv("FLASK_PORT", 5000)))
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "False") == "True"
SECRET_KEY = os.getenv("SECRET_KEY", "default-secure-key")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'database.db'}")

# Dashboard Auth & Security
DASHBOARD_AUTH_ENABLED = os.getenv("DASHBOARD_AUTH_ENABLED", "False") == "True"
DASHBOARD_ADMIN_USER = os.getenv("DASHBOARD_ADMIN_USER", "admin")
DASHBOARD_ADMIN_PASSWORD = os.getenv("DASHBOARD_ADMIN_PASSWORD", "admin")
CSRF_ENABLED = os.getenv("CSRF_ENABLED", "True") == "True"


def _detect_app_version() -> str:
    """Short version/commit string shown in the dashboard footer.

    Render injects RENDER_GIT_COMMIT automatically; APP_VERSION can be set
    manually; otherwise fall back to the local git SHA, then "dev".
    """
    for env_key in ("RENDER_GIT_COMMIT", "APP_VERSION"):
        val = os.getenv(env_key, "").strip()
        if val:
            return val[:12]
    try:
        import subprocess
        here = Path(__file__).resolve().parent.parent
        sha = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(here), capture_output=True, text=True, timeout=5,
        ).stdout.strip()
        if sha:
            return sha[:12]
    except Exception:
        pass
    return "dev"


APP_VERSION = _detect_app_version()
