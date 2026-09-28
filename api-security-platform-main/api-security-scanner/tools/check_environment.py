"""
Preflight environment checker for API Security Platform.

Checks performed:
 - Required model artifacts (Isolation Forest, LSTM, Autoencoder, char vocab, scalers)
 - .env SECRET_KEY configuration security
 - docker-compose volume mounts that may mask container-packaged models

Exit codes:
 - 0: all checks passed (or only non-critical warnings)
 - 1: warnings present (non-critical)
 - 2: missing critical items (models) - critical failure

This module exposes run_preflight(...) for programmatic invocation and a CLI entrypoint.
"""
from __future__ import annotations
import os
import sys
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional

# Anchor everything to the repository root (parent of this file's directory),
# never to the current working directory: the import of config.settings and
# all default path resolution must behave identically no matter where the
# checker is invoked from.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from config.settings import MODELS_DIR, ISOLATION_FOREST_PATH, LSTM_MODEL_PATH, AUTOENCODER_PATH
from config.settings import BASE_DIR, SECRET_KEY as SETTINGS_SECRET_KEY

# Values that must never be accepted as a production SECRET_KEY. This includes
# the actual default from config/settings.py (not just a guessed placeholder).
INSECURE_SECRET_VALUES = {
    "default-secure-key",  # config/settings.py default
    "dev-secret-key-change-in-production",
    "changeme",
    "secret",
    "password",
}

CRITICAL_MODEL_FILES = [
    ISOLATION_FOREST_PATH,
    LSTM_MODEL_PATH,
    AUTOENCODER_PATH,
    os.path.join(MODELS_DIR, "char_vocab.json")
]

OPTIONAL_MODEL_FILES = [
    os.path.join(MODELS_DIR, "feature_scaler.pkl"),
    os.path.join(MODELS_DIR, "autoencoder_scaler.pkl"),
    os.path.join(MODELS_DIR, "autoencoder_threshold.txt")
]


def check_model_artifacts(models_dir: Optional[str] = None,
                          isolation_forest_path: Optional[str] = None,
                          lstm_path: Optional[str] = None,
                          autoencoder_path: Optional[str] = None) -> Dict[str, Any]:
    """Check presence of required and optional model artifacts.
    Returns a dict with keys: missing_critical, missing_optional, present_files
    """
    models_dir = models_dir or MODELS_DIR
    isolation_forest_path = isolation_forest_path or ISOLATION_FOREST_PATH
    lstm_path = lstm_path or LSTM_MODEL_PATH
    autoencoder_path = autoencoder_path or AUTOENCODER_PATH

    # Resolve paths relative to BASE_DIR if not absolute
    def resolve(p: str) -> str:
        pth = Path(p)
        if not pth.is_absolute():
            return str((Path(BASE_DIR) / pth).resolve())
        return str(pth)

    resolved = {
        "isolation_forest": resolve(isolation_forest_path),
        "lstm": resolve(lstm_path),
        "autoencoder": resolve(autoencoder_path),
        "char_vocab": resolve(os.path.join(models_dir, "char_vocab.json")),
        "feature_scaler": resolve(os.path.join(models_dir, "feature_scaler.pkl")),
        "autoencoder_scaler": resolve(os.path.join(models_dir, "autoencoder_scaler.pkl")),
        "autoencoder_threshold": resolve(os.path.join(models_dir, "autoencoder_threshold.txt"))
    }

    missing_critical = []
    missing_optional = []
    present_files = []

    for key in ["isolation_forest", "lstm", "autoencoder", "char_vocab"]:
        if not Path(resolved[key]).exists():
            missing_critical.append(resolved[key])
        else:
            present_files.append(resolved[key])

    for key in ["feature_scaler", "autoencoder_scaler", "autoencoder_threshold"]:
        if not Path(resolved[key]).exists():
            missing_optional.append(resolved[key])
        else:
            present_files.append(resolved[key])

    return {
        "resolved": resolved,
        "missing_critical": missing_critical,
        "missing_optional": missing_optional,
        "present_files": present_files
    }


def check_env_secret(env_path: Optional[str] = None) -> Tuple[bool, str]:
    """Check .env file and SECRET_KEY configuration.
    Returns (is_secure, message)
    is_secure True means no insecure default detected.
    """
    # Prefer reading .env if present
    env_file = Path(env_path) if env_path else Path(BASE_DIR) / ".env"
    secret_value = None
    if env_file.exists():
        try:
            with open(env_file, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip().startswith("SECRET_KEY"):
                        parts = line.split("=", 1)
                        if len(parts) == 2:
                            secret_value = parts[1].strip().strip('\"\'')
                            break
        except Exception:
            pass

    # Fall back to runtime settings if not found in .env
    if not secret_value:
        secret_value = SETTINGS_SECRET_KEY or None

    if not secret_value:
        return (False, "SECRET_KEY not set; recommend setting a strong SECRET_KEY in .env or env vars.")

    if secret_value in INSECURE_SECRET_VALUES or len(secret_value) < 32:
        return (False, f"Insecure SECRET_KEY detected (length {len(secret_value)}). Replace with a strong secret in .env.")

    return (True, "SECRET_KEY appears configured and sufficiently long.")


def check_docker_compose_volumes(compose_path: Optional[str] = None) -> Tuple[bool, List[str]]:
    """Inspect docker-compose.yml for host volume mounts that may mask container-packaged models.
    Returns (has_issue, list_of_problematic_entries)
    """
    compose_file = Path(compose_path) if compose_path else Path(BASE_DIR) / "docker-compose.yml"
    problematic = []
    if not compose_file.exists():
        return (False, [])
    try:
        content = compose_file.read_text(encoding="utf-8")
    except Exception:
        return (False, [])

    # Simple heuristics: look for './models' or './models:' or '/models:' or './models/' usage in volumes
    for line in content.splitlines():
        if "./models" in line or "./models:" in line or ":/app/models" in line or "/models:/app/models" in line:
            problematic.append(line.strip())

    return (len(problematic) > 0, problematic)


def run_preflight(models_dir: Optional[str] = None,
                  compose_path: Optional[str] = None,
                  env_path: Optional[str] = None,
                  verbose: bool = True) -> int:
    """Execute all checks and return exit code: 0 ok, 1 warnings, 2 critical missing artifacts."""
    # If a models_dir override is provided, ensure the specific expected artifact paths point inside it
    if models_dir:
        isolation_path = os.path.join(models_dir, "isolation_forest.pkl")
        lstm_path = os.path.join(models_dir, "lstm_model.pt")
        autoencoder_path = os.path.join(models_dir, "autoencoder.pt")
        results = check_model_artifacts(models_dir=models_dir, isolation_forest_path=isolation_path, lstm_path=lstm_path, autoencoder_path=autoencoder_path)
    else:
        results = check_model_artifacts(models_dir=models_dir)

    missing_critical = results["missing_critical"]
    missing_optional = results["missing_optional"]

    if verbose:
        print("[Preflight] Checking required model artifacts...")
        if missing_critical:
            print("  MISSING CRITICAL MODEL FILES:")
            for m in missing_critical:
                print("    - ", m)
        else:
            print("  All critical model artifacts present.")

        if missing_optional:
            print("  Missing optional model artifacts (recommended):")
            for m in missing_optional:
                print("    - ", m)
        else:
            print("  All optional model artifacts present or not required.")

    # Check SECRET_KEY
    secure, msg = check_env_secret(env_path=env_path)
    if verbose:
        print(f"[Preflight] SECRET_KEY check: {msg}")

    # Check docker-compose mounts
    has_issue, problematic = check_docker_compose_volumes(compose_path=compose_path)
    if verbose:
        if has_issue:
            print("[Preflight] Docker-compose volume mounts may mask container-packaged models:")
            for p in problematic:
                print("    - ", p)
            print("    Recommend removing host ./models mount or ensuring host models contain required artifacts.")
        else:
            print("[Preflight] No obvious docker-compose model volume masking detected.")

    # Decide exit code
    if missing_critical:
        print("\n[Preflight] CRITICAL: Missing required model artifacts. See list above.")
        return 2

    if (not secure) or has_issue:
        print("\n[Preflight] WARNING: Non-critical issues detected. Address recommended items before production runs.")
        return 1

    print("\n[Preflight] OK: Environment checks passed.")
    return 0


def main(argv: Optional[List[str]] = None) -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Preflight environment checker for API Security Platform")
    parser.add_argument("--models-dir", help="Override models directory", default=None)
    parser.add_argument("--compose-path", help="Path to docker-compose.yml", default=None)
    parser.add_argument("--env-path", help="Path to .env file", default=None)
    args = parser.parse_args(argv)

    code = run_preflight(models_dir=args.models_dir, compose_path=args.compose_path, env_path=args.env_path, verbose=True)
    sys.exit(code)


if __name__ == "__main__":
    main()
