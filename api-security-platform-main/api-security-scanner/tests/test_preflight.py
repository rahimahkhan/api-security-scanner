import tempfile
import os
from pathlib import Path
from tools.check_environment import run_preflight


def test_preflight_missing_models_and_insecure_env():
    # Create a temporary models directory with no model files
    with tempfile.TemporaryDirectory() as tmp_models:
        # Create a docker-compose.yml that mounts host ./models to container models (problematic)
        with tempfile.TemporaryDirectory() as tmp_dir:
            compose_path = Path(tmp_dir) / "docker-compose.yml"
            compose_path.write_text("""
version: '3.8'
services:
  api-scanner:
    volumes:
      - ./models:/app/models
""")
            # Create a .env file with insecure SECRET_KEY
            env_path = Path(tmp_dir) / ".env"
            env_path.write_text('SECRET_KEY=dev-secret-key-change-in-production\n')

            # Run preflight pointing to the temp models dir and compose/env paths
            exit_code = run_preflight(models_dir=tmp_models, compose_path=str(compose_path), env_path=str(env_path), verbose=False)

            # Since critical model files are missing, expect exit code 2
            assert exit_code == 2


def test_preflight_positive_all_artifacts_present():
    # Create temporary models and place dummy files to simulate presence
    with tempfile.TemporaryDirectory() as tmp_models:
        models_path = Path(tmp_models)
        # Create required critical files
        required = [
            "isolation_forest.pkl",
            "response_lstm.pt",
            "autoencoder.pt",
            "response_char_vocab.json",
        ]
        for fname in required:
            (models_path / fname).write_bytes(b"dummy")

        # Optional files
        optional = ["feature_scaler.pkl", "autoencoder_scaler.pkl", "autoencoder_threshold.txt"]
        for fname in optional:
            (models_path / fname).write_bytes(b"opt")

        # Create a docker-compose.yml that does NOT mount host ./models (safe)
        with tempfile.TemporaryDirectory() as tmp_dir:
            compose_path = Path(tmp_dir) / "docker-compose.yml"
            compose_path.write_text("""
version: '3.8'
services:
  api-scanner:
    image: example/api-scanner:latest
""")
            # Create a .env file with a strong SECRET_KEY
            env_path = Path(tmp_dir) / ".env"
            env_path.write_text('SECRET_KEY=abcdefghijklmnopqrstuvwxyz1234567890\n')

            # Run preflight pointing to the temp models dir and safe compose/env paths
            exit_code = run_preflight(models_dir=tmp_models, compose_path=str(compose_path), env_path=str(env_path), verbose=False)

            # All artifacts present and secure env: expect exit code 0
            assert exit_code == 0
