#!/usr/bin/env python3
"""Script to provision and install trained ML/DL model artifacts into scanner models directory."""
import argparse
import shutil
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

EXPECTED_ARTIFACTS = [
    "tabular_ranker.pkl",
    "isolation_forest.pkl",
    "feature_scaler.pkl",
    "autoencoder.pt",
    "autoencoder_scaler.pkl",
    "autoencoder_threshold.txt",
    "response_lstm.pt",
    "response_char_vocab.json",
    "model_manifest.json",
    "metrics.json",
]


def install_bundle(bundle_dir: Path, target_dir: Path) -> bool:
    if not bundle_dir.exists():
        print(f"[-] Error: Source bundle directory not found: {bundle_dir}")
        return False

    target_dir.mkdir(parents=True, exist_ok=True)
    installed = []
    missing = []

    print(f"[+] Provisioning ML/DL artifacts from {bundle_dir} -> {target_dir}...")

    for artifact in EXPECTED_ARTIFACTS:
        src = bundle_dir / artifact
        dst = target_dir / artifact
        if src.exists():
            shutil.copy2(src, dst)
            installed.append(artifact)
        else:
            missing.append(artifact)

    print(f"[+] Successfully installed {len(installed)}/{len(EXPECTED_ARTIFACTS)} artifacts into {target_dir}:")
    for item in installed:
        print(f"    - {item}")

    if missing:
        print(f"[!] Optional or missing artifacts ({len(missing)}):")
        for item in missing:
            print(f"    ? {item}")

    return len(installed) > 0


def main():
    parser = argparse.ArgumentParser(description="Install and provision ML/DL bundle artifacts.")
    parser.add_argument(
        "--bundle",
        type=Path,
        default=ROOT_DIR / "models",
        help="Source directory containing model artifact bundle.",
    )
    parser.add_argument(
        "--models-dir",
        type=Path,
        default=ROOT_DIR / "models",
        help="Destination directory for scanner model artifacts.",
    )

    args = parser.parse_args()
    success = install_bundle(args.bundle, args.models_dir)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
