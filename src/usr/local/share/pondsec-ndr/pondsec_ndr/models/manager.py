"""Safe external model management."""

from __future__ import annotations

import hashlib
import json
import urllib.request
from pathlib import Path
from typing import Any

from pondsec_ndr.schema import FEATURE_SCHEMA_VERSION


MODEL_CATALOG: dict[str, dict[str, Any]] = {
    "saidimn-ids-cnn-cicids2017": {
        "model_id": "saidimn-ids-cnn-cicids2017",
        "provider": "Hugging Face",
        "repository": "saidimn/ids-cnn-cicids2017",
        "source_url": "https://huggingface.co/saidimn/ids-cnn-cicids2017",
        "license": "MIT",
        "model_type": "cnn1d_cicids2017",
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "trained_on": "CICIDS2017 flow features",
        "preferred": True,
        "runtime": "optional_pytorch",
        "status": "catalog",
        "notes": [
            "Requires CICFlowMeter-style feature mapping.",
            "Artifacts are PyTorch/joblib pickle formats and must be loaded only in the unprivileged ML worker.",
            "Automatic blocking is not allowed from this model alone."
        ],
        "artifacts": [
            {
                "name": "cnn1d_binary.pth",
                "url": "https://huggingface.co/saidimn/ids-cnn-cicids2017/resolve/main/cnn1d_binary.pth",
                "sha256": "0fdc478c0bce4ed0e514023ca8db9ae13617430467d91c46d072aa3b56e222ee",
                "size": 900418,
                "role": "binary_classifier"
            },
            {
                "name": "cnn1d_attacks_only.pth",
                "url": "https://huggingface.co/saidimn/ids-cnn-cicids2017/resolve/main/cnn1d_attacks_only.pth",
                "sha256": "997a4724bfa6a8915de129fac597362e2df9b36aa3ae4577fdf353dff30e351b",
                "size": 1970386,
                "role": "attack_classifier"
            },
            {
                "name": "scaler.pkl",
                "url": "https://huggingface.co/saidimn/ids-cnn-cicids2017/resolve/main/scaler.pkl",
                "sha256": "61384def8823e6b59aab863cd16d8d6f45185b0bda2e658a7ade9723acd59e5d",
                "size": 2455,
                "role": "feature_scaler"
            },
            {
                "name": "label_encoder_attacks.pkl",
                "url": "https://huggingface.co/saidimn/ids-cnn-cicids2017/resolve/main/label_encoder_attacks.pkl",
                "sha256": "1616c99b7c5185c7e926d893636bf9e15cc95a29f390e97108edd375f2184074",
                "size": 695,
                "role": "attack_label_encoder"
            }
        ]
    },
    "gehad-lstm-cicids2017": {
        "model_id": "gehad-lstm-cicids2017",
        "provider": "Hugging Face",
        "repository": "gehad-alaa-abaas/RNN-IDS-MODEL",
        "source_url": "https://huggingface.co/gehad-alaa-abaas/RNN-IDS-MODEL",
        "license": "MIT",
        "model_type": "lstm_cicids2017",
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "trained_on": "CICIDS2017 80-feature vectors",
        "preferred": False,
        "runtime": "optional_pytorch",
        "status": "catalog",
        "notes": [
            "Model card states two trained PyTorch LSTM models are provided.",
            "Requires the original 80-feature preprocessing pipeline.",
            "Kept as a secondary candidate until architecture and preprocessing are audited."
        ],
        "artifacts": []
    }
}


class ModelError(ValueError):
    """Raised when a model is missing, corrupt, or incompatible."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def model_dir(data_dir: Path) -> Path:
    directory = data_dir / "models"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def get_catalog_model(model_id: str) -> dict[str, Any]:
    try:
        return MODEL_CATALOG[model_id]
    except KeyError as exc:
        raise ModelError(f"unknown model: {model_id}") from exc


def installed_artifacts(data_dir: Path, model_id: str) -> list[dict[str, Any]]:
    model = get_catalog_model(model_id)
    directory = data_dir / "models" / model_id
    results = []
    for artifact in model.get("artifacts", []):
        path = directory / artifact["name"]
        present = path.exists()
        checksum = sha256_file(path) if present else None
        results.append({
            "name": artifact["name"],
            "path": str(path),
            "present": present,
            "sha256": checksum,
            "expected_sha256": artifact["sha256"],
            "valid": present and checksum == artifact["sha256"],
            "role": artifact.get("role"),
            "size": path.stat().st_size if present else None,
        })
    return results


def is_model_installed(data_dir: Path, model_id: str) -> bool:
    artifacts = installed_artifacts(data_dir, model_id)
    return bool(artifacts) and all(item["valid"] for item in artifacts)


def download_model_artifacts(data_dir: Path, model_id: str, timeout: int = 120) -> dict[str, Any]:
    model = get_catalog_model(model_id)
    directory = model_dir(data_dir) / model_id
    directory.mkdir(parents=True, exist_ok=True)
    downloaded = []
    for artifact in model.get("artifacts", []):
        path = directory / artifact["name"]
        tmp = path.with_suffix(path.suffix + ".tmp")
        with urllib.request.urlopen(artifact["url"], timeout=timeout) as response:
            with tmp.open("wb") as handle:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    handle.write(chunk)
        checksum = sha256_file(tmp)
        if checksum != artifact["sha256"]:
            tmp.unlink(missing_ok=True)
            raise ModelError(f"checksum mismatch for {artifact['name']}")
        tmp.replace(path)
        downloaded.append({"name": artifact["name"], "sha256": checksum, "path": str(path)})
    manifest = {
        "model_id": model_id,
        "source_url": model["source_url"],
        "license": model["license"],
        "feature_schema_version": model["feature_schema_version"],
        "artifacts": downloaded,
    }
    with (directory / "pondsec-manifest.json").open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
    return manifest


def model_inventory(data_dir: Path | None = None) -> list[dict[str, Any]]:
    inventory = []
    for model in MODEL_CATALOG.values():
        installed = False
        artifacts: list[dict[str, Any]] = []
        if data_dir is not None:
            artifacts = installed_artifacts(data_dir, model["model_id"])
            installed = bool(artifacts) and all(item["valid"] for item in artifacts)
        inventory.append({
            "model_id": model["model_id"],
            "provider": model["provider"],
            "repository": model["repository"],
            "source_url": model["source_url"],
            "license": model["license"],
            "model_type": model["model_type"],
            "feature_schema_version": model["feature_schema_version"],
            "trained_on": model["trained_on"],
            "runtime": model["runtime"],
            "status": "installed" if installed else model["status"],
            "preferred": model["preferred"],
            "active": installed and model["preferred"],
            "artifacts": artifacts,
            "notes": model["notes"],
        })
    return inventory
