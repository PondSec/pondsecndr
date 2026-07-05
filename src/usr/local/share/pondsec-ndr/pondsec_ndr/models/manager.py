"""Safe external model management."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import time
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
                "sha256": "e006a6e86b7d05f1e97046522d19c02b8eac159096f5a3002ee2934a2e26e206",
                "size": 900418,
                "role": "binary_classifier"
            },
            {
                "name": "cnn1d_attacks_only.pth",
                "url": "https://huggingface.co/saidimn/ids-cnn-cicids2017/resolve/main/cnn1d_attacks_only.pth",
                "sha256": "f26410d597d8ced01ee015ee23979ca1598dfeff434067313216ff70289a2a59",
                "size": 1970386,
                "role": "attack_classifier"
            },
            {
                "name": "scaler.pkl",
                "url": "https://huggingface.co/saidimn/ids-cnn-cicids2017/resolve/main/scaler.pkl",
                "sha256": "4968219cf473023279d1820a7cde79c3db3caa219c8f1afc8a29d9951f167c3a",
                "size": 2455,
                "role": "feature_scaler"
            },
            {
                "name": "label_encoder_attacks.pkl",
                "url": "https://huggingface.co/saidimn/ids-cnn-cicids2017/resolve/main/label_encoder_attacks.pkl",
                "sha256": "3da642b0e425704932e5c150588226e55a1f064153e6e6240c89b4a54e5fd35a",
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
        checksum = ""
        size = 0
        for attempt in range(3):
            tmp.unlink(missing_ok=True)
            _download_url(artifact["url"], tmp, timeout)
            checksum = sha256_file(tmp)
            size = tmp.stat().st_size
            if checksum == artifact["sha256"] and size == artifact["size"]:
                break
            time.sleep(1 + attempt)
        if checksum != artifact["sha256"] or size != artifact["size"]:
            tmp.unlink(missing_ok=True)
            raise ModelError(
                f"checksum mismatch for {artifact['name']}: got sha256={checksum} size={size}, "
                f"expected sha256={artifact['sha256']} size={artifact['size']}"
            )
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


def _download_url(url: str, target: Path, timeout: int) -> None:
    curl = shutil.which("curl")
    if curl:
        result = subprocess.run(
            [curl, "-L", "--fail", "--retry", "3", "--retry-all-errors", "--max-time", str(timeout), "-o", str(target), url],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return
        raise ModelError(f"curl download failed: {result.stderr.strip()}")

    fetch = shutil.which("fetch")
    if fetch:
        result = subprocess.run(
            [fetch, "-q", "-o", str(target), url],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode == 0:
            return
        raise ModelError(f"fetch download failed: {result.stderr.strip()}")

    with urllib.request.urlopen(url, timeout=timeout) as response:
        with target.open("wb") as handle:
            while True:
                chunk = response.read(64 * 1024)
                if not chunk:
                    break
                handle.write(chunk)


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
