#!/usr/bin/env python3
"""Export the verified saidimn CICIDS2017 PyTorch artifacts to a safe NPZ runtime.

This script intentionally runs outside the OPNsense service path. It may use
PyTorch, scikit-learn and joblib to audit upstream artifacts, then writes a
pickle-free NumPy archive that PondSec NDR can execute on OPNsense with numpy.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import torch


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    source = args.source_dir
    arrays: dict[str, np.ndarray] = {}

    binary = torch.load(source / "cnn1d_binary.pth", map_location="cpu", weights_only=True)
    attack = torch.load(source / "cnn1d_attacks_only.pth", map_location="cpu", weights_only=True)
    for prefix, state_dict in (("binary", binary), ("attack", attack)):
        for key, value in state_dict.items():
            arrays[f"{prefix}.{key}"] = value.detach().cpu().numpy()

    scaler = joblib.load(source / "scaler.pkl")
    label_encoder = joblib.load(source / "label_encoder_attacks.pkl")
    arrays["scaler.mean"] = np.asarray(scaler.mean_, dtype=np.float32)
    arrays["scaler.scale"] = np.asarray(scaler.scale_, dtype=np.float32)
    arrays["attack.classes"] = np.asarray(label_encoder.classes_, dtype=str)
    arrays["metadata.json"] = np.asarray(json.dumps({
        "model_id": "saidimn-ids-cnn-cicids2017",
        "source_url": "https://huggingface.co/saidimn/ids-cnn-cicids2017",
        "runtime": "pondsec-numpy-cnn1d",
        "scaler_type": type(scaler).__name__,
        "label_encoder_type": type(label_encoder).__name__,
        "feature_count": int(getattr(scaler, "n_features_in_", 78)),
    }, sort_keys=True))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(args.output, **arrays)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
