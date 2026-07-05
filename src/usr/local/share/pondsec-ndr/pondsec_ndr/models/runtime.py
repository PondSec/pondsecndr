"""Pretrained IDS model runtime for OPNsense.

The firewall runtime uses a pickle-free NumPy archive exported from the verified
Hugging Face PyTorch artifacts. This keeps the pretrained model active without
requiring fragile PyTorch packages on every OPNsense installation.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from pondsec_ndr.models.cicids_features import CICIDS2017_FEATURES, cicids_vector_from_feature


MODEL_ID = "saidimn-ids-cnn-cicids2017"
RUNTIME_VERSION = "pondsec-numpy-cnn1d-v1"
DEFAULT_RUNTIME_PATH = Path(__file__).with_name("artifacts") / "saidimn_ids_cnn_cicids2017.npz"
DEFAULT_RUNTIME_SHA256 = "51bec93ec2c8ac9a480fcef8694852792a8869a817b07d1cef11a2f1fd62c45b"
SYNTHETIC_AI_VALIDATION_VECTOR = [
    227.1844482421875, 16145999.0, 3.5857882499694824, 11.17403507232666,
    14.117317199707031, 17282.978515625, 484.5901794433594, 22.829853057861328,
    142.24351501464844, 672.3494262695312, 1898.962890625, 22.85487937927246,
    206.6375732421875, 35.887821197509766, 2712823.0, 152242.90625,
    17221.9296875, 1605136.125, 7774913.5, 22882.142578125,
    4880653.5, 79086.2578125, 825969.8125, 27841972.0,
    2303605.5, 5838944.0, 727616.5625, 34425.2265625,
    7213066.0, 753377.3125, 0.5452418327331543, 0.0360860638320446,
    0.13400433957576752, 0.015980372205376625, 0.23819909989833832,
    0.05332816392183304, 15728.1826171875, 1829.6553955078125,
    11.846921920776367, 579.3692016601562, 182.05067443847656,
    267.43658447265625, 380588.78125, 0.7424153089523315,
    1.173059105873108, 0.11429675668478012, 0.23449653387069702,
    0.5729040503501892, 0.42709505558013916, 0.09515353292226791,
    0.25698569416999817, 0.8416632413864136, 310.20849609375,
    168.6941680908203, 93.42359924316406, 3.1768205165863037,
    3.2078676223754883, 0.3783320486545563, 1.545061707496643,
    1.394691824913025, 1.7438603639602661, 0.4415431618690491,
    1.5570331811904907, 832.3474731445312, 42.736473083496094,
    21907.078125, 21875.353515625, 277.4992370605469,
    30.088586807250977, 8.14010238647461, 98683.7421875,
    2448.317626953125, 51958.64453125, 11043.4384765625,
    6632003.0, 165594.03125, 5708666.5, 99280.1640625,
]


class ModelRuntimeUnavailable(RuntimeError):
    """Raised when the pretrained model runtime cannot be loaded."""


class SaidimnIdsCnnRuntime:
    def __init__(self, path: Path | None = None) -> None:
        try:
            import numpy as np  # type: ignore
        except ImportError as exc:
            raise ModelRuntimeUnavailable("numpy is required for pretrained model inference") from exc
        self.np = np
        self.path = path or DEFAULT_RUNTIME_PATH
        if not self.path.exists():
            raise ModelRuntimeUnavailable(f"pretrained runtime artifact is missing: {self.path}")
        self.weights = np.load(self.path, allow_pickle=False)
        self.attack_classes = [str(item) for item in self.weights["attack.classes"].tolist()]
        self.checksum = sha256_file(self.path)
        try:
            self.metadata = json.loads(str(self.weights["metadata.json"].tolist()))
        except (KeyError, TypeError, json.JSONDecodeError):
            self.metadata = {}

    def score_features(self, features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not features:
            return []
        np = self.np
        vectors_list = [cicids_vector_from_feature(item) for item in features]
        vectors = np.asarray(vectors_list, dtype=np.float32)
        scaled = (vectors - self.weights["scaler.mean"]) / self.weights["scaler.scale"]
        binary_logits = self._binary(scaled)
        binary_probs = _softmax(np, binary_logits)
        attack_logits = self._attack(scaled)
        attack_probs = _softmax(np, attack_logits)
        results = []
        for index, feature in enumerate(features):
            attack_index = int(np.argmax(attack_probs[index]))
            results.append({
                "source_ip": feature["source_ip"],
                "model_id": MODEL_ID,
                "model_version": RUNTIME_VERSION,
                "model_checksum": self.checksum,
                "artifact_path": str(self.path),
                "runtime_version": RUNTIME_VERSION,
                "attack_probability": float(binary_probs[index, 1]),
                "benign_probability": float(binary_probs[index, 0]),
                "attack_class": self.attack_classes[attack_index],
                "attack_class_probability": float(attack_probs[index, attack_index]),
                "feature_values": _named_feature_values(vectors_list[index]),
            })
        return results

    def self_test(self) -> dict[str, Any]:
        started = time.perf_counter()
        score = self.score_features([{"source_ip": "synthetic-ai-validation", "cicids_vector": SYNTHETIC_AI_VALIDATION_VECTOR}])[0]
        duration_ms = round((time.perf_counter() - started) * 1000, 3)
        checksum_ok = self.checksum == DEFAULT_RUNTIME_SHA256
        score_ok = score["attack_probability"] >= 0.95
        return {
            "status": "ok" if checksum_ok and score_ok else "failed",
            "model_id": MODEL_ID,
            "model_version": RUNTIME_VERSION,
            "model_checksum": self.checksum,
            "expected_checksum": DEFAULT_RUNTIME_SHA256,
            "checksum_ok": checksum_ok,
            "runtime_version": RUNTIME_VERSION,
            "artifact_path": str(self.path),
            "manifest": self.metadata,
            "feature_schema_version": "1",
            "synthetic_ai_validation_vector": True,
            "attack_probability": round(float(score["attack_probability"]), 6),
            "predicted_class": score["attack_class"],
            "inference_duration_ms": duration_ms,
        }

    def _w(self, prefix: str, key: str):
        return self.weights[f"{prefix}.{key}"]

    def _binary(self, x):
        x = x[:, None, :]
        x = self._conv_block("binary", x, 0, 1)
        x = self._conv_block("binary", x, 3, 4)
        x = _maxpool1d(self.np, x)
        x = self._conv_block("binary", x, 8, 9)
        x = self._conv_block("binary", x, 11, 12)
        x = _maxpool1d(self.np, x)
        x = self._conv_block("binary", x, 16, 17)
        x = x.mean(axis=2)
        x = _linear(self.np, x, self._w("binary", "classifier.1.weight"), self._w("binary", "classifier.1.bias"))
        x = _batchnorm2d(self.np, x, self._w("binary", "classifier.2.weight"), self._w("binary", "classifier.2.bias"), self._w("binary", "classifier.2.running_mean"), self._w("binary", "classifier.2.running_var"))
        x = _relu(self.np, x)
        return _linear(self.np, x, self._w("binary", "classifier.5.weight"), self._w("binary", "classifier.5.bias"))

    def _attack(self, x):
        x = x[:, None, :]
        x = self._conv_block("attack", x, 0, 1)
        x = self._conv_block("attack", x, 3, 4)
        x = _maxpool1d(self.np, x)
        x = self._conv_block("attack", x, 8, 9)
        x = self._conv_block("attack", x, 11, 12)
        x = _maxpool1d(self.np, x)
        x = self._conv_block("attack", x, 16, 17)
        x = self._conv_block("attack", x, 19, 20)
        x = x.mean(axis=2)
        x = _linear(self.np, x, self._w("attack", "classifier.1.weight"), self._w("attack", "classifier.1.bias"))
        x = _batchnorm2d(self.np, x, self._w("attack", "classifier.2.weight"), self._w("attack", "classifier.2.bias"), self._w("attack", "classifier.2.running_mean"), self._w("attack", "classifier.2.running_var"))
        x = _relu(self.np, x)
        x = _linear(self.np, x, self._w("attack", "classifier.5.weight"), self._w("attack", "classifier.5.bias"))
        x = _batchnorm2d(self.np, x, self._w("attack", "classifier.6.weight"), self._w("attack", "classifier.6.bias"), self._w("attack", "classifier.6.running_mean"), self._w("attack", "classifier.6.running_var"))
        x = _relu(self.np, x)
        return _linear(self.np, x, self._w("attack", "classifier.9.weight"), self._w("attack", "classifier.9.bias"))

    def _conv_block(self, prefix: str, x, conv_index: int, bn_index: int):
        x = _conv1d(self.np, x, self._w(prefix, f"features.{conv_index}.weight"), self._w(prefix, f"features.{conv_index}.bias"))
        x = _batchnorm3d(self.np, x, self._w(prefix, f"features.{bn_index}.weight"), self._w(prefix, f"features.{bn_index}.bias"), self._w(prefix, f"features.{bn_index}.running_mean"), self._w(prefix, f"features.{bn_index}.running_var"))
        return _relu(self.np, x)


def _conv1d(np, x, weight, bias):
    padded = np.pad(x, ((0, 0), (0, 0), (1, 1)), mode="constant")
    out_len = x.shape[2]
    out = np.zeros((x.shape[0], weight.shape[0], out_len), dtype=np.float32)
    for kernel_index in range(weight.shape[2]):
        out += np.einsum("ncl,oc->nol", padded[:, :, kernel_index:kernel_index + out_len], weight[:, :, kernel_index])
    out += bias[None, :, None]
    return out


def _batchnorm3d(np, x, weight, bias, running_mean, running_var):
    return ((x - running_mean[None, :, None]) / np.sqrt(running_var[None, :, None] + 1e-5)) * weight[None, :, None] + bias[None, :, None]


def _batchnorm2d(np, x, weight, bias, running_mean, running_var):
    return ((x - running_mean[None, :]) / np.sqrt(running_var[None, :] + 1e-5)) * weight[None, :] + bias[None, :]


def _maxpool1d(np, x):
    length = (x.shape[2] // 2) * 2
    return np.maximum(x[:, :, :length:2], x[:, :, 1:length:2])


def _linear(np, x, weight, bias):
    return x @ weight.T + bias


def _relu(np, x):
    return np.maximum(x, 0)


def _softmax(np, x):
    shifted = x - np.max(x, axis=1, keepdims=True)
    exp = np.exp(shifted)
    return exp / np.sum(exp, axis=1, keepdims=True)


def _named_feature_values(vector: list[float]) -> dict[str, float]:
    return {name: round(float(value), 6) for name, value in zip(CICIDS2017_FEATURES, vector)}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
