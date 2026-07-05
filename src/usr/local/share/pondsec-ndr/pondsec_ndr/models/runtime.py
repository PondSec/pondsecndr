"""Pretrained IDS model runtime for OPNsense.

The firewall runtime uses a pickle-free NumPy archive exported from the verified
Hugging Face PyTorch artifacts. This keeps the pretrained model active without
requiring fragile PyTorch packages on every OPNsense installation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pondsec_ndr.models.cicids_features import cicids_vector_from_feature


MODEL_ID = "saidimn-ids-cnn-cicids2017"
RUNTIME_VERSION = "pondsec-numpy-cnn1d-v1"
DEFAULT_RUNTIME_PATH = Path(__file__).with_name("artifacts") / "saidimn_ids_cnn_cicids2017.npz"


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

    def score_features(self, features: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not features:
            return []
        np = self.np
        vectors = np.asarray([cicids_vector_from_feature(item) for item in features], dtype=np.float32)
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
                "runtime_version": RUNTIME_VERSION,
                "attack_probability": float(binary_probs[index, 1]),
                "benign_probability": float(binary_probs[index, 0]),
                "attack_class": self.attack_classes[attack_index],
                "attack_class_probability": float(attack_probs[index, attack_index]),
            })
        return results

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
