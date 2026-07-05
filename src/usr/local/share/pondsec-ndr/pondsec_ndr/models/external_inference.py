"""Optional inference hook for external pretrained models."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pondsec_ndr.models.cicids_features import cicids_vector_from_feature
from pondsec_ndr.models.manager import is_model_installed


class ExternalInferenceUnavailable(RuntimeError):
    """Raised when the optional ML runtime is not installed or verified."""


def score_with_external_model(data_dir: Path, model_id: str, features: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not is_model_installed(data_dir, model_id):
        raise ExternalInferenceUnavailable(f"model is not installed: {model_id}")
    try:
        import torch  # type: ignore
    except ImportError as exc:
        raise ExternalInferenceUnavailable("PyTorch runtime is not installed") from exc

    # The architecture still needs target-box validation against the upstream
    # model card. Until then the vectors are exposed for an audited worker, and
    # this function deliberately refuses to deserialize pickle artifacts.
    del torch
    vectors = [cicids_vector_from_feature(item) for item in features]
    raise ExternalInferenceUnavailable(f"external model vectors prepared but inference worker is not enabled: {len(vectors)} vectors")
