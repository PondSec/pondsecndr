# Model Lifecycle

The first version prepares model metadata, artifact verification, and compatibility checks for external pretrained IDS models. It does not train a private PondSec model in the package path.

## Requirements

Every model record must include:

- `model_id`
- `model_type`
- `model_version`
- `created_at`
- `trained_at`
- `feature_schema_version`
- `training_dataset`
- `training_window`
- `hyperparameters`
- `input_dimensions`
- `sha256`
- `status`
- `metrics`

## Safety Rules

- Training and inference are separate.
- Training never runs in the packet path.
- Inference never runs per Ethernet frame.
- External pickle files are not trusted.
- Incompatible schema versions are rejected.
- Checksum mismatch blocks activation.
- Rollback metadata is retained.
- Activation is audited.

## External Pretrained Models

The preferred catalog entry is `saidimn/ids-cnn-cicids2017`, an MIT-licensed Hugging Face model repository with trained CNN-1D artifacts for CICIDS2017 binary and attack-class classification. A secondary catalog entry tracks `gehad-alaa-abaas/RNN-IDS-MODEL`, an MIT-licensed LSTM IDS model repository trained on CICIDS2017 feature vectors.

These models are not loaded blindly:

- Downloads are verified with SHA-256 checksums.
- Pickle/joblib artifacts are not deserialized by the root service.
- Runtime loading for the preferred model uses the exported pickle-free NumPy artifact installed with the backend.
- The model output is correlated into normal PondSec detections and incidents; response policy and allowlist/protected-network gates still decide whether any block is allowed.
- PondSec maps normalized metadata to CICIDS2017-like feature vectors and marks unavailable packet-level fields as unavailable or zero instead of fabricating values.

## Current Implementation

The model manager exposes:

- `pondsec-ndrctl model list`
- `pondsec-ndrctl model verify`
- `pondsec-ndrctl model fetch <model_id>`
- `pondsec-ndrctl model self-test`
- `pondsec-ndrctl model validate-flow --kind attack|benign`

Full PyTorch inference on OPNsense remains out of the privileged service path. The validated runtime path is the NumPy CNN-1D export plus explicit checksum/manifest verification and a target-box self-test.
