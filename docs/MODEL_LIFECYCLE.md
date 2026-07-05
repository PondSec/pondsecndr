# Model Lifecycle

The first version prepares model metadata and compatibility checks but does not depend on a large ML runtime.

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

## Current Implementation

The model manager table and CLI placeholders are present. Isolation Forest support is planned after FreeBSD-compatible packaging and safe serialization are verified.
