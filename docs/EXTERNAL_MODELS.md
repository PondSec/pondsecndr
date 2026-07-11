# External Pretrained Models

PondSec NDR uses externally trained IDS/NDR models where that is safer and more reproducible than inventing an opaque in-repository model.

## Selected Preferred Model

Preferred catalog ID:

```text
saidimn-ids-cnn-cicids2017
```

Upstream:

- Hugging Face: https://huggingface.co/saidimn/ids-cnn-cicids2017
- License: MIT
- Model family: CNN-1D IDS pipeline
- Training data: CICIDS2017 flow features
- Artifacts:
  - `cnn1d_binary.pth`
  - `cnn1d_attacks_only.pth`
  - `scaler.pkl`
  - `label_encoder_attacks.pkl`

PondSec verifies downloaded artifacts with SHA-256 before use.

The production firewall runtime does not deserialize the upstream `.pth` or `.pkl` files. PondSec ships a verified, pickle-free NumPy export of the preferred CNN pipeline and records its SHA-256 checksum and runtime self-test result before the model is shown as active.

## Secondary Candidate

Catalog ID:

```text
gehad-lstm-cicids2017
```

Upstream:

- Hugging Face: https://huggingface.co/gehad-alaa-abaas/RNN-IDS-MODEL
- License: MIT
- Model family: LSTM IDS
- Training data: CICIDS2017 80-feature vectors

This model is tracked as a secondary candidate until its architecture and preprocessing pipeline are fully audited.

## Dataset Context

CICIDS2017 is published by the Canadian Institute for Cybersecurity and provides PCAPs plus labeled flow CSVs generated from network traffic analysis. The official dataset page describes benign and attack traffic, including brute force, DoS, Heartbleed, web attacks, infiltration, botnet, DDoS, and scans.

Official source:

- https://www.unb.ca/cic/datasets/ids-2017.html

## Safety Rules

- Do not deserialize `.pkl`, `.pth`, or joblib artifacts in the privileged service path.
- Use the bundled NumPy export for product inference on OPNsense.
- Treat PyTorch as an offline/export-worker dependency, not as a required firewall service dependency.
- Do not treat model output as sufficient for automatic blocking.
- Require checksums before activation.
- Keep inference in an optional unprivileged ML worker.
- Keep deterministic detectors and Suricata alerts active when ML runtime is unavailable.
- Show model/runtime errors as degraded diagnostics, not firewall failures.

## Feature Compatibility

Most public NIDS models are trained on CICFlowMeter/CICIDS-style feature vectors, not raw Suricata EVE JSON. PondSec therefore maps normalized metadata into a CICIDS2017-like vector. Packet-level fields that are not available from metadata are left as zero or unavailable; no fake packet measurements are invented.

This means external model inference is useful as an additional signal, but it must be calibrated against firewall-local traffic before prevent-mode use.

## Current Validation

The preferred Hugging Face artifacts have been downloaded in a temporary local test directory and verified by SHA-256 using the PondSec model fetch command.
