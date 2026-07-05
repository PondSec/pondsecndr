# Development

## Local Test Setup

Run tests from the repository root:

```sh
python3 -m unittest discover -s tests
```

Run CLI commands locally by setting `PYTHONPATH`:

```sh
PYTHONPATH=src/usr/local/share/pondsec-ndr python3 -m pondsec_ndr.cli health --json
```

For isolated local state, set:

```sh
export PONDSEC_NDR_CONFIG=/tmp/pondsec-ndr.json
export PONDSEC_NDR_DATA_DIR=/tmp/pondsec-ndr-db
export PONDSEC_NDR_LOG_DIR=/tmp/pondsec-ndr-log
export PONDSEC_NDR_RUN_DIR=/tmp/pondsec-ndr-run
```

## Coding Rules

- Keep GUI code in OPNsense MVC controllers and Volt templates.
- Keep business logic in the Python backend.
- Use configd for GUI/API to backend calls.
- Avoid shell commands built from user input.
- Use structured JSON logs.
- Use synthetic test data.
- Do not store payloads or secrets.

## Adding Detectors

New detectors must implement the detector interface, return the versioned detection schema, and include deterministic tests.

## Adding Data Sources

New collectors should normalize into the internal event schema before reaching the detection engine.
