# DART-Guard: experimental PyPI source release

Package name in pyproject.toml: `dartguard-research`; availability has not been verified.

## Validate

```bash
python -m pip install -U build twine pytest
python -m pip install -e '.[dev]'
python -m pytest -q
python -m build
python -m twine check dist/*
```

Upload to TestPyPI, verify a clean isolated installation and inspect metadata and package contents before publishing to PyPI. Publication requires maintainer credentials and approval.

## Security limitations

This is **research software**, not a production security-certified agent gateway. The `TrustedDecisionService` reference adds HMAC-SHA256 permits tied to principal, action ID and canonical JSON arguments, plus SQLite atomic replay claims. These do not create an isolated, authenticated operating-system or network service. Hardware-isolated verification, trustworthy authorization data, protected signing keys, executor bypass prevention and independent security review remain unverified.

Controlled evidence from the earlier trained-proxy benchmark: 6,300 FP32 fault attempts, 109 fault-induced EXECUTE transitions, 0 permitted with a clean verifier, and 85 passed under shared corruption. These do not establish a general production guarantee.
